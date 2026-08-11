mod doctor;
mod firewall;
mod gateway;
mod process;
mod routing;
mod tunnel;

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use hushwire::config::Config;
use hushwire::router::Router;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "hushwire")]
#[command(about = "A debuggable WireGuard-like L3 tunnel")]
#[command(version)]
struct Cli {
    #[arg(long, global = true, default_value = "text")]
    log_format: LogFormat,

    /// Start in a new POSIX session so a transient privileged launcher cannot
    /// terminate the long-running tunnel when the launcher is reclaimed.
    #[arg(long, global = true, hide = true)]
    detach_session: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    Route {
        #[arg(short, long)]
        config: PathBuf,
        destination: Ipv4Addr,
    },
    Explain {
        #[arg(short, long)]
        config: PathBuf,
        destination: Ipv4Addr,
    },
    PlanRoutes {
        #[arg(short, long)]
        config: PathBuf,
    },
    Doctor {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        exit_node: bool,
    },
    Up {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        exit_node: bool,
    },
    /// Manage the explicit Linux LAN-to-HushWire forwarding gateway policy.
    Gateway {
        #[command(subcommand)]
        command: GatewayCommand,
    },
    /// Generate a new static key pair for the Noise handshake.
    /// Prints the private key (for your config) and public key (for your peer's config).
    Genkey,
}

#[derive(Debug, Subcommand)]
enum GatewayCommand {
    /// Print the forwarding, NAT, and MSS changes without applying them.
    Plan {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Apply the owned forwarding, NAT, and bidirectional MSS rules.
    Apply {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Inspect the effective gateway interfaces, MTU, forwarding, and rules.
    Status {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Remove only the rules owned by this gateway configuration.
    Remove {
        #[arg(short, long)]
        config: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_format);

    if cli.detach_session {
        let detached = process::detach_session().context("detaching from launcher session")?;
        tracing::info!(
            pid = detached.pid,
            previous_process_group = detached.previous_process_group,
            session_id = detached.session_id,
            "detached process from launcher session"
        );
    }

    match cli.command {
        Command::Check { config } => {
            let config = Config::load(&config)?;
            let router = Router::new(&config)?;
            println!("config ok");
            println!("interface: {}", config.interface.name);
            println!("listen: {}", config.interface.listen);
            println!("routes: {}", router.routes().len());
        }
        Command::Route {
            config,
            destination,
        } => {
            let config = Config::load(&config)?;
            let router = Router::new(&config)?;
            match router.lookup(destination) {
                Some(route) => {
                    println!(
                        "{} -> peer={} endpoint={} via={}",
                        destination, route.peer.name, route.peer.endpoint, route.prefix
                    );
                }
                None => {
                    println!("{destination} -> no route");
                }
            }
        }
        Command::Explain {
            config,
            destination,
        } => {
            let config = Config::load(&config)?;
            let router = Router::new(&config)?;
            explain_route(&config, &router, destination);
        }
        Command::PlanRoutes { config } => {
            let config = Config::load(&config)?;
            let router = Router::new(&config)?;
            plan_routes(&config, &router);
        }
        Command::Doctor { config, exit_node } => {
            let config = Config::load(&config)?;
            let router = Router::new(&config)?;
            doctor::run(&config, &router, exit_node)?;
        }
        Command::Up { config, exit_node } => {
            let config = Config::load(&config)?;
            tunnel::run(config, exit_node).context("tunnel stopped")?;
        }
        Command::Gateway { command } => match command {
            GatewayCommand::Plan { config } => {
                let config = Config::load(&config)?;
                gateway::GatewayPlan::from_config(&config)?.print();
            }
            GatewayCommand::Apply { config } => {
                let config = Config::load(&config)?;
                gateway::GatewayPlan::from_config(&config)?.apply()?;
            }
            GatewayCommand::Status { config } => {
                let config = Config::load(&config)?;
                let plan = gateway::GatewayPlan::from_config(&config)?;
                let status = plan.status()?;
                plan.print_status(&status);
                if !status.healthy() {
                    anyhow::bail!("gateway configuration is incomplete");
                }
            }
            GatewayCommand::Remove { config } => {
                let config = Config::load(&config)?;
                gateway::GatewayPlan::from_config(&config)?.remove()?;
            }
        },
        Command::Genkey => {
            genkey();
        }
    }

    Ok(())
}

fn genkey() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    println!("PrivateKey = {}", STANDARD.encode(secret.to_bytes()));
    println!("PublicKey  = {}", STANDARD.encode(public.as_bytes()));
    println!();
    println!("# Put PrivateKey in your [interface] section.");
    println!("# Put the peer's PublicKey in their [[peer]] section.");
}

fn explain_route(config: &Config, router: &Router, destination: Ipv4Addr) {
    println!("Config: {}", config.interface.name);
    println!("Destination: {destination}");
    println!("Local tunnel address: {}", config.interface.address.addr());
    println!(
        "Transport: {:?} listening on {}",
        config.interface.transport, config.interface.listen
    );

    match router.lookup(destination) {
        Some(route) => {
            println!("Decision: send");
            println!(
                "Reason: {destination} matches allowed_ips entry {}.",
                route.prefix
            );
            println!("Peer: {}", route.peer.name);
            println!("Peer endpoint: {}", route.peer.endpoint);
        }
        None => {
            println!("Decision: drop");
            println!("Reason: no peer allowed_ips entry matches {destination}.");
            if router.routes().is_empty() {
                println!("Configured routes: none");
            } else {
                println!("Configured routes:");
                for route in router.routes() {
                    println!("  {} -> {}", route.prefix, route.peer.name);
                }
            }
        }
    }
}

fn plan_routes(config: &Config, router: &Router) {
    println!("Interface: {}", config.interface.name);
    println!("Tunnel address: {}", config.interface.address);
    println!("Transport listen: {}", config.interface.listen);

    if router.routes().is_empty() {
        println!("No allowed_ips routes are configured.");
        return;
    }

    println!();
    println!("Routes HushWire will use internally:");
    for route in router.routes() {
        println!(
            "  {} -> peer {} ({})",
            route.prefix, route.peer.name, route.peer.endpoint
        );
    }

    if !router.excluded_routes().is_empty() {
        println!();
        println!("Configured routes that remain on the physical network:");
        for route in router.excluded_routes() {
            println!(
                "  {} (excluded from peer {})",
                route.prefix, route.peer.name
            );
        }
    }

    println!();
    println!("Host routes you need outside HushWire:");

    for route in router.routes() {
        if route.prefix.prefix_len() == 0 {
            println!();
            println!("Full-tunnel route detected: {}", route.prefix);
            println!("Before replacing the default route, keep the peer endpoint reachable outside the tunnel:");
            println!(
                "  sudo route add -host {} <current_gateway>",
                route.peer.endpoint.ip()
            );
            println!("Then route default traffic into the TUN interface:");
            println!(
                "  sudo route add default -interface {}",
                config.interface.name
            );
            println!("If your OS already has a default route, replace/add semantics may differ.");
        } else if route.prefix.prefix_len() == 32 {
            println!(
                "  sudo route add -host {} -interface {}",
                route.prefix.addr(),
                config.interface.name
            );
        } else {
            println!(
                "  sudo route add -net {} -interface {}",
                route.prefix, config.interface.name
            );
        }
    }

    println!();
    println!("Exit-node peer requirements:");
    println!("  enable IPv4 forwarding");
    println!("  enable NAT/masquerade from the tunnel subnet to the outbound interface");
}

fn init_tracing(format: &LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    match format {
        LogFormat::Text => subscriber.init(),
        LogFormat::Json => subscriber.json().init(),
    }
}
