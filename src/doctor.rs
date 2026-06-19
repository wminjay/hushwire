use std::net::IpAddr;
use std::process::Command;

use anyhow::Context;

use crate::config::Config;
use crate::router::Router;

pub fn run(config: &Config, router: &Router, exit_node: bool) -> anyhow::Result<()> {
    println!("HushWire doctor");
    println!("Interface: {}", config.interface.name);
    println!("Tunnel address: {}", config.interface.address);
    println!(
        "Transport: {:?} {}",
        config.interface.transport, config.interface.listen
    );
    println!();

    check_routes(config, router);

    if exit_node {
        println!();
        check_forwarding()?;
        println!("NAT: manual check required");
        println!(
            "  tunnel subnet {} must be masqueraded/NATed to the outbound interface",
            config.interface.address.network()
        );
    }

    Ok(())
}

fn check_routes(config: &Config, router: &Router) {
    if router.routes().is_empty() {
        println!("WARN no peer allowed_ips routes are configured");
        return;
    }

    println!("Configured HushWire routes:");
    for route in router.routes() {
        println!(
            "  {} -> {} ({})",
            route.prefix, route.peer.name, route.peer.endpoint
        );
    }

    let full_tunnel_routes: Vec<_> = router
        .routes()
        .iter()
        .filter(|route| route.prefix.prefix_len() == 0)
        .collect();

    if full_tunnel_routes.is_empty() {
        println!("OK no full-tunnel route configured");
        return;
    }

    println!("WARN full-tunnel route configured");
    println!(
        "  before routing default traffic into {}, add endpoint exception routes:",
        config.interface.name
    );

    for route in full_tunnel_routes {
        let endpoint_ip = route.peer.endpoint.ip();
        println!("  endpoint {} for peer {}", endpoint_ip, route.peer.name);

        match host_route_to(endpoint_ip) {
            Ok(host_route) => {
                if host_route.uses_interface(&config.interface.name) {
                    println!(
                        "  FAIL current host route appears to use {}; this can loop the tunnel",
                        config.interface.name
                    );
                } else {
                    println!(
                        "  OK current host route does not appear to use {}",
                        config.interface.name
                    );
                }
                for line in host_route.summary_lines() {
                    println!("    {line}");
                }
            }
            Err(error) => {
                println!("  WARN could not inspect host route: {error:#}");
            }
        }

        println!("  suggested macOS exception:");
        println!("    sudo route add -host {endpoint_ip} <current_gateway>");
    }
}

fn check_forwarding() -> anyhow::Result<()> {
    println!("Exit-node checks:");

    let forwarding = ipv4_forwarding().context("failed to inspect IPv4 forwarding")?;
    match forwarding {
        Some(true) => println!("OK IPv4 forwarding appears enabled"),
        Some(false) => {
            println!("FAIL IPv4 forwarding appears disabled");
            println!("  macOS: sudo sysctl -w net.inet.ip.forwarding=1");
            println!("  Linux: sudo sysctl -w net.ipv4.ip_forward=1");
        }
        None => println!("WARN IPv4 forwarding status is unknown on this OS"),
    }

    Ok(())
}

fn ipv4_forwarding() -> anyhow::Result<Option<bool>> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
            .context("failed to run sysctl")?;
        if !output.status.success() {
            return Ok(None);
        }
        let value = String::from_utf8_lossy(&output.stdout);
        Ok(Some(value.trim() == "1"))
    }

    #[cfg(target_os = "linux")]
    {
        let value = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("failed to read /proc/sys/net/ipv4/ip_forward")?;
        return Ok(Some(value.trim() == "1"));
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Ok(None)
    }
}

#[derive(Debug)]
struct HostRoute {
    output: String,
}

impl HostRoute {
    fn uses_interface(&self, interface: &str) -> bool {
        self.output.lines().map(str::trim).any(|line| {
            line == format!("interface: {interface}")
                || line.ends_with(&format!(" dev {interface}"))
        })
    }

    fn summary_lines(&self) -> impl Iterator<Item = &str> {
        self.output.lines().map(str::trim).filter(|line| {
            line.starts_with("gateway:")
                || line.starts_with("interface:")
                || line.starts_with("route to:")
                || line.contains(" dev ")
                || line.starts_with("default via ")
        })
    }
}

fn host_route_to(ip: IpAddr) -> anyhow::Result<HostRoute> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args(["-n", "get", &ip.to_string()])
            .output()
            .context("failed to run route -n get")?;
        command_output(output)
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "get", &ip.to_string()])
            .output()
            .context("failed to run ip route get")?;
        return command_output(output);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = ip;
        anyhow::bail!("host route inspection is not implemented on this OS")
    }
}

fn command_output(output: std::process::Output) -> anyhow::Result<HostRoute> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{}", stderr.trim());
    }

    Ok(HostRoute {
        output: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}
