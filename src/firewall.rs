use std::process::Command;

use anyhow::Context;
use tracing::{info, warn};

/// Manages NAT and forwarding rules for an exit node.
#[derive(Debug)]
pub struct FirewallManager {
    tun_name: String,
    subnet: String,
    original_ip_forward: Option<String>,
    rules: Vec<IptablesRule>,
}

#[derive(Clone, Debug)]
struct IptablesRule {
    table: Option<String>,
    chain: String,
    spec: Vec<String>,
}

impl FirewallManager {
    pub fn new(tun_name: String, subnet: String) -> Self {
        Self {
            tun_name,
            subnet,
            original_ip_forward: None,
            rules: Vec::new(),
        }
    }

    /// Enable forwarding and NAT for the tunnel subnet.
    pub fn setup(&mut self) -> anyhow::Result<()> {
        let tun_name = self.tun_name.clone();
        let subnet = self.subnet.clone();
        info!(%subnet, tun = %tun_name, "configuring exit-node firewall");

        self.enable_ip_forward()?;

        // NAT/masquerade traffic from tunnel subnet to any interface except the tunnel itself.
        self.add_iptables_rule(
            Some("nat"),
            "POSTROUTING",
            &["-s", &subnet, "!", "-o", &tun_name, "-j", "MASQUERADE"],
        )?;

        // Allow forwarding into and out of the tunnel.
        self.add_iptables_rule(None, "FORWARD", &["-i", &tun_name, "-j", "ACCEPT"])?;
        self.add_iptables_rule(None, "FORWARD", &["-o", &tun_name, "-j", "ACCEPT"])?;

        Ok(())
    }

    /// Remove all rules that were added.
    pub fn cleanup(&self) {
        info!(rules = self.rules.len(), "cleaning up firewall rules");
        for rule in &self.rules {
            if let Err(e) = del_iptables_rule(rule) {
                warn!(?rule, error = %e, "failed to delete iptables rule");
            }
        }

        if let Some(ref original) = self.original_ip_forward {
            if let Err(e) = write_ip_forward(original) {
                warn!(error = %e, "failed to restore ip_forward");
            }
        }
    }

    fn enable_ip_forward(&mut self) -> anyhow::Result<()> {
        self.original_ip_forward = read_ip_forward().ok();
        if self.original_ip_forward.as_deref() != Some("1") {
            info!("enabling IPv4 forwarding");
            write_ip_forward("1")?;
        }
        Ok(())
    }

    fn add_iptables_rule(
        &mut self,
        table: Option<&str>,
        chain: &str,
        spec: &[&str],
    ) -> anyhow::Result<()> {
        let status = run_iptables(table, chain, "-A", spec)?;
        if !status.success() {
            anyhow::bail!("iptables -A failed");
        }
        self.rules.push(IptablesRule {
            table: table.map(String::from),
            chain: chain.to_string(),
            spec: spec.iter().map(|s| s.to_string()).collect(),
        });
        Ok(())
    }
}

fn run_iptables(
    table: Option<&str>,
    chain: &str,
    action: &str,
    spec: &[&str],
) -> anyhow::Result<std::process::ExitStatus> {
    let mut args = Vec::new();
    if let Some(t) = table {
        args.push("-t");
        args.push(t);
    }
    args.push(action);
    args.push(chain);
    for s in spec {
        args.push(s);
    }
    Command::new("iptables")
        .args(&args)
        .status()
        .with_context(|| format!("running iptables {action} {chain}"))
}

fn del_iptables_rule(rule: &IptablesRule) -> anyhow::Result<()> {
    let spec: Vec<&str> = rule.spec.iter().map(|s| s.as_str()).collect();
    let status = run_iptables(rule.table.as_deref(), &rule.chain, "-D", &spec)?;
    if !status.success() {
        anyhow::bail!("iptables -D failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_ip_forward() -> anyhow::Result<String> {
    let value = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .context("reading /proc/sys/net/ipv4/ip_forward")?;
    Ok(value.trim().to_string())
}

#[cfg(target_os = "linux")]
fn write_ip_forward(val: &str) -> anyhow::Result<()> {
    let status = Command::new("sysctl")
        .args(["-w", &format!("net.ipv4.ip_forward={val}")])
        .status()
        .context("running sysctl")?;
    if !status.success() {
        anyhow::bail!("sysctl failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn read_ip_forward() -> anyhow::Result<String> {
    let output = Command::new("sysctl")
        .args(["-n", "net.inet.ip.forwarding"])
        .output()
        .context("running sysctl")?;
    if !output.status.success() {
        anyhow::bail!("sysctl failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "macos")]
fn write_ip_forward(val: &str) -> anyhow::Result<()> {
    let status = Command::new("sysctl")
        .args(["-w", &format!("net.inet.ip.forwarding={val}")])
        .status()
        .context("running sysctl")?;
    if !status.success() {
        anyhow::bail!("sysctl failed");
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_ip_forward() -> anyhow::Result<String> {
    anyhow::bail!("ip_forward inspection not implemented on this OS")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn write_ip_forward(_val: &str) -> anyhow::Result<()> {
    anyhow::bail!("ip_forward modification not implemented on this OS")
}

/// Compute the subnet CIDR from an interface address (e.g. 10.77.0.1/24 -> 10.77.0.0/24).
pub fn subnet_cidr(addr: &ipnet::Ipv4Net) -> String {
    format!("{}/{}", addr.network(), addr.prefix_len())
}
