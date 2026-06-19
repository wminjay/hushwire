use std::net::IpAddr;
use std::process::Command;

use anyhow::Context;
use tracing::{info, warn};

use crate::router::Router;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    Tun,
    EndpointException,
}

#[derive(Clone, Debug)]
pub struct InstalledRoute {
    pub kind: RouteKind,
    pub spec: String,
    pub tun_name: String,
}

/// Manages OS-level routes for the tunnel.
#[derive(Debug)]
pub struct RouteManager {
    tun_name: String,
    installed: Vec<InstalledRoute>,
}

impl RouteManager {
    pub fn new(tun_name: String) -> Self {
        Self {
            tun_name,
            installed: Vec::new(),
        }
    }

    pub fn installed(&self) -> &[InstalledRoute] {
        &self.installed
    }

    /// Install routes based on the router configuration.
    pub fn setup(&mut self, router: &Router) -> anyhow::Result<()> {
        for route in router.routes() {
            if route.prefix.prefix_len() == 0 {
                // Full-tunnel: split default route to avoid replacing it directly.
                info!(peer = %route.peer.name, endpoint = %route.peer.endpoint, "installing full-tunnel routes");
                self.add_endpoint_exception(&route.peer.endpoint.ip())?;
                self.add_tun_route("0.0.0.0/1")?;
                self.add_tun_route("128.0.0.0/1")?;
            } else if route.prefix.prefix_len() == 32 {
                self.add_tun_route(&format!("{}/32", route.prefix.addr()))?;
            } else {
                self.add_tun_route(&route.prefix.to_string())?;
            }
        }
        Ok(())
    }

    /// Remove all routes that were previously installed.
    #[allow(dead_code)]
    pub fn cleanup(&self) {
        cleanup_routes(&self.installed);
    }

    fn add_tun_route(&mut self, prefix: &str) -> anyhow::Result<()> {
        info!(prefix = %prefix, dev = %self.tun_name, "adding route");
        add_route_to_dev(prefix, &self.tun_name)
            .with_context(|| format!("add route {prefix} dev {}", self.tun_name))?;
        self.installed.push(InstalledRoute {
            kind: RouteKind::Tun,
            spec: prefix.to_string(),
            tun_name: self.tun_name.clone(),
        });
        Ok(())
    }

    fn add_endpoint_exception(&mut self, ip: &IpAddr) -> anyhow::Result<()> {
        let host = ip.to_string();
        match get_route_info(&host) {
            Ok((Some(gateway), dev)) => {
                info!(host = %host, gateway = %gateway, dev = %dev, "adding endpoint exception route");
                if let Err(e) = add_host_route_via(&host, &gateway, &dev) {
                    warn!(host = %host, error = %e, "failed to add endpoint exception route via gateway");
                }
            }
            Ok((None, dev)) => {
                info!(host = %host, dev = %dev, "adding endpoint exception route (no gateway)");
                if let Err(e) = add_host_route_dev(&host, &dev) {
                    warn!(host = %host, error = %e, "failed to add endpoint exception route via dev");
                }
            }
            Err(e) => {
                warn!(host = %host, error = %e, "could not determine gateway for endpoint; manual route may be required");
            }
        }
        self.installed.push(InstalledRoute {
            kind: RouteKind::EndpointException,
            spec: host,
            tun_name: self.tun_name.clone(),
        });
        Ok(())
    }
}

/// Delete a list of installed routes (useful for signal handlers).
pub fn cleanup_routes(routes: &[InstalledRoute]) {
    info!(routes = routes.len(), "cleaning up routes");
    for entry in routes {
        if let Err(e) = match entry.kind {
            RouteKind::Tun => del_tun_route(&entry.spec, &entry.tun_name),
            RouteKind::EndpointException => del_host_route(&entry.spec),
        } {
            warn!(spec = %entry.spec, error = %e, "failed to delete route");
        }
    }
}

// ------------------------------------------------------------------
// Linux implementations
// ------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn add_route_to_dev(prefix: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("ip")
        .args(["route", "add", prefix, "dev", dev])
        .status()
        .context("running ip route add")?;
    if !status.success() {
        anyhow::bail!("ip route add failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn del_tun_route(prefix: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("ip")
        .args(["route", "del", prefix, "dev", dev])
        .status()
        .context("running ip route del")?;
    if !status.success() {
        anyhow::bail!("ip route del failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_host_route_via(host: &str, gateway: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("ip")
        .args(["route", "add", host, "via", gateway, "dev", dev])
        .status()
        .context("running ip route add host via")?;
    if !status.success() {
        anyhow::bail!("ip route add host via failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_host_route_dev(host: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("ip")
        .args(["route", "add", host, "dev", dev])
        .status()
        .context("running ip route add host dev")?;
    if !status.success() {
        anyhow::bail!("ip route add host dev failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn del_host_route(host: &str) -> anyhow::Result<()> {
    let status = Command::new("ip")
        .args(["route", "del", host])
        .status()
        .context("running ip route del host")?;
    if !status.success() {
        anyhow::bail!("ip route del host failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn get_route_info(dst: &str) -> anyhow::Result<(Option<String>, String)> {
    let output = Command::new("ip")
        .args(["route", "get", dst])
        .output()
        .context("running ip route get")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next().context("empty ip route get output")?;

    let mut gateway = None;
    let mut dev = None;

    let parts: Vec<&str> = line.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "via" && i + 1 < parts.len() {
            gateway = Some(parts[i + 1].to_string());
        }
        if *part == "dev" && i + 1 < parts.len() {
            dev = Some(parts[i + 1].to_string());
        }
    }

    let dev = dev.context("could not find 'dev' in ip route get output")?;
    Ok((gateway, dev))
}

// ------------------------------------------------------------------
// macOS implementations
// ------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn add_route_to_dev(prefix: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("route")
        .args(["add", "-net", prefix, "-interface", dev])
        .status()
        .context("running route add")?;
    if !status.success() {
        anyhow::bail!("route add failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn del_tun_route(prefix: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("route")
        .args(["delete", "-net", prefix, "-interface", dev])
        .status()
        .context("running route delete")?;
    if !status.success() {
        anyhow::bail!("route delete failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn add_host_route_via(host: &str, gateway: &str, _dev: &str) -> anyhow::Result<()> {
    let status = Command::new("route")
        .args(["add", "-host", host, gateway])
        .status()
        .context("running route add host")?;
    if !status.success() {
        anyhow::bail!("route add host failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn add_host_route_dev(host: &str, _dev: &str) -> anyhow::Result<()> {
    // macOS route requires a gateway address; use "interface" syntax
    // as a fallback (may not work on all macOS versions).
    warn!(host = %host, "macOS endpoint exception without gateway; manual route may be required");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn del_host_route(host: &str) -> anyhow::Result<()> {
    let status = Command::new("route")
        .args(["delete", "-host", host])
        .status()
        .context("running route delete host")?;
    if !status.success() {
        anyhow::bail!("route delete host failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn get_route_info(dst: &str) -> anyhow::Result<(Option<String>, String)> {
    let output = Command::new("route")
        .args(["-n", "get", dst])
        .output()
        .context("running route -n get")?;
    let text = String::from_utf8_lossy(&output.stdout);

    let mut gateway = None;
    let mut interface = None;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            gateway = line.split_whitespace().nth(1).map(String::from);
        }
        if line.starts_with("interface:") {
            interface = line.split_whitespace().nth(1).map(String::from);
        }
    }

    let interface = interface.context("could not find interface in route output")?;
    Ok((gateway, interface))
}
