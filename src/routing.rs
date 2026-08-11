use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::time::Duration;

use anyhow::Context;
use hushwire::router::Router;
use tracing::{info, warn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    Tun,
    EndpointException,
    ExcludedPrefix,
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
        let result = self.setup_inner(router);
        if result.is_err() {
            cleanup_routes(&self.installed);
            self.installed.clear();
        }
        result
    }

    fn setup_inner(&mut self, router: &Router) -> anyhow::Result<()> {
        // Resolve and pin every captured transport endpoint before installing
        // any tunnel route. This protects both a /0 full tunnel and large
        // split-route sets from recursively routing their own encrypted flow.
        let mut installed_exclusions = HashSet::new();
        for route in router.excluded_routes() {
            if installed_exclusions.insert(route.prefix) {
                info!(peer = %route.peer.name, prefix = %route.prefix, "installing configured direct-route exclusion");
                self.add_prefix_exception(&route.prefix)?;
            }
        }
        for peer in router.endpoint_exception_peers() {
            info!(peer = %peer.name, endpoint = %peer.endpoint, "installing endpoint exception");
            self.add_endpoint_exception(&peer.endpoint.ip())?;
        }

        for route in router.routes() {
            if route.prefix.prefix_len() == 0 {
                // Full-tunnel: split default route to avoid replacing it directly.
                info!(peer = %route.peer.name, endpoint = %route.peer.endpoint, "installing full-tunnel routes");
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
                add_host_route_via(&host, &gateway, &dev)
                    .with_context(|| format!("add endpoint exception for {host} via {gateway}"))?;
            }
            Ok((None, dev)) => {
                info!(host = %host, dev = %dev, "adding endpoint exception route (no gateway)");
                add_host_route_dev(&host, &dev)
                    .with_context(|| format!("add endpoint exception for {host} on {dev}"))?;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("determine physical route before excluding endpoint {host}")
                });
            }
        }
        self.installed.push(InstalledRoute {
            kind: RouteKind::EndpointException,
            spec: host,
            tun_name: self.tun_name.clone(),
        });
        Ok(())
    }

    fn add_prefix_exception(&mut self, prefix: &ipnet::Ipv4Net) -> anyhow::Result<()> {
        let spec = prefix.to_string();
        let probe = if prefix.prefix_len() == 32 {
            prefix.network()
        } else {
            std::net::Ipv4Addr::from(u32::from(prefix.network()).saturating_add(1))
        };
        let (gateway, dev) = get_route_info(&probe.to_string())
            .with_context(|| format!("determine physical route before excluding {spec}"))?;
        if let Some(gateway) = gateway {
            info!(prefix = %spec, gateway = %gateway, dev = %dev, "adding configured direct-route exclusion");
            add_prefix_route_via(&spec, &gateway, &dev)
                .with_context(|| format!("add direct-route exclusion {spec} via {gateway}"))?;
        } else {
            info!(prefix = %spec, dev = %dev, "adding configured direct-route exclusion without gateway");
            add_prefix_route_dev(&spec, &dev)
                .with_context(|| format!("add direct-route exclusion {spec} on {dev}"))?;
        }
        self.installed.push(InstalledRoute {
            kind: RouteKind::ExcludedPrefix,
            spec,
            tun_name: dev,
        });
        Ok(())
    }
}

/// Delete a list of installed routes (useful for signal handlers).
pub fn cleanup_routes(routes: &[InstalledRoute]) {
    info!(routes = routes.len(), "cleaning up routes");
    for entry in routes.iter().rev() {
        if let Err(e) = match entry.kind {
            RouteKind::Tun => del_tun_route(&entry.spec, &entry.tun_name),
            RouteKind::EndpointException => del_host_route(&entry.spec),
            RouteKind::ExcludedPrefix => del_prefix_exception(&entry.spec, &entry.tun_name),
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
    delete_linux_route(&["route", "del", prefix, "dev", dev], prefix, Some(dev))
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
fn add_prefix_route_via(prefix: &str, gateway: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("ip")
        .args(["route", "add", prefix, "via", gateway, "dev", dev])
        .status()
        .context("running ip route add excluded prefix via")?;
    if !status.success() {
        anyhow::bail!("ip route add excluded prefix via failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_prefix_route_dev(prefix: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("ip")
        .args(["route", "add", prefix, "dev", dev])
        .status()
        .context("running ip route add excluded prefix dev")?;
    if !status.success() {
        anyhow::bail!("ip route add excluded prefix dev failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn del_prefix_exception(prefix: &str, dev: &str) -> anyhow::Result<()> {
    delete_linux_route(&["route", "del", prefix, "dev", dev], prefix, Some(dev))
}

#[cfg(target_os = "linux")]
pub fn del_host_route(host: &str) -> anyhow::Result<()> {
    delete_linux_route(&["route", "del", host], host, None)
}

#[cfg(target_os = "linux")]
fn delete_linux_route(arguments: &[&str], prefix: &str, dev: Option<&str>) -> anyhow::Result<()> {
    // systemd's default KillMode=control-group can race with shutdown cleanup:
    // an `ip` child spawned while systemd is enumerating the cgroup may inherit
    // the unit's SIGTERM and exit without stderr. A short bounded retry runs
    // after that enumeration while still requiring the exact route to vanish.
    const ATTEMPTS: usize = 3;
    const RETRY_DELAY: Duration = Duration::from_millis(10);

    let mut last_failure = None;
    let mut last_check_error = None;
    for attempt in 0..ATTEMPTS {
        let output = Command::new("ip")
            .args(arguments)
            .output()
            .context("running ip route del")?;
        if output.status.success() {
            return Ok(());
        }

        match linux_route_exists(prefix, dev) {
            Ok(false) => return Ok(()),
            Ok(true) => last_check_error = None,
            Err(error) => last_check_error = Some(error),
        }
        last_failure = Some(output);

        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(RETRY_DELAY);
        }
    }

    let output = last_failure.expect("route deletion attempted at least once");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = if stderr.trim().is_empty() {
        "no stderr".to_string()
    } else {
        stderr.trim().to_string()
    };
    if let Some(error) = last_check_error {
        anyhow::bail!(
            "ip route del failed ({}, {detail}); final route check failed: {error}",
            output.status
        );
    }
    anyhow::bail!("ip route del failed ({}, {detail})", output.status);
}

#[cfg(target_os = "linux")]
fn linux_route_exists(prefix: &str, dev: Option<&str>) -> anyhow::Result<bool> {
    // Query without a device filter. If the TUN has already disappeared,
    // `ip route show ... dev <tun>` itself can fail even though cleanup has
    // reached the desired state.
    let output = Command::new("ip")
        .args(["route", "show", prefix])
        .output()
        .context("running ip route show after delete")?;
    if !output.status.success() {
        anyhow::bail!("ip route show failed after delete");
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    Ok(route_listing_contains(&listing, dev))
}

#[cfg(any(target_os = "linux", test))]
fn route_listing_contains(listing: &str, dev: Option<&str>) -> bool {
    listing.lines().any(|line| match dev {
        None => !line.trim().is_empty(),
        Some(expected) => route_line_uses_dev(line, expected),
    })
}

#[cfg(any(target_os = "linux", test))]
fn route_line_uses_dev(line: &str, expected: &str) -> bool {
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next() == Some(expected);
        }
    }
    false
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
fn add_host_route_dev(host: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("route")
        .args(["add", "-host", host, "-interface", dev])
        .status()
        .context("running route add host via interface")?;
    if !status.success() {
        anyhow::bail!("route add host via interface failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn add_prefix_route_via(prefix: &str, gateway: &str, _dev: &str) -> anyhow::Result<()> {
    let status = Command::new("route")
        .args(["add", "-net", prefix, gateway])
        .status()
        .context("running route add excluded prefix")?;
    if !status.success() {
        anyhow::bail!("route add excluded prefix failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn add_prefix_route_dev(prefix: &str, dev: &str) -> anyhow::Result<()> {
    let status = Command::new("route")
        .args(["add", "-net", prefix, "-interface", dev])
        .status()
        .context("running route add excluded prefix via interface")?;
    if !status.success() {
        anyhow::bail!("route add excluded prefix via interface failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn del_prefix_exception(prefix: &str, _dev: &str) -> anyhow::Result<()> {
    let status = Command::new("route")
        .args(["delete", "-net", prefix])
        .status()
        .context("running route delete excluded prefix")?;
    if !status.success() {
        anyhow::bail!("route delete excluded prefix failed");
    }
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

#[cfg(test)]
mod tests {
    use super::route_listing_contains;

    #[test]
    fn route_listing_distinguishes_target_device() {
        let listing = "10.77.60.2 dev hwmactw0 scope link\n";
        assert!(route_listing_contains(listing, Some("hwmactw0")));
        assert!(!route_listing_contains(listing, Some("stb0")));
        assert!(route_listing_contains(listing, None));
        assert!(!route_listing_contains("", None));
    }
}
