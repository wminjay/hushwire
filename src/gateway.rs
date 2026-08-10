use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context};
use hushwire::config::Config;

const IPV4_MINIMUM_TCP_MSS: u16 = 536;
const IPV4_TCP_HEADER_BYTES: u16 = 40;
const STATE_DIRECTORY_ENV: &str = "HUSHWIRE_GATEWAY_STATE_DIR";

#[derive(Clone, Debug)]
pub struct GatewayPlan {
    lan_interface: String,
    tunnel_interface: String,
    tunnel_mtu: u16,
    tcp_mss: u16,
    tcp_mss_is_explicit: bool,
    owner_tag: String,
    rules: Vec<IptablesRule>,
}

#[derive(Clone, Debug)]
struct IptablesRule {
    table: Option<&'static str>,
    chain: &'static str,
    spec: Vec<String>,
    description: &'static str,
}

#[derive(Debug)]
pub struct GatewayStatus {
    pub forwarding_enabled: bool,
    pub lan_interface_exists: bool,
    pub tunnel_interface_exists: bool,
    pub tunnel_mtu: Option<u16>,
    pub expected_tunnel_mtu: u16,
    pub state_recorded: bool,
    pub owned_rule_count: usize,
    pub expected_rule_count: usize,
    pub rules: Vec<(&'static str, bool)>,
}

impl GatewayStatus {
    pub fn healthy(&self) -> bool {
        self.forwarding_enabled
            && self.lan_interface_exists
            && self.tunnel_interface_exists
            && self.tunnel_mtu == Some(self.expected_tunnel_mtu)
            && self.state_recorded
            && self.owned_rule_count == self.expected_rule_count
            && self.rules.iter().all(|(_, present)| *present)
    }
}

impl GatewayPlan {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let gateway = config.gateway.as_ref().context(
            "configuration has no [gateway] section; ordinary clients must not manage forwarding",
        )?;
        let tunnel_mtu = config.interface.mtu;
        let maximum_mss = tunnel_mtu
            .checked_sub(IPV4_TCP_HEADER_BYTES)
            .context("tunnel MTU is too small to derive an IPv4 TCP MSS")?;
        let tcp_mss = gateway.tcp_mss.unwrap_or(maximum_mss);
        if !(IPV4_MINIMUM_TCP_MSS..=maximum_mss).contains(&tcp_mss) {
            bail!(
                "TCP MSS {tcp_mss} is outside the safe range {IPV4_MINIMUM_TCP_MSS}..={maximum_mss} for tunnel MTU {tunnel_mtu}"
            );
        }

        let lan_interface = gateway.lan_interface.trim().to_string();
        let tunnel_interface = config.interface.name.clone();
        // The tunnel interface is the stable policy identity. This lets an
        // operator change the LAN interface or MSS and have apply reconcile
        // old rules instead of leaving stale rules ahead of the new policy.
        let owner_tag = format!("hushwire-gateway:{tunnel_interface}");
        let comment = vec![
            "-m".to_string(),
            "comment".to_string(),
            "--comment".to_string(),
            owner_tag.clone(),
        ];

        let mut outbound_mss = vec![
            "-i".into(),
            lan_interface.clone(),
            "-o".into(),
            tunnel_interface.clone(),
            "-p".into(),
            "tcp".into(),
            "--tcp-flags".into(),
            "SYN,RST".into(),
            "SYN".into(),
        ];
        outbound_mss.extend(comment.clone());
        outbound_mss.extend([
            "-j".into(),
            "TCPMSS".into(),
            "--set-mss".into(),
            tcp_mss.to_string(),
        ]);

        let mut inbound_mss = vec![
            "-i".into(),
            tunnel_interface.clone(),
            "-o".into(),
            lan_interface.clone(),
            "-p".into(),
            "tcp".into(),
            "--tcp-flags".into(),
            "SYN,RST".into(),
            "SYN".into(),
        ];
        inbound_mss.extend(comment.clone());
        inbound_mss.extend([
            "-j".into(),
            "TCPMSS".into(),
            "--set-mss".into(),
            tcp_mss.to_string(),
        ]);

        let mut masquerade = vec!["-o".into(), tunnel_interface.clone()];
        masquerade.extend(comment.clone());
        masquerade.extend(["-j".into(), "MASQUERADE".into()]);

        let mut allow_outbound = vec![
            "-i".into(),
            lan_interface.clone(),
            "-o".into(),
            tunnel_interface.clone(),
        ];
        allow_outbound.extend(comment.clone());
        allow_outbound.extend(["-j".into(), "ACCEPT".into()]);

        let mut allow_return = vec![
            "-i".into(),
            tunnel_interface.clone(),
            "-o".into(),
            lan_interface.clone(),
            "-m".into(),
            "conntrack".into(),
            "--ctstate".into(),
            "RELATED,ESTABLISHED".into(),
        ];
        allow_return.extend(comment);
        allow_return.extend(["-j".into(), "ACCEPT".into()]);

        Ok(Self {
            lan_interface,
            tunnel_interface,
            tunnel_mtu,
            tcp_mss,
            tcp_mss_is_explicit: gateway.tcp_mss.is_some(),
            owner_tag,
            rules: vec![
                IptablesRule::new(
                    Some("mangle"),
                    "FORWARD",
                    outbound_mss,
                    "LAN to tunnel TCP MSS",
                ),
                IptablesRule::new(
                    Some("mangle"),
                    "FORWARD",
                    inbound_mss,
                    "tunnel to LAN TCP MSS",
                ),
                IptablesRule::new(Some("nat"), "POSTROUTING", masquerade, "tunnel masquerade"),
                IptablesRule::new(None, "FORWARD", allow_outbound, "LAN to tunnel forwarding"),
                IptablesRule::new(
                    None,
                    "FORWARD",
                    allow_return,
                    "established return forwarding",
                ),
            ],
        })
    }

    pub fn print(&self) {
        println!("HushWire gateway plan");
        println!("LAN interface: {}", self.lan_interface);
        println!("Tunnel interface: {}", self.tunnel_interface);
        println!("Tunnel MTU: {}", self.tunnel_mtu);
        println!(
            "TCP MSS: {} ({})",
            self.tcp_mss,
            if self.tcp_mss_is_explicit {
                "explicit"
            } else {
                "automatic: tunnel MTU - 40"
            }
        );
        println!("Rule owner: {}", self.owner_tag);
        println!();
        println!("Changes when applied:");
        println!("  enable net.ipv4.ip_forward");
        for rule in &self.rules {
            println!("  {}", rule.render("-A"));
        }
        println!();
        println!("No changes made by plan.");
    }

    pub fn apply(&self) -> anyhow::Result<()> {
        ensure_linux_root()?;
        self.preflight_interfaces()?;
        ensure_iptables_available()?;

        let state = GatewayStatePaths::new(self)?;
        state.ensure_directory()?;
        let _state_lock = state.lock()?;
        let forwarding_before = read_ip_forward()?;
        let original_created = state.record_original_forwarding(&forwarding_before)?;
        let marker_created = match state.record_gateway(self) {
            Ok(created) => created,
            Err(error) => {
                if original_created {
                    let _ = fs::remove_file(&state.original_forwarding);
                }
                return Err(error).context("recording gateway ownership before system changes");
            }
        };

        let mut added_rules = Vec::new();
        let result = (|| -> anyhow::Result<()> {
            let expected_rules_present = self
                .rules
                .iter()
                .map(IptablesRule::exists)
                .collect::<anyhow::Result<Vec<_>>>()?
                .into_iter()
                .all(|present| present);
            let owned_rule_count = self.count_owned_rules()?;
            if !expected_rules_present || owned_rule_count != self.rules.len() {
                self.delete_owned_rules()?;
            }
            for rule in &self.rules {
                if rule.add_if_missing()? {
                    added_rules.push(rule.clone());
                }
            }
            if forwarding_before != "1" {
                write_ip_forward("1")?;
            }
            Ok(())
        })();

        if let Err(error) = result {
            for rule in added_rules.iter().rev() {
                let _ = rule.delete_once();
            }
            if marker_created {
                let _ = fs::remove_file(&state.marker);
            }
            if original_created && !state.has_gateway_markers()? {
                let _ = write_ip_forward(&forwarding_before);
                let _ = fs::remove_file(&state.original_forwarding);
            }
            return Err(error).context("gateway apply rolled back after a failed system change");
        }

        println!("gateway applied");
        println!("  {} -> {}", self.lan_interface, self.tunnel_interface);
        println!("  TCP MSS {} in both directions", self.tcp_mss);
        println!("  {} owned firewall rules active", self.rules.len());
        Ok(())
    }

    pub fn remove(&self) -> anyhow::Result<()> {
        ensure_linux_root()?;
        ensure_iptables_available()?;
        let state = GatewayStatePaths::new(self)?;
        state.ensure_directory()?;
        let _state_lock = state.lock()?;

        let removed = self.delete_owned_rules()?;

        if state.marker.exists() {
            fs::remove_file(&state.marker)
                .with_context(|| format!("removing {}", state.marker.display()))?;
        }

        let mut restored_forwarding = None;
        if state.original_forwarding.exists() && !state.has_gateway_markers()? {
            let original = fs::read_to_string(&state.original_forwarding)
                .with_context(|| format!("reading {}", state.original_forwarding.display()))?;
            let original = original.trim();
            if matches!(original, "0" | "1") {
                write_ip_forward(original)?;
                restored_forwarding = Some(original.to_string());
            }
            fs::remove_file(&state.original_forwarding)
                .with_context(|| format!("removing {}", state.original_forwarding.display()))?;
        }

        println!("gateway removed");
        println!("  removed {removed} owned firewall rules");
        match restored_forwarding {
            Some(value) => println!("  restored net.ipv4.ip_forward={value}"),
            None => println!("  left shared net.ipv4.ip_forward unchanged"),
        }
        Ok(())
    }

    pub fn status(&self) -> anyhow::Result<GatewayStatus> {
        ensure_linux()?;
        let forwarding_enabled = read_ip_forward()? == "1";
        let lan_interface_exists = interface_path(&self.lan_interface).exists();
        let tunnel_interface_exists = interface_path(&self.tunnel_interface).exists();
        let tunnel_mtu = if tunnel_interface_exists {
            Some(read_interface_mtu(&self.tunnel_interface)?)
        } else {
            None
        };
        let state = GatewayStatePaths::new(self)?;
        let mut rules = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            rules.push((rule.description, rule.exists()?));
        }
        let owned_rule_count = self.count_owned_rules()?;
        Ok(GatewayStatus {
            forwarding_enabled,
            lan_interface_exists,
            tunnel_interface_exists,
            tunnel_mtu,
            expected_tunnel_mtu: self.tunnel_mtu,
            state_recorded: state.marker.exists(),
            owned_rule_count,
            expected_rule_count: self.rules.len(),
            rules,
        })
    }

    pub fn print_status(&self, status: &GatewayStatus) {
        println!("HushWire gateway status");
        println!("{} IPv4 forwarding", result_word(status.forwarding_enabled));
        println!(
            "{} LAN interface {}",
            result_word(status.lan_interface_exists),
            self.lan_interface
        );
        println!(
            "{} tunnel interface {}",
            result_word(status.tunnel_interface_exists),
            self.tunnel_interface
        );
        match status.tunnel_mtu {
            Some(actual) if actual == status.expected_tunnel_mtu => {
                println!("OK tunnel MTU {actual}")
            }
            Some(actual) => println!(
                "FAIL tunnel MTU {actual}; configuration expects {}",
                status.expected_tunnel_mtu
            ),
            None => println!(
                "FAIL tunnel MTU unavailable; configuration expects {}",
                status.expected_tunnel_mtu
            ),
        }
        for (description, present) in &status.rules {
            println!("{} {description}", result_word(*present));
        }
        if status.owned_rule_count == status.expected_rule_count {
            println!("OK {} owned firewall rules", status.owned_rule_count);
        } else {
            println!(
                "FAIL found {} owned firewall rules; expected exactly {}",
                status.owned_rule_count, status.expected_rule_count
            );
        }
        println!(
            "{} gateway state record",
            if status.state_recorded { "OK" } else { "WARN" }
        );
        if let Ok(Some(frag_fails)) = read_ip_frag_fails() {
            println!("INFO cumulative IPv4 fragmentation failures: {frag_fails}");
        }
    }

    fn preflight_interfaces(&self) -> anyhow::Result<()> {
        for interface in [&self.lan_interface, &self.tunnel_interface] {
            if !interface_path(interface).exists() {
                bail!("network interface {interface} does not exist");
            }
        }
        let actual_mtu = read_interface_mtu(&self.tunnel_interface)?;
        if actual_mtu != self.tunnel_mtu {
            bail!(
                "tunnel interface {} has MTU {actual_mtu}, but configuration expects {}; refusing to install an unsafe MSS",
                self.tunnel_interface,
                self.tunnel_mtu
            );
        }
        Ok(())
    }

    fn count_owned_rules(&self) -> anyhow::Result<usize> {
        let mut count = 0usize;
        for location in owned_rule_locations() {
            let output = list_iptables_chain(location.table, location.chain)?;
            count += String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| iptables_line_has_owner(line, &self.owner_tag))
                .count();
        }
        Ok(count)
    }

    fn delete_owned_rules(&self) -> anyhow::Result<usize> {
        let mut removed = 0usize;
        for location in owned_rule_locations() {
            loop {
                let output = list_iptables_chain(location.table, location.chain)?;
                let mut rule_number = 0usize;
                let mut owned_rule_number = None;
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    if !line.starts_with("-A ") {
                        continue;
                    }
                    rule_number += 1;
                    if iptables_line_has_owner(line, &self.owner_tag) {
                        owned_rule_number = Some(rule_number);
                        break;
                    }
                }

                let Some(rule_number) = owned_rule_number else {
                    break;
                };
                delete_iptables_rule_number(location.table, location.chain, rule_number)?;
                removed += 1;
                if removed > 128 {
                    bail!("refusing to remove more than 128 owned gateway rules");
                }
            }
        }
        Ok(removed)
    }
}

#[derive(Clone, Copy, Debug)]
struct IptablesLocation {
    table: Option<&'static str>,
    chain: &'static str,
}

fn owned_rule_locations() -> [IptablesLocation; 3] {
    [
        IptablesLocation {
            table: Some("mangle"),
            chain: "FORWARD",
        },
        IptablesLocation {
            table: Some("nat"),
            chain: "POSTROUTING",
        },
        IptablesLocation {
            table: None,
            chain: "FORWARD",
        },
    ]
}

impl IptablesRule {
    fn new(
        table: Option<&'static str>,
        chain: &'static str,
        spec: Vec<String>,
        description: &'static str,
    ) -> Self {
        Self {
            table,
            chain,
            spec,
            description,
        }
    }

    fn command_args(&self, action: &str) -> Vec<OsString> {
        // Cooperate with package managers and other firewall services rather
        // than failing immediately while the global xtables lock is busy.
        let mut args = vec![OsString::from("--wait"), OsString::from("5")];
        if let Some(table) = self.table {
            args.extend([OsString::from("-t"), OsString::from(table)]);
        }
        args.extend([OsString::from(action), OsString::from(self.chain)]);
        args.extend(self.spec.iter().map(OsString::from));
        args
    }

    fn render(&self, action: &str) -> String {
        let args = self.command_args(action);
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        format!("iptables {rendered}")
    }

    fn exists(&self) -> anyhow::Result<bool> {
        let output = run_iptables(self.command_args("-C"))?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => bail!(
                "{} failed: {}",
                self.render("-C"),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        }
    }

    fn add_if_missing(&self) -> anyhow::Result<bool> {
        if self.exists()? {
            return Ok(false);
        }
        let output = run_iptables(self.command_args("-A"))?;
        if !output.status.success() {
            bail!(
                "{} failed: {}",
                self.render("-A"),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(true)
    }

    fn delete_once(&self) -> anyhow::Result<()> {
        let output = run_iptables(self.command_args("-D"))?;
        if !output.status.success() {
            bail!(
                "{} failed: {}",
                self.render("-D"),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
struct GatewayStatePaths {
    directory: PathBuf,
    namespace_id: String,
    marker: PathBuf,
    original_forwarding: PathBuf,
}

impl GatewayStatePaths {
    fn new(plan: &GatewayPlan) -> anyhow::Result<Self> {
        let directory = std::env::var_os(STATE_DIRECTORY_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/hushwire"));
        let namespace_id = network_namespace_id()?;
        let marker = directory.join(format!(
            "gateway-{namespace_id}-{}.state",
            plan.tunnel_interface
        ));
        let original_forwarding = directory.join(format!("ip-forward-{namespace_id}.original"));
        Ok(Self {
            directory,
            namespace_id,
            marker,
            original_forwarding,
        })
    }

    fn ensure_directory(&self) -> anyhow::Result<()> {
        fs::create_dir_all(&self.directory)
            .with_context(|| format!("creating {}", self.directory.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("securing {}", self.directory.display()))?;
        }
        Ok(())
    }

    fn record_original_forwarding(&self, value: &str) -> anyhow::Result<bool> {
        write_new_file(&self.original_forwarding, &format!("{value}\n"))
    }

    fn record_gateway(&self, plan: &GatewayPlan) -> anyhow::Result<bool> {
        let contents = format!(
            "version=1\nnamespace={}\nlan_interface={}\ntunnel_interface={}\ntunnel_mtu={}\ntcp_mss={}\n",
            self.namespace_id,
            plan.lan_interface,
            plan.tunnel_interface,
            plan.tunnel_mtu,
            plan.tcp_mss
        );
        if write_new_file(&self.marker, &contents)? {
            return Ok(true);
        }
        fs::write(&self.marker, contents)
            .with_context(|| format!("updating {}", self.marker.display()))?;
        Ok(false)
    }

    fn lock(&self) -> anyhow::Result<GatewayStateLock> {
        let path = self
            .directory
            .join(format!("gateway-{}.lock", self.namespace_id));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening gateway state lock {}", path.display()))?;

        #[cfg(unix)]
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error)
                    .with_context(|| format!("locking gateway state {}", path.display()));
            }
        }

        #[cfg(not(unix))]
        bail!("gateway state locking is unsupported on this operating system");

        Ok(GatewayStateLock { file })
    }

    fn has_gateway_markers(&self) -> anyhow::Result<bool> {
        if !self.directory.exists() {
            return Ok(false);
        }
        let prefix = format!("gateway-{}-", self.namespace_id);
        for entry in fs::read_dir(&self.directory)
            .with_context(|| format!("reading {}", self.directory.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".state") {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn write_new_file(path: &Path, contents: &str) -> anyhow::Result<bool> {
    let file = OpenOptions::new().write(true).create_new(true).open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("creating {}", path.display())),
    };
    if let Err(error) = file.write_all(contents.as_bytes()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).with_context(|| format!("writing {}", path.display()));
    }
    Ok(true)
}

#[derive(Debug)]
struct GatewayStateLock {
    file: fs::File,
}

#[cfg(unix)]
impl Drop for GatewayStateLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn result_word(success: bool) -> &'static str {
    if success {
        "OK"
    } else {
        "FAIL"
    }
}

fn ensure_linux() -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("gateway firewall management is currently supported only on Linux");
    }
    Ok(())
}

fn ensure_linux_root() -> anyhow::Result<()> {
    ensure_linux()?;
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        bail!("gateway apply/remove must run as root");
    }
    Ok(())
}

fn ensure_iptables_available() -> anyhow::Result<()> {
    let output = Command::new(iptables_program())
        .arg("--version")
        .output()
        .context("running iptables --version")?;
    if !output.status.success() {
        bail!("iptables is unavailable or failed its version check");
    }
    Ok(())
}

fn iptables_program() -> OsString {
    if let Some(program) = std::env::var_os("HUSHWIRE_IPTABLES") {
        return program;
    }
    if Path::new("/usr/sbin/iptables").exists() {
        OsString::from("/usr/sbin/iptables")
    } else {
        OsString::from("iptables")
    }
}

fn run_iptables(args: Vec<OsString>) -> anyhow::Result<Output> {
    Command::new(iptables_program())
        .args(args)
        .output()
        .context("running iptables")
}

fn list_iptables_chain(table: Option<&str>, chain: &str) -> anyhow::Result<Output> {
    let mut args = vec![OsString::from("--wait"), OsString::from("5")];
    if let Some(table) = table {
        args.extend([OsString::from("-t"), OsString::from(table)]);
    }
    args.extend([OsString::from("-S"), OsString::from(chain)]);
    let output = run_iptables(args)?;
    if !output.status.success() {
        bail!(
            "could not list iptables chain {chain}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

fn delete_iptables_rule_number(
    table: Option<&str>,
    chain: &str,
    rule_number: usize,
) -> anyhow::Result<()> {
    let mut args = vec![OsString::from("--wait"), OsString::from("5")];
    if let Some(table) = table {
        args.extend([OsString::from("-t"), OsString::from(table)]);
    }
    args.extend([
        OsString::from("-D"),
        OsString::from(chain),
        OsString::from(rule_number.to_string()),
    ]);
    let output = run_iptables(args)?;
    if !output.status.success() {
        bail!(
            "could not delete owned rule {rule_number} from iptables chain {chain}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn iptables_line_has_owner(line: &str, owner_tag: &str) -> bool {
    let tokens: Vec<_> = line
        .split_ascii_whitespace()
        .map(|token| token.trim_matches(['\'', '"']))
        .collect();
    tokens
        .windows(2)
        .any(|pair| pair[0] == "--comment" && pair[1] == owner_tag)
}

fn interface_path(interface: &str) -> PathBuf {
    Path::new("/sys/class/net").join(interface)
}

fn read_interface_mtu(interface: &str) -> anyhow::Result<u16> {
    let path = interface_path(interface).join("mtu");
    let value = fs::read_to_string(&path)
        .with_context(|| format!("reading interface MTU from {}", path.display()))?;
    value
        .trim()
        .parse()
        .with_context(|| format!("parsing interface MTU from {}", path.display()))
}

fn read_ip_forward() -> anyhow::Result<String> {
    let value = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .context("reading /proc/sys/net/ipv4/ip_forward")?;
    Ok(value.trim().to_string())
}

fn write_ip_forward(value: &str) -> anyhow::Result<()> {
    let output = Command::new("sysctl")
        .args(["-w", &format!("net.ipv4.ip_forward={value}")])
        .output()
        .context("running sysctl")?;
    if !output.status.success() {
        bail!(
            "sysctl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn network_namespace_id() -> anyhow::Result<String> {
    let target = fs::read_link("/proc/self/ns/net").context("reading current network namespace")?;
    let digits: String = target
        .to_string_lossy()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        bail!("could not identify current network namespace");
    }
    Ok(digits)
}

pub fn read_ip_frag_fails() -> anyhow::Result<Option<u64>> {
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    let contents = fs::read_to_string("/proc/net/snmp").context("reading /proc/net/snmp")?;
    parse_ip_frag_fails(&contents)
}

fn parse_ip_frag_fails(contents: &str) -> anyhow::Result<Option<u64>> {
    let mut lines = contents.lines();
    while let Some(header) = lines.next() {
        let Some(values) = lines.next() else {
            break;
        };
        if !header.starts_with("Ip:") || !values.starts_with("Ip:") {
            continue;
        }
        let names: Vec<_> = header.split_whitespace().skip(1).collect();
        let fields: Vec<_> = values.split_whitespace().skip(1).collect();
        let Some(index) = names.iter().position(|name| *name == "FragFails") else {
            return Ok(None);
        };
        let value = fields
            .get(index)
            .context("/proc/net/snmp Ip field count mismatch")?
            .parse()
            .context("parsing IpFragFails")?;
        return Ok(Some(value));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hushwire::config::{GatewayConfig, InterfaceConfig, TransportConfig};

    fn config(mtu: u16, tcp_mss: Option<u16>) -> Config {
        Config {
            interface: InterfaceConfig {
                name: "stb0".to_string(),
                address: "10.77.4.2/30".parse().unwrap(),
                listen: "0.0.0.0:27779".parse().unwrap(),
                transport: TransportConfig::Udp,
                mtu,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: Some(GatewayConfig {
                lan_interface: "eth0".to_string(),
                tcp_mss,
            }),
            peer: vec![],
        }
    }

    #[test]
    fn derives_ipv4_mss_from_tunnel_mtu() {
        let plan = GatewayPlan::from_config(&config(1280, None)).unwrap();
        assert_eq!(plan.tcp_mss, 1240);
        assert!(!plan.tcp_mss_is_explicit);
    }

    #[test]
    fn accepts_conservative_explicit_mss() {
        let plan = GatewayPlan::from_config(&config(1280, Some(1160))).unwrap();
        assert_eq!(plan.tcp_mss, 1160);
        assert!(plan.tcp_mss_is_explicit);
    }

    #[test]
    fn creates_bidirectional_owned_mss_rules() {
        let plan = GatewayPlan::from_config(&config(1280, Some(1160))).unwrap();
        let rendered: Vec<_> = plan.rules.iter().map(|rule| rule.render("-A")).collect();
        assert!(rendered.iter().any(|rule| {
            rule.contains("-t mangle -A FORWARD -i eth0 -o stb0") && rule.contains("--set-mss 1160")
        }));
        assert!(rendered.iter().any(|rule| {
            rule.contains("-t mangle -A FORWARD -i stb0 -o eth0") && rule.contains("--set-mss 1160")
        }));
        assert!(rendered
            .iter()
            .all(|rule| rule.contains("hushwire-gateway:stb0")));
    }

    #[test]
    fn matches_only_the_exact_owned_comment() {
        assert!(iptables_line_has_owner(
            r#"-A FORWARD -m comment --comment "hushwire-gateway:stb0" -j ACCEPT"#,
            "hushwire-gateway:stb0"
        ));
        assert!(!iptables_line_has_owner(
            "-A FORWARD -m comment --comment hushwire-gateway:stb01 -j ACCEPT",
            "hushwire-gateway:stb0"
        ));
    }

    #[test]
    fn parses_linux_fragment_failure_counter() {
        let sample = "Ip: Forwarding DefaultTTL InReceives FragOKs FragFails FragCreates\n\
                      Ip: 1 64 10 2 4275 4\n";
        assert_eq!(parse_ip_frag_fails(sample).unwrap(), Some(4275));
    }
}
