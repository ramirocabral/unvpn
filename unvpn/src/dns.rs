//! The system resolver while a tunnel is up.
//!
//! When lookups go through systemd-resolved, the tunnel's servers are set on its
//! own link: a split tunnel answers only for its domains, a full tunnel for every
//! name, and several tunnels coexist. Otherwise `/etc/resolv.conf` is rewritten
//! from the servers of every running session (newest first) and put back when the
//! last one ends.

use std::fmt::{Debug, Display};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use unvpn_profiles::control::RUN_DIR;

pub const RESOLV_CONF: &str = "/etc/resolv.conf";
const NSSWITCH: &str = "/etc/nsswitch.conf";
const RESOLVED_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve";
/// First line of the resolv.conf we write, used to recognise our own.
const DNS_MARKER: &str = "# written by unvpn";
/// The resolv.conf from before the first session changed it. `/run` is tmpfs,
/// like the file's usual source.
const DNS_SIDECAR: &str = "/run/unvpn/resolv.orig";
const LOCK: &str = "/run/unvpn/dns.lock";
/// glibc reads at most this many `nameserver` lines.
const MAXNS: usize = 3;

/// What a session changed, undone by [`restore_dns`].
pub enum DnsBackup {
    /// Servers and domains set on this link in systemd-resolved.
    Resolved(String),
    /// This session's entry in the shared resolv.conf.
    File,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Resolved,
    File,
}

/// `UNVPN_DNS=resolved|file` overrides the choice.
fn mode() -> Mode {
    match std::env::var("UNVPN_DNS").as_deref() {
        Ok("file") => return Mode::File,
        Ok("resolved") => return Mode::Resolved,
        _ => {}
    }
    let resolv = std::fs::read_to_string(RESOLV_CONF).unwrap_or_default();
    let link = std::fs::read_link(RESOLV_CONF).ok();
    let nss = std::fs::read_to_string(NSSWITCH).unwrap_or_default();
    if resolved_running() && goes_through_resolved(link.as_deref(), &resolv, &nss) {
        Mode::Resolved
    } else {
        Mode::File
    }
}

fn resolved_running() -> bool {
    std::os::unix::net::UnixStream::connect(RESOLVED_SOCKET).is_ok()
}

/// Lookups reach systemd-resolved: resolv.conf is one of its files or points at
/// its stub listener, or NSS asks it directly.
fn goes_through_resolved(link: Option<&Path>, resolv: &str, nsswitch: &str) -> bool {
    let its_file = link.is_some_and(|t| {
        t.starts_with("/run/systemd/resolve/") || t.starts_with("/usr/lib/systemd/")
    });
    let stub = resolv.lines().any(|l| {
        let mut w = l.split_whitespace();
        w.next() == Some("nameserver") && matches!(w.next(), Some("127.0.0.53" | "127.0.0.54"))
    });
    its_file || stub || nss_uses_resolve(nsswitch)
}

fn nss_uses_resolve(nsswitch: &str) -> bool {
    nsswitch.lines().any(|l| {
        let l = l.split('#').next().unwrap_or("");
        let Some(srcs) = l.trim_start().strip_prefix("hosts:") else {
            return false;
        };
        srcs.split_whitespace()
            .filter(|w| !w.starts_with('['))
            .any(|w| w == "resolve")
    })
}

/// Point the resolver at `dns` (IPv4 or IPv6 servers of the tunnel on `iface`)
/// with the search `domains`. `full`: every name goes to the tunnel; otherwise
/// only its domains do (or, when it sent none, its servers join the system's).
/// `None` (nothing changed) when `dns` is empty.
pub fn set_dns<A: Display + Debug>(
    iface: &str,
    dns: &[A],
    domains: &str,
    full: bool,
) -> Option<DnsBackup> {
    let servers: Vec<IpAddr> = dns
        .iter()
        .filter_map(|d| d.to_string().parse().ok())
        .collect();
    if servers.is_empty() {
        crate::report::dns(&servers);
        return None;
    }
    let search: Vec<String> = search_domains(domains)
        .into_iter()
        .map(String::from)
        .collect();
    if mode() == Mode::Resolved {
        match resolved_set(iface, &servers, &search, full) {
            Ok(()) => {
                let scope = if full {
                    "every lookup".to_string()
                } else if search.is_empty() {
                    "alongside the system's servers (the gateway sent no domains)".to_string()
                } else {
                    format!("only {}", search.join(" "))
                };
                out!("# DNS → {servers:?} on {iface} via systemd-resolved — {scope}");
                crate::report::dns(&servers);
                return Some(DnsBackup::Resolved(iface.to_string()));
            }
            Err(e) => {
                let _ = resolvectl(&["revert", iface]);
                out!("# (systemd-resolved refused the DNS settings: {e} — writing {RESOLV_CONF} instead)");
            }
        }
    }
    file_set(&servers, &search)
}

/// Undo [`set_dns`].
pub fn restore_dns(backup: Option<DnsBackup>) {
    match backup {
        None => {}
        Some(DnsBackup::Resolved(iface)) => {
            let _ = resolvectl(&["revert", &iface]);
            out!("# DNS restored");
        }
        Some(DnsBackup::File) => {
            let _lock = Lock::take();
            let _ = std::fs::remove_file(entry_path(std::process::id()));
            if write_shared() {
                out!("# DNS restored");
            }
        }
    }
}

/// `unvpn recover`: drop the entries of sessions that are gone, then rewrite
/// resolv.conf for the ones still running or put the original back. True when
/// resolv.conf changed.
pub fn recover() -> bool {
    let _lock = Lock::take();
    let had = entries().len();
    let live = live_entries().len();
    if live == 0 {
        return write_shared();
    }
    is_ours() && live < had && write_shared()
}

fn resolved_set(
    iface: &str,
    servers: &[IpAddr],
    search: &[String],
    full: bool,
) -> Result<(), String> {
    let mut args = vec!["dns".to_string(), iface.to_string()];
    args.extend(servers.iter().map(|s| s.to_string()));
    // A link this new may not be known to resolved yet.
    let mut tries = 0;
    loop {
        match resolvectl(&args.iter().map(String::as_str).collect::<Vec<_>>()) {
            Ok(()) => break,
            Err(e) if e.contains("not known") && tries < 10 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(e),
        }
    }
    let routing = resolved_domains(search, full);
    if !routing.is_empty() {
        let mut args = vec!["domain", iface];
        args.extend(routing.iter().map(String::as_str));
        resolvectl(&args)?;
    }
    let default_route = if full || search.is_empty() {
        "yes"
    } else {
        "no"
    };
    resolvectl(&["default-route", iface, default_route])?;
    for proto in ["llmnr", "mdns"] {
        let _ = resolvectl(&[proto, iface, "no"]);
    }
    Ok(())
}

/// The link's domains: its search domains, and `~.` for a full tunnel so names
/// outside them go to the tunnel too, not to the other links.
fn resolved_domains(search: &[String], full: bool) -> Vec<String> {
    let mut d = search.to_vec();
    if full {
        d.push("~.".into());
    }
    d
}

fn resolvectl(args: &[&str]) -> Result<(), String> {
    let out = Command::new("resolvectl")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("resolvectl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn file_set(servers: &[IpAddr], search: &[String]) -> Option<DnsBackup> {
    let _lock = Lock::take();
    if !is_ours() {
        save_original();
    }
    let _ = std::fs::create_dir_all(RUN_DIR);
    if let Err(e) = std::fs::write(
        entry_path(std::process::id()),
        encode_entry(servers, search),
    ) {
        out!("# (could not set DNS: {e})");
        return None;
    }
    let others = live_entries().len().saturating_sub(1);
    write_shared();
    if search.is_empty() {
        out!("# DNS → {servers:?}");
    } else {
        out!("# DNS → {servers:?} (search {})", search.join(" "));
    }
    if others > 0 {
        out!("# note: {others} other tunnel(s) share {RESOLV_CONF}, which can't send each domain to its own servers (systemd-resolved can)");
    }
    crate::report::dns(servers);
    Some(DnsBackup::File)
}

fn is_ours() -> bool {
    std::fs::read_to_string(RESOLV_CONF).is_ok_and(|c| c.starts_with(DNS_MARKER))
}

/// Keep the current resolv.conf (file or symlink) to put back at the end.
fn save_original() {
    let is_link = std::fs::symlink_metadata(RESOLV_CONF).is_ok_and(|m| m.file_type().is_symlink());
    let orig = if is_link {
        std::fs::read_link(RESOLV_CONF).ok().map(Original::Symlink)
    } else {
        std::fs::read_to_string(RESOLV_CONF)
            .ok()
            .map(Original::File)
    };
    if let Some(o) = orig {
        let _ = std::fs::create_dir_all(RUN_DIR);
        let _ = std::fs::write(DNS_SIDECAR, encode_sidecar(&o));
    }
}

/// resolv.conf for the running sessions, or the original once none is left.
/// True when the file was written.
fn write_shared() -> bool {
    let live = live_entries();
    if live.is_empty() {
        let orig = std::fs::read_to_string(DNS_SIDECAR)
            .ok()
            .and_then(|s| decode_sidecar(&s));
        let _ = std::fs::remove_file(DNS_SIDECAR);
        if !is_ours() {
            return false;
        }
        return match orig {
            Some(Original::Symlink(t)) => {
                let _ = std::fs::remove_file(RESOLV_CONF);
                std::os::unix::fs::symlink(t, RESOLV_CONF).is_ok()
            }
            Some(Original::File(c)) => std::fs::write(RESOLV_CONF, c).is_ok(),
            None => false,
        };
    }
    let content = compose(&live);
    if std::fs::symlink_metadata(RESOLV_CONF).is_ok_and(|m| m.file_type().is_symlink()) {
        let _ = std::fs::remove_file(RESOLV_CONF);
    }
    std::fs::write(RESOLV_CONF, content).is_ok()
}

struct Entry {
    servers: Vec<IpAddr>,
    search: Vec<String>,
}

fn entry_path(pid: u32) -> PathBuf {
    Path::new(RUN_DIR).join(format!("{pid}.dns"))
}

/// Every session's entry, newest first: `(pid, entry)`.
fn entries() -> Vec<(u32, Entry)> {
    let Ok(dir) = std::fs::read_dir(RUN_DIR) else {
        return Vec::new();
    };
    let mut found: Vec<(std::time::SystemTime, u32, Entry)> = dir
        .filter_map(|e| {
            let e = e.ok()?;
            let pid: u32 = e.file_name().to_str()?.strip_suffix(".dns")?.parse().ok()?;
            let when = e.metadata().ok()?.modified().ok()?;
            let text = std::fs::read_to_string(e.path()).ok()?;
            Some((when, pid, decode_entry(&text)))
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    found.into_iter().map(|(_, pid, e)| (pid, e)).collect()
}

/// The entries of sessions still running; the others' files are removed.
fn live_entries() -> Vec<Entry> {
    entries()
        .into_iter()
        .filter_map(|(pid, e)| {
            if Path::new("/proc").join(pid.to_string()).exists() {
                Some(e)
            } else {
                let _ = std::fs::remove_file(entry_path(pid));
                None
            }
        })
        .collect()
}

fn encode_entry(servers: &[IpAddr], search: &[String]) -> String {
    let mut s = String::new();
    for d in servers {
        s.push_str(&format!("nameserver {d}\n"));
    }
    if !search.is_empty() {
        s.push_str(&format!("search {}\n", search.join(" ")));
    }
    s
}

fn decode_entry(text: &str) -> Entry {
    let mut e = Entry {
        servers: Vec::new(),
        search: Vec::new(),
    };
    for l in text.lines() {
        if let Some(a) = l.strip_prefix("nameserver ") {
            if let Ok(ip) = a.trim().parse() {
                e.servers.push(ip);
            }
        } else if let Some(d) = l.strip_prefix("search ") {
            e.search
                .extend(search_domains(d).into_iter().map(String::from));
        }
    }
    e
}

/// The shared resolv.conf: every session's domains and servers, newest session
/// first, without repeats.
fn compose(entries: &[Entry]) -> String {
    let mut search: Vec<&str> = Vec::new();
    let mut servers: Vec<IpAddr> = Vec::new();
    for e in entries {
        for d in &e.search {
            if !search.contains(&d.as_str()) {
                search.push(d);
            }
        }
        for s in &e.servers {
            if !servers.contains(s) {
                servers.push(*s);
            }
        }
    }
    let mut out = format!("{DNS_MARKER} — restored on disconnect\n");
    if !search.is_empty() {
        out.push_str(&format!("search {}\n", search.join(" ")));
    }
    for s in servers.iter().take(MAXNS) {
        out.push_str(&format!("nameserver {s}\n"));
    }
    out
}

/// The gateway's search list, keeping only plausible domain names so nothing it
/// sends can add a line of its own to resolv.conf or an option to resolvectl.
fn search_domains(domains: &str) -> Vec<&str> {
    domains
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|d| {
            !d.is_empty()
                && d.len() <= 253
                && !d.starts_with('-')
                && d.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        })
        .collect()
}

#[derive(Debug, PartialEq)]
enum Original {
    Symlink(PathBuf),
    File(String),
}

/// `SYMLINK <target>` or `FILE\n<original bytes>`.
fn encode_sidecar(o: &Original) -> String {
    match o {
        Original::Symlink(t) => format!("SYMLINK {}\n", t.display()),
        Original::File(c) => format!("FILE\n{c}"),
    }
}

fn decode_sidecar(raw: &str) -> Option<Original> {
    if let Some(rest) = raw.strip_prefix("SYMLINK ") {
        let target = rest.lines().next().unwrap_or("").trim();
        (!target.is_empty()).then(|| Original::Symlink(PathBuf::from(target)))
    } else {
        raw.strip_prefix("FILE\n")
            .map(|rest| Original::File(rest.to_string()))
    }
}

/// Serialises resolv.conf changes between sessions.
struct Lock(Option<std::fs::File>);

impl Lock {
    fn take() -> Lock {
        let _ = std::fs::create_dir_all(RUN_DIR);
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(LOCK)
            .ok();
        if let Some(f) = &f {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
        }
        Lock(f)
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if let Some(f) = &self.0 {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

/// The resolvers in `dns` whose queries the kernel routes into `tun`, checked once
/// the tunnel's routes are in. A split tunnel's gateway often pushes resolvers its
/// routes don't cover (a corporate DNS outside the include list, 8.8.8.8): those
/// queries leave via the LAN, where the corporate one just times out — and every
/// lookup stalls ~5 s per try on it before the next server — while the public one
/// only displaces the LAN resolver. Logs what it leaves out.
pub fn tunnelled_dns<A: Display + Debug + Clone>(dns: &[A], tun: &str) -> Vec<A> {
    let (keep, outside): (Vec<A>, Vec<A>) = dns
        .iter()
        .cloned()
        .partition(|d| route_dev(&d.to_string()).as_deref() == Some(tun));
    if !outside.is_empty() {
        out!("# DNS {outside:?} not routed through the tunnel — not used");
        if keep.is_empty() {
            out!("# no tunnelled DNS server — leaving the system resolver as is");
        }
    }
    keep
}

/// The `dev` the kernel picks for `dst` (`ip route get`).
fn route_dev(dst: &str) -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "get", dst])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    dev_of(&String::from_utf8_lossy(&out.stdout))
}

fn dev_of(route_get: &str) -> Option<String> {
    let toks: Vec<&str> = route_get.lines().next()?.split_whitespace().collect();
    toks.windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn resolved_is_used_when_lookups_reach_it() {
        let stub = Path::new("/run/systemd/resolve/stub-resolv.conf");
        let uplink = Path::new("/run/systemd/resolve/resolv.conf");
        let nm = "# Generated by NetworkManager\nnameserver 192.0.2.53\n";
        let plain = "hosts: files mymachines myhostname dns\n";
        assert!(goes_through_resolved(Some(stub), "", plain));
        assert!(goes_through_resolved(Some(uplink), "", plain));
        assert!(goes_through_resolved(
            None,
            "nameserver 127.0.0.53\noptions edns0\n",
            plain
        ));
        assert!(!goes_through_resolved(None, nm, plain));
        assert!(!goes_through_resolved(
            Some(Path::new("/run/NetworkManager/resolv.conf")),
            nm,
            plain
        ));
        assert!(goes_through_resolved(
            None,
            nm,
            "passwd: files\nhosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n"
        ));
    }

    #[test]
    fn nsswitch_resolve_must_be_a_hosts_source() {
        assert!(!nss_uses_resolve("# hosts: resolve\nhosts: files dns\n"));
        assert!(!nss_uses_resolve("hosts: files dns # resolve later\n"));
        assert!(!nss_uses_resolve("networks: resolve\nhosts: files dns\n"));
        assert!(!nss_uses_resolve("hosts: files [resolve] dns\n"));
        assert!(nss_uses_resolve("hosts:\tfiles resolve dns\n"));
    }

    #[test]
    fn a_full_tunnel_takes_every_name_and_a_split_one_only_its_domains() {
        let corp = vec!["corp.example.com".to_string()];
        assert_eq!(resolved_domains(&corp, false), ["corp.example.com"]);
        assert_eq!(resolved_domains(&corp, true), ["corp.example.com", "~."]);
        assert_eq!(resolved_domains(&[], true), ["~."]);
        assert!(resolved_domains(&[], false).is_empty());
    }

    #[test]
    fn shared_resolv_conf_lists_newest_session_first_without_repeats() {
        let newest = decode_entry(&encode_entry(
            &[ip("10.1.0.53"), ip("10.1.0.54")],
            &["b.example.org".into()],
        ));
        let oldest = decode_entry(&encode_entry(
            &[ip("10.0.0.53"), ip("10.1.0.54")],
            &["a.example.com".into(), "b.example.org".into()],
        ));
        assert_eq!(
            compose(&[newest, oldest]),
            format!(
                "{DNS_MARKER} — restored on disconnect\nsearch b.example.org a.example.com\n\
                 nameserver 10.1.0.53\nnameserver 10.1.0.54\nnameserver 10.0.0.53\n"
            )
        );
    }

    #[test]
    fn only_three_nameservers_reach_resolv_conf() {
        let e = Entry {
            servers: ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
                .map(ip)
                .to_vec(),
            search: Vec::new(),
        };
        let c = compose(&[e]);
        assert_eq!(c.matches("nameserver").count(), 3);
        assert!(!c.contains("search"));
    }

    #[test]
    fn an_entry_reads_back_only_addresses_and_domains() {
        let e = decode_entry(
            "nameserver 10.0.0.1\nnameserver not-an-ip\nsearch ok.example.com bad$x\noptions rotate\n",
        );
        assert_eq!(e.servers, [ip("10.0.0.1")]);
        assert_eq!(e.search, ["ok.example.com"]);
    }

    #[test]
    fn search_domains_drops_anything_that_could_add_a_line_or_an_option() {
        assert_eq!(
            search_domains("corp.example.com, b.example.org;c-1.example.net"),
            ["corp.example.com", "b.example.org", "c-1.example.net"]
        );
        assert_eq!(
            search_domains("a.example.com\nnameserver 203.0.113.9"),
            ["a.example.com", "nameserver", "203.0.113.9"]
        );
        assert_eq!(
            search_domains("ok.example.com bad$name x\u{0}y --help -x"),
            ["ok.example.com"]
        );
        assert!(search_domains(&"a".repeat(254)).is_empty());
        assert!(search_domains("").is_empty());
    }

    #[test]
    fn dev_of_route_get() {
        assert_eq!(
            dev_of("10.1.2.3 dev cpfg0 src 10.0.0.5 uid 0 \n    cache \n").as_deref(),
            Some("cpfg0")
        );
        assert_eq!(
            dev_of("192.168.50.25 via 192.168.1.1 dev eth0 src 192.168.1.2 uid 1000 \n").as_deref(),
            Some("eth0")
        );
        assert_eq!(dev_of(""), None);
    }

    #[test]
    fn sidecar_roundtrip() {
        let f = Original::File("# Generated by NetworkManager\nnameserver 192.0.2.53\n".into());
        assert_eq!(decode_sidecar(&encode_sidecar(&f)), Some(f));
        let l = Original::Symlink(PathBuf::from("/run/systemd/resolve/stub-resolv.conf"));
        let enc = encode_sidecar(&l);
        assert!(enc.starts_with("SYMLINK /run/systemd/resolve/stub-resolv.conf"));
        assert_eq!(decode_sidecar(&enc), Some(l));
        assert_eq!(decode_sidecar("SYMLINK \n"), None);
        assert_eq!(decode_sidecar("garbage"), None);
    }
}
