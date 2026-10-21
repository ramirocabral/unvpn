//! Linux TUN device + interface configuration for the VPN data plane.
//!
//! Opens `/dev/net/tun`, binds a `tunN` interface via TUNSETIFF (IFF_TUN |
//! IFF_NO_PI so reads/writes are raw IPv4 packets), and shells out to `ip(8)`
//! for addressing and routing. Requires root / CAP_NET_ADMIN.

use std::fs::{File, OpenOptions};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::process::Command;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

/// Open a TUN device, requesting `name`. If that name is already in use (EBUSY —
/// e.g. another unvpn back-end's tunnel is up), fall back to a kernel-assigned
/// variant (`<base>%d`) instead of failing — so concurrent tunnels coexist and we
/// never need to touch an existing device. Returns the file and the actual name.
///
/// IPv6 is disabled on the new interface before it goes up: all our tunnels are
/// IPv4-only, and otherwise the kernel autoconfigures a link-local address and
/// sends DAD/RS/MLD into the tunnel as soon as the link is up.
pub fn open_tun(name: &str) -> Result<(File, String), String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| format!("open /dev/net/tun: {e} (need root / CAP_NET_ADMIN)"))?;

    let actual = match tunsetiff(&file, name) {
        Ok(actual) => actual,
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
            let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
            let template = format!("{}%d", if base.is_empty() { "tun" } else { base });
            tunsetiff(&file, &template).map_err(|e| format!("TUNSETIFF (fallback {template}): {e}"))?
        }
        Err(e) => return Err(format!("TUNSETIFF: {e}")),
    };
    // Best-effort: absent when the kernel has no IPv6 at all, which is fine too.
    let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{actual}/disable_ipv6"), "1");
    Ok((file, actual))
}

/// Make tun reads non-blocking, so a data loop can drain every queued packet per
/// wakeup (and send them as one batch) instead of one packet per `poll`.
pub fn set_nonblocking(f: &File) {
    unsafe {
        let fd = f.as_raw_fd();
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

/// True for an IPv4 packet (version nibble 4). The data loops only forward these:
/// every tunnel we speak (PPP IPCP, ESP next-header 4) carries IPv4 only.
pub fn is_ipv4(pkt: &[u8]) -> bool {
    pkt.first().is_some_and(|b| b >> 4 == 4)
}

/// Bind the open `/dev/net/tun` file to interface `name` (IFF_TUN | IFF_NO_PI).
/// An empty or `%d`-templated name lets the kernel assign one. Returns the actual
/// interface name the kernel used.
fn tunsetiff(file: &File, name: &str) -> std::io::Result<String> {
    // struct ifreq: 16-byte name, then the flags in the union.
    let mut ifr = [0u8; 40];
    let nb = name.as_bytes();
    let n = nb.len().min(15);
    ifr[..n].copy_from_slice(&nb[..n]);
    ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());

    let ret = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, ifr.as_mut_ptr()) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let end = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
    Ok(String::from_utf8_lossy(&ifr[..end]).into_owned())
}

/// Apply many `ip` commands in one process via `ip -force -batch -` (commands on
/// stdin, one per line, WITHOUT the leading `ip`). `-force` continues past errors
/// (e.g. a duplicate route), so a large split-tunnel route set installs/removes in
/// one shot instead of hundreds of `ip` spawns. A no-op for an empty list.
pub fn ip_batch(lines: &[String]) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if lines.is_empty() {
        return Ok(());
    }
    let mut child = Command::new("ip")
        .args(["-force", "-batch", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn ip -batch: {e}"))?;
    {
        let mut si = child.stdin.take().ok_or("ip -batch: no stdin")?;
        for l in lines {
            let _ = writeln!(si, "{l}");
        }
        // si dropped here → EOF, so `ip` processes the batch and exits.
    }
    child.wait().map_err(|e| format!("ip -batch wait: {e}"))?;
    Ok(())
}

/// [`ip_batch`] that also reports which lines failed (0-based indices into
/// `lines`). With `-force`, iproute2 keeps going and prints `Command failed -:N`
/// (1-based line) on stderr for each failure — e.g. a route that already existed,
/// which then must NOT be deleted again on teardown.
pub fn ip_batch_failed(lines: &[String]) -> Result<std::collections::HashSet<usize>, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut failed = std::collections::HashSet::new();
    if lines.is_empty() {
        return Ok(failed);
    }
    let mut child = Command::new("ip")
        .args(["-force", "-batch", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn ip -batch: {e}"))?;
    {
        let mut si = child.stdin.take().ok_or("ip -batch: no stdin")?;
        for l in lines {
            let _ = writeln!(si, "{l}");
        }
    }
    let out = child.wait_with_output().map_err(|e| format!("ip -batch wait: {e}"))?;
    for line in String::from_utf8_lossy(&out.stderr).lines() {
        if let Some(n) = line.split("Command failed -:").nth(1) {
            if let Ok(n) = n.trim().parse::<usize>() {
                failed.insert(n.saturating_sub(1));
            }
        }
    }
    Ok(failed)
}

pub fn ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("spawn ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

pub fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ipv4_passes() {
        assert!(is_ipv4(&[0x45, 0x00, 0x00, 0x54]));
        assert!(!is_ipv4(&[0x60, 0x00, 0x00, 0x00]));
        assert!(!is_ipv4(&[]));
    }

    #[test]
    fn prefix_from_mask() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 248, 0)), 21);
    }
}
