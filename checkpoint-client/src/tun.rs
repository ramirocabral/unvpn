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
/// e.g. another cpvpn back-end's tunnel is up), fall back to a kernel-assigned
/// variant (`<base>%d`) instead of failing — so concurrent tunnels coexist and we
/// never need to touch an existing device. Returns the file and the actual name.
pub fn open_tun(name: &str) -> Result<(File, String), String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| format!("open /dev/net/tun: {e} (need root / CAP_NET_ADMIN)"))?;

    match tunsetiff(&file, name) {
        Ok(actual) => Ok((file, actual)),
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
            // Name taken — ask the kernel to pick the next free `<base>N`.
            let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
            let template = format!("{}%d", if base.is_empty() { "tun" } else { base });
            let actual = tunsetiff(&file, &template)
                .map_err(|e| format!("TUNSETIFF (fallback {template}): {e}"))?;
            Ok((file, actual))
        }
        Err(e) => Err(format!("TUNSETIFF: {e}")),
    }
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

/// Run `ip <args>`, failing on a non-zero exit.
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

/// Netmask (e.g. 255.255.248.0) → prefix length (e.g. 21).
pub fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}
