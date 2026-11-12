//! TLS to a gateway, shared by every back-end. The handshake itself never fails
//! on the certificate; afterwards the system's CAs (and the host name) judge it,
//! and when they don't vouch for it [`trust::accept`] decides: a pin, the
//! certificate already trusted for the host, or the user's answer.

use super::trust;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::X509VerifyResult;
use std::cell::RefCell;
use std::net::TcpStream;
use std::sync::OnceLock;
use std::time::Duration;

pub type TlsStream = SslStream<TcpStream>;

thread_local! {
    /// What the chain check of the handshake running on this thread objected to.
    static OBJECTIONS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

/// Connect to `host:port` with `timeout` for the connect and as the stream's
/// read/write timeout, and judge the gateway's certificate.
pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<TlsStream, String> {
    let tcp = connect_tcp(host, port, timeout)?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    tcp.set_nodelay(true).ok();
    let config = connector()?
        .configure()
        .map_err(|e| format!("TLS to {host}: {e}"))?;
    OBJECTIONS.with(|o| o.borrow_mut().clear());
    let tls = config
        .connect(host, tcp)
        .map_err(|e| format!("TLS to {host}: {e}"));
    let objections = OBJECTIONS.with(|o| std::mem::take(&mut *o.borrow_mut()));
    let tls = tls?;
    let cert = tls
        .ssl()
        .peer_certificate()
        .ok_or_else(|| format!("TLS to {host}: no server certificate"))?;
    let endpoint = format!("{host}:{port}");
    match tls.ssl().verify_result() {
        X509VerifyResult::OK => {
            trust::note_verified(&endpoint, &cert.to_der().map_err(|e| e.to_string())?)
        }
        v if objections.is_empty() => trust::accept(&endpoint, &cert, v.error_string())?,
        _ => trust::accept(&endpoint, &cert, &objections.join(", "))?,
    }
    Ok(tls)
}

fn connector() -> Result<&'static SslConnector, String> {
    static CONNECTOR: OnceLock<Result<SslConnector, String>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let mut b =
                SslConnector::builder(SslMethod::tls()).map_err(|e| format!("TLS setup: {e}"))?;
            // The system's CA bundle wherever this distro keeps it (a vendored OpenSSL
            // only looks in its own build prefix).
            let probe = openssl_probe::probe();
            if let Some(f) = &probe.cert_file {
                let _ = b.load_verify_locations(Some(f), None);
            }
            for d in &probe.cert_dir {
                let _ = b.load_verify_locations(None, Some(d));
            }
            b.set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| format!("TLS setup: {e}"))?;
            // Recorded, not enforced, here: `connect` judges the result afterwards.
            b.set_verify_callback(SslVerifyMode::PEER, |ok, ctx| {
                if !ok {
                    let e = ctx.error().error_string();
                    OBJECTIONS.with(|o| {
                        let mut o = o.borrow_mut();
                        if !o.contains(&e) {
                            o.push(e);
                        }
                    });
                }
                true
            });
            Ok(b.build())
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// TCP connect with a timeout per address (a plain `connect` to a dead gateway
/// hangs ~2 min), trying each resolved address in turn.
fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?;
    let mut last = format!("connect {host}:{port}: no address");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("connect {host}:{port} ({a}): {e}"),
        }
    }
    Err(last)
}
