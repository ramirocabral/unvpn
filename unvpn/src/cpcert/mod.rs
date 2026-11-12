//! Check Point certificate authentication: enrollment with the internal CA and
//! the identity (PKCS#12) used to log in.

pub mod cmc;
pub mod der;
pub mod enroll;
pub mod p12;
pub mod rfc1751;

use std::path::PathBuf;

/// What the gateway's ClientHello says that matters for certificate login.
#[derive(Default, Debug, Clone)]
pub struct GatewayInfo {
    /// Internal CA fingerprints (RFC 1751 words).
    pub ca_fingerprints: Vec<String>,
    /// Login options: (id, display name, factor types, secondary realm hash).
    pub login_options: Vec<LoginOption>,
}

#[derive(Debug, Clone)]
pub struct LoginOption {
    pub id: String,
    pub display_name: String,
    pub factors: Vec<String>,
    pub secondary_realm_hash: String,
}

impl GatewayInfo {
    pub fn from_hello(resp: &crate::ccc::Packet) -> GatewayInfo {
        use crate::ccc::Value;
        let mut info = GatewayInfo::default();
        if let Some(Value::Map(fps)) = resp.path(&[
            "ResponseData",
            "connectivity_info",
            "internal_ca_fingerprint",
        ]) {
            for (_, v) in fps {
                if let Some(t) = v.text() {
                    if let Ok(b) = crate::ccc::deobfuscate(&t) {
                        info.ca_fingerprints
                            .push(String::from_utf8_lossy(&b).trim().to_string());
                    }
                }
            }
        }
        if let Some(Value::Map(opts)) =
            resp.path(&["ResponseData", "login_options_data", "login_options_list"])
        {
            for (_, o) in opts {
                let text = |k: &str| o.get(k).and_then(|v| v.text()).unwrap_or_default();
                let mut factors = Vec::new();
                if let Some(Value::Map(fs)) = o.get("factors") {
                    for (_, f) in fs {
                        if let Some(t) = f.get("factor_type").and_then(|v| v.text()) {
                            factors.push(t);
                        }
                    }
                }
                info.login_options.push(LoginOption {
                    id: text("id"),
                    display_name: text("display_name"),
                    factors,
                    secondary_realm_hash: text("secondary_realm_hash"),
                });
            }
        }
        info
    }

    pub fn option(&self, id: &str) -> Option<&LoginOption> {
        self.login_options.iter().find(|o| o.id == id)
    }

    /// The login option to use with a certificate: `wanted` if given, else the
    /// first one whose first factor is a certificate.
    pub fn certificate_option(&self, wanted: Option<&str>) -> Result<LoginOption, String> {
        if let Some(w) = wanted {
            return self.option(w).cloned().ok_or_else(|| {
                format!(
                    "the gateway has no login option {w:?} (it offers: {})",
                    self.describe_options()
                )
            });
        }
        self.login_options
            .iter()
            .find(|o| {
                o.factors
                    .first()
                    .map(|f| f == "certificate")
                    .unwrap_or(false)
            })
            .cloned()
            .ok_or_else(|| {
                format!(
                    "the gateway offers no certificate login (it offers: {})",
                    self.describe_options()
                )
            })
    }

    pub fn describe_options(&self) -> String {
        self.login_options
            .iter()
            .map(|o| format!("{} \"{}\" [{}]", o.id, o.display_name, o.factors.join("+")))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: unvpn cp-enroll -g <gateway> [-r <registration-key>] -o <file.p12> [--key-bits 2048]\n\
         \x20                   [--port 18264] [--resume | --resend] [--trust-ca] [--probe]\n\
         \n\
         Obtains a user certificate from the gateway's internal CA with the one-time\n\
         registration key (<reference>-<code>) and writes it, with its new private key,\n\
         to <file.p12>. Without -r the key is read from stdin; then the certificate\n\
         password (asked twice on a TTY)."
    );
    std::process::exit(2);
}

pub fn cmd_enroll(args: &[String]) {
    let mut gateway = None;
    let mut regkey = None;
    let mut out = None;
    let mut key_bits = 2048u32;
    let mut port = enroll::ICA_PORT;
    let (mut resume, mut resend, mut trust_ca, mut probe) = (false, false, false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-g" | "--gateway" => gateway = it.next().cloned(),
            "-r" | "--regkey" | "--registration-key" => regkey = it.next().cloned(),
            "-o" | "--out" => out = it.next().cloned(),
            "--key-bits" => {
                key_bits = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--port" => {
                port = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--resume" => resume = true,
            "--resend" => resend = true,
            "--trust-ca" => trust_ca = true,
            "--probe" => probe = true,
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }
    let Some(gateway) = gateway else { usage() };

    let info = match crate::gateway_hello(&gateway) {
        Ok(p) => GatewayInfo::from_hello(&p),
        Err(e) => {
            println!("# warning: could not read the gateway's site information: {e}");
            GatewayInfo::default()
        }
    };
    for f in &info.ca_fingerprints {
        println!("# gateway internal CA fingerprint: {f}");
    }
    if !info.login_options.is_empty() {
        println!("# gateway login options: {}", info.describe_options());
    }

    if probe {
        let addr = format!("{gateway}:{port}");
        match std::net::ToSocketAddrs::to_socket_addrs(&addr.as_str())
            .ok()
            .and_then(|mut a| a.next())
            .map(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_secs(10)))
        {
            Some(Ok(_)) => println!("# internal CA port {addr} is reachable (nothing was sent)"),
            Some(Err(e)) => {
                eprintln!("internal CA port {addr} is not reachable: {e}");
                std::process::exit(1);
            }
            None => {
                eprintln!("cannot resolve {gateway}");
                std::process::exit(1);
            }
        }
        return;
    }

    let Some(out) = out else { usage() };
    // Without -r the key is read from stdin (keeps it out of the process list).
    let regkey = match regkey {
        Some(r) => r,
        None => match crate::anyconnect::read_secret("Registration key: ") {
            Some(r) => r,
            None => {
                eprintln!("no registration key given");
                std::process::exit(2);
            }
        },
    };
    let regkey = match cmc::RegKey::parse(&regkey) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let password = match read_new_password() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let opts = enroll::Options {
        gateway: gateway.clone(),
        port,
        regkey,
        out: PathBuf::from(&out),
        password,
        key_bits,
        resume,
        resend,
        trust_ca,
        expected_ca: info.ca_fingerprints.clone(),
    };
    match enroll::run(&opts) {
        Ok(subject) => {
            println!("# ENROLLED: certificate for {subject}");
            println!("# saved to {out}");
        }
        Err(e) => {
            eprintln!("enrollment failed: {e}");
            std::process::exit(1);
        }
    }
}

/// The certificate password: one stdin line from a pipe (the GUI), or typed
/// twice on a terminal.
fn read_new_password() -> Result<String, String> {
    let tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    let first = crate::anyconnect::read_secret("Certificate password: ")
        .ok_or("no certificate password given")?;
    if tty {
        let again = crate::anyconnect::read_secret("Repeat the password: ")
            .ok_or("no certificate password given")?;
        if again != first {
            return Err("the passwords do not match".into());
        }
    }
    enroll::validate_password(&first)?;
    Ok(first)
}
