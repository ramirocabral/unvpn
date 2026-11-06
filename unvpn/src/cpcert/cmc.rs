//! Check Point internal CA enrollment messages (CMC over CMS, RFC 2797 family).
//!
//! The request is a CMC Full PKI Request carrying a CRMF `CertReqMsg`, wrapped in a
//! CMS SignedData signed with the new key. The CA answers with a CMC Full PKI
//! Response whose SignedData carries the issued certificate and the CA's own.

use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::rsa::Padding;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;

use super::der::{self, Tlv};

pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const OID_DATA: &str = "1.2.840.113549.1.7.1";
pub const OID_SHA1: &str = "1.3.14.3.2.26";
pub const OID_RSA: &str = "1.2.840.113549.1.1.1";
pub const OID_SHA1_RSA: &str = "1.2.840.113549.1.1.5";
pub const OID_CMC_STATUS_INFO: &str = "1.3.6.1.5.5.7.7.1";
pub const OID_CMC_IDENTIFICATION: &str = "1.3.6.1.5.5.7.7.2";
pub const OID_CMC_IDENTITY_PROOF: &str = "1.3.6.1.5.5.7.7.3";
pub const OID_CMC_STATUS_INFO_V2: &str = "1.3.6.1.5.5.7.7.25";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// The certReqId the CA echoes back.
pub const CERT_REQ_ID: u64 = 101;

/// A registration key as handed out by the administrator: `<reference>-<authcode>`.
#[derive(Clone, Debug, PartialEq)]
pub struct RegKey {
    /// Reference number of the pending certificate (decimal).
    pub reference: String,
    /// Authorization code (shared secret).
    pub authcode: String,
}

impl RegKey {
    /// Split at the first `-` (the code itself may contain dashes). Surrounding
    /// whitespace from a copy/paste is dropped; the parts are taken verbatim.
    pub fn parse(s: &str) -> Result<RegKey, String> {
        let s = s.trim();
        let (reference, authcode) =
            s.split_once('-').ok_or("not a valid registration key (expected <reference>-<code>)")?;
        if reference.is_empty() || authcode.is_empty() {
            return Err("not a valid registration key (expected <reference>-<code>)".into());
        }
        if c_atoi(reference) < 1 {
            return Err("wrong reference number in the registration key".into());
        }
        Ok(RegKey { reference: reference.to_string(), authcode: authcode.to_string() })
    }

    /// The certificate serial requested in the template.
    pub fn serial(&self) -> u64 {
        c_atoi(&self.reference) as u64
    }
}

/// C `atoi`: optional leading whitespace and sign, then decimal digits.
fn c_atoi(s: &str) -> i64 {
    let s = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let mut v: i64 = 0;
    for c in digits.bytes().take_while(u8::is_ascii_digit) {
        v = v.wrapping_mul(10).wrapping_add((c - b'0') as i64);
    }
    let v = if neg { v.wrapping_neg() } else { v };
    v as i32 as i64
}

fn sign_sha1(key: &PKeyRef<Private>, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut s = Signer::new(MessageDigest::sha1(), key).map_err(|e| e.to_string())?;
    s.set_rsa_padding(Padding::PKCS1).map_err(|e| e.to_string())?;
    s.update(data).map_err(|e| e.to_string())?;
    s.sign_to_vec().map_err(|e| e.to_string())
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let k = PKey::hmac(key).map_err(|e| e.to_string())?;
    let mut s = Signer::new(MessageDigest::sha1(), &k).map_err(|e| e.to_string())?;
    s.update(data).map_err(|e| e.to_string())?;
    s.sign_to_vec().map_err(|e| e.to_string())
}

fn sha1(data: &[u8]) -> Result<Vec<u8>, String> {
    hash(MessageDigest::sha1(), data).map(|d| d.to_vec()).map_err(|e| e.to_string())
}

/// SHA-1 over the whole subjectPublicKey BIT STRING element (tag and length
/// included). This is the key identifier the CA expects in the SignerInfo.
pub fn key_identifier(spki_der: &[u8]) -> Result<Vec<u8>, String> {
    let spki = der::parse_single(spki_der)?.expect(der::SEQUENCE)?;
    let parts = spki.children()?;
    let bits = parts.get(1).ok_or("SubjectPublicKeyInfo without a key")?.expect(der::BIT_STRING)?;
    sha1(bits.raw)
}

/// Encode the enrollment request (a DER `ContentInfo`).
pub fn build_request(key: &PKeyRef<Private>, rk: &RegKey) -> Result<Vec<u8>, String> {
    let spki = key.public_key_to_der().map_err(|e| e.to_string())?;
    let spki_content = der::parse_single(&spki)?.content;

    let template = der::seq(&[
        &der::tlv(0x81, &der::uint_content(&rk.serial().to_be_bytes())),
        &der::tlv(0xa5, &[]),
        &der::tlv(0xa6, spki_content),
    ]);
    let cert_req = der::seq(&[&der::uint(CERT_REQ_ID), &template]);
    let pop_sig = sign_sha1(key, &cert_req)?;
    let popo = der::cons(0xa1, &[&der::alg_null(OID_SHA1_RSA), &der::bit_string(&pop_sig)]);
    let crm = der::cons(0xa1, &[&cert_req, &popo]);
    let req_seq = der::seq(&[&crm]);

    let proof_key = sha1(format!("{}{}", rk.authcode, rk.reference).as_bytes())?;
    let proof = hmac_sha1(&proof_key, &req_seq)?;
    let controls = der::seq(&[
        &der::seq(&[&der::uint(1), &der::oid(OID_CMC_IDENTITY_PROOF), &der::set(&[&der::octets(&proof)])]),
        &der::seq(&[&der::uint(2), &der::oid(OID_CMC_IDENTIFICATION), &der::set(&[&der::utf8(&rk.reference)])]),
    ]);
    let pki_data = der::seq(&[&controls, &req_seq, &der::seq(&[]), &der::seq(&[])]);

    let sig = sign_sha1(key, &pki_data)?;
    let signer_info = der::seq(&[
        &der::uint(3),
        &der::tlv(0x80, &key_identifier(&spki)?),
        &der::alg_null(OID_SHA1),
        &der::alg_null(OID_RSA),
        &der::octets(&sig),
    ]);
    let signed_data = der::seq(&[
        &der::uint(3),
        &der::set(&[&der::alg_null(OID_SHA1)]),
        &der::seq(&[&der::oid(OID_DATA), &der::cons(0xa0, &[&der::octets(&pki_data)])]),
        &der::set(&[&signer_info]),
    ]);
    Ok(der::seq(&[&der::oid(OID_SIGNED_DATA), &der::cons(0xa0, &[&signed_data])]))
}

/// Outcome of a successful enrollment response.
pub struct Issued {
    /// The certificate issued for our key.
    pub cert: X509,
    /// The issuing (internal) CA, when present in the response.
    pub ca: Option<X509>,
    /// The CA's identity proof control: `None` when absent, else whether it
    /// matches the registration key (the CA proved it knows the key).
    pub ca_proof: Option<bool>,
    /// Human-readable remarks about non-fatal oddities.
    pub notes: Vec<String>,
}

fn md_for_oid(oid: &str) -> Option<MessageDigest> {
    Some(match oid {
        "1.3.14.3.2.26" | "1.2.840.113549.1.1.5" => MessageDigest::sha1(),
        "2.16.840.1.101.3.4.2.1" | "1.2.840.113549.1.1.11" => MessageDigest::sha256(),
        "2.16.840.1.101.3.4.2.2" | "1.2.840.113549.1.1.12" => MessageDigest::sha384(),
        "2.16.840.1.101.3.4.2.3" | "1.2.840.113549.1.1.13" => MessageDigest::sha512(),
        "2.16.840.1.101.3.4.2.4" | "1.2.840.113549.1.1.14" => MessageDigest::sha224(),
        "1.2.840.113549.2.5" | "1.2.840.113549.1.1.4" => MessageDigest::md5(),
        _ => return None,
    })
}

fn status_name(s: u64) -> &'static str {
    match s {
        0 => "success",
        2 => "failed",
        3 => "pending",
        4 => "noSupport",
        5 => "confirmRequired",
        6 => "popRequired",
        7 => "partial",
        _ => "unknown",
    }
}

fn fail_name(f: u64) -> &'static str {
    match f {
        0 => "badAlg",
        1 => "badMessageCheck",
        2 => "badRequest",
        3 => "badTime",
        4 => "badCertId",
        5 => "unsupportedExt",
        6 => "mustArchiveKeys",
        7 => "badIdentity (wrong registration key or reference number)",
        8 => "popRequired",
        9 => "popFailed",
        10 => "noKeyReuse",
        11 => "internalCAError",
        12 => "tryLater",
        _ => "unknown",
    }
}

/// `CMCStatusInfo` / `CMCStatusInfoV2`: status, optional text, optional failInfo.
fn parse_status(info: &Tlv) -> Result<(u64, Option<String>, Option<u64>), String> {
    let f = info.children()?;
    let status = f.first().ok_or("empty CMCStatusInfo")?.as_u64()?;
    let mut text = None;
    let mut fail = None;
    for e in f.iter().skip(2) {
        match e.tag {
            der::UTF8_STRING => text = Some(String::from_utf8_lossy(e.content).into_owned()),
            der::INTEGER => fail = e.as_u64().ok(),
            _ => {}
        }
    }
    Ok((status, text, fail))
}

fn spki_of(cert: &X509) -> Result<Vec<u8>, String> {
    cert.public_key().and_then(|k| k.public_key_to_der()).map_err(|e| e.to_string())
}

/// Certificates in the SignedData whose key could have produced `sid`.
fn signer_matches(sid: &Tlv, cert: &X509) -> bool {
    match sid.tag {
        der::SEQUENCE => {
            let Ok(p) = sid.children() else { return false };
            let (Some(issuer), Some(serial)) = (p.first(), p.get(1)) else { return false };
            let ours_issuer = cert.issuer_name().to_der().unwrap_or_default();
            let ours_serial = cert.serial_number().to_bn().map(|b| b.to_vec()).unwrap_or_default();
            issuer.raw == ours_issuer.as_slice() && der::uint_content(serial.content) == der::uint_content(&ours_serial)
        }
        0x80 => {
            let Ok(spki) = spki_of(cert) else { return false };
            let ext = cert.subject_key_id().map(|k| k.as_slice().to_vec());
            let std = der::parse_single(&spki)
                .ok()
                .and_then(|s| s.children().ok())
                .and_then(|p| p.get(1).map(|b| sha1(&b.content[1..]).unwrap_or_default()));
            let cp = key_identifier(&spki).ok();
            [ext, std, cp].iter().flatten().any(|k| k.as_slice() == sid.content)
        }
        _ => false,
    }
}

fn verify_signer_info(si: &Tlv, econtent: &[u8], key: &PKey<Public>) -> Result<(), String> {
    let f = si.children()?;
    let dig_oid = f.get(2).ok_or("SignerInfo without digestAlgorithm")?.children()?[0].as_oid()?;
    let md = md_for_oid(&dig_oid).ok_or(format!("unsupported digest algorithm {dig_oid}"))?;
    let mut i = 3;
    let mut signed_attrs = None;
    if f.get(i).map(|t| t.tag) == Some(0xa0) {
        signed_attrs = Some(f[i]);
        i += 1;
    }
    let sig_alg = f.get(i).ok_or("SignerInfo without signatureAlgorithm")?.children()?[0].as_oid()?;
    let md = md_for_oid(&sig_alg).unwrap_or(md);
    let sig = f.get(i + 1).ok_or("SignerInfo without signature")?.octet_value()?;

    let to_verify: Vec<u8> = match signed_attrs {
        None => econtent.to_vec(),
        Some(attrs) => {
            let digest = hash(md, econtent).map_err(|e| e.to_string())?;
            let mut found = false;
            for a in attrs.children()? {
                let p = a.children()?;
                if p.first().and_then(|o| o.as_oid().ok()).as_deref() == Some(OID_MESSAGE_DIGEST) {
                    let vals = p.get(1).ok_or("messageDigest without value")?.children()?;
                    let v = vals.first().ok_or("messageDigest without value")?.octet_value()?;
                    if v != digest.as_ref() {
                        return Err("messageDigest does not match the content".into());
                    }
                    found = true;
                }
            }
            if !found {
                return Err("signed attributes without messageDigest".into());
            }
            der::cons(der::SET, &[attrs.content])
        }
    };
    let mut v = Verifier::new(md, key).map_err(|e| e.to_string())?;
    v.set_rsa_padding(Padding::PKCS1).map_err(|e| e.to_string())?;
    v.update(&to_verify).map_err(|e| e.to_string())?;
    match v.verify(&sig) {
        Ok(true) => Ok(()),
        _ => Err("CMS signature does not verify".into()),
    }
}

/// Decode and check the CA's answer. `our_spki` is the DER SubjectPublicKeyInfo
/// of the key we enrolled.
pub fn parse_response(body: &[u8], our_spki: &[u8], rk: &RegKey) -> Result<Issued, String> {
    let ci = der::parse(body)?.0.expect(der::SEQUENCE)?.children()?;
    let ct = ci.first().ok_or("empty ContentInfo")?.as_oid()?;
    if ct != OID_SIGNED_DATA {
        return Err(format!("response is not CMS SignedData (content type {ct})"));
    }
    let sd = ci.get(1).ok_or("ContentInfo without content")?.children()?;
    let sd = sd.first().ok_or("empty SignedData")?.children()?;
    let encap = sd.get(2).ok_or("SignedData without encapsulated content")?.children()?;
    let econtent = match encap.get(1) {
        Some(e) => e.children()?.first().ok_or("empty eContent")?.octet_value()?,
        None => Vec::new(),
    };

    let mut certs = Vec::new();
    let mut signer_infos = None;
    for e in sd.iter().skip(3) {
        match e.tag {
            0xa0 => {
                for c in e.children()? {
                    if c.tag == der::SEQUENCE {
                        if let Ok(x) = X509::from_der(c.raw) {
                            certs.push((x, c.raw.to_vec()));
                        }
                    }
                }
            }
            der::SET => signer_infos = Some(*e),
            _ => {}
        }
    }

    let mut notes = Vec::new();
    let mut status_seen = None;
    let mut proof = None;
    if !econtent.is_empty() {
        let resp = der::parse_single(&econtent)?.children()?;
        if let Some(controls) = resp.first() {
            for c in controls.children()? {
                let p = c.children()?;
                let Some(oid) = p.get(1).and_then(|o| o.as_oid().ok()) else { continue };
                let Some(vals) = p.get(2).and_then(|v| v.children().ok()) else { continue };
                let Some(val) = vals.first() else { continue };
                match oid.as_str() {
                    OID_CMC_STATUS_INFO | OID_CMC_STATUS_INFO_V2 => {
                        let (s, text, fail) = parse_status(val)?;
                        if s != 0 {
                            let mut m = format!("the CA refused the request: status {} ({})", s, status_name(s));
                            if let Some(f) = fail {
                                m.push_str(&format!(", failInfo {} ({})", f, fail_name(f)));
                            }
                            if let Some(t) = text {
                                m.push_str(&format!(": {t}"));
                            }
                            return Err(m);
                        }
                        status_seen = Some(s);
                    }
                    OID_CMC_IDENTITY_PROOF => proof = Some(val.octet_value()?),
                    _ => notes.push(format!("ignored response control {oid}")),
                }
            }
        }
    }
    if status_seen.is_none() {
        notes.push("no CMC status in the response".into());
    }

    let leaf_idx = certs
        .iter()
        .position(|(c, _)| spki_of(c).map(|k| k == our_spki).unwrap_or(false))
        .ok_or("the response does not contain a certificate for our key")?;
    let (cert, _) = certs[leaf_idx].clone();
    let ca = certs.iter().enumerate().find_map(|(i, (c, d))| {
        let issued = c.public_key().ok().map(|k| cert.verify(&k).unwrap_or(false)).unwrap_or(false);
        (i != leaf_idx && issued).then(|| (c.clone(), d.clone()))
    });
    if ca.is_none() {
        notes.push("the issuing CA certificate is not in the response".into());
    }

    let infos = signer_infos.ok_or("SignedData without SignerInfos")?.children()?;
    let si = infos.first().ok_or("SignedData without a signer")?;
    let sid = si.children()?.get(1).copied().ok_or("SignerInfo without sid")?;
    let mut order: Vec<&X509> = certs.iter().filter(|(c, _)| signer_matches(&sid, c)).map(|(c, _)| c).collect();
    for (c, _) in &certs {
        if !order.iter().any(|o| std::ptr::eq(*o, c)) {
            order.push(c);
        }
    }
    let mut verified = false;
    let mut last_err = String::from("no certificate to verify the response signature");
    for c in order {
        let key = c.public_key().map_err(|e| e.to_string())?;
        match verify_signer_info(si, &econtent, &key) {
            Ok(()) => {
                verified = true;
                break;
            }
            Err(e) => last_err = e,
        }
    }
    if !verified {
        return Err(format!("the response signature does not verify: {last_err}"));
    }

    let ca_proof = match proof {
        None => None,
        Some(p) => {
            let key = sha1(rk.authcode.as_bytes())?;
            let candidates: Vec<&[u8]> = match &ca {
                Some((_, d)) => vec![d.as_slice()],
                None => certs.iter().map(|(_, d)| d.as_slice()).collect(),
            };
            let mut ok = false;
            for d in candidates {
                ok |= hmac_sha1(&key, d)? == p;
            }
            Some(ok)
        }
    };

    Ok(Issued { cert, ca: ca.map(|(c, _)| c), ca_proof, notes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regkey_parsing() {
        let k = RegKey::parse(" 12345-abcdefgh\n").unwrap();
        assert_eq!(k, RegKey { reference: "12345".into(), authcode: "abcdefgh".into() });
        assert_eq!(k.serial(), 12345);
        let k = RegKey::parse("0042-Ab-c9z").unwrap();
        assert_eq!((k.reference.as_str(), k.authcode.as_str(), k.serial()), ("0042", "Ab-c9z", 42));
        assert!(RegKey::parse("12345abcdef").is_err());
        assert!(RegKey::parse("-abc").is_err());
        assert!(RegKey::parse("12-").is_err());
        assert!(RegKey::parse("0-abc").is_err());
        assert!(RegKey::parse("abc-def").is_err());
    }

    fn rk() -> RegKey {
        RegKey::parse("12345-abcdefgh").unwrap()
    }

    /// SubjectPublicKeyInfo carried in a request's certificate template.
    fn spki_from_request(req: &[u8]) -> Vec<u8> {
        let ci = der::parse_single(req).unwrap().children().unwrap();
        let sd = ci[1].children().unwrap()[0].children().unwrap();
        let pki = sd[2].children().unwrap()[1].children().unwrap()[0].octet_value().unwrap();
        let p = der::parse_single(&pki).unwrap().children().unwrap();
        let crm = p[1].children().unwrap()[0];
        let cert_req = crm.children().unwrap()[0];
        let tmpl = cert_req.children().unwrap()[1].children().unwrap();
        der::cons(der::SEQUENCE, &[tmpl[2].content])
    }

    #[test]
    fn request_matches_the_reference_byte_for_byte() {
        let key = PKey::private_key_from_pem(include_bytes!("testdata/reference_key.pem")).unwrap();
        let ours = build_request(&key, &rk()).unwrap();
        let reference: &[u8] = include_bytes!("testdata/reference_request.der");
        assert_eq!(ours.len(), reference.len());
        assert!(ours == reference, "request differs from the reference");
    }

    /// Compare against another reference request:
    /// `REF_KEY=k.pem REF_REQ=r.der REF_REGKEY=ref-code cargo test reference_request -- --ignored`
    #[test]
    #[ignore]
    fn reference_request_from_env() {
        let key = std::fs::read(std::env::var("REF_KEY").unwrap()).unwrap();
        let key = PKey::private_key_from_pem(&key).unwrap();
        let reference = std::fs::read(std::env::var("REF_REQ").unwrap()).unwrap();
        let rk = RegKey::parse(&std::env::var("REF_REGKEY").unwrap()).unwrap();
        assert!(build_request(&key, &rk).unwrap() == reference, "request differs from the reference");
    }

    #[test]
    fn key_identifier_is_sha1_of_the_bit_string_element() {
        let key = PKey::private_key_from_pem(include_bytes!("testdata/reference_key.pem")).unwrap();
        let spki = key.public_key_to_der().unwrap();
        assert_eq!(spki_from_request(include_bytes!("testdata/reference_request.der")), spki);
        let ski = key_identifier(&spki).unwrap();
        assert_eq!(ski.len(), 20);
        assert!(include_bytes!("testdata/reference_request.der").windows(20).any(|w| w == ski.as_slice()));
    }

    #[test]
    fn accepts_a_valid_response() {
        let spki = spki_from_request(include_bytes!("testdata/reference_request.der"));
        let r = parse_response(include_bytes!("testdata/response_noproof.der"), &spki, &rk()).unwrap();
        assert_eq!(r.ca_proof, None);
        assert!(r.ca.is_some());
        assert_eq!(r.cert.public_key().unwrap().public_key_to_der().unwrap(), spki);
    }

    #[test]
    fn verifies_the_ca_identity_proof() {
        let spki = spki_from_request(include_bytes!("testdata/request_for_proof.der"));
        let r = parse_response(include_bytes!("testdata/response_proof.der"), &spki, &rk()).unwrap();
        assert_eq!(r.ca_proof, Some(true));
    }

    #[test]
    fn flags_a_wrong_ca_identity_proof() {
        let spki = spki_from_request(include_bytes!("testdata/request_for_badproof.der"));
        let r = parse_response(include_bytes!("testdata/response_badproof.der"), &spki, &rk()).unwrap();
        assert_eq!(r.ca_proof, Some(false));
    }

    #[test]
    fn rejects_a_response_for_another_key() {
        let spki = spki_from_request(include_bytes!("testdata/request_for_proof.der"));
        assert!(parse_response(include_bytes!("testdata/response_noproof.der"), &spki, &rk()).is_err());
    }
}
