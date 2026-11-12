//! Minimal ASN.1 DER encoder and a tolerant BER/DER reader.
//!
//! The encoder emits definite-length DER. The reader also accepts the BER forms a
//! peer may legitimately send (indefinite lengths, constructed OCTET STRINGs).

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0c;

fn len_bytes(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let b = n.to_be_bytes();
    let skip = b.iter().take_while(|&&x| x == 0).count();
    let mut out = vec![0x80 | (b.len() - skip) as u8];
    out.extend_from_slice(&b[skip..]);
    out
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(len_bytes(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn cons(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag, &parts.concat())
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    cons(SEQUENCE, parts)
}

/// A SET holding the given elements in the given order (callers pass one element
/// or elements already in DER order).
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    cons(SET, parts)
}

/// Content octets of a non-negative INTEGER (two's complement, minimal).
pub fn uint_content(v: &[u8]) -> Vec<u8> {
    let skip = v.iter().take_while(|&&x| x == 0).count();
    let mut out: Vec<u8> = v[skip..].to_vec();
    if out.is_empty() {
        out.push(0);
    } else if out[0] & 0x80 != 0 {
        out.insert(0, 0);
    }
    out
}

pub fn uint(v: u64) -> Vec<u8> {
    tlv(INTEGER, &uint_content(&v.to_be_bytes()))
}

pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

pub fn null() -> Vec<u8> {
    vec![NULL, 0]
}

pub fn utf8(s: &str) -> Vec<u8> {
    tlv(UTF8_STRING, s.as_bytes())
}

pub fn bit_string(b: &[u8]) -> Vec<u8> {
    let mut c = vec![0u8];
    c.extend_from_slice(b);
    tlv(BIT_STRING, &c)
}

pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|a| a.parse().expect("OID arc"))
        .collect();
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut enc = vec![(a & 0x7f) as u8];
        let mut v = a >> 7;
        while v > 0 {
            enc.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        enc.reverse();
        out.extend(enc);
    }
    tlv(OID, &out)
}

/// `SEQUENCE { algorithm OID, parameters NULL }`.
pub fn alg_null(dotted: &str) -> Vec<u8> {
    seq(&[&oid(dotted), &null()])
}

/// One decoded element. `raw` is the whole encoding (tag, length and content).
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn is_constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    pub fn children(&self) -> Result<Vec<Tlv<'a>>, String> {
        if !self.is_constructed() {
            return Err(format!(
                "element with tag {:#04x} is not constructed",
                self.tag
            ));
        }
        parse_all(self.content)
    }

    pub fn expect(self, tag: u8) -> Result<Tlv<'a>, String> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(format!("expected tag {tag:#04x}, found {:#04x}", self.tag))
        }
    }

    /// Value of a non-negative INTEGER that fits in 64 bits.
    pub fn as_u64(&self) -> Result<u64, String> {
        if self.tag != INTEGER {
            return Err(format!("expected INTEGER, found tag {:#04x}", self.tag));
        }
        let c = self.content;
        if c.is_empty() || c[0] & 0x80 != 0 || c.len() > 9 || (c.len() == 9 && c[0] != 0) {
            return Err("INTEGER out of range".into());
        }
        Ok(c.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }

    /// Dotted form of an OBJECT IDENTIFIER.
    pub fn as_oid(&self) -> Result<String, String> {
        if self.tag != OID || self.content.is_empty() {
            return Err("expected OBJECT IDENTIFIER".into());
        }
        let c = self.content;
        let mut arcs = vec![(c[0] / 40) as u64, (c[0] % 40) as u64];
        let mut v = 0u64;
        for &b in &c[1..] {
            v = (v << 7) | (b & 0x7f) as u64;
            if b & 0x80 == 0 {
                arcs.push(v);
                v = 0;
            }
        }
        Ok(arcs
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."))
    }

    /// OCTET STRING value; a BER constructed OCTET STRING is reassembled.
    pub fn octet_value(&self) -> Result<Vec<u8>, String> {
        match self.tag {
            OCTET_STRING => Ok(self.content.to_vec()),
            0x24 => {
                let mut out = Vec::new();
                for c in self.children()? {
                    out.extend(c.octet_value()?);
                }
                Ok(out)
            }
            t => Err(format!("expected OCTET STRING, found tag {t:#04x}")),
        }
    }
}

/// Parse the element at the start of `b`; returns it and the remaining bytes.
pub fn parse<'a>(b: &'a [u8]) -> Result<(Tlv<'a>, &'a [u8]), String> {
    if b.len() < 2 {
        return Err("truncated ASN.1 element".into());
    }
    let tag = b[0];
    if tag & 0x1f == 0x1f {
        return Err("multi-byte ASN.1 tags are not supported".into());
    }
    let l0 = b[1] as usize;
    let (hdr, len) = if l0 < 0x80 {
        (2, Some(l0))
    } else if l0 == 0x80 {
        (2, None)
    } else {
        let n = l0 & 0x7f;
        if n > 4 || b.len() < 2 + n {
            return Err("bad ASN.1 length".into());
        }
        (
            2 + n,
            Some(
                b[2..2 + n]
                    .iter()
                    .fold(0usize, |a, &x| (a << 8) | x as usize),
            ),
        )
    };
    match len {
        Some(l) => {
            if b.len() < hdr + l {
                return Err("truncated ASN.1 content".into());
            }
            let t = Tlv {
                tag,
                content: &b[hdr..hdr + l],
                raw: &b[..hdr + l],
            };
            Ok((t, &b[hdr + l..]))
        }
        None => {
            if tag & 0x20 == 0 {
                return Err("indefinite length on a primitive element".into());
            }
            let mut rest = &b[hdr..];
            loop {
                if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                    let clen = b.len() - hdr - rest.len();
                    let t = Tlv {
                        tag,
                        content: &b[hdr..hdr + clen],
                        raw: &b[..hdr + clen + 2],
                    };
                    return Ok((t, &rest[2..]));
                }
                let (_, r) = parse(rest)?;
                rest = r;
            }
        }
    }
}

pub fn parse_all(mut b: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (t, r) = parse(b)?;
        out.push(t);
        b = r;
    }
    Ok(out)
}

/// Parse exactly one element spanning all of `b`.
pub fn parse_single(b: &[u8]) -> Result<Tlv<'_>, String> {
    let (t, rest) = parse(b)?;
    if !rest.is_empty() {
        return Err(format!("{} trailing bytes after ASN.1 element", rest.len()));
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        for o in [
            "1.2.840.113549.1.7.2",
            "1.3.6.1.5.5.7.7.3",
            "1.3.14.3.2.26",
            "2.5.4.3",
        ] {
            let e = oid(o);
            assert_eq!(parse_single(&e).unwrap().as_oid().unwrap(), o);
        }
        assert_eq!(
            oid("1.3.6.1.5.5.7.7.3"),
            [0x06, 0x08, 0x2b, 6, 1, 5, 5, 7, 7, 3]
        );
    }

    #[test]
    fn integers_are_minimal() {
        assert_eq!(uint(101), [0x02, 0x01, 0x65]);
        assert_eq!(uint(12345), [0x02, 0x02, 0x30, 0x39]);
        assert_eq!(uint(200), [0x02, 0x02, 0x00, 0xc8]);
        assert_eq!(uint(0), [0x02, 0x01, 0x00]);
        assert_eq!(
            parse_single(&uint(1 << 40)).unwrap().as_u64().unwrap(),
            1 << 40
        );
    }

    #[test]
    fn long_lengths() {
        let c = vec![7u8; 300];
        let e = octets(&c);
        assert_eq!(&e[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(parse_single(&e).unwrap().content, &c[..]);
    }

    #[test]
    fn indefinite_and_constructed_octets() {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "c" } }
        let b = [
            0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0, 0,
        ];
        let s = parse_single(&b).unwrap();
        let kids = s.children().unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].octet_value().unwrap(), b"abc");
    }
}
