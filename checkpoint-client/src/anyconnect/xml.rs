//! A small, tolerant XML reader for the AnyConnect aggregate-auth documents.
//!
//! The gateway's `<config-auth>` replies are tiny and well-formed in practice, so
//! a full XML stack is overkill; this builds a minimal DOM (elements, attributes,
//! text) and remembers each element's byte span in the source, which lets the
//! auth layer echo the server's `<opaque>` block back verbatim — exactly what the
//! protocol requires.
//!
//! Tolerant by design: comments, processing instructions, DOCTYPE and CDATA are
//! handled; a stray or mismatched closing tag closes the nearest matching open
//! element instead of failing the whole parse.

/// One XML element.
#[derive(Debug, Clone, Default)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// Direct text content (entity-decoded), concatenated across text nodes.
    pub text: String,
    /// Byte range of the whole element (start tag … end tag) in the source.
    pub span: (usize, usize),
}

impl Element {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// First direct child with this name.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    /// All direct children with this name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Trimmed direct text of the first child with this name, if non-empty.
    pub fn child_text(&self, name: &str) -> Option<String> {
        self.child(name).map(|c| c.text.trim().to_string()).filter(|s| !s.is_empty())
    }

    /// All text in this element and its descendants (libxml2's `xmlNodeGetContent`).
    pub fn deep_text(&self) -> String {
        let mut out = self.text.clone();
        for c in &self.children {
            out.push_str(&c.deep_text());
        }
        out
    }
}

/// Parse `src` and return its root element.
pub fn parse(src: &str) -> Result<Element, String> {
    let b = src.as_bytes();
    let mut i = 0usize;
    // Stack of open elements; index 0 is a synthetic document node.
    let mut stack: Vec<Element> = vec![Element::default()];

    while i < b.len() {
        if b[i] != b'<' {
            let end = find(b, i, b"<").unwrap_or(b.len());
            let text = decode_entities(&src[i..end]);
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&text);
            }
            i = end;
            continue;
        }
        // Markup.
        if starts(b, i, b"<!--") {
            i = find(b, i + 4, b"-->").map(|e| e + 3).unwrap_or(b.len());
        } else if starts(b, i, b"<![CDATA[") {
            let end = find(b, i + 9, b"]]>").unwrap_or(b.len());
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&src[i + 9..end]);
            }
            i = (end + 3).min(b.len());
        } else if starts(b, i, b"<?") {
            i = find(b, i + 2, b"?>").map(|e| e + 2).unwrap_or(b.len());
        } else if starts(b, i, b"<!") {
            i = find(b, i + 2, b">").map(|e| e + 1).unwrap_or(b.len());
        } else if starts(b, i, b"</") {
            let end = find(b, i, b">").ok_or("unterminated end tag")?;
            let name = src[i + 2..end].trim().to_string();
            let close_at = end + 1;
            // Close up to the nearest open element with this name (tolerates a
            // missing end tag); ignore a stray end tag that matches nothing open.
            if let Some(pos) = stack.iter().rposition(|e| e.name == name) {
                if pos > 0 {
                    while stack.len() > pos {
                        let mut done = stack.pop().unwrap_or_default();
                        done.span.1 = close_at;
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(done);
                        }
                    }
                }
            }
            i = close_at;
        } else {
            // Start tag (possibly self-closing). Quotes may hide a '>'.
            let (end, self_closing) = scan_tag_end(b, i + 1).ok_or("unterminated start tag")?;
            let inner = &src[i + 1..if self_closing { end - 1 } else { end }];
            let (name, attrs) = parse_tag(inner);
            let el = Element { name, attrs, span: (i, end + 1), ..Default::default() };
            if self_closing {
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(el);
                }
            } else {
                stack.push(el);
            }
            i = end + 1;
        }
    }
    // Close anything left open at EOF.
    while stack.len() > 1 {
        let mut done = stack.pop().unwrap_or_default();
        done.span.1 = b.len();
        if let Some(parent) = stack.last_mut() {
            parent.children.push(done);
        }
    }
    let doc = stack.pop().unwrap_or_default();
    doc.children.into_iter().next().ok_or_else(|| "no root element".to_string())
}

/// Escape text for an XML element body or attribute value.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Decode the predefined entities plus numeric character references.
pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        let Some(semi) = after.find(';').filter(|&p| p <= 10) else {
            out.push('&');
            rest = &after[1..];
            continue;
        };
        let ent = &after[1..semi];
        let decoded = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32)
            }
            _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &after[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn starts(b: &[u8], i: usize, pat: &[u8]) -> bool {
    b.len() >= i + pat.len() && &b[i..i + pat.len()] == pat
}

fn find(b: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    if from > b.len() {
        return None;
    }
    b[from..].windows(pat.len()).position(|w| w == pat).map(|p| p + from)
}

/// Index of the `>` closing a start tag that begins at `from` (just after `<`),
/// skipping quoted attribute values; and whether it was self-closing (`/>`).
fn scan_tag_end(b: &[u8], from: usize) -> Option<(usize, bool)> {
    let mut quote: Option<u8> = None;
    let mut i = from;
    while i < b.len() {
        let c = b[i];
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == b'"' || c == b'\'' => quote = Some(c),
            None if c == b'>' => return Some((i, i > from && b[i - 1] == b'/')),
            None => {}
        }
        i += 1;
    }
    None
}

/// Split a start tag's inside (`name a="1" b='2'`) into name + attributes.
fn parse_tag(inner: &str) -> (String, Vec<(String, String)>) {
    let inner = inner.trim();
    let name_end = inner.find(|c: char| c.is_whitespace()).unwrap_or(inner.len());
    let name = inner[..name_end].to_string();
    let mut attrs = Vec::new();
    let b = inner.as_bytes();
    let mut i = name_end;
    while i < b.len() {
        while i < b.len() && (b[i] as char).is_whitespace() {
            i += 1;
        }
        let k_start = i;
        while i < b.len() && b[i] != b'=' && !(b[i] as char).is_whitespace() {
            i += 1;
        }
        let key = inner[k_start..i].to_string();
        while i < b.len() && (b[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            if !key.is_empty() {
                attrs.push((key, String::new())); // valueless attribute (HTML-ish)
            }
            continue;
        }
        i += 1; // '='
        while i < b.len() && (b[i] as char).is_whitespace() {
            i += 1;
        }
        let value = if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
            let q = b[i];
            let v_start = i + 1;
            let v_end = inner[v_start..].bytes().position(|c| c == q).map(|p| p + v_start).unwrap_or(b.len());
            i = (v_end + 1).min(b.len());
            &inner[v_start..v_end]
        } else {
            let v_start = i;
            while i < b.len() && !(b[i] as char).is_whitespace() {
                i += 1;
            }
            &inner[v_start..i]
        };
        if !key.is_empty() {
            attrs.push((key, decode_entities(value)));
        }
    }
    (name, attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_REQ: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg">
<tunnel-group>AnyConnect_VPN</tunnel-group>
<aggauth-handle>4235996973563796626</aggauth-handle>
</opaque>
<auth id="main">
<form>
<input type="text" name="username" label="Username:"></input>
<input type="password" name="password" label="Password:"></input>
<select name="group_list" label="GROUP:">
<option selected="true">GROUP_A</option>
<option>GROUP_B</option>
</select>
</form>
</auth>
</config-auth>"#;

    #[test]
    fn parses_auth_request_tree() {
        let root = parse(AUTH_REQ).unwrap();
        assert_eq!(root.name, "config-auth");
        assert_eq!(root.attr("type"), Some("auth-request"));
        let auth = root.child("auth").unwrap();
        assert_eq!(auth.attr("id"), Some("main"));
        let form = auth.child("form").unwrap();
        let inputs: Vec<_> = form.children_named("input").collect();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[1].attr("type"), Some("password"));
        let sel = form.child("select").unwrap();
        let opts: Vec<_> = sel.children_named("option").collect();
        assert_eq!(opts[0].text, "GROUP_A");
        assert_eq!(opts[0].attr("selected"), Some("true"));
        assert_eq!(opts[1].text, "GROUP_B");
    }

    #[test]
    fn span_extracts_opaque_verbatim() {
        let root = parse(AUTH_REQ).unwrap();
        let op = root.child("opaque").unwrap();
        let raw = &AUTH_REQ[op.span.0..op.span.1];
        assert!(raw.starts_with("<opaque is-for=\"sg\">"));
        assert!(raw.ends_with("</opaque>"));
        assert!(raw.contains("<aggauth-handle>4235996973563796626</aggauth-handle>"));
    }

    #[test]
    fn decodes_entities_in_text_and_attrs() {
        let root = parse(r#"<a href="x?a=1&#x26;b=2"><u>https://h/p?ctx=1&#x26;acsamlcap=v2 &amp; &lt;ok&gt;</u></a>"#).unwrap();
        assert_eq!(root.attr("href"), Some("x?a=1&b=2"));
        assert_eq!(root.child_text("u").unwrap(), "https://h/p?ctx=1&acsamlcap=v2 & <ok>");
    }

    #[test]
    fn self_closing_comments_and_missing_end_tags() {
        let root = parse("<r><!-- c --><x a='1'/><y>t<z>u</r>").unwrap();
        assert_eq!(root.name, "r");
        assert_eq!(root.child("x").unwrap().attr("a"), Some("1"));
        let y = root.child("y").unwrap();
        assert_eq!(y.text, "t");
        assert_eq!(y.child("z").unwrap().text, "u");
        assert_eq!(root.deep_text(), "tu");
    }

    #[test]
    fn quoted_gt_inside_attribute() {
        let root = parse(r#"<m note="a>b">x</m>"#).unwrap();
        assert_eq!(root.attr("note"), Some("a>b"));
        assert_eq!(root.text, "x");
    }

    #[test]
    fn escape_roundtrip() {
        let s = r#"p&ss<w>"rd'"#;
        assert_eq!(decode_entities(&escape(s)), s);
    }
}
