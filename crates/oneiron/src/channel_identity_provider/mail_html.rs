//! A mail body's HTML alternative (fix list row 17645). The HTML an agent
//! drafts is read through an HTML parser and written again from a small set
//! of elements and attributes, so the document the owner approves and the
//! document that sends are one canonical text. Markup outside the set is
//! refused, not dropped, so the drafter learns what would not send. A body
//! renders as `text/plain` alone, or as `multipart/alternative` with the
//! text first and the HTML second (RFC 2046 5.1.4), each UTF-8 in base64.

use std::fmt::Write as _;

use base64::Engine as _;
use dom_query::{Document, NodeRef};

use crate::error::{Error, Result};

/// The longest HTML alternative a message carries, in bytes, as drafted and
/// as written again.
pub(crate) const MAX_MAIL_HTML_BYTES: usize = 256 * 1024;
/// The deepest element nesting the HTML may hold.
const MAX_DEPTH: usize = 64;
/// The longest link a message carries, in bytes.
const MAX_HREF_BYTES: usize = 2048;
/// The elements a message sends.
const ELEMENTS: &[&str] = &[
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "div",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "s",
    "span",
    "strong",
    "sub",
    "sup",
    "u",
    "ul",
];
/// The elements of them that hold no content.
const VOID: &[&str] = &["br", "hr"];
/// What a `<head>` may hold: none of it is sent.
const HEAD_DROPPED: &[&str] = &["meta", "title"];

fn refused(message: impl AsRef<str>) -> Error {
    Error::InvalidConfig(format!("mail html: {}", message.as_ref()))
}

/// One step of the walk: a node to write, at its nesting depth, or the
/// closing tag of an element written.
enum Step<'a> {
    Open(NodeRef<'a>, usize),
    Close(String),
}

/// `html` written again as the one document a message sends: its text, and
/// of its markup only links (`http`, `https`, `mailto`), paragraphs, line
/// breaks, rules, headings, lists, quotes, code and simple emphasis, with
/// `dir` and `lang` on any of them. Comments and a `<head>`'s `<meta>` and
/// `<title>` are left out; any other element or attribute is refused.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the first element or attribute that is
/// not sent, a link of another scheme, nesting deeper than 64, or HTML that
/// is blank or longer than 256 KiB as drafted or as written again.
pub(crate) fn sanitize_mail_html(html: &str) -> Result<String> {
    if html.trim().is_empty() || html.len() > MAX_MAIL_HTML_BYTES {
        return Err(refused(format!(
            "the HTML is 1 to {MAX_MAIL_HTML_BYTES} bytes"
        )));
    }
    let document = Document::from(html);
    let mut out = String::with_capacity(html.len() + 64);
    out.push_str("<!DOCTYPE html><html><body>");
    let mut pending = vec![Step::Open(document.root(), 0)];
    while let Some(step) = pending.pop() {
        let (node, depth) = match step {
            Step::Close(name) => {
                let _ = write!(out, "</{name}>");
                continue;
            }
            Step::Open(node, depth) => (node, depth),
        };
        if node.is_text() {
            escape_into(&mut out, &node.text(), false);
            continue;
        }
        if node.is_comment() || node.is_doctype() {
            continue;
        }
        let children: Vec<NodeRef<'_>> = node.children_it(false).collect();
        let Some(name) = node.node_name() else {
            if node.is_document() || node.is_fragment() {
                push_children(&mut pending, children, depth);
                continue;
            }
            return Err(refused("the HTML holds a node that is not sent"));
        };
        let name = name.to_ascii_lowercase();
        match name.as_str() {
            // The frame the parser puts around any text: one is written
            // around the whole, with no attribute.
            "html" | "body" => {
                if !node.attrs().is_empty() {
                    return Err(refused(format!("<{name}> takes no attribute")));
                }
                push_children(&mut pending, children, depth);
                continue;
            }
            "head" => {
                for child in &children {
                    let dropped = child.node_name().is_some_and(|child| {
                        HEAD_DROPPED.contains(&child.to_ascii_lowercase().as_str())
                    });
                    if !(dropped || child.is_comment() || child.is_text()) {
                        return Err(refused("a <head> holds only <meta> and <title>"));
                    }
                }
                continue;
            }
            _ => {}
        }
        if !ELEMENTS.contains(&name.as_str()) {
            return Err(refused(format!(
                "<{name}> is not sent: use text, links, paragraphs, lists, quotes, code and \
                 simple emphasis"
            )));
        }
        if depth >= MAX_DEPTH {
            return Err(refused("the HTML nests deeper than 64 elements"));
        }
        let _ = write!(out, "<{name}");
        for attribute in node.attrs() {
            let key = attribute.name.local.to_ascii_lowercase();
            let value: &str = &attribute.value;
            if attribute.name.prefix.is_some() || !attribute_sent(&name, &key, value) {
                return Err(refused(format!(
                    "the attribute {key} on <{name}> is not sent: only href on <a> (http, \
                     https or mailto), dir and lang"
                )));
            }
            let _ = write!(out, " {key}=\"");
            escape_into(&mut out, value.trim(), true);
            out.push('"');
        }
        out.push('>');
        if VOID.contains(&name.as_str()) {
            continue;
        }
        // A parser drops one line break right after `<pre>`: one is written
        // there, so the text reads back exactly as it stands.
        if name == "pre" {
            out.push('\n');
        }
        pending.push(Step::Close(name));
        push_children(&mut pending, children, depth + 1);
    }
    out.push_str("</body></html>");
    if out.len() > MAX_MAIL_HTML_BYTES {
        return Err(refused(format!(
            "the HTML is longer than {MAX_MAIL_HTML_BYTES} bytes once written again"
        )));
    }
    Ok(out)
}

/// Queues `children` to be written in document order, at `depth`.
fn push_children<'a>(pending: &mut Vec<Step<'a>>, children: Vec<NodeRef<'a>>, depth: usize) {
    pending.extend(
        children
            .into_iter()
            .rev()
            .map(|child| Step::Open(child, depth)),
    );
}

/// Whether the attribute `key="value"` on `<element>` is sent.
fn attribute_sent(element: &str, key: &str, value: &str) -> bool {
    let value = value.trim();
    match key {
        "href" => {
            let lower = value.to_ascii_lowercase();
            element == "a"
                && value.len() <= MAX_HREF_BYTES
                && !value.chars().any(|c| c.is_control() || c.is_whitespace())
                && ["https://", "http://", "mailto:"]
                    .iter()
                    .any(|scheme| lower.starts_with(scheme) && lower.len() > scheme.len())
        }
        "dir" => matches!(value, "ltr" | "rtl" | "auto"),
        "lang" => {
            (1..=35).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }
        _ => false,
    }
}

/// Writes `text` escaped for HTML text, or for a quoted attribute value. A
/// carriage return is written as a reference: a parser reads a bare one as a
/// line feed, so the document would not read back as it stands.
fn escape_into(out: &mut String, text: &str, attribute: bool) {
    for c in text.chars() {
        match c {
            '\r' => out.push_str("&#13;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
}

/// Writes a message body's MIME headers, the blank line and the body: the
/// text alone as `text/plain`, or, with an HTML alternative, both under
/// `multipart/alternative`, the text first. Each part is UTF-8 in base64,
/// so no line of either reaches the header block or passes the line limit,
/// and the boundary, drawn from both parts, holds `_`, which base64 never
/// writes.
pub(crate) fn push_mail_body(out: &mut String, text: &str, html: Option<&str>) {
    let text = text.replace("\r\n", "\n").replace('\n', "\r\n");
    let Some(html) = html else {
        out.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
        out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        push_base64(out, text.as_bytes());
        return;
    };
    let mut seed = blake3::Hasher::new();
    seed.update(b"oneiron.mail.body.boundary.v1");
    seed.update(&(text.len() as u64).to_le_bytes());
    seed.update(text.as_bytes());
    seed.update(html.as_bytes());
    let digest = seed.finalize().to_hex();
    let boundary = format!("=_oneiron_{}", &digest.as_str()[..32]);
    let _ = write!(
        out,
        "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"
    );
    for (kind, bytes) in [
        ("text/plain", text.as_bytes()),
        ("text/html", html.as_bytes()),
    ] {
        let _ = write!(
            out,
            "--{boundary}\r\nContent-Type: {kind}; charset=UTF-8\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n"
        );
        push_base64(out, bytes);
    }
    let _ = write!(out, "--{boundary}--\r\n");
}

/// The characters one base64 body line holds (RFC 2045 6.8); a file's
/// name folds at the same width ([`super::mail_attachments`]).
pub(super) const MAIL_LINE_CHARS: usize = 76;

/// Writes `bytes` in base64, [`MAIL_LINE_CHARS`] characters a line.
pub(super) fn push_base64(out: &mut String, bytes: &[u8]) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    for line in encoded.as_bytes().chunks(MAIL_LINE_CHARS) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push_str("\r\n");
    }
}
