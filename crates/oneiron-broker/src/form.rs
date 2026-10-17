//! `multipart/form-data` bodies, for the shapes that upload a file: the check
//! the broker runs on one, which finds the `model` field without rewriting a
//! byte, and [`FormData`], which builds one the check passes.
//!
//! The check takes one plain form only. The content type names a bare token
//! boundary. The body opens on the first delimiter and closes on the last,
//! with no preamble and nothing after but one line break. The boundary
//! appears nowhere but at those delimiters. Each part has one
//! `content-disposition: form-data` header with a quoted `name` (and maybe a
//! file name), at most one `content-type`, and no other header. So no parser
//! between here and the provider can find a part, or a `model` field, that
//! the check did not.

use crate::Refusal;
use crate::shape::ROUTE_OVERRIDES;

/// The content type's spelling before the boundary.
const PREFIX: &str = "multipart/form-data; boundary=";

/// The longest boundary (RFC 2046).
const MAX_BOUNDARY: usize = 70;

/// The blake3 key-derivation context of a built form's boundary.
const BOUNDARY_CONTEXT: &str = "oneiron-broker 2026-10-17 form boundary v1";

/// Reads the one `model` field of the form `body`, sent under
/// `content_type`, or `None` when it has none.
pub(crate) fn read_model(content_type: &str, body: &[u8]) -> Result<Option<String>, Refusal> {
    let boundary = content_type
        .strip_prefix(PREFIX)
        .filter(|boundary| plain_boundary(boundary))
        .ok_or(Refusal::Body)?;
    let mut delimiter = b"--".to_vec();
    delimiter.extend_from_slice(boundary.as_bytes());
    let mut model = None;
    for bytes in parts(body, &delimiter)? {
        let field = part(bytes)?;
        if ROUTE_OVERRIDES.contains(&field.name) {
            return Err(Refusal::RouteOverride);
        }
        if field.name != "model" {
            continue;
        }
        if model.is_some() {
            return Err(Refusal::SelectorRepeated);
        }
        if field.file || field.typed {
            return Err(Refusal::SelectorNotString);
        }
        let value = std::str::from_utf8(field.content)
            .ok()
            .filter(|value| !value.contains(['\r', '\n']))
            .ok_or(Refusal::SelectorNotString)?;
        model = Some(value.to_owned());
    }
    Ok(model)
}

/// A boundary of letters, digits and `-._`, at most [`MAX_BOUNDARY`] long.
fn plain_boundary(boundary: &str) -> bool {
    (1..=MAX_BOUNDARY).contains(&boundary.len())
        && boundary
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
}

/// The parts of `body`, each between a delimiter's line break and the line
/// break before the next delimiter. Every place the delimiter appears must be
/// one: at the start or after a line break, and followed by a line break, or
/// by `--` for the last one, which ends the body.
fn parts<'b>(body: &'b [u8], delimiter: &[u8]) -> Result<Vec<&'b [u8]>, Refusal> {
    let mut parts = Vec::new();
    let mut open = None;
    let mut closed = false;
    for at in memchr::memmem::find_iter(body, delimiter) {
        if closed {
            return Err(Refusal::Body);
        }
        match open {
            None if at != 0 => return Err(Refusal::Body),
            None => {}
            Some(start) => {
                let end = at
                    .checked_sub(2)
                    .filter(|end| *end >= start && &body[*end..at] == b"\r\n")
                    .ok_or(Refusal::Body)?;
                parts.push(&body[start..end]);
            }
        }
        let after = &body[at + delimiter.len()..];
        if let Some(rest) = after.strip_prefix(b"--") {
            if !rest.is_empty() && rest != b"\r\n" {
                return Err(Refusal::Body);
            }
            closed = true;
        } else if after.starts_with(b"\r\n") {
            open = Some(at + delimiter.len() + 2);
        } else {
            return Err(Refusal::Body);
        }
    }
    if closed && !parts.is_empty() {
        Ok(parts)
    } else {
        Err(Refusal::Body)
    }
}

/// One part's field name, whether it is a file or carries a content type,
/// and its content.
struct Part<'b> {
    name: &'b str,
    file: bool,
    typed: bool,
    content: &'b [u8],
}

fn part(bytes: &[u8]) -> Result<Part<'_>, Refusal> {
    let split = memchr::memmem::find(bytes, b"\r\n\r\n").ok_or(Refusal::Body)?;
    let head = std::str::from_utf8(&bytes[..split]).map_err(|_| Refusal::Body)?;
    let mut disposition = None;
    let mut typed = false;
    for line in head.split("\r\n") {
        // Visible ASCII and spaces only: no lone line break, tab or fold.
        if !line.bytes().all(|byte| (0x20..0x7f).contains(&byte)) {
            return Err(Refusal::Body);
        }
        let (name, value) = line.split_once(':').ok_or(Refusal::Body)?;
        if name.eq_ignore_ascii_case("content-disposition") && disposition.is_none() {
            disposition = Some(value.trim_matches(' '));
        } else if name.eq_ignore_ascii_case("content-type") && !typed {
            typed = true;
        } else {
            return Err(Refusal::Body);
        }
    }
    let (name, file) = disposition_fields(disposition.ok_or(Refusal::Body)?)?;
    Ok(Part {
        name,
        file,
        typed,
        content: &bytes[split + 4..],
    })
}

/// `form-data; name="…"` and maybe `; filename="…"` or `; filename*=…`, each
/// once and spelled lowercase. A quoted value holds no quote, backslash or
/// `;`, and a name is not empty.
fn disposition_fields(value: &str) -> Result<(&str, bool), Refusal> {
    let mut params = value.split(';');
    if !params
        .next()
        .is_some_and(|kind| kind.trim_matches(' ').eq_ignore_ascii_case("form-data"))
    {
        return Err(Refusal::Body);
    }
    let mut name = None;
    let mut file = false;
    for param in params {
        let (key, raw) = param
            .trim_matches(' ')
            .split_once('=')
            .ok_or(Refusal::Body)?;
        let quoted = raw
            .strip_prefix('"')
            .and_then(|raw| raw.strip_suffix('"'))
            .filter(|value| !value.contains(['"', '\\']));
        match key {
            "name" if name.is_none() => {
                name = Some(
                    quoted
                        .filter(|name| !name.is_empty())
                        .ok_or(Refusal::Body)?,
                );
            }
            "filename" if !file && quoted.is_some() => file = true,
            "filename*" if !file && !raw.is_empty() && !raw.contains(['"', '\\', ' ']) => {
                file = true;
            }
            _ => return Err(Refusal::Body),
        }
    }
    Ok((name.ok_or(Refusal::Body)?, file))
}

/// A `multipart/form-data` body that [`crate::CallHeader::check`] passes:
/// text fields and files, in the order added. Its boundary is derived from
/// the parts, so one form always gives the same bytes, and so the same
/// digest at admission and at the send.
#[derive(Debug, Clone, Default)]
pub struct FormData {
    parts: Vec<FormPart>,
}

#[derive(Debug, Clone)]
struct FormPart {
    name: String,
    /// The file name and media type of a file part.
    file: Option<(String, String)>,
    bytes: Vec<u8>,
}

impl FormData {
    /// An empty form.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a text field. The `model` field is the call's selector.
    #[must_use]
    pub fn text(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parts.push(FormPart {
            name: name.into(),
            file: None,
            bytes: value.into().into_bytes(),
        });
        self
    }

    /// Adds a file under the field `name`, with its file name and media type.
    /// A name or file name holding a quote, backslash, `;` or line break
    /// makes a form the check refuses.
    #[must_use]
    pub fn file(
        mut self,
        name: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        self.parts.push(FormPart {
            name: name.into(),
            file: Some((filename.into(), media_type.into())),
            bytes,
        });
        self
    }

    /// The content type, with its boundary, and the body.
    #[must_use]
    pub fn finish(&self) -> (String, Vec<u8>) {
        let mut hasher = blake3::Hasher::new_derive_key(BOUNDARY_CONTEXT);
        for part in &self.parts {
            let (filename, media_type) = part
                .file
                .as_ref()
                .map_or(("", ""), |(filename, media_type)| {
                    (filename.as_str(), media_type.as_str())
                });
            for field in [
                part.name.as_bytes(),
                filename.as_bytes(),
                media_type.as_bytes(),
                part.bytes.as_slice(),
            ] {
                hasher.update(&(field.len() as u64).to_le_bytes());
                hasher.update(field);
            }
        }
        let boundary = format!("oneiron-{}", &hasher.finalize().to_hex().as_str()[..32]);
        let mut body = Vec::new();
        for part in &self.parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{}\"", part.name).as_bytes(),
            );
            if let Some((filename, media_type)) = &part.file {
                body.extend_from_slice(
                    format!("; filename=\"{filename}\"\r\nContent-Type: {media_type}").as_bytes(),
                );
            }
            body.extend_from_slice(b"\r\n\r\n");
            body.extend_from_slice(&part.bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (format!("{PREFIX}{boundary}"), body)
    }
}
