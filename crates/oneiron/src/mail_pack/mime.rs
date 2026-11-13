//! A native RFC 5322 and MIME reader (FIX 12559: mbox and Google Takeout
//! intake). It reads one message's header fields, decoded (RFC 2047 encoded
//! words, RFC 2231 parameters, any charset `encoding_rs` knows), and its part
//! tree. Parts are numbered the way Gmail numbers them: `""` for the message,
//! `"0"`, `"1"` for a multipart's children, `"1.0"` below them. So a message
//! read from a Takeout export names its attachments by the part ids the Gmail
//! wire opens them by.

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use super::rest::html_text;
use super::wire::{MailAddressHeaders, MailAttachmentRef};

/// The deepest part nesting read.
const MAX_PART_DEPTH: usize = 32;
/// The most parts one message is read into.
const MAX_PARTS: usize = 1_024;
/// The most header fields one part keeps.
const MAX_FIELDS: usize = 1_024;

/// Base64 as mail writes it: padding or none, stray trailing bits allowed.
const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// One line of a byte text: where it starts, where its words end (before
/// its `\r\n` or `\n`), and where the next line starts.
#[derive(Debug, Clone, Copy)]
struct Line {
    start: usize,
    end: usize,
    next: usize,
}

fn lines(bytes: &[u8]) -> impl Iterator<Item = Line> + '_ {
    let mut at = 0;
    std::iter::from_fn(move || {
        if at >= bytes.len() {
            return None;
        }
        let start = at;
        let (end, next) = match bytes[start..].iter().position(|&byte| byte == b'\n') {
            Some(offset) => {
                let newline = start + offset;
                let end = if newline > start && bytes[newline - 1] == b'\r' {
                    newline - 1
                } else {
                    newline
                };
                (end, newline + 1)
            }
            None => (bytes.len(), bytes.len()),
        };
        at = next;
        Some(Line { start, end, next })
    })
}

/// A header block's fields, names lowercased, values unfolded, and where the
/// body after it starts.
fn split_header(bytes: &[u8]) -> (Vec<(String, Vec<u8>)>, usize) {
    let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
    for line in lines(bytes) {
        let text = &bytes[line.start..line.end];
        if text.is_empty() {
            return (fields, line.next);
        }
        if matches!(text[0], b' ' | b'\t') {
            if let Some((_, value)) = fields.last_mut() {
                value.extend_from_slice(text);
            }
            continue;
        }
        let Some(colon) = text.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let name = String::from_utf8_lossy(&text[..colon])
            .trim()
            .to_ascii_lowercase();
        if name.is_empty() || name.contains(char::is_whitespace) {
            continue;
        }
        if fields.len() < MAX_FIELDS {
            fields.push((name, text[colon + 1..].trim_ascii_start().to_vec()));
        }
    }
    (fields, bytes.len())
}

/// Bytes as text in `charset`, else as UTF-8, else as Windows-1252.
fn decode_charset(bytes: &[u8], charset: Option<&str>) -> String {
    if let Some(encoding) =
        charset.and_then(|label| encoding_rs::Encoding::for_label(label.trim().as_bytes()))
    {
        return encoding.decode(bytes).0.into_owned();
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => encoding_rs::WINDOWS_1252.decode(bytes).0.into_owned(),
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

/// The byte a `=XX` or `%XX` escape at `at` names.
fn hex_pair(bytes: &[u8], at: usize) -> Option<u8> {
    let high = hex_value(*bytes.get(at + 1)?)?;
    let low = hex_value(*bytes.get(at + 2)?)?;
    Some((high << 4) | low)
}

/// A header value's words: RFC 2047 encoded words decoded, the space between
/// two of them dropped, 8-bit text read as UTF-8 (Windows-1252 when it is
/// not UTF-8).
pub(super) fn decode_words(raw: &[u8]) -> String {
    let text = decode_charset(raw, None);
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    let mut after_word = false;
    while let Some(start) = rest.find("=?") {
        let (before, candidate) = rest.split_at(start);
        if let Some((decoded, used)) = encoded_word(candidate) {
            if !(after_word && before.chars().all(|ch| ch == ' ' || ch == '\t')) {
                out.push_str(before);
            }
            out.push_str(&decoded);
            rest = &candidate[used..];
            after_word = true;
        } else {
            out.push_str(before);
            out.push_str("=?");
            rest = &candidate[2..];
            after_word = false;
        }
    }
    out.push_str(rest);
    out
}

/// The address fields a reply reads, lowercased, in the order of
/// [`MailAddressHeaders`]'s fields.
const ADDRESS_FIELDS: [&str; 4] = ["from", "reply-to", "to", "cc"];

/// The address headers of the raw message `bytes`: From, Reply-To, To and
/// Cc, each the first field of its name, read by [`address_values`]. The
/// header block is read to its end and only these four fields are kept, so a
/// message with more fields than a parse keeps ([`MAX_FIELDS`]) still names
/// each address field it carries, however late (fix list rows 20520, 20852:
/// every landing and every reply reads its addresses here). Values are
/// unfolded as [`split_header`] unfolds them.
pub(super) fn raw_address_headers(bytes: &[u8]) -> MailAddressHeaders {
    let mut fields: [Option<Vec<u8>>; 4] = Default::default();
    // The kept field a continuation line goes on: the one on the line above.
    let mut continued: Option<usize> = None;
    for line in lines(bytes) {
        let text = &bytes[line.start..line.end];
        if text.is_empty() {
            break;
        }
        if matches!(text[0], b' ' | b'\t') {
            if let Some(slot) = continued
                && let Some(value) = fields[slot].as_mut()
            {
                value.extend_from_slice(text);
            }
            continue;
        }
        continued = None;
        let Some(colon) = text.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let name = String::from_utf8_lossy(&text[..colon])
            .trim()
            .to_ascii_lowercase();
        if let Some(slot) = ADDRESS_FIELDS.iter().position(|field| *field == name)
            && fields[slot].is_none()
        {
            fields[slot] = Some(text[colon + 1..].trim_ascii_start().to_vec());
            continued = Some(slot);
        }
    }
    let [from, reply_to, to, cc] =
        fields.map(|value| value.as_deref().map(address_values).unwrap_or_default());
    MailAddressHeaders {
        from,
        reply_to,
        to,
        cc,
    }
}

/// The mailboxes of one raw address field value (From, To, Cc, Reply-To),
/// one entry each. The value is split at its top-level commas BEFORE any
/// encoded word is decoded, so a comma an encoded display name decodes to
/// never splits a mailbox (fix list row 17645). A display name with encoded
/// words is then decoded and written as a display name again
/// ([`display_name`]); every other mailbox, and a group's bounds, stay as the
/// sender wrote them.
fn address_values(value: &[u8]) -> Vec<String> {
    super::gmail::address_list(&decode_charset(value, None))
        .iter()
        .map(|mailbox| decoded_mailbox(mailbox))
        .collect()
}

/// One mailbox of a raw address header (`phrase <address>` or an address):
/// a phrase with encoded words decoded and written as a display name again
/// (a quoted phrase read without its quotes first), the angle address as
/// the sender wrote it. The angle address is the one outside quoted strings
/// and comments; a mailbox with no encoded word, not exactly one such angle
/// address ending it, or a `:` in its phrase (a group's opening) is left
/// as it is.
fn decoded_mailbox(mailbox: &str) -> String {
    let mailbox = mailbox.trim();
    let (places, unclosed) = super::gmail::address_places(mailbox);
    let mut angles = places.iter().filter(|(_, character, place)| {
        *character == '<' && *place == super::gmail::AddressPlace::Top
    });
    let (Some(&(open, _, _)), None, false) = (angles.next(), angles.next(), unclosed) else {
        return mailbox.to_owned();
    };
    let (phrase, address) = (mailbox[..open].trim(), &mailbox[open..]);
    if !phrase.contains("=?") || !address.ends_with('>') || phrase.contains(':') {
        return mailbox.to_owned();
    }
    let unquoted = match phrase
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
    {
        Some(inner) => {
            let mut text = String::with_capacity(inner.len());
            let mut escaped = false;
            for character in inner.chars() {
                if escaped || character != '\\' {
                    text.push(character);
                    escaped = false;
                } else {
                    escaped = true;
                }
            }
            text
        }
        None => phrase.to_owned(),
    };
    let name = decode_words(unquoted.as_bytes());
    let name = name.trim();
    if name.is_empty() {
        return address.to_owned();
    }
    format!("{} {address}", display_name(name))
}

/// `name` as an RFC 5322 display name: as it is when it is plain words
/// (atom characters and spaces), else a quoted string with each `\\` and `"`
/// escaped and each control character written as a space, so a comma,
/// colon or angle bracket in it never reads as a list, group or address
/// boundary (fix list row 17645).
pub(super) fn display_name(name: &str) -> String {
    let plain = name.chars().all(|character| {
        character.is_alphanumeric() || character == ' ' || "!#$%&'*+-/=?^_`{|}~".contains(character)
    });
    if plain {
        return name.to_owned();
    }
    let mut quoted = String::with_capacity(name.len() + 2);
    quoted.push('"');
    for character in name.chars() {
        match character {
            '\\' | '"' => {
                quoted.push('\\');
                quoted.push(character);
            }
            control if control.is_control() => quoted.push(' '),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// One encoded word at the start of `text`: its words, and how many bytes
/// of `text` it took.
fn encoded_word(text: &str) -> Option<(String, usize)> {
    let body = text.strip_prefix("=?")?;
    let (charset, body) = body.split_once('?')?;
    let (encoding, body) = body.split_once('?')?;
    let end = body.find("?=")?;
    let payload = &body[..end];
    if charset.is_empty() || payload.contains(' ') {
        return None;
    }
    let used = 2 + charset.len() + 1 + encoding.len() + 1 + end + 2;
    let bytes = match encoding {
        "B" | "b" => LENIENT_BASE64.decode(payload.trim_end_matches('=')).ok()?,
        "Q" | "q" => q_decode(payload),
        _ => return None,
    };
    let charset = charset.split('*').next().unwrap_or(charset);
    Some((decode_charset(&bytes, Some(charset)), used))
}

/// RFC 2047 "Q": `_` is a space, `=XX` a byte.
fn q_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'_' => {
                out.push(b' ');
                at += 1;
            }
            b'=' => match hex_pair(bytes, at) {
                Some(byte) => {
                    out.push(byte);
                    at += 3;
                }
                None => {
                    out.push(b'=');
                    at += 1;
                }
            },
            byte => {
                out.push(byte);
                at += 1;
            }
        }
    }
    out
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && let Some(byte) = hex_pair(bytes, at)
        {
            out.push(byte);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    out
}

/// The pieces of a parameterized value, split at the `;` outside quotes.
fn split_params(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => {
                current.push(ch);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            ';' if !quoted => out.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    out.push(current);
    out
}

/// A parameter value without its quotes and escapes.
fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let mut out = String::with_capacity(value.len());
        let mut escaped = false;
        for ch in value[1..value.len() - 1].chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    value.to_owned()
}

/// A `Content-Type` or `Content-Disposition` value: its first word,
/// lowercased, and its parameters by lowercased name, RFC 2231
/// continuations joined and their charsets read.
#[derive(Debug, Clone, Default)]
struct Parameterized {
    value: String,
    params: Vec<(String, String)>,
}

impl Parameterized {
    fn parse(raw: &str) -> Self {
        let mut pieces = split_params(raw).into_iter();
        let value = pieces
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let mut params: Vec<(String, String)> = Vec::new();
        let mut extended: Vec<(String, u32, bool, String)> = Vec::new();
        for piece in pieces {
            let Some((name, value)) = piece.split_once('=') else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let value = unquote(value);
            match name.split_once('*') {
                Some((base, "")) => extended.push((base.to_owned(), 0, true, value)),
                Some((base, rest)) => {
                    let encoded = rest.ends_with('*');
                    let Ok(index) = rest.trim_end_matches('*').parse::<u32>() else {
                        continue;
                    };
                    extended.push((base.to_owned(), index, encoded, value));
                }
                None => params.push((name, value)),
            }
        }
        extended.sort_by(|left, right| (left.0.as_str(), left.1).cmp(&(right.0.as_str(), right.1)));
        let mut at = 0;
        while at < extended.len() {
            let base = extended[at].0.clone();
            let mut bytes = Vec::new();
            let mut charset: Option<String> = None;
            let mut first = true;
            while at < extended.len() && extended[at].0 == base {
                let (_, _, encoded, value) = &extended[at];
                if *encoded {
                    let mut text = value.as_str();
                    if first {
                        let mut split = text.splitn(3, '\'');
                        if let (Some(set), Some(_language), Some(rest)) =
                            (split.next(), split.next(), split.next())
                        {
                            if !set.is_empty() {
                                charset = Some(set.to_owned());
                            }
                            text = rest;
                        }
                    }
                    bytes.extend(percent_decode(text));
                } else {
                    bytes.extend_from_slice(value.as_bytes());
                }
                first = false;
                at += 1;
            }
            let decoded = decode_charset(&bytes, charset.as_deref());
            params.retain(|(name, _)| *name != base);
            params.push((base, decoded));
        }
        Self { value, params }
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value.as_str())
    }
}

/// One entity of a message: its header fields and its body, still
/// transfer-encoded, or its children for a multipart.
#[derive(Debug, Clone)]
pub(super) struct MimePart<'m> {
    part_id: String,
    fields: Vec<(String, Vec<u8>)>,
    content_type: Parameterized,
    transfer: String,
    body: &'m [u8],
    children: Vec<MimePart<'m>>,
}

/// The first field named `name` (lowercase), as text.
fn field_text(fields: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    fields
        .iter()
        .find(|(held, _)| held == name)
        .map(|(_, value)| decode_charset(value, None))
}

impl<'m> MimePart<'m> {
    fn parse(bytes: &'m [u8], part_id: String, depth: usize, budget: &mut usize) -> Self {
        let (fields, body_start) = split_header(bytes);
        let body = &bytes[body_start.min(bytes.len())..];
        let content_type = field_text(&fields, "content-type")
            .map(|value| Parameterized::parse(&value))
            .filter(|parsed| parsed.value.contains('/'))
            .unwrap_or_else(|| Parameterized {
                value: "text/plain".to_owned(),
                params: Vec::new(),
            });
        let transfer = field_text(&fields, "content-transfer-encoding")
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let mut part = Self {
            part_id,
            fields,
            content_type,
            transfer,
            body,
            children: Vec::new(),
        };
        if part.is_multipart()
            && depth < MAX_PART_DEPTH
            && let Some(boundary) = part
                .content_type
                .param("boundary")
                .filter(|boundary| !boundary.is_empty())
                .map(str::to_owned)
        {
            for (index, child) in split_multipart(body, boundary.as_bytes())
                .into_iter()
                .enumerate()
            {
                if *budget == 0 {
                    break;
                }
                *budget -= 1;
                let child_id = if part.part_id.is_empty() {
                    index.to_string()
                } else {
                    format!("{}.{index}", part.part_id)
                };
                let child = Self::parse(child, child_id, depth + 1, budget);
                part.children.push(child);
            }
        }
        part
    }

    fn is_multipart(&self) -> bool {
        self.content_type.value.starts_with("multipart/")
    }

    /// The body's bytes, its transfer encoding undone.
    fn decoded(&self) -> Vec<u8> {
        match self.transfer.as_str() {
            "base64" => base64_body(self.body),
            "quoted-printable" => quoted_printable(self.body),
            _ => self.body.to_vec(),
        }
    }

    /// The file name its disposition or its type names, decoded.
    fn filename(&self, disposition: Option<&Parameterized>) -> Option<String> {
        disposition
            .and_then(|disposition| disposition.param("filename"))
            .or_else(|| self.content_type.param("name"))
            .map(|name| decode_words(name.as_bytes()))
            .filter(|name| !name.trim().is_empty())
    }
}

/// A multipart body's parts, between its boundary lines. The line break
/// before a boundary line belongs to it.
fn split_multipart<'m>(body: &'m [u8], boundary: &[u8]) -> Vec<&'m [u8]> {
    let mut parts = Vec::new();
    let mut open: Option<usize> = None;
    let mut content_end = 0;
    for line in lines(body) {
        let text = &body[line.start..line.end];
        if let Some(rest) = text
            .strip_prefix(b"--")
            .and_then(|rest| rest.strip_prefix(boundary))
        {
            let rest = rest.trim_ascii_end();
            let closing = rest == b"--";
            if rest.is_empty() || closing {
                if let Some(start) = open.take() {
                    parts.push(&body[start..content_end.max(start)]);
                }
                if closing {
                    return parts;
                }
                open = Some(line.next);
                content_end = line.next;
                continue;
            }
        }
        content_end = line.end;
    }
    if let Some(start) = open {
        parts.push(&body[start..]);
    }
    parts
}

fn base64_body(body: &[u8]) -> Vec<u8> {
    let mut clean: Vec<u8> = body
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
        .collect();
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    LENIENT_BASE64.decode(&clean).unwrap_or_default()
}

fn quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    for line in lines(body) {
        let text = body[line.start..line.end].trim_ascii_end();
        let (text, soft) = match text.strip_suffix(b"=") {
            Some(text) => (text, true),
            None => (text, false),
        };
        let mut at = 0;
        while at < text.len() {
            if text[at] == b'='
                && let Some(byte) = hex_pair(text, at)
            {
                out.push(byte);
                at += 3;
                continue;
            }
            out.push(text[at]);
            at += 1;
        }
        if !soft {
            out.extend_from_slice(&body[line.end..line.next]);
        }
    }
    out
}

/// One message read whole.
#[derive(Debug, Clone)]
pub(super) struct MimeMessage<'m> {
    root: MimePart<'m>,
}

/// A message's readable words and its attachments, described.
#[derive(Debug, Clone, Default)]
pub(super) struct MimeBody {
    /// Its plain text, or its HTML's text when it has no plain part.
    pub(super) text: Option<String>,
    pub(super) attachments: Vec<MailAttachmentRef>,
}

impl<'m> MimeMessage<'m> {
    pub(super) fn parse(raw: &'m [u8]) -> Self {
        let mut budget = MAX_PARTS;
        Self {
            root: MimePart::parse(raw, String::new(), 0, &mut budget),
        }
    }

    /// The first header field named `name`, its encoded words decoded.
    pub(super) fn header(&self, name: &str) -> Option<String> {
        let name = name.to_ascii_lowercase();
        self.root
            .fields
            .iter()
            .find(|(held, _)| *held == name)
            .map(|(_, value)| decode_words(value).trim().to_owned())
    }

    /// Its plain text (or its HTML's text) and its attachments, the way the
    /// Gmail wire reads a message: a part with a file name, an attachment
    /// disposition, or a type that is not text is an attachment.
    pub(super) fn body(&self) -> MimeBody {
        let mut plain = Vec::new();
        let mut html = Vec::new();
        let mut attachments = Vec::new();
        collect(&self.root, &mut plain, &mut html, &mut attachments);
        let text = if !plain.is_empty() {
            Some(plain.join("\n\n"))
        } else if !html.is_empty() {
            Some(html_text(&html.join("\n")))
        } else {
            None
        };
        MimeBody {
            text: text.filter(|text| !text.trim().is_empty()),
            attachments,
        }
    }

    /// One part's bytes, by its part id.
    pub(super) fn part_bytes(&self, part_id: &str) -> Option<Vec<u8>> {
        find(&self.root, part_id).map(MimePart::decoded)
    }
}

fn find<'p, 'm>(part: &'p MimePart<'m>, part_id: &str) -> Option<&'p MimePart<'m>> {
    if part.part_id == part_id {
        return Some(part);
    }
    part.children.iter().find_map(|child| find(child, part_id))
}

fn collect(
    part: &MimePart<'_>,
    plain: &mut Vec<String>,
    html: &mut Vec<String>,
    attachments: &mut Vec<MailAttachmentRef>,
) {
    if part.is_multipart() {
        for child in &part.children {
            collect(child, plain, html, attachments);
        }
        return;
    }
    let disposition =
        field_text(&part.fields, "content-disposition").map(|value| Parameterized::parse(&value));
    let filename = part.filename(disposition.as_ref());
    let attached = disposition
        .as_ref()
        .is_some_and(|disposition| disposition.value == "attachment");
    let media_type = part.content_type.value.as_str();
    if filename.is_some() || attached || !media_type.starts_with("text/") {
        attachments.push(MailAttachmentRef {
            part_id: part.part_id.clone(),
            provider_attachment_id: None,
            filename,
            media_type: media_type.to_owned(),
            size_bytes: u64::try_from(part.decoded().len()).unwrap_or(u64::MAX),
        });
        return;
    }
    let text =
        decode_charset(&part.decoded(), part.content_type.param("charset")).replace("\r\n", "\n");
    match media_type {
        "text/plain" => plain.push(text),
        "text/html" => html.push(text),
        _ => {}
    }
}
