//! Moved from `crates/oneiron/src/mail_pack/reply_mime.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// The prefix of a frozen reply's content ref.
pub const REPLY_MESSAGE_REF_PREFIX: &str = "mail-reply:message:v1:";

/// The longest Subject a reply carries, in bytes.
pub const MAX_SUBJECT_BYTES: usize = 900;

/// The longest body a reply carries, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// The most hygiene headers one send carries.
pub const MAX_HYGIENE_HEADERS: usize = 16;

/// The longest hygiene header value, in bytes.
pub const MAX_HYGIENE_VALUE_BYTES: usize = 900;

/// The most references a reply carries: the oldest go first beyond it.
pub const MAX_REFERENCES: usize = 50;

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("mail reply message: {message}"))
}

pub fn hash_part(hasher: &mut blake3::Hasher, part: &str) {
    hasher.update(&(part.len() as u64).to_le_bytes());
    hasher.update(part.as_bytes());
}

pub fn push_header(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

/// A header the message writes itself; a hygiene header may not restate it.
pub fn owned_header(name: &str) -> bool {
    [
        "from",
        "sender",
        "reply-to",
        "to",
        "cc",
        "bcc",
        "subject",
        "date",
        "message-id",
        "in-reply-to",
        "references",
        "mime-version",
        "content-type",
        "content-transfer-encoding",
    ]
    .iter()
    .any(|owned| name.eq_ignore_ascii_case(owned))
}

/// Header text carries no line break or other control character: that is
/// how a value would smuggle a second header into the block.
pub fn header_text(value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(invalid("a header is too long"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("a header carries a control character"));
    }
    Ok(())
}

/// RFC 2047 `B` encoded words for non-ASCII header text; ASCII passes as it
/// is. No word passes 75 bytes.
pub fn encode_word(text: &str) -> String {
    if text.is_ascii() {
        return text.to_owned();
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for character in text.chars() {
        if chunk.len() + character.len_utf8() > 45 {
            words.push(std::mem::take(&mut chunk));
        }
        chunk.push(character);
    }
    if !chunk.is_empty() {
        words.push(chunk);
    }
    words
        .iter()
        .map(|word| {
            format!(
                "=?UTF-8?B?{}?=",
                base64::engine::general_purpose::STANDARD.encode(word.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join("\r\n ")
}
