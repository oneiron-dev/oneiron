//! The files a mail message carries (fix list row 17645): one frozen
//! description of each, shared by a drafted reply, its send plan and its
//! review, and the one `multipart/mixed` writer every renderer uses. A
//! message with files is its body first (the text, or the text and its HTML
//! alternative, as [`super::mail_html::push_mail_body`] writes it), then each
//! file in its frozen order as an `attachment` part, its exact bytes in
//! base64 and its name in RFC 2231 form. Nothing here reads a file: the
//! drafter's door admits each one and hands its exact copy in, and the
//! message is written once, when it is frozen. A kept plan names its files
//! and message only by their manifest's digest; their holder's live row
//! keeps them.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The one disposition a file part takes: a file never shows inline.
pub(crate) const ATTACHMENT_DISPOSITION: &str = "attachment";

/// One file a message carries, as its draft froze it: the exact version of
/// the artifact it is, that version's CLAIM and stored BLAKE3, the name and
/// type the version was appended with, and the length and BLAKE3 of the
/// exact copy that sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MailAttachment {
    pub(crate) artifact: EntityId,
    pub(crate) version: u64,
    /// The CLAIM the pinned version is bound to.
    pub(crate) version_claim: EntityId,
    /// BLAKE3 of the stored version, as its record names it.
    pub(crate) stored_blake3: [u8; 32],
    pub(crate) filename: String,
    pub(crate) media_type: String,
    /// The exact copy's length, in bytes.
    pub(crate) octets: u64,
    /// BLAKE3 of the exact copy that sends.
    pub(crate) copy_blake3: [u8; 32],
}

impl MailAttachment {
    /// Checks what a part header carries of this file: a name with no
    /// control character that names no path, and a bare `type/subtype`.
    /// Refused, never cleaned.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a name or a type a part header may not
    /// carry.
    pub(crate) fn validate(&self) -> Result<()> {
        validate_filename(&self.filename)?;
        validate_media_type(&self.media_type)
    }

    /// Whether `bytes` are exactly the copy this file names.
    #[must_use]
    pub(crate) fn is_copy(&self, bytes: &[u8]) -> bool {
        bytes.len() as u64 == self.octets && blake3::hash(bytes).as_bytes() == &self.copy_blake3
    }
}

/// The exact message a send with files sends: its length in octets and its
/// BLAKE3, as written once when it was frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MailMessageIdentity {
    pub(crate) octets: u64,
    pub(crate) blake3: [u8; 32],
}

impl MailMessageIdentity {
    /// The identity of `message`.
    #[must_use]
    pub(crate) fn of(message: &[u8]) -> Self {
        Self {
            octets: message.len() as u64,
            blake3: *blake3::hash(message).as_bytes(),
        }
    }

    /// Whether `message` is exactly the message this identity names.
    #[must_use]
    pub(crate) fn matches(&self, message: &[u8]) -> bool {
        message.len() as u64 == self.octets && blake3::hash(message).as_bytes() == &self.blake3
    }
}

/// What a send with files was frozen with, as its holder's own live row
/// keeps it (fix list row 17645): its files in their order and its exact
/// message. A kept plan names it only by [`Self::digest`], so no image of
/// the plan carries a file's name, ref or hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MailManifest {
    pub(crate) attachments: Vec<MailAttachment>,
    pub(crate) message: MailMessageIdentity,
}

impl MailManifest {
    /// The digest a kept plan names this manifest by: every file in its
    /// slot, then the exact message.
    #[must_use]
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.mail.attachment.manifest.v1");
        hash_attachments(&mut hasher, &self.attachments);
        hash_message(&mut hasher, Some(&self.message));
        *hasher.finalize().as_bytes()
    }
}

/// The one message a send plan with files sends, kept by its holder where
/// it was frozen (fix list row 17645): the plan names its length and BLAKE3,
/// and only its holder opens it. The holder judges the send again in the
/// writer that admits it, at egress, and in the credential door's writer,
/// and never renders, exports or masks anything again.
pub(crate) trait RetainedMailMessage {
    /// The content ref of the plan this message is.
    fn content_ref(&self) -> &str;

    /// The ref of the carrier that holds the message: one per draft and
    /// revision, as the kept plan names it.
    fn carrier_ref(&self) -> &str;

    /// The files and the exact message the plan was frozen with, read from
    /// the holder's own live row; `None` once that row no longer names
    /// them, and the kept plan is then no plan.
    ///
    /// # Errors
    ///
    /// The failure of its read.
    fn manifest(&self) -> Result<Option<MailManifest>>;

    /// Judges the frozen send again in `txn`, a writer: the one that admits
    /// it, and the credential door's before the message leaves.
    ///
    /// # Errors
    ///
    /// The refusal, or the failure of its read.
    fn admit_in(&self, txn: &heed::RoTxn<'_>) -> Result<()>;

    /// The exact message, opened at egress once its send is judged again in
    /// the snapshot it is read in.
    ///
    /// # Errors
    ///
    /// The refusal, a message no longer held, or the failure of its read.
    fn open_for_egress(&self) -> Result<Zeroizing<Vec<u8>>>;
}

/// Feeds one file's description into a content ref: every field in its
/// place, each text framed by its length.
fn hash_attachment(hasher: &mut blake3::Hasher, file: &MailAttachment) {
    hasher.update(file.artifact.as_bytes());
    hasher.update(&file.version.to_le_bytes());
    hasher.update(file.version_claim.as_bytes());
    hasher.update(&file.stored_blake3);
    for text in [
        file.filename.as_str(),
        file.media_type.as_str(),
        ATTACHMENT_DISPOSITION,
    ] {
        hasher.update(&(text.len() as u64).to_le_bytes());
        hasher.update(text.as_bytes());
    }
    hasher.update(&file.octets.to_le_bytes());
    hasher.update(&file.copy_blake3);
}

/// Feeds `files` into a content ref: counted, each in its slot, so no two
/// lists hash alike and a file named twice counts twice.
pub(crate) fn hash_attachments(hasher: &mut blake3::Hasher, files: &[MailAttachment]) {
    hasher.update(&(files.len() as u64).to_le_bytes());
    for file in files {
        hash_attachment(hasher, file);
    }
}

/// Feeds the exact message a send with files was frozen with into its
/// content ref; a plan not yet bound to one hashes apart.
pub(crate) fn hash_message(hasher: &mut blake3::Hasher, message: Option<&MailMessageIdentity>) {
    match message {
        Some(message) => {
            hasher.update(&[1]);
            hasher.update(&message.octets.to_le_bytes());
            hasher.update(&message.blake3);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

/// Writes a message body with files after its MIME-Version: one
/// `multipart/mixed`, the body [`super::mail_html::push_mail_body`] writes
/// first, then each of `files` in its order as an `attachment` part, its
/// bytes exactly as handed in, in base64, 76 characters a line. The boundary
/// is drawn from the body and the files' descriptions, holds `_`, which
/// base64 never writes, and is never the body's own alternative boundary.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a file whose bytes are not the copy its
/// description names, or whose name or type a part header may not carry.
pub(crate) fn push_mixed_body(
    out: &mut String,
    text: &str,
    html: Option<&str>,
    files: &[(&MailAttachment, &[u8])],
) -> Result<()> {
    let mut seed = blake3::Hasher::new();
    seed.update(b"oneiron.mail.mixed.boundary.v1");
    for part in [Some(text), html] {
        match part {
            Some(part) => {
                seed.update(&[1]);
                seed.update(&(part.len() as u64).to_le_bytes());
                seed.update(part.as_bytes());
            }
            None => {
                seed.update(&[0]);
            }
        }
    }
    seed.update(&(files.len() as u64).to_le_bytes());
    for (file, bytes) in files {
        file.validate()?;
        if !file.is_copy(bytes) {
            return Err(Error::InvalidConfig(
                "a mail file's bytes are not the copy its description names".to_owned(),
            ));
        }
        hash_attachment(&mut seed, file);
    }
    let digest = seed.finalize().to_hex();
    let boundary = format!("=_oneiron_mixed_{}", &digest.as_str()[..32]);
    let _ = write!(
        out,
        "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n"
    );
    super::mail_html::push_mail_body(out, text, html);
    for (file, bytes) in files {
        let _ = write!(
            out,
            "--{boundary}\r\nContent-Type: {}\r\nContent-Disposition: {ATTACHMENT_DISPOSITION};",
            file.media_type
        );
        push_filename(out, &file.filename);
        out.push_str("\r\nContent-Transfer-Encoding: base64\r\n\r\n");
        super::mail_html::push_base64(out, bytes);
    }
    let _ = write!(out, "--{boundary}--\r\n");
    Ok(())
}

/// Whether `byte` stands for itself in an RFC 2231 parameter value: RFC
/// 5987's `attr-char`.
fn is_attr_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte)
}

/// Writes the `filename` parameter of a part's `Content-Disposition` (RFC
/// 2231), on a folded line of its own: the name's UTF-8 octets, each outside
/// `attr-char` as `%HH`. A name longer than one base64 body line is written
/// in numbered sections, each on its own folded line and each `%HH` whole in
/// one section, so no header line passes RFC 5322's limit.
fn push_filename(out: &mut String, name: &str) {
    let mut sections = vec![String::new()];
    for byte in name.bytes() {
        let mut token = String::new();
        if is_attr_char(byte) {
            token.push(char::from(byte));
        } else {
            let _ = write!(token, "%{byte:02X}");
        }
        let full = sections.last().is_some_and(|section| {
            !section.is_empty() && section.len() + token.len() > super::mail_html::MAIL_LINE_CHARS
        });
        if full {
            sections.push(String::new());
        }
        if let Some(section) = sections.last_mut() {
            section.push_str(&token);
        }
    }
    if let [only] = sections.as_slice() {
        let _ = write!(out, "\r\n filename*=UTF-8''{only}");
        return;
    }
    for (index, section) in sections.iter().enumerate() {
        if index == 0 {
            let _ = write!(out, "\r\n filename*0*=UTF-8''{section}");
        } else {
            let _ = write!(out, ";\r\n filename*{index}*={section}");
        }
    }
}

/// A file's name as a part header carries it: not blank, no control
/// character (no CR, LF or NUL among them), and no path.
fn validate_filename(name: &str) -> Result<()> {
    let refuse = |why: &str| Err(Error::InvalidConfig(format!("a mail file's name {why}")));
    if name.trim().is_empty() {
        return refuse("is blank");
    }
    if name.chars().any(char::is_control) {
        return refuse("carries a control character");
    }
    if name.contains(['/', '\\']) || name == "." || name == ".." {
        return refuse("names a path");
    }
    Ok(())
}

/// A file's media type as a part header carries it: a bare `type/subtype`,
/// each an RFC 2045 token, with no parameter.
fn validate_media_type(media_type: &str) -> Result<()> {
    let token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&byte))
    };
    match media_type.split_once('/') {
        Some((kind, subtype)) if token(kind) && token(subtype) => Ok(()),
        _ => Err(Error::InvalidConfig(
            "a mail file's media type is not a bare type/subtype".to_owned(),
        )),
    }
}
