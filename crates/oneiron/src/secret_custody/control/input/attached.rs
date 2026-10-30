//! What a sealed register's recorder attaches beside the envelope its
//! owner's surface sealed, under the digest the request names: the manifest
//! it resolved for a stated `manifest_ref` (CALLS CUSTODY_MANIFEST_RECHECK),
//! or for a surface that stated none, every secret manifest the vault
//! publishes, else a "no manifest" or an "unread" mark (CALLS
//! CUSTODY_MANIFEST_UNSTATED_MULTI). An attachment is never refused for its
//! size: an input past one row's bound travels in parts (`super`).
//!
//! The envelope stays where it lies (FIX 11140): a recorder frames it by
//! its length alone, a head before it and a tail after it, and a holder
//! reads the head, the envelope and the tail of a kept input in turn.

use super::refused;
use crate::error::Result;

/// The label of a sealed register's input as its recorder records it: the
/// envelope the owner's surface sealed, then the manifest the recorder
/// resolved for the `manifest_ref` that surface stated (CALLS
/// CUSTODY_MANIFEST_RECHECK). The request names the digest of the whole, so
/// the manifest is the recorder's as the envelope is the surface's.
const ATTACHED_LABEL: &[u8] = b"oneiron/custody-input-attached/v1\0";
/// The label of a sealed register's input whose surface stated no
/// `manifest_ref` and whose vault publishes one secret manifest: the
/// envelope, then that manifest's ref and text (CALLS
/// CUSTODY_MANIFEST_UNSTATED_MULTI).
const CURRENT_LABEL: &[u8] = b"oneiron/custody-input-current/v1\0";
/// The label of a sealed register's input whose surface stated no
/// `manifest_ref` and whose vault publishes several secret manifests: the
/// envelope, then their count and each one's ref and text, ordered by ref
/// (CALLS CUSTODY_MANIFEST_UNSTATED_MULTI).
const PUBLISHED_LABEL: &[u8] = b"oneiron/custody-input-published/v1\0";
/// The label of a sealed register's input whose surface stated no
/// `manifest_ref` and whose vault publishes no secret manifest: the
/// envelope alone, registered without a manifest check (CALLS
/// CUSTODY_MANIFEST_UNSTATED).
const NO_MANIFEST_LABEL: &[u8] = b"oneiron/custody-input-no-manifest/v1\0";
/// The label of a sealed register's input whose surface stated no
/// `manifest_ref` and whose recorder could not read the manifests the vault
/// publishes: the envelope alone, registered without a manifest check.
const UNREAD_LABEL: &[u8] = b"oneiron/custody-input-unread/v1\0";

/// The manifest a recorder resolved for a sealed register and attached to
/// its input: the `manifest_ref` it resolved and the file's text.
pub(crate) struct AttachedManifest {
    pub(crate) manifest_ref: String,
    pub(crate) text: String,
}

/// What a sealed register's recorder attached beside the envelope its
/// owner's surface sealed, under the digest the request names.
pub(crate) enum Attached {
    /// The manifest it resolved for the `manifest_ref` the surface stated
    /// (CALLS CUSTODY_MANIFEST_RECHECK).
    Stated(AttachedManifest),
    /// The surface stated none: every secret manifest the vault publishes,
    /// one at least, ordered by ref (CALLS CUSTODY_MANIFEST_UNSTATED_MULTI).
    Published(Vec<AttachedManifest>),
    /// The surface stated none and the vault publishes no secret manifest:
    /// the record registers without a manifest check.
    NoManifest,
    /// The surface stated none and its recorder could not read the
    /// manifests the vault publishes: the record registers without a
    /// manifest check.
    Unread,
}

/// What a recorder attaches around the envelope its owner's surface sealed
/// (FIX 11140): the head before the envelope, its label and the envelope's
/// length, and the tail after it. The envelope itself stays where it lies.
pub(crate) struct Attachment {
    pub(super) head: Vec<u8>,
    pub(super) tail: Vec<u8>,
}

/// The form a kept input's recorder framed its envelope in, named by the
/// label its head opens with.
#[derive(Clone, Copy)]
pub(crate) enum AttachedForm {
    /// [`Attached::Stated`].
    Stated,
    /// [`Attached::Published`] with one manifest.
    Current,
    /// [`Attached::Published`] with several.
    Published,
    /// [`Attached::NoManifest`].
    NoManifest,
    /// [`Attached::Unread`].
    Unread,
}

/// Every form, each by its own label.
const FORMS: [AttachedForm; 5] = [
    AttachedForm::Stated,
    AttachedForm::Current,
    AttachedForm::Published,
    AttachedForm::NoManifest,
    AttachedForm::Unread,
];

/// The most bytes a kept input's head takes: its longest label, then the
/// envelope's length.
pub(crate) const ATTACHED_HEAD_MAX: usize = {
    let mut most = 0;
    let mut index = 0;
    while index < FORMS.len() {
        if FORMS[index].label().len() > most {
            most = FORMS[index].label().len();
        }
        index += 1;
    }
    most + 4
};

impl AttachedForm {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Stated => ATTACHED_LABEL,
            Self::Current => CURRENT_LABEL,
            Self::Published => PUBLISHED_LABEL,
            Self::NoManifest => NO_MANIFEST_LABEL,
            Self::Unread => UNREAD_LABEL,
        }
    }

    /// The bytes its head takes: its label, then the envelope's length.
    pub(crate) const fn head_len(self) -> usize {
        self.label().len() + 4
    }
}

/// A sealed register's envelope of `len` bytes with the manifest its
/// recorder resolved for it attached: what the request then names the
/// digest of, the envelope between.
pub(crate) fn attach_manifest(len: u64, manifest_ref: &str, text: &str) -> Result<Attachment> {
    frame_one(ATTACHED_LABEL, len, manifest_ref, text)
}

/// A sealed register's envelope of `len` bytes whose surface stated no
/// `manifest_ref`, with every secret manifest the vault publishes attached,
/// each its ref and its text, in the order given (CALLS
/// CUSTODY_MANIFEST_UNSTATED_MULTI): one in the frame a single manifest has
/// always had, several in a counted list. None is left out: an input past
/// one row's bound travels in parts.
pub(crate) fn attach_published_manifests(
    len: u64,
    published: &[(&str, &str)],
) -> Result<Attachment> {
    if let [(manifest_ref, text)] = published {
        return frame_one(CURRENT_LABEL, len, manifest_ref, text);
    }
    let mut tail = Vec::new();
    put_len(&mut tail, published.len())?;
    for (manifest_ref, text) in published {
        put_framed(&mut tail, manifest_ref.as_bytes())?;
        put_framed(&mut tail, text.as_bytes())?;
    }
    Ok(Attachment {
        head: head(PUBLISHED_LABEL, len)?,
        tail,
    })
}

/// A sealed register's envelope of `len` bytes whose surface stated no
/// `manifest_ref`, marked as carrying no manifest: the vault publishes none
/// (CALLS CUSTODY_MANIFEST_UNSTATED).
pub(crate) fn attach_no_manifest(len: u64) -> Result<Attachment> {
    Ok(Attachment {
        head: head(NO_MANIFEST_LABEL, len)?,
        tail: Vec::new(),
    })
}

/// A sealed register's envelope of `len` bytes whose surface stated no
/// `manifest_ref`, marked as carrying none because its recorder could not
/// read the manifests the vault publishes.
pub(crate) fn attach_unread(len: u64) -> Result<Attachment> {
    Ok(Attachment {
        head: head(UNREAD_LABEL, len)?,
        tail: Vec::new(),
    })
}

/// `label` and the envelope's length before it, then one manifest's ref
/// length, ref and text after it.
fn frame_one(label: &[u8], len: u64, manifest_ref: &str, text: &str) -> Result<Attachment> {
    let mut tail = Vec::new();
    put_framed(&mut tail, manifest_ref.as_bytes())?;
    tail.extend_from_slice(text.as_bytes());
    Ok(Attachment {
        head: head(label, len)?,
        tail,
    })
}

/// `label`, then the envelope's length: every attachment's head.
fn head(label: &[u8], len: u64) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(label.len() + 4);
    out.extend_from_slice(label);
    put_len(&mut out, usize::try_from(len).unwrap_or(usize::MAX))?;
    Ok(out)
}

/// `bytes`' length as a `u32`, then `bytes`.
fn put_framed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// `len` as a `u32`: the attachment's own codec bound.
fn put_len(out: &mut Vec<u8>, len: usize) -> Result<()> {
    let len = u32::try_from(len)
        .map_err(|_| refused("a custody input attachment is longer than its frame states"))?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

/// The bytes a `u32` length frames at the head of `bytes`, and the rest.
fn take_framed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    rest.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)
}

/// A manifest's ref and text, read as UTF-8.
fn attached_manifest(manifest_ref: &[u8], text: &[u8]) -> Option<AttachedManifest> {
    Some(AttachedManifest {
        manifest_ref: std::str::from_utf8(manifest_ref).ok()?.to_owned(),
        text: std::str::from_utf8(text).ok()?.to_owned(),
    })
}

/// The one manifest a [`frame_one`] frame holds after its envelope.
fn split_one(rest: &[u8]) -> Option<AttachedManifest> {
    let (manifest_ref, text) = take_framed(rest)?;
    attached_manifest(manifest_ref, text)
}

/// How a kept input that opens with `prefix` is framed: the form its
/// recorder attached in and the envelope's length after the label, or
/// `None` within for an input that is the envelope alone. `None` for a
/// label with no length after it.
pub(crate) fn attached_head(prefix: &[u8]) -> Option<Option<(AttachedForm, u32)>> {
    for form in FORMS {
        if let Some(rest) = prefix.strip_prefix(form.label()) {
            let (len, _) = rest.split_first_chunk::<4>()?;
            return Some(Some((form, u32::from_be_bytes(*len))));
        }
    }
    Some(None)
}

/// What a kept input's recorder attached in `form`, read from the `tail`
/// after its envelope; `None` for a malformed attachment.
pub(crate) fn attached_tail(form: AttachedForm, tail: &[u8]) -> Option<Attached> {
    match form {
        AttachedForm::Stated => Some(Attached::Stated(split_one(tail)?)),
        AttachedForm::Current => published(vec![split_one(tail)?], &[]),
        AttachedForm::Published => {
            let (count, mut rest) = tail.split_first_chunk::<4>()?;
            let mut listed = Vec::new();
            for _ in 0..u32::from_be_bytes(*count) {
                let (manifest_ref, after) = take_framed(rest)?;
                let (text, after) = take_framed(after)?;
                listed.push(attached_manifest(manifest_ref, text)?);
                rest = after;
            }
            published(listed, rest)
        }
        AttachedForm::NoManifest => tail.is_empty().then_some(Attached::NoManifest),
        AttachedForm::Unread => tail.is_empty().then_some(Attached::Unread),
    }
}

/// Published manifests as their frame ends: one at least, each naming its
/// ref, and nothing after them.
fn published(listed: Vec<AttachedManifest>, rest: &[u8]) -> Option<Attached> {
    (rest.is_empty()
        && !listed.is_empty()
        && listed
            .iter()
            .all(|manifest| !manifest.manifest_ref.is_empty()))
    .then_some(Attached::Published(listed))
}
