//! What a sealed register's recorder attaches beside the envelope its
//! owner's surface sealed, under the digest the request names: the manifest
//! it resolved for a stated `manifest_ref` (CALLS CUSTODY_MANIFEST_RECHECK),
//! or for a surface that stated none, every secret manifest the vault
//! publishes, else a "no manifest" or an "unread" mark (CALLS
//! CUSTODY_MANIFEST_UNSTATED_MULTI). An attachment is never refused for its
//! size: an input past one row's bound travels in parts (`super`).

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

/// A sealed register's `envelope` with the manifest its recorder resolved
/// for it attached: what the request then names the digest of.
pub(crate) fn attach_manifest(envelope: &[u8], manifest_ref: &str, text: &str) -> Result<Vec<u8>> {
    frame_one(ATTACHED_LABEL, envelope, manifest_ref, text)
}

/// A sealed register's `envelope` whose surface stated no `manifest_ref`,
/// with every secret manifest the vault publishes attached, each its ref and
/// its text, in the order given (CALLS CUSTODY_MANIFEST_UNSTATED_MULTI): one
/// in the frame a single manifest has always had, several in a counted list.
/// None is left out: an input past one row's bound travels in parts.
pub(crate) fn attach_published_manifests(
    envelope: &[u8],
    published: &[(&str, &str)],
) -> Result<Vec<u8>> {
    if let [(manifest_ref, text)] = published {
        return frame_one(CURRENT_LABEL, envelope, manifest_ref, text);
    }
    let mut out = frame_envelope(PUBLISHED_LABEL, envelope)?;
    put_len(&mut out, published.len())?;
    for (manifest_ref, text) in published {
        put_framed(&mut out, manifest_ref.as_bytes())?;
        put_framed(&mut out, text.as_bytes())?;
    }
    Ok(out)
}

/// A sealed register's `envelope` whose surface stated no `manifest_ref`,
/// marked as carrying no manifest: the vault publishes none (CALLS
/// CUSTODY_MANIFEST_UNSTATED).
pub(crate) fn attach_no_manifest(envelope: &[u8]) -> Result<Vec<u8>> {
    frame_envelope(NO_MANIFEST_LABEL, envelope)
}

/// A sealed register's `envelope` whose surface stated no `manifest_ref`,
/// marked as carrying none because its recorder could not read the
/// manifests the vault publishes.
pub(crate) fn attach_unread(envelope: &[u8]) -> Result<Vec<u8>> {
    frame_envelope(UNREAD_LABEL, envelope)
}

/// `label`, the envelope's length and bytes, then one manifest's ref length,
/// ref and text.
fn frame_one(label: &[u8], envelope: &[u8], manifest_ref: &str, text: &str) -> Result<Vec<u8>> {
    let mut out = frame_envelope(label, envelope)?;
    put_framed(&mut out, manifest_ref.as_bytes())?;
    out.extend_from_slice(text.as_bytes());
    Ok(out)
}

/// `label`, then the envelope's length and bytes: every attachment's head.
fn frame_envelope(label: &[u8], envelope: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(label.len() + 4 + envelope.len());
    out.extend_from_slice(label);
    put_framed(&mut out, envelope)?;
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

/// The envelope and the one manifest a [`frame_one`] frame holds after its
/// label.
fn split_one(rest: &[u8]) -> Option<(&[u8], AttachedManifest)> {
    let (envelope, rest) = take_framed(rest)?;
    let (manifest_ref, text) = take_framed(rest)?;
    Some((envelope, attached_manifest(manifest_ref, text)?))
}

/// The envelope a kept input holds, and what its recorder attached, if
/// anything; `None` for a malformed attachment.
pub(crate) fn split_attached(kept: &[u8]) -> Option<(&[u8], Option<Attached>)> {
    if let Some(rest) = kept.strip_prefix(ATTACHED_LABEL) {
        let (envelope, stated) = split_one(rest)?;
        return Some((envelope, Some(Attached::Stated(stated))));
    }
    if let Some(rest) = kept.strip_prefix(CURRENT_LABEL) {
        let (envelope, current) = split_one(rest)?;
        return published_frame((envelope, vec![current]), &[]);
    }
    if let Some(rest) = kept.strip_prefix(PUBLISHED_LABEL) {
        let (envelope, rest) = take_framed(rest)?;
        let (count, mut rest) = rest.split_first_chunk::<4>()?;
        let mut listed = Vec::new();
        for _ in 0..u32::from_be_bytes(*count) {
            let (manifest_ref, after) = take_framed(rest)?;
            let (text, after) = take_framed(after)?;
            listed.push(attached_manifest(manifest_ref, text)?);
            rest = after;
        }
        return published_frame((envelope, listed), rest);
    }
    for (label, attached) in [
        (NO_MANIFEST_LABEL, Attached::NoManifest),
        (UNREAD_LABEL, Attached::Unread),
    ] {
        if let Some(rest) = kept.strip_prefix(label) {
            let (envelope, rest) = take_framed(rest)?;
            return rest.is_empty().then_some((envelope, Some(attached)));
        }
    }
    Some((kept, None))
}

/// Published manifests as their frame ends: one at least, each naming its
/// ref, and nothing after them.
fn published_frame<'a>(
    (envelope, listed): (&'a [u8], Vec<AttachedManifest>),
    rest: &[u8],
) -> Option<(&'a [u8], Option<Attached>)> {
    (rest.is_empty()
        && !listed.is_empty()
        && listed
            .iter()
            .all(|manifest| !manifest.manifest_ref.is_empty()))
    .then_some((envelope, Some(Attached::Published(listed))))
}
