//! The pre-receive scan over every pushed blob, binary bytes included
//! (owner ruling G7-BINARY = A, FIX 6871).
//!
//! Detection and disposition stay apart. [`scan_receive_blob`] reads one
//! blob's ORIGINAL bytes and answers a [`ReceiveScanHit`] or none; it never
//! decodes, converts or rewrites them, so a clean blob keeps its Git object
//! identity. Clean text (valid UTF-8 with no NUL) is read line by line with
//! the very detector calls the door made before, byte for byte. Anything
//! else is read twice: by the custody automaton over the raw bytes, which
//! finds provider keys inside arbitrary byte runs and private-key armor, and
//! by the shipped release reader, which carries the blocklist, phrase,
//! assignment, container and framed-carrier rules. A scan that cannot run is
//! a refusal, never a pass.
//!
//! [`resolve_receive_scan_hits`] is the ONE place a hit becomes an outcome.
//! Today that is the door's refusal with lift advice, as before; the owner's
//! later handle/mark alignment replaces this function's body, not the
//! detection. Nothing here can turn the scan off.

use std::io::Cursor;

use super::door_types::{
    CredentialDoorError, DoorResult, DoorScanVerdict, PushedBlob, SecretLiftProposal,
};
use crate::batch::secret_scan::{scan_file_content, scan_file_content_reader};
use crate::codebase::RepoRef;
use crate::origin::lfs::find_custody_credential;

/// How the door read one blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiveBlobKind {
    /// Valid UTF-8 with no NUL byte: read line by line, as before.
    Text,
    /// Any other bytes: the custody automaton, then the release reader.
    Binary,
}

/// One detector hit on one pushed blob: where it is and which rule named
/// it. It carries no byte of the blob, so its `Debug` and every error made
/// from it are safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReceiveScanHit {
    /// The blob's repository-relative path.
    pub(super) path: String,
    /// The blob's object id (hex).
    pub(super) oid: String,
    /// The detector's reason code.
    pub(super) reason: &'static str,
    /// How the blob was read.
    pub(super) content_kind: ReceiveBlobKind,
}

/// Scans one pushed blob's whole original content.
///
/// # Errors
/// [`CredentialDoorError::ScanFailure`] when a binary read could not run:
/// a scan that did not happen refuses, it never passes.
pub(super) fn scan_receive_blob(blob: &PushedBlob) -> DoorResult<Option<ReceiveScanHit>> {
    let text = !blob.content.contains(&0) && std::str::from_utf8(&blob.content).is_ok();
    let (content_kind, reason) = if text {
        // The old admitting path, unchanged: each line, the same detector.
        let reason = blob
            .lines()
            .find_map(|line| scan_file_content(&blob.path, line));
        (ReceiveBlobKind::Text, reason)
    } else {
        (ReceiveBlobKind::Binary, scan_binary_blob(blob)?)
    };
    Ok(reason.map(|reason| ReceiveScanHit {
        path: blob.path.clone(),
        oid: blob.oid.clone(),
        reason,
        content_kind,
    }))
}

/// The binary read: the custody automaton over the raw bytes first, then
/// the release reader over the same bytes. Only the automaton's own
/// detection becomes a hit; any other failure refuses the scan.
fn scan_binary_blob(blob: &PushedBlob) -> DoorResult<Option<&'static str>> {
    if let Some(reason) =
        find_custody_credential(&blob.content).map_err(|_| scan_failed(&blob.path))?
    {
        return Ok(Some(reason));
    }
    let mut source = Cursor::new(blob.content.as_slice());
    scan_file_content_reader(&blob.path, &mut source).map_err(|_| scan_failed(&blob.path))
}

fn scan_failed(path: &str) -> CredentialDoorError {
    CredentialDoorError::ScanFailure {
        path: path.to_owned(),
        reason: "the binary content scan could not run",
    }
}

/// The ONE disposition of a push's scan hits (G7-BINARY policy point).
///
/// No hit is [`DoorScanVerdict::Clean`]. Any hit is today's refusal: one
/// lift proposal per offending blob, naming its path and reason, never its
/// bytes. A hit that names no blob of this push is a scan failure, never a
/// pass. There is no knob here and no unimplemented mark branch; a later
/// handle/mark disposition replaces this body once its custody proof
/// exists, with the blobs' original bytes and ids still in hand.
///
/// # Errors
/// [`CredentialDoorError::ScanFailure`] for a hit outside `blobs`.
pub(super) fn resolve_receive_scan_hits(
    repo: &RepoRef,
    blobs: &[PushedBlob],
    hits: Vec<ReceiveScanHit>,
) -> DoorResult<DoorScanVerdict> {
    if hits.is_empty() {
        return Ok(DoorScanVerdict::Clean);
    }
    let mut proposals = Vec::with_capacity(hits.len());
    for hit in hits {
        if !blobs
            .iter()
            .any(|blob| blob.path == hit.path && blob.oid == hit.oid)
        {
            return Err(scan_failed(&hit.path));
        }
        tracing::debug!(
            reason = hit.reason,
            binary = hit.content_kind == ReceiveBlobKind::Binary,
            "receive scan hit refused with lift advice"
        );
        proposals.push(SecretLiftProposal::new(repo, &hit.path, hit.reason));
    }
    Ok(DoorScanVerdict::Rejected { proposals })
}
