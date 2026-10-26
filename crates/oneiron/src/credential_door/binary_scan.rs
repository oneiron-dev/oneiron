//! The pre-receive scan over every pushed blob, binary bytes included
//! (owner ruling G7-BINARY = A, FIX 6871).
//!
//! Detection and disposition stay apart. [`scan_receive_blob`] reads one
//! blob's ORIGINAL bytes and answers a [`ReceiveScanHit`] or none; it never
//! decodes, converts or rewrites them, so a clean blob keeps its Git object
//! identity. Clean text (valid UTF-8 with no NUL) is read line by line with
//! the very detector calls the door made before, byte for byte, and then
//! whole by the release reader, whose phrase rule spans lines, so a
//! recovery phrase wrapped across short lines is still seen (FIX 8804).
//! Anything
//! else is read twice: by the custody automaton over the raw bytes, which
//! finds provider keys inside arbitrary byte runs and private-key armor, and
//! by the shipped release reader, which carries the blocklist, phrase,
//! assignment, container and framed-carrier rules. A scan that cannot run is
//! a refusal, never a pass.
//!
//! [`resolve_receive_scan_hits`] is the ONE place a hit becomes an outcome,
//! through ONE statement choosing a [`ReceiveScanDisposition`] (FIX 7608,
//! SECRETS-IN-REPOS = A). Since the FIX 7608 flip it admits the push and
//! marks each hit: the hits ride the verdict to the admitted intent, which
//! writes their marks, and the masked readers serve the masked copy from
//! then on. The refusal with lift advice stays the other arm of that one
//! statement. Nothing here can turn the scan off.

use std::io::Cursor;

use super::door_types::{
    CheckoutSecretLiftProposal, CredentialDoorError, DoorResult, DoorScanVerdict, PushedBlob,
    ReceiveScanDisposition,
};
// The hit's types live with the verdict that carries them; this module's
// old path still names them.
pub(super) use super::door_types::{ReceiveBlobKind, ReceiveScanHit};
use crate::batch::secret_scan::{scan_file_content, scan_file_content_reader};
use crate::codebase::RepoRef;
use crate::origin::lfs::find_custody_credential;

/// Scans one pushed blob's whole original content.
///
/// # Errors
/// [`CredentialDoorError::ScanFailure`] when a binary read could not run:
/// a scan that did not happen refuses, it never passes.
pub(super) fn scan_receive_blob(blob: &PushedBlob) -> DoorResult<Option<ReceiveScanHit>> {
    let text = !blob.content.contains(&0) && std::str::from_utf8(&blob.content).is_ok();
    let (content_kind, reason) = if text {
        // The old admitting path, unchanged: each line, the same detector.
        // Then the whole text once through the streaming release reader,
        // which keeps its phrase state across lines (FIX 8804): a scan that
        // cannot run refuses, as the binary read does.
        let reason = match blob
            .lines()
            .find_map(|line| scan_file_content(&blob.path, line))
        {
            Some(reason) => Some(reason),
            None => {
                let mut source = Cursor::new(blob.content.as_slice());
                scan_file_content_reader(&blob.path, &mut source)
                    .map_err(|_| scan_failed(&blob.path))?
            }
        };
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

/// The ONE disposition of a push's scan hits (G7-BINARY policy point, FIX
/// 7608).
///
/// No hit is [`DoorScanVerdict::Clean`]. A hit that names no blob of this
/// push is a scan failure, never a pass. Every hit then takes the one
/// disposition the single `let disposition` statement below names, text and
/// binary alike; there is no knob, flag or caller choice.
///
/// - Refuse (today): one lift proposal per offending blob, naming its path
///   and reason, never its bytes, and the push is refused with them.
/// - Admit-marked (after the masked readers land): the value-free hits go
///   on to the admitted intent, whose transaction marks them or refuses the
///   push whole. No refusal is logged.
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
    for hit in &hits {
        if !blobs
            .iter()
            .any(|blob| blob.path == hit.path && blob.oid == hit.oid)
        {
            return Err(scan_failed(&hit.path));
        }
    }
    let disposition = ReceiveScanDisposition::AdmitMarked;
    match disposition {
        ReceiveScanDisposition::Refuse => {
            let mut proposals = Vec::with_capacity(hits.len());
            for hit in &hits {
                tracing::debug!(
                    reason = hit.reason,
                    binary = hit.content_kind == ReceiveBlobKind::Binary,
                    "receive scan hit refused with lift advice"
                );
                proposals.push(CheckoutSecretLiftProposal::new(repo, &hit.path, hit.reason));
            }
            Ok(DoorScanVerdict::Rejected { proposals, hits })
        }
        ReceiveScanDisposition::AdmitMarked => Ok(DoorScanVerdict::AdmitMarked { hits }),
    }
}
