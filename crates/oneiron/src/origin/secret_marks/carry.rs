//! The mark a translated sync copy edit's landed bytes carry (FIX 10732, L04
//! 05:5x).
//!
//! A sync peer edits the masked copy of a marked source, and the shipped
//! visible diff lands its edit on the source: new bytes whose BLAKE3 is no
//! longer the marked blob's. Unmarked, every later copy of the source is the
//! sealed-file placeholder and every later edit holds as
//! `sealed_file_edited`. The landing's own writer therefore marks the landed
//! bytes as the receive door marks a pushed blob: the planner places each key
//! in exactly those bytes (the file mask's detectors, field rules and the
//! values custody knows, so a key of the old blob left in place is found
//! again), each key goes to custody and the spans to the mask row under the
//! new BLAKE3, and one fact per store observation of the old blob and per
//! placement names the new bytes by their BLAKE3 and Git blob OID, under
//! [`RepoSecretSource::SyncLanding`]. No span is shifted from the old blob.
//!
//! Landed bytes with residue no span isolates, or with no key the rules
//! place, take no fact: their copy stays the sealed-file placeholder, as
//! before.

use heed::RwTxn;

use super::{
    RepoSecretMark, RepoSecretSource, placements, put_repo_secret_mark_in_txn,
    repo_secret_marks_for_hash_in_txn,
};
use crate::Vault;
use crate::batch::secret_scan::{
    RetainedRepoCustody, mark_retained_repo_blob_in_txn, plan_retained_repo_blob,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::GitOid;
use crate::secret_custody::{CustodyWrite, KnownValues};

/// The reason landed bytes no rule places a key in are planned under: the
/// plan's whole-blob residue, for which no fact is written.
const SYNC_LANDING_REASON: &str = "sync.copy_edit_landing";

/// Marks `landed`, the bytes a translated sync copy edit lands on the marked
/// source `source` whose old bytes hash to `old`, in `wtxn`, the landing's
/// own writer. Returns how many facts it newly wrote: 0 when the old blob has
/// no readable mark, when the bytes did not change, and when the landed bytes
/// hold residue no span isolates or no key at all.
///
/// # Errors
/// A plan, custody, mark or claim failure: the landing aborts with it, so the
/// landed bytes are never committed without their mark.
pub(crate) fn carry_repo_secret_marks_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    old: &[u8; 32],
    landed: &[u8],
    source: EntityId,
) -> Result<u64> {
    let raw_blake3 = *blake3::hash(landed).as_bytes();
    if raw_blake3 == *old {
        return Ok(0);
    }
    let prior = repo_secret_marks_for_hash_in_txn(vault, wtxn, old)?;
    if prior.is_empty() {
        return Ok(0);
    }
    let path = prior.marks().iter().find_map(|mark| mark.path.clone());
    let known = KnownValues::load_in_writer(&vault.store, wtxn)?;
    let plan = plan_retained_repo_blob(
        path.as_deref().unwrap_or_default(),
        landed,
        known.as_ref(),
        SYNC_LANDING_REASON,
        source,
    )?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let mut custody = RetainedRepoCustody::load_in_writer(&vault.store, wtxn)?;
    let placed = mark_retained_repo_blob_in_txn(
        &CustodyWrite::of(vault),
        wtxn,
        &mut custody,
        plan,
        source,
        at,
    )?;
    if placed.opaque.is_some() || placed.keys.is_empty() {
        return Ok(0);
    }
    let blob_oid = git_blob_oid(landed)?;
    let placements = placements(&placed);
    let mut observed: Vec<&RepoSecretMark> = Vec::new();
    let mut written: u64 = 0;
    for mark in prior.marks() {
        // One store observation of the old blob: its operation, store,
        // path and content kind, whatever placements it named.
        if observed.iter().any(|seen| same_observation(seen, mark)) {
            continue;
        }
        observed.push(mark);
        for (placement, detector_kind) in &placements {
            let carried = RepoSecretMark {
                schema_version: RepoSecretMark::SCHEMA,
                operation_id: mark.operation_id,
                store_id: mark.store_id,
                store_identity: mark.store_identity.clone(),
                source: RepoSecretSource::SyncLanding { source },
                blob_oid: blob_oid.clone(),
                raw_blake3,
                path: mark.path.clone(),
                detector_kind: detector_kind.clone(),
                content_kind: mark.content_kind,
                placement: placement.clone(),
                marked_at: at,
            };
            if put_repo_secret_mark_in_txn(vault, wtxn, &carried)? {
                written = written
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow("a landing's repo secret marks"))?;
            }
        }
    }
    // The index copies these bytes already derive are refreshed under their
    // new marks, as a push's are (FIX 7608 slice 3).
    if written > 0 {
        crate::origin::secret_projection::index::refresh_repo_index_projection_in_txn(
            vault,
            wtxn,
            &[raw_blake3],
        )?;
    }
    Ok(written)
}

/// Whether `a` and `b` are one store observation of a blob.
fn same_observation(a: &RepoSecretMark, b: &RepoSecretMark) -> bool {
    a.operation_id == b.operation_id
        && a.store_id == b.store_id
        && a.store_identity == b.store_identity
        && a.path == b.path
        && a.content_kind == b.content_kind
}

/// The Git blob OID of exactly `bytes`.
fn git_blob_oid(bytes: &[u8]) -> Result<GitOid> {
    let oid = gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Blob, bytes)
        .map_err(|_| Error::InvariantViolation("a landed blob's Git object id"))?;
    Ok(GitOid::parse_hex(oid.to_string())?)
}
