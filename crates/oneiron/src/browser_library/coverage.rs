//! The Coach's coverage and seen reads (FIX 10841, 10513): the same
//! reads the index keeps its rows for, in a caller's own transaction
//! where it has one, and the filing anchors' authorized read. Kept
//! beside the index so its file keeps its headroom.

use super::evidence::{WORKFLOW_FILING_PREDICATE, WorkflowFiling, workflow_filing_id};
use super::index::{COVERAGE, ProgramSeen, SEEN};
use crate::Vault;
use crate::claim::{ScopedRead, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The live programs filed in the group `digest` keys, read in `txn`
/// (FIX 10841): [`super::solved_group_coverage`] without its own read
/// transaction, for a caller inside its write.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn solved_group_coverage_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Vec<EntityId>> {
    Ok(COVERAGE
        .scan_keys(&vault.store, txn, digest)?
        .into_iter()
        .map(|(_, id)| id)
        .collect())
}

/// The Coach's mark for the candidate `fingerprint` names, read in
/// `txn` (FIX 10841): [`super::program_seen`] without its own read
/// transaction, for a caller inside its write.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn program_seen_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fingerprint: &[u8; 32],
) -> Result<Option<ProgramSeen>> {
    SEEN.get(&vault.store, txn, fingerprint)
}

/// The live programs covering the group `digest` keys that `read` may
/// read (FIX 10513): each covered program's filing anchor claim is read
/// through `read`, and only a program whose anchor reads back as its
/// own filing of this group is named. A withheld anchor withholds its
/// program, counted in the receipt. A raw covered id is no read grant.
///
/// # Errors
///
/// Storage errors.
pub fn solved_group_coverage_read(
    read: &ScopedRead<'_>,
    digest: &[u8; 32],
) -> Result<ScopedReadResult<Vec<EntityId>>> {
    let vault = read.vault();
    let ids = {
        let rtxn = vault.store.env.read_txn()?;
        solved_group_coverage_in(vault, &rtxn, digest)?
    };
    let anchors = ids
        .iter()
        .map(|id| workflow_filing_id(id, digest))
        .collect::<Result<Vec<_>>>()?;
    let rows = read.get_entities_parts_with_receipt(&anchors, None)?;
    let mut named = Vec::new();
    for (id, row) in ids.iter().zip(rows.value) {
        let Some((entity_type, _, body)) = row else {
            continue;
        };
        if let Some(filing) = filing_of(entity_type, &body)
            && filing.workflow == *id
            && filing.group == *digest
        {
            named.push(*id);
        }
    }
    Ok(ScopedReadResult {
        value: named,
        receipt: rows.receipt,
    })
}

/// The filing a `browser.workflow.filing` claim's body holds.
fn filing_of(entity_type: u8, body: &[u8]) -> Option<WorkflowFiling> {
    if entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return None;
    }
    let claim = crate::claim::decode_claim_body(body, true).ok()?;
    if claim.predicate != WORKFLOW_FILING_PREDICATE {
        return None;
    }
    serde_json::from_str(claim.value.as_str()?).ok()
}
