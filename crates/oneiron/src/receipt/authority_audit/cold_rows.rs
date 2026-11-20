//! The cold rows of an audit page (OF-469): the entries the adopted image
//! covers past the page's cursor, in entity-id order, and the row each one
//! projects to.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use super::super::kernel::hex_lower;
use super::issues::FoldIssues;
use super::{
    AUTHORITY_AUDIT_COLD_ROWS_IGNORE_KIND_FILTER, AuthorityAuditEventKind, ColdAuthorityAuditRow,
    agent_grant_act, key_hex, project_body,
};
use crate::Vault;
use crate::authority::{AuthorityCheckpointRow, AuthorityFold, VerifiedAuthorityCheckpoint};
use crate::entity_id::EntityId;
use crate::error::Result;
use oneiron_authority::authority::{AuthorityLogEntry, authority_log_entity_id_from_hash};
use oneiron_contracts::authority::{AUTHORITY_HASH_LEN, AuthorityEntryHash};

/// A row the adopted image covers, with the entity id its hash derives and
/// the signed body the image carries of it, decoded.
#[derive(Clone, Copy)]
pub(super) struct Covered<'a> {
    pub(super) id: EntityId,
    hash: &'a AuthorityEntryHash,
    row: &'a AuthorityCheckpointRow,
    body: Option<&'a AuthorityLogEntry>,
    checkpoint: &'a VerifiedAuthorityCheckpoint,
}

/// The adopted image's covered rows past `after`, ascending by entity id,
/// each with its carried body from `adopted`'s decoded bodies; none when
/// nothing was adopted. An entry's id is its hash's first 16 bytes, so hash
/// order is id order, and the first row past the cursor is the first hash
/// above `after` padded with `0xff`.
pub(super) fn covered_after<'a>(
    adopted: Option<(
        &'a VerifiedAuthorityCheckpoint,
        &'a BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    )>,
    after: Option<EntityId>,
) -> impl Iterator<Item = Result<Covered<'a>>> {
    let start = after.map_or(Bound::Unbounded, |after| {
        let mut floor = [0xffu8; AUTHORITY_HASH_LEN];
        floor[..after.as_bytes().len()].copy_from_slice(after.as_bytes());
        Bound::Excluded(floor)
    });
    adopted.into_iter().flat_map(move |(checkpoint, bodies)| {
        checkpoint
            .image()
            .rows
            .range((start, Bound::Unbounded))
            .map(move |(hash, row)| -> Result<Covered<'a>> {
                Ok(Covered {
                    id: authority_log_entity_id_from_hash(hash)?,
                    hash,
                    row,
                    body: bodies.get(hash),
                    checkpoint,
                })
            })
    })
}

/// Whether a page under `kinds` lists a cold row
/// ([`AUTHORITY_AUDIT_COLD_ROWS_IGNORE_KIND_FILTER`]).
pub(super) fn lists_cold_rows(kinds: &BTreeSet<AuthorityAuditEventKind>) -> bool {
    AUTHORITY_AUDIT_COLD_ROWS_IGNORE_KIND_FILTER || kinds.is_empty()
}

/// The cold row of `cold`. Where the image carries its body, the row names
/// what the body says as a stored row of the entry would, the mark of a
/// withdrawn mint and the op's own issue codes included.
pub(super) fn project_cold_row(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cold: Covered<'_>,
    fold: &AuthorityFold,
    issues: &FoldIssues,
) -> Result<ColdAuthorityAuditRow> {
    let fold_valid = fold.valid_entries.contains(cold.hash);
    let (carried_body, issue_codes) = match cold.body {
        Some(entry) => {
            let mut body = project_body(entry);
            agent_grant_act::pair_marked_withdrawal(
                vault,
                txn,
                &entry.op,
                fold_valid,
                &mut body.detail,
            )?;
            (Some(body), issues.codes(cold.hash, &entry.op))
        }
        None => (None, issues.cold_codes(cold.hash)),
    };
    Ok(ColdAuthorityAuditRow {
        entry_ref: cold.id,
        entry_hash: hex_lower(cold.hash),
        checkpoint: hex_lower(&cold.checkpoint.id()),
        signer_key: key_hex(&cold.row.signer),
        seq: cold.row.seq,
        parents: cold
            .row
            .parents
            .iter()
            .map(|parent| hex_lower(parent))
            .collect(),
        carried_body,
        fold_valid,
        issue_codes,
    })
}
