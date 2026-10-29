//! An erase in the attribution ledgers (FIX 8265, OF-568 L10; FIX 8988): the
//! rows that name an erased skill or actor drop it in the erase's own write,
//! as a cause row does
//! ([`super::causes::erase_attribution_cause_entity_in_txn`]).
//!
//! An evidence row keeps its receipt and outcome with its skill or actor
//! slot nil, so a projection that reads it again routes it with no one to
//! name. A judgment charging an erased skill goes, as does every edit
//! proposal naming that skill, and the projector, whose cursor is past them,
//! routes neither again. A lapse judgment charging an erased actor stays,
//! its subject nil, and charges no one.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{SideCodec, SideKey, SideTable};

use super::codec::{EDIT_PROPOSAL, EVIDENCE, JUDGMENT};
use super::types::AttributionVerdict;

/// Forgets erased `entity` as the skill or the actor of every evidence row
/// that names it.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_evidence_skill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (sequence, mut row) in erase_scan_in_txn(vault, wtxn, EVIDENCE)? {
        let skill = row.evidence.skill == Some(*entity);
        let actor = row.evidence.actor == Some(*entity);
        if !skill && !actor {
            continue;
        }
        if skill {
            row.evidence.skill = None;
        }
        if actor {
            row.evidence.actor = None;
        }
        EVIDENCE.put(&vault.store, wtxn, &sequence, &row)?;
    }
    Ok(())
}

/// Drops every judgment that charges erased `entity` as its skill, and every
/// edit proposal that names it; a lapse judgment that charges it as its
/// actor stays, its subject nil.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_judgment_skill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (sequence, mut judgment) in erase_scan_in_txn(vault, wtxn, JUDGMENT)? {
        if judgment.subject != Some(*entity) {
            continue;
        }
        match judgment.verdict {
            AttributionVerdict::SkillDefect
            | AttributionVerdict::Discovery
            | AttributionVerdict::ExecutionLapse => {
                judgment.subject = None;
                JUDGMENT.put(&vault.store, wtxn, &sequence, &judgment)?;
            }
            _ => {}
        }
    }
    for (sequence, proposal) in erase_scan_in_txn(vault, wtxn, EDIT_PROPOSAL)? {
        if proposal.skill == *entity {
            EDIT_PROPOSAL.delete(&vault.store, wtxn, &sequence)?;
        }
    }
    Ok(())
}

/// Every row of `table` whose key and value decode, in key order, for an
/// erase's scrub (FIX 8988). A row whose value no longer decodes is deleted
/// by its key and counted, so an erase never fails on it; a key that does
/// not decode names nothing a scrub can match, and is left as it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_scan_in_txn<K: SideKey, V, C: SideCodec<V>>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    table: SideTable<K, V, C>,
) -> Result<Vec<(K, V)>> {
    let raw = table
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let mut rows = Vec::with_capacity(raw.len());
    let mut dropped = 0_usize;
    for (key, value) in raw {
        let Some(key) = K::decode_key(&key) else {
            continue;
        };
        match table.decode_value(&value) {
            Ok(value) => rows.push((key, value)),
            Err(_) => {
                table.delete(&vault.store, wtxn, &key)?;
                dropped += 1;
            }
        }
    }
    if dropped > 0 {
        tracing::warn!(
            dropped,
            table = table.decl().name,
            "an erase deleted rows that no longer decode"
        );
    }
    Ok(rows)
}
