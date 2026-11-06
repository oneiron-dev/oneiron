//! Explicit original output-placement requests for native reliability outcomes.

use crate::attempt_queue::ManifestEntry;
use crate::{EntityId, Result, Vault};

use super::super::codec::invalid;
use super::super::outcome_position::OutcomeReadPosition;
use super::{
    ATTEMPT_OUTCOME_COMPLETED, read_skill, receipt_executor, receipt_manifest_names_skill,
};

/// Records the outcome with independently declared original output placement.
///
/// The position is not read authority and cannot restamp an existing row.
pub fn record_skill_contributing_win_with_position(
    vault: &Vault,
    skill: &EntityId,
    receipt_ref: &str,
    at: u64,
    output_position: Option<&OutcomeReadPosition>,
) -> Result<()> {
    let record = read_skill(vault, skill)?;
    if crate::skill::resident_of(&record)?.is_some() {
        return Err(invalid("resident win requires its attributed actor"));
    }
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, receipt_ref)? else {
        return Err(invalid("contributing win cites an unstamped receipt"));
    };
    if receipt.outcome != ATTEMPT_OUTCOME_COMPLETED {
        return Err(invalid(
            "a contributing win requires a completed attempt receipt",
        ));
    }
    if !receipt_manifest_names_skill(&receipt, &record) {
        return Err(invalid(
            "contributing win names a skill absent from the receipt manifest",
        ));
    }
    vault.with_write_txn_grouped(|wtxn| {
        super::super::outcome_write::record_outcome_positioned_in_txn(
            vault,
            wtxn,
            skill,
            receipt_executor(&receipt),
            receipt_ref,
            true,
            at,
            output_position,
        )
    })
}

/// Records the outcome with independently declared original output placement.
///
/// The position is not read authority and cannot restamp an existing row.
pub(crate) fn record_skill_settled_loss_with_position(
    vault: &Vault,
    skill: &EntityId,
    receipt_ref: &str,
    at: u64,
    output_position: Option<&OutcomeReadPosition>,
) -> Result<()> {
    let record = read_skill(vault, skill)?;
    if crate::skill::resident_of(&record)?.is_some() {
        return Err(invalid("resident loss requires its attributed actor"));
    }
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, receipt_ref)? else {
        return Err(invalid("settled loss cites an unstamped receipt"));
    };
    if !receipt_manifest_names_skill(&receipt, &record) {
        return Err(invalid(
            "settled loss names a skill absent from the receipt manifest",
        ));
    }
    vault.with_write_txn_grouped(|wtxn| {
        super::super::outcome_write::record_outcome_positioned_in_txn(
            vault,
            wtxn,
            skill,
            receipt_executor(&receipt),
            receipt_ref,
            false,
            at,
            output_position,
        )
    })
}

/// Records the outcome with independently declared original output placement.
///
/// The position is not read authority and cannot restamp an existing row.
pub fn record_resident_skill_contributing_win_with_position(
    vault: &Vault,
    resident: &EntityId,
    skill: &EntityId,
    receipt_ref: &str,
    at: u64,
    output_position: Option<&OutcomeReadPosition>,
) -> Result<()> {
    let record = read_skill(vault, skill)?;
    if crate::skill::resident_of(&record)? != Some(*resident)
        || crate::skill::resident::receipt_resident(vault, receipt_ref)? != Some(*resident)
        || !crate::skill::resident::receipt_loaded_skill(vault, receipt_ref, skill)?
    {
        return Err(invalid(
            "resident win names a foreign or unowned skill or attempt",
        ));
    }
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, receipt_ref)? else {
        return Err(invalid("contributing win cites an unstamped receipt"));
    };
    if receipt.outcome != ATTEMPT_OUTCOME_COMPLETED {
        return Err(invalid(
            "a contributing win requires a completed attempt receipt",
        ));
    }
    let Some(manifest) = receipt.pack_manifest_skills() else {
        return Err(invalid("resident win needs a versioned manifest"));
    };
    if !manifest.iter().any(|entry| {
        ManifestEntry::parse_wire_form(entry)
            .is_some_and(|(name, version)| name == record.skill_id && version == record.version)
    }) {
        return Err(invalid("resident win needs its exact revision"));
    }
    vault.with_write_txn_grouped(|txn| {
        super::super::outcome_write::record_outcome_positioned_in_txn(
            vault,
            txn,
            skill,
            receipt_executor(&receipt),
            receipt_ref,
            true,
            at,
            output_position,
        )
    })
}
