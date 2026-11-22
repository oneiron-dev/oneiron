//! The owner's archive restore of the Hook receipts: the row invariants an archived
//! receipt must keep before it lands, and the landing of the archived Hook and regen
//! receipt rows.

use crate::receipt::{ReceiptRecord, hex_lower};
use crate::{Result, Vault};

use super::{RECEIPTS, RunKey};

/// Whether `text` is `len` lowercase hex characters.
fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether a usage count spells a number or the unmeasured marker.
fn archived_usage_holds(text: &str) -> bool {
    text == "unavailable" || text.parse::<u64>().is_ok()
}

/// Whether a decoded Hook receipt keeps the writer's pure row invariants.
fn archived_hooks_receipt_holds(key: &RunKey, receipt: &ReceiptRecord) -> bool {
    if receipt.receipt_kind != crate::receipt::ReceiptKind::Hook {
        return false;
    }
    match receipt.outcome.as_str() {
        "continue" | "rewrite" | "skip" | "ask" | "add_block" | "annotate" | "redact"
        | "propose" | "enqueue" | "effect" | "nothing" | "refused" | "failed" => {}
        _ => return false,
    }
    let key_hex = hex_lower(key);
    if receipt.receipt_id != format!("hook:{key_hex}") {
        return false;
    }
    if receipt.job_ref.is_some() {
        return false;
    }
    if !receipt.policy_trace.is_empty() {
        return false;
    }
    let Some(actor) = receipt.actor.as_deref() else {
        return false;
    };
    if !is_lower_hex(actor, 32) {
        return false;
    }
    if let Some(caller) = receipt.on_behalf_of.as_deref()
        && caller != crate::receipt::ERASED_CALL_IDENTITY
        && !is_lower_hex(caller, 32)
    {
        return false;
    }
    let Some(trigger) = receipt.trigger_ref.as_deref() else {
        return false;
    };
    if !is_lower_hex(trigger, 32) {
        return false;
    }
    let Some(run_key) = receipt.fields.get("run_key") else {
        return false;
    };
    if run_key != &key_hex {
        return false;
    }
    let (Some(binding), Some(code), Some(body_hash)) = (
        receipt.fields.get("binding"),
        receipt.fields.get("code"),
        receipt.fields.get("body_hash"),
    ) else {
        return false;
    };
    if !is_lower_hex(binding, 32) || !is_lower_hex(code, 32) || !is_lower_hex(body_hash, 64) {
        return false;
    }
    let (Some(hook), Some(version)) = (
        receipt.fields.get("hook"),
        receipt.fields.get("hook_version"),
    ) else {
        return false;
    };
    if hook.is_empty() || !hook.contains('/') || version.is_empty() {
        return false;
    }
    let (Some(duration), Some(now), Some(rows)) = (
        receipt.fields.get("duration_ms"),
        receipt.fields.get("now"),
        receipt.fields.get("rows_read"),
    ) else {
        return false;
    };
    if duration.parse::<u64>().is_err()
        || now.parse::<u64>().is_err()
        || rows.parse::<u64>().is_err()
    {
        return false;
    }
    let (Some(fuel), Some(calls)) = (
        receipt.fields.get("fuel_used"),
        receipt.fields.get("host_calls"),
    ) else {
        return false;
    };
    if !archived_usage_holds(fuel) || !archived_usage_holds(calls) {
        return false;
    }
    if receipt.fields.contains_key("invocation") {
        let (Some(invocation), Some(verb), Some(phase), Some(class)) = (
            receipt.fields.get("invocation"),
            receipt.fields.get("verb"),
            receipt.fields.get("phase"),
            receipt.fields.get("class"),
        ) else {
            return false;
        };
        if !is_lower_hex(invocation, 32) || verb.is_empty() {
            return false;
        }
        match phase.as_str() {
            "pre" | "post" | "fact" => {}
            _ => return false,
        }
        match class.as_str() {
            "human" | "agent" | "system" => {}
            _ => return false,
        }
        if receipt.fields.contains_key("fact")
            || receipt.fields.contains_key("source")
            || receipt.fields.contains_key("position")
        {
            return false;
        }
    } else {
        let (Some(fact), Some(source), Some(position)) = (
            receipt.fields.get("fact"),
            receipt.fields.get("source"),
            receipt.fields.get("position"),
        ) else {
            return false;
        };
        if fact.is_empty() || source.is_empty() || position.is_empty() {
            return false;
        }
        if receipt.fields.contains_key("verb")
            || receipt.fields.contains_key("phase")
            || receipt.fields.contains_key("class")
        {
            return false;
        }
    }
    let overrun = [
        receipt.fields.get("budget_ms"),
        receipt.fields.get("elapsed_ms"),
        receipt.fields.get("overrun_ms"),
        receipt.fields.get("callback_ms"),
        receipt.fields.get("read_overruns"),
        receipt.fields.get("verdict_overruns"),
    ];
    let present = overrun.iter().filter(|slot| slot.is_some()).count();
    if present != 0 && present != 6 {
        return false;
    }
    if present == 6
        && (overrun[0].is_some_and(|text| text.parse::<u32>().is_err())
            || overrun[1].is_some_and(|text| text.parse::<u64>().is_err())
            || overrun[2].is_some_and(|text| text.parse::<u64>().is_err())
            || overrun[3].is_some_and(|text| text.parse::<u64>().is_err())
            || overrun[4].is_some_and(|text| text.parse::<u32>().is_err())
            || overrun[5].is_some_and(|text| text.parse::<u32>().is_err()))
    {
        return false;
    }
    true
}

/// Lands one archived Hook receipt, preserving erased callers and retired payloads.
fn land_archived_hooks_receipt_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &crate::batch::export::OwnerArchiveRestorePermit,
    row: &crate::batch::export::ArchiveRetainedSideRow,
) -> Result<crate::batch::export::archive_side_install::ArchivedSideRowOutcome> {
    use crate::batch::export::RetainedSideHeldBackReason;
    use crate::batch::export::archive_side_install::{
        ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
    };
    let (key, receipt) = match decode_archived_row(&RECEIPTS, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    if !archived_hooks_receipt_holds(&key, &receipt) {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    install_archived_row(&RECEIPTS, vault, txn, permit, &key, row)
}

impl Vault {
    /// Lands the owner's archived Hook and regen receipts in input order, never touching runs or
    /// packs.
    pub(crate) fn land_archived_runtime_hooks_rows_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &crate::batch::export::OwnerArchiveRestorePermit,
        rows: &[crate::batch::export::ArchiveRetainedSideRow],
    ) -> Result<Vec<crate::batch::export::archive_side_install::ArchivedSideRowOutcome>> {
        use crate::batch::export::RetainedSideHeldBackReason;
        use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            if row.source_table.as_str() == crate::side_table::HOOKS_RECEIPT.name {
                outcomes.push(land_archived_hooks_receipt_row_in_txn(
                    vault, txn, permit, row,
                )?);
            } else if row.source_table.as_str() == crate::side_table::HOOKS_REGEN_RECEIPT.name {
                outcomes.push(crate::Vault::land_archived_hooks_regen_receipt_row_in_txn(
                    vault, txn, permit, row,
                )?);
            } else {
                outcomes.push(ArchivedSideRowOutcome::HeldBack(
                    RetainedSideHeldBackReason::InvalidEncoding,
                ));
            }
        }
        Ok(outcomes)
    }
}
