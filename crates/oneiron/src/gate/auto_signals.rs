//! Receipt-derived rate and failure streak supplied to the existing auto checker.
//! There is no trip threshold, demotion, durable counter, or reset operation here.
use crate::claim_check::AutoCheckSignals;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;
use crate::store::gate_reason::GateReceiptOutcome;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignalWindow {
    window_secs: u64,
}

/// Cached configuration window (seconds) for the receipt-derived auto-checker signal; no engine
/// write path found in this repo, likely operator-provisioned. Key: ().
const AUTO_SIGNALS_WINDOW: SideTable<(), SignalWindow, LegacyJson> =
    SideTable::new(&side_table::GATE_AUTO_SIGNALS_WINDOW);

pub(super) fn auto_check_signals(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor_ref: Option<&str>,
    now: u64,
) -> Result<AutoCheckSignals> {
    let config: SignalWindow = match AUTO_SIGNALS_WINDOW.get(store, txn, &())? {
        Some(config) => config,
        None => serde_json::from_str(include_str!("auto_signal_defaults.json"))
            .map_err(|_| Error::CorruptedIndex("default auto signal window"))?,
    };
    if config.window_secs == 0 {
        return Err(Error::InvalidConfig(
            "auto signal window must be positive".into(),
        ));
    }
    let mut signals = AutoCheckSignals {
        window_secs: config.window_secs,
        ..Default::default()
    };
    let Some(actor_ref) = actor_ref else {
        return Ok(signals);
    };
    // These are advisory observations, not admission counters. Bound work
    // even when unrelated actors dominate the ledger; report the recent sample.
    for record in store
        .gate_decisions_page_in_txn(txn, None, 1_024)?
        .into_iter()
        .rev()
    {
        // An engine restatement of a held write's open question names the
        // writer it asks for, but the writer wrote nothing: it is neither a
        // write nor a step of the streak.
        if record.actor_ref.as_deref() != Some(actor_ref)
            || record.content_kind != "claim"
            || record.created_at > now
            || record.context.restates.is_some()
        {
            continue;
        }
        let outcome = record.gate_outcome();
        // A write is the gate's own decision on it. An answer to a held write
        // (a tray close, receipted as its author or its closer) or an audit
        // note is no new write, so it never counts.
        if outcome.is_none_or(decides_a_write)
            && now.saturating_sub(record.created_at) < config.window_secs
        {
            signals.recent_writes = signals.recent_writes.saturating_add(1);
        }
        match outcome {
            Some(GateReceiptOutcome::Allow) => signals.failure_streak = 0,
            Some(GateReceiptOutcome::Deny) => {
                signals.failure_streak = signals.failure_streak.saturating_add(1);
            }
            Some(GateReceiptOutcome::Pending)
                if record
                    .reason_codes
                    .iter()
                    .any(|code| code.starts_with("gate.pending.checker")) =>
            {
                signals.failure_streak = signals.failure_streak.saturating_add(1);
            }
            Some(
                GateReceiptOutcome::Pending
                | GateReceiptOutcome::Approved
                | GateReceiptOutcome::ApprovedAmended
                | GateReceiptOutcome::Rejected
                | GateReceiptOutcome::LetGo
                | GateReceiptOutcome::Superseded
                | GateReceiptOutcome::Retracted
                | GateReceiptOutcome::Invalidated
                | GateReceiptOutcome::Revoked
                | GateReceiptOutcome::Noted,
            )
            | None => {}
        }
    }
    Ok(signals)
}

/// Whether a receipt with this outcome is the gate's own decision on a write
/// (the rule let it go, held it, or refused it), not an answer to an earlier
/// one or a note.
const fn decides_a_write(outcome: GateReceiptOutcome) -> bool {
    match outcome {
        GateReceiptOutcome::Allow | GateReceiptOutcome::Pending | GateReceiptOutcome::Deny => true,
        GateReceiptOutcome::Approved
        | GateReceiptOutcome::ApprovedAmended
        | GateReceiptOutcome::Rejected
        | GateReceiptOutcome::LetGo
        | GateReceiptOutcome::Superseded
        | GateReceiptOutcome::Retracted
        | GateReceiptOutcome::Invalidated
        | GateReceiptOutcome::Revoked
        | GateReceiptOutcome::Noted => false,
    }
}
