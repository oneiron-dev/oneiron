//! Receipt-derived rate and failure streak supplied to the existing auto checker.
//! There is no trip threshold, demotion, durable counter, or reset operation here.
use crate::llm::AutoCheckSignals;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;
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
        if record.actor_ref.as_deref() != Some(actor_ref)
            || record.content_kind != "claim"
            || record.created_at > now
        {
            continue;
        }
        if now.saturating_sub(record.created_at) < config.window_secs {
            signals.recent_writes = signals.recent_writes.saturating_add(1);
        }
        match record.outcome.as_str() {
            "allow" => signals.failure_streak = 0,
            "deny" => signals.failure_streak = signals.failure_streak.saturating_add(1),
            "pending"
                if record
                    .reason_codes
                    .iter()
                    .any(|code| code.starts_with("gate.pending.checker")) =>
            {
                signals.failure_streak = signals.failure_streak.saturating_add(1);
            }
            _ => {}
        }
    }
    Ok(signals)
}
