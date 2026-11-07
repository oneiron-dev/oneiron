//! One write a run bound to an off-record session stages in its room, kept
//! on its receipt in the same segment (WILL L11-01, S01-2a).
//!
//! The receipt is the run's own AgentVerb write receipt, in the run's replay
//! records: one segment of the run's captured route compares it, stages the
//! write's rows and keeps the write's answer as its first row. A write whose
//! receipt cannot be kept stages nothing, so the room holds no row a replay
//! of the step would make again.
//!
//! A write the room or the door refuses keeps its refusal on the same
//! receipt (FIX 5299). Its own segment rolled back, so a second segment of
//! the same route makes the same compare and keeps the exact refusal the
//! guest read as the first row. It stages no data row. A refusal whose
//! receipt cannot be kept so is the run's error, never the guest's refusal.
//! A write a verb hook stopped before it was prepared keeps the canonical
//! path's mark on the same receipt, in one segment that stages no data row
//! (FIX 18654): the never-ran mark, or a hidden result as its answer.
//!
//! The receipt is the write's bookkeeping, as a row's record position is
//! (#3160): for as long as the room holds it, its row is neither refused
//! for the room's budget nor counted in its total, so a room at its limit
//! takes exactly the writes and checkpoints it took before, receipt and all.
//! The write's own rows, the run's checkpoints and every other row stay
//! budgeted as before (Engine 10-19 15:1x).
//!
//! A verb's answer on the receipt also keeps the caller's view of it (FIX
//! 5426). The post chain runs over the staged answer after the segment
//! commits, and a post hook may change what the caller reads. So the
//! segment marks the view pending, and the post chain's view, or none when
//! no hook changed it, settles the receipt after. A resumed step answers
//! the kept view and never runs the write's hooks again; a receipt still
//! pending, whose post chain never settled, answers its output withheld.

use std::cell::Cell;

use rmpv::Value;

use crate::code_run::replay::{CodeRunBridgeCall, CodeRunReplayGeneration, CodeRunReplayRecord};
use crate::code_run::types::{AgentVerbAnswer, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome};
use crate::entity_id::EntityId;
use crate::session_overlay::{JournalEntry, OverlayKeyspace};
use crate::{Error, Result};

use super::records::{REPLAY_RECORDS, replay_generation_matches};
use super::routing::SessionBinding;

impl SessionBinding<'_> {
    /// `call`, one write of the run, staged by `stage` in ONE segment of the
    /// run's captured route. With `receipt`, the same segment first compares
    /// the receipt's stored generation with the one given, then keeps the
    /// receipt with the write's answer as its first row, so the rows and
    /// their receipt commit together or not at all. A route that flipped or
    /// went stale refuses inside the segment; nothing re-targets.
    ///
    /// The outer error is the receipt's: a changed generation, or a receipt
    /// that could not be kept. The inner one is the write's own refusal
    /// (the room's, its route's or `stage`'s), with nothing staged.
    pub(crate) fn stage_session_write(
        &self,
        call: &SelfAgentVerbCall,
        receipt: Option<(&CodeRunReplayRecord, Option<CodeRunReplayGeneration>)>,
        stage: impl FnOnce(
            &mut heed::RwTxn<'_>,
            &dyn Fn(&mut heed::RwTxn<'_>, JournalEntry) -> Result<()>,
        ) -> Result<SelfDispatchOutcome>,
    ) -> Result<std::result::Result<SelfDispatchOutcome, Error>> {
        let unkept = Cell::new(false);
        let kept = |step: Result<()>| step.inspect_err(|_| unkept.set(true));
        let written = self
            .session
            .overlay_write_routed(&self.route, |wtxn, apply| {
                if let Some((receipt, expected)) = receipt {
                    kept(self.session_write_receipt_unchanged(wtxn, receipt, expected))?;
                }
                let outcome = stage(wtxn, apply)?;
                if let Some((receipt, _)) = receipt {
                    let row = CodeRunBridgeCall::record(
                        0,
                        &SelfCall::AgentVerb(call.clone()),
                        &outcome,
                        0,
                        0,
                    );
                    kept(row.and_then(|mut row| {
                        if matches!(outcome, SelfDispatchOutcome::AgentVerb(_)) {
                            set_caller_view(&mut row.outcome, Value::Nil);
                        }
                        self.put_session_write_receipt(wtxn, receipt, row)
                    }))?;
                }
                Ok(outcome)
            });
        match written {
            Ok(outcome) => Ok(Ok(outcome)),
            Err(error) if unkept.get() => Err(error),
            Err(error) => Ok(Err(error)),
        }
    }

    /// FIX 5299: keeps `refused` on `receipt` for `call`, a room write the
    /// room or the door refused, in ONE segment of the run's captured route,
    /// after the write's own segment rolled back. `refused` is the exact
    /// answer the guest reads. The segment compares the receipt's stored
    /// generation with the one given, as a staged write's does, then keeps
    /// the receipt with `refused` as its first row. It stages no data row,
    /// and no hook runs. The refusal's view is settled as kept: no post chain
    /// runs over a refusal. A replay of the step gets the same refusal back
    /// and asks nothing again.
    ///
    /// FIX 18654: a write a verb hook stopped keeps the canonical path's mark
    /// here too, before any segment of its own ran. A never-ran mark makes a
    /// replay of the step make the write again, under the mark's generation.
    ///
    /// # Errors
    ///
    /// A changed generation, the route's refusal (it flipped or went stale)
    /// and storage errors. Each is the run's error: the refusal is not kept,
    /// and nothing re-targets.
    pub(crate) fn keep_session_write_refusal(
        &self,
        call: &SelfAgentVerbCall,
        receipt: (&CodeRunReplayRecord, Option<CodeRunReplayGeneration>),
        refused: &SelfDispatchOutcome,
    ) -> Result<()> {
        let (receipt, expected) = receipt;
        let row = CodeRunBridgeCall::record(0, &SelfCall::AgentVerb(call.clone()), refused, 0, 0)?;
        self.session
            .overlay_write_routed(&self.route, |wtxn, _apply| {
                self.session_write_receipt_unchanged(wtxn, receipt, expected)?;
                self.put_session_write_receipt(wtxn, receipt, row)
            })
    }

    /// Whether `receipt`'s stored generation in `wtxn` is still `expected`.
    /// A changed one is a `ConcurrentWrite`.
    fn session_write_receipt_unchanged(
        &self,
        wtxn: &heed::RwTxn<'_>,
        receipt: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
    ) -> Result<()> {
        let current = REPLAY_RECORDS.get(&self.session.read_view()?, wtxn, &receipt.run_id)?;
        replay_generation_matches(current.as_ref(), expected)
    }

    /// Keeps `receipt` in `wtxn` with `row` as its first row, for a staged
    /// write and a refused one alike. The receipt's row is the write's
    /// bookkeeping, past the room's budget: a replay record row in
    /// `vault_meta`, as the side table stages it.
    fn put_session_write_receipt(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt: &CodeRunReplayRecord,
        row: CodeRunBridgeCall,
    ) -> Result<()> {
        let mut answered = receipt.clone();
        answered.bridge_calls.push(row);
        self.session.overlay().mark_bookkeeping_row(
            OverlayKeyspace::VaultMeta,
            &REPLAY_RECORDS.key_bytes(&answered.run_id),
        )?;
        let view = self.session.read_view()?;
        REPLAY_RECORDS.put(&view, wtxn, &answered.run_id, &answered)
    }

    /// Settles the caller's view on the receipt `receipt` keeps for `call`:
    /// its first row becomes `answer`, with every hook's disposition, and
    /// `view`, the caller's reply when a post hook changed it. One segment
    /// of the run's captured route; the receipt row stays bookkeeping.
    ///
    /// # Errors
    ///
    /// A receipt that is gone or holds no row, the route's refusal and
    /// storage errors. The receipt then stays pending.
    pub(crate) fn settle_session_write_view(
        &self,
        receipt: EntityId,
        call: &SelfAgentVerbCall,
        answer: &AgentVerbAnswer,
        view: Option<&serde_json::Value>,
    ) -> Result<()> {
        let mut row = CodeRunBridgeCall::record(
            0,
            &SelfCall::AgentVerb(call.clone()),
            &SelfDispatchOutcome::AgentVerb(answer.clone()),
            0,
            0,
        )?;
        if let Some(view) = view {
            set_caller_view(&mut row.outcome, Value::from(view.to_string()));
        }
        self.session
            .overlay_write_routed(&self.route, |wtxn, _apply| {
                let store = self.session.read_view()?;
                let Some(mut record) = REPLAY_RECORDS.get(&store, wtxn, &receipt)? else {
                    return Err(Error::InvariantViolation("a room write's receipt is gone"));
                };
                let Some(first) = record.bridge_calls.first_mut() else {
                    return Err(Error::InvariantViolation(
                        "a room write's receipt holds no row",
                    ));
                };
                *first = row;
                REPLAY_RECORDS.put(&store, wtxn, &receipt, &record)
            })
    }
}

/// What a kept room write's receipt says its caller read.
pub(crate) enum KeptCallerView {
    /// The answer as kept: no hook changed it, or it is no room write's.
    Unchanged,
    /// Its post chain never settled: the caller reads its output withheld.
    Pending,
    /// The caller's reply, as a post hook changed it.
    Changed(serde_json::Value),
}

/// The caller's view a receipt row's `outcome` keeps.
///
/// # Errors
///
/// A kept view that does not decode.
pub(crate) fn kept_caller_view(outcome: &Value) -> Result<KeptCallerView> {
    let Value::Map(entries) = outcome else {
        return Ok(KeptCallerView::Unchanged);
    };
    let kept = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(CALLER_VIEW))
        .map(|(_, view)| view);
    match kept {
        None => Ok(KeptCallerView::Unchanged),
        Some(Value::Nil) => Ok(KeptCallerView::Pending),
        Some(view) => view
            .as_str()
            .and_then(|text| serde_json::from_str(text).ok())
            .map(KeptCallerView::Changed)
            .ok_or(Error::InvariantViolation(
                "a room write's kept caller view does not decode",
            )),
    }
}

/// The outcome key a room write's caller view rides under on its receipt:
/// nil while pending, else the caller's reply as JSON text.
const CALLER_VIEW: &str = "caller_view";

/// Sets `outcome`'s caller view to `view`, replacing any it holds.
fn set_caller_view(outcome: &mut Value, view: Value) {
    if let Value::Map(entries) = outcome {
        entries.retain(|(key, _)| key.as_str() != Some(CALLER_VIEW));
        entries.push((Value::from(CALLER_VIEW), view));
    }
}
