//! The composite state index's inputs, measured from the subject's own
//! records (OF-335). Engagement is the share of an expected number of days
//! in the window on which the subject spoke; goal velocity is the share of
//! an expected number of completions among the TASKs it owns; affect is the
//! VAD the vault already annotated on the turns it spoke. These are activity
//! counts over owned records, never a clinical label, and the owner sets
//! every target.

use std::collections::BTreeSet;
use std::ops::Bound;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::state_index::{ENGAGEMENT, GOAL_VELOCITY, StateIndex, StateIndexEvidence};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TimeAxis, TimelineQuery};
use crate::vault::LiveEntityRow;
use crate::{EdgeKind, EntityId, Error, Result, TimeRange, Vault};

const DAY_SECS: u64 = 86_400;
/// The longest window a refresh reads.
const MAX_WINDOW_SECS: u64 = 366 * DAY_SECS;
/// Most timeline rows one refresh reads: the window's rows of every kind.
const MAX_WINDOW_ROWS: usize = 100_000;
/// Most VAD turns the composite reads, newest first.
const MAX_VAD_TURNS: usize = 256;
/// Most records one signal claim cites.
const MAX_SIGNAL_REFS: usize = 256;

/// The owner's targets for one window. They describe this person's own
/// pace, not a clinical or population norm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateWindow {
    pub window_secs: u64,
    pub expected_goal_completions: u32,
    pub expected_engaged_days: u32,
}

impl StateWindow {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.window_secs == 0
            || self.window_secs > MAX_WINDOW_SECS
            || self.expected_goal_completions == 0
            || self.expected_engaged_days == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Vault {
    /// Measures the subject's window and refreshes its composite index in
    /// the caller's write: both signal claims, their evidence and the index
    /// commit together. `None` when a source family is missing (no annotated
    /// turn the subject spoke, or no TASK it owns): absence is not a low
    /// score, and the index it already had stays as it was.
    pub(crate) fn refresh_state_index_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        subject: &EntityId,
        window: &StateWindow,
        at: u64,
    ) -> Result<Option<(EntityId, StateIndex)>> {
        window.validate()?;
        let start = at.saturating_sub(window.window_secs);
        let (turns, owned, completed) = {
            let rtxn: &heed::RoTxn<'_> = txn;
            let turns = subject_turns_in(self, rtxn, subject, start, at)?;
            let (owned, completed) = goal_tasks_in(self, rtxn, subject, start, at)?;
            (turns, owned, completed)
        };
        let mut vad_turns = Vec::new();
        for (_, turn) in &turns {
            if vad_turns.len() == MAX_VAD_TURNS {
                break;
            }
            if self
                .turn_vad_annotation_in_txn(txn, turn)?
                .is_some_and(|annotation| annotation.annotated_at <= at)
            {
                vad_turns.push(*turn);
            }
        }
        if vad_turns.is_empty() || owned.is_empty() {
            return Ok(None);
        }
        let days: BTreeSet<u64> = turns
            .iter()
            .map(|(occurred, _)| occurred / DAY_SECS)
            .collect();
        let range = TimeRange { start, end: at };
        let valid_to = at.saturating_add(window.window_secs);
        let goal_velocity = put_signal_in_txn(
            self,
            txn,
            subject,
            Signal {
                predicate: GOAL_VELOCITY,
                value: ratio(completed.len(), window.expected_goal_completions),
                target: window.expected_goal_completions,
                refs: if completed.is_empty() {
                    &owned
                } else {
                    &completed
                },
            },
            range,
            valid_to,
        )?;
        let spoken: Vec<EntityId> = turns.iter().map(|(_, turn)| *turn).collect();
        let engagement = put_signal_in_txn(
            self,
            txn,
            subject,
            Signal {
                predicate: ENGAGEMENT,
                value: ratio(days.len(), window.expected_engaged_days),
                target: window.expected_engaged_days,
                refs: &spoken,
            },
            range,
            valid_to,
        )?;
        let claim = self.derive_state_index_in_txn(
            txn,
            subject,
            &StateIndexEvidence {
                vad_turns,
                goal_velocity,
                engagement,
            },
            at,
        )?;
        let index = self.state_index_in_txn(txn, subject, at)?;
        Ok(Some((claim, index)))
    }
}

/// The live TURNs in `[start, at]` the subject spoke in, newest first, with
/// their occurrence time. Only a message the subject authored counts: a
/// room's other speakers never add to this subject's engagement or affect.
fn subject_turns_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
    start: u64,
    at: u64,
) -> Result<Vec<(u64, EntityId)>> {
    let query = TimelineQuery {
        axis: TimeAxis::OccurredStart,
        start: Bound::Included(start),
        end: Bound::Included(at),
        after: None,
        reverse: true,
    };
    let mut turns = Vec::new();
    for row in vault
        .store
        .port_entity_timeline(rtxn, query)?
        .take(MAX_WINDOW_ROWS)
    {
        let row = row?;
        if !matches!(
            crate::vault::live_entity_row_in_txn(&vault.store, rtxn, &row.id)?,
            LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_TURN,
                ..
            }
        ) {
            continue;
        }
        if spoke_in(vault, rtxn, subject, &row.id)? {
            turns.push((row.timestamp, row.id));
        }
    }
    Ok(turns)
}

/// Whether a live message of `turn` names the subject as its author.
fn spoke_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
    turn: &EntityId,
) -> Result<bool> {
    for message in vault
        .store
        .port_edge_peers(rtxn, turn, EdgeDirection::In, EdgeKind::PartOf)?
    {
        let message = message?;
        if vault
            .store
            .port_edge_get(rtxn, &message, EdgeKind::AuthoredBy, subject)?
            .is_some()
            && matches!(
                crate::vault::live_entity_row_in_txn(&vault.store, rtxn, &message)?,
                LiveEntityRow::Live { .. }
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every TASK the subject provably owns (the owner index is rechecked
/// against the task's authority fold), and those completed in `[start, at]`.
fn goal_tasks_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
    start: u64,
    at: u64,
) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
    let mut owned = Vec::new();
    let mut completed = Vec::new();
    for task in crate::task_verb::indexed_tasks_of_in(&vault.store, rtxn, subject)? {
        // A forked or unprovable authority is no task this subject owns.
        if !vault
            .task_authority_state_in(rtxn, task)
            .ok()
            .flatten()
            .is_some_and(|state| state.owner_ref == *subject)
        {
            continue;
        }
        owned.push(task);
        if crate::task_verb::completed_task_at_in_txn(vault, rtxn, task)?
            .is_some_and(|finished| start <= finished && finished <= at)
        {
            completed.push(task);
        }
    }
    Ok((owned, completed))
}

/// `count / expected`, capped at 1.
fn ratio(count: usize, expected: u32) -> f32 {
    ((count as f64) / f64::from(expected)).min(1.0) as f32
}

struct Signal<'a> {
    predicate: &'a str,
    value: f32,
    target: u32,
    refs: &'a [EntityId],
}

/// One measured signal as an observed claim, keyed by its own bytes: the
/// same measurement twice is one claim.
fn put_signal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    signal: Signal<'_>,
    window: TimeRange,
    valid_to: u64,
) -> Result<EntityId> {
    let mut body = ClaimBody::new(
        signal.predicate,
        ClaimSubject::Entity(*subject),
        Value::F32(signal.value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    body.valid_from = Some(window.end);
    body.valid_to = Some(valid_to);
    body.evidence = Some(Value::Map(vec![
        (Value::from("window_start"), Value::from(window.start)),
        (Value::from("window_end"), Value::from(window.end)),
        (Value::from("target"), Value::from(signal.target)),
        (
            Value::from("refs"),
            Value::Array(
                signal
                    .refs
                    .iter()
                    .take(MAX_SIGNAL_REFS)
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
        ),
    ]));
    let bytes = encode_claim_body(&body)?;
    let id =
        crate::codebase::entity_id_from_hash_material(b"oneiron:state-index-signal:v1", &[&bytes])?;
    if vault.get_claim_in_txn(txn, &id)?.is_none() {
        vault.put_claim_in_txn(txn, &id, &body, window, window.end)?;
    }
    Ok(id)
}

fn invalid() -> Error {
    Error::InvalidClaimBody("invalid state index window")
}
