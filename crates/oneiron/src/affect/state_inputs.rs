//! Live, subject-bound observations feeding the composite state index.

use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::state_index::{ENGAGEMENT, GOAL_VELOCITY, StateIndex, StateIndexEvidence};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::{EdgeKind, EntityId, Error, Result, TimeRange, Vault};

const UTC_DAY_SECS: u64 = 86_400;

/// The host selects the goal work set and turn history; this grants no authority.
/// Targets describe this observation window, not a clinical or population norm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateIndexSources {
    #[serde(with = "crate::serialize::entity_ref::sequence")]
    pub turns: Vec<EntityId>,
    /// Live typed TASKs owned by the subject, selected for its goals/behavior.
    #[serde(with = "crate::serialize::entity_ref::sequence")]
    pub goal_tasks: Vec<EntityId>,
    pub window_secs: u64,
    pub expected_goal_completions: u32,
    pub expected_engaged_days: u32,
}

impl StateIndexSources {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.window_secs == 0
            || self.expected_goal_completions == 0
            || self.expected_engaged_days == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Vault {
    /// Measure owned TASK completions and active UTC days, then blend them with
    /// the subject's admitted turn VAD. Signals, evidence and index commit together.
    /// Missing source families return an explicitly absent neutral state, not a low score.
    pub fn refresh_state_index(
        &self,
        subject: &EntityId,
        sources: &StateIndexSources,
        at: u64,
    ) -> Result<StateIndex> {
        self.with_write_txn_grouped(|txn| {
            self.refresh_state_index_in_txn(txn, subject, sources, at)
        })
    }

    pub(crate) fn refresh_state_index_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        subject: &EntityId,
        sources: &StateIndexSources,
        at: u64,
    ) -> Result<StateIndex> {
        sources.validate()?;
        let start = at.saturating_sub(sources.window_secs);
        let valid_to = at.checked_add(sources.window_secs).ok_or_else(invalid)?;
        let mut active_days = BTreeSet::new();
        let mut engagement_turns = Vec::new();
        let mut vad_turns = Vec::new();
        for turn in sources.turns.iter().copied().collect::<BTreeSet<_>>() {
            let Some(row) = self.store.port_entity_record(txn, &turn)? else {
                continue;
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_TURN
                || row.occurred.start < start
                || row.occurred.start > at
                || row.learned_at > at
                || !subject_turn_in_txn(self, txn, subject, &turn)?
            {
                continue;
            }
            active_days.insert(row.occurred.start / UTC_DAY_SECS);
            engagement_turns.push(turn);
            if self
                .turn_vad_annotation_in_txn(txn, &turn)?
                .is_some_and(|annotation| annotation.annotated_at <= at)
            {
                vad_turns.push((row.occurred.start, turn));
            }
        }
        // The existing composite accepts at most 256 VAD turns. Keep the newest
        // observations; engagement still counts the whole selected window.
        vad_turns.sort_unstable();
        let vad_turns: Vec<_> = vad_turns
            .into_iter()
            .rev()
            .take(256)
            .map(|(_, turn)| turn)
            .collect();
        let mut tasks = Vec::new();
        let mut completed = 0_u64;
        for task in sources.goal_tasks.iter().copied().collect::<BTreeSet<_>>() {
            let Some(row) = self.store.port_entity_record(txn, &task)? else {
                continue;
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_TASK
                || crate::task_verb::task_binding(&row.body).is_none()
                || row.occurred.start > at
                || row.learned_at > at
                || self.archive_tombstone_in_txn(txn, &task)?.is_some()
            {
                continue;
            }
            let owner = self.task_authority_state_in(txn, task)?;
            if owner.is_none_or(|state| state.owner_ref != *subject) {
                return Err(invalid());
            }
            tasks.push(task);
            if crate::task_verb::completed_task_at_in_txn(self, txn, task)?
                .is_some_and(|finished| start <= finished && finished <= at)
            {
                completed += 1;
            }
        }
        if vad_turns.is_empty() || tasks.is_empty() {
            self.clear_state_index_in_txn(txn, subject, at)?;
            return Ok(StateIndex::default());
        }
        let goal_velocity = put_signal_in_txn(
            self,
            txn,
            subject,
            SignalMeasurement {
                predicate: GOAL_VELOCITY,
                value: (completed as f64 / f64::from(sources.expected_goal_completions)).min(1.0)
                    as f32,
                refs: &tasks,
                target: sources.expected_goal_completions,
            },
            TimeRange { start, end: at },
            valid_to,
        )?;
        let engagement = put_signal_in_txn(
            self,
            txn,
            subject,
            SignalMeasurement {
                predicate: ENGAGEMENT,
                value: (active_days.len() as f64 / f64::from(sources.expected_engaged_days))
                    .min(1.0) as f32,
                refs: &engagement_turns,
                target: sources.expected_engaged_days,
            },
            TimeRange { start, end: at },
            valid_to,
        )?;
        self.derive_state_index_in_txn(
            txn,
            subject,
            &StateIndexEvidence {
                vad_turns,
                goal_velocity,
                engagement,
            },
            at,
        )?;
        self.state_index_in_txn(txn, subject, at)
    }
}

/// Count only visible, non-empty messages with a single subject author. A
/// room's other participants never contribute affect or engagement to this subject.
fn subject_turn_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    turn: &EntityId,
) -> Result<bool> {
    let Some(messages) =
        crate::tagging::turn_members_in_txn(vault, &vault.store, txn, turn, false)?
    else {
        return Ok(false);
    };
    let mut has_message = false;
    for (message, text, _) in messages {
        if text.is_none() {
            continue;
        }
        let authors: BTreeSet<_> = vault
            .store
            .port_edges(
                txn,
                &message,
                EdgeDirection::Out,
                Some(EdgeKind::AuthoredBy),
                None,
            )?
            .map(|edge| edge.map(|edge| edge.target))
            .collect::<Result<_>>()?;
        if authors.len() != 1 || !authors.contains(subject) {
            return Ok(false);
        }
        has_message = true;
    }
    Ok(has_message)
}

struct SignalMeasurement<'a> {
    predicate: &'a str,
    value: f32,
    refs: &'a [EntityId],
    target: u32,
}

fn put_signal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    signal: SignalMeasurement<'_>,
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
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
        ),
    ]));
    let bytes = encode_claim_body(&body)?;
    let id =
        crate::codebase::entity_id_from_hash_material(b"oneiron:state-index-signal:v1", &[&bytes])?;
    if let Some(stored) = vault.get_claim_in_txn(txn, &id)? {
        if encode_claim_body(&stored)? != bytes {
            return Err(invalid());
        }
    } else {
        vault.put_claim_in_txn(txn, &id, &body, window, window.end)?;
    }
    Ok(id)
}

fn invalid() -> Error {
    Error::InvalidClaimBody("invalid state index sources")
}
