//! The due-refresh pump and its scheduling helpers (FIX 8914, pure moves from `refresh.rs`).

use super::super::arrival;
use super::super::backfill::{BackfillAtKey, QUESTION_BACKFILL_AT};
use super::super::graph_ask::GraphAnswerer;
use super::super::records::{ARTIFACT_ADAPTER, QuestionRecord, RefreshTrigger};
use super::super::store::*;
use super::asker;
use super::calls::graph_proposal;
use super::execution::refresh_with;
use super::{FAILED_REFRESH_HOLD_SECS, RefreshBatch, RefreshFailure};
use crate::llm::decision::{AskRoleResolver, AskTo, HolderKind};
use crate::side_table::SideKey;
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// The run's writer for `to`: the first live holder of the first role on its
/// chain that has one, a person as a human and a bound agent as an agent.
pub(super) fn role_runner(vault: &Vault, to: &AskTo) -> Result<WriteActor> {
    let holder = vault
        .next_role(to, None)?
        .and_then(|role| role.holders.into_iter().next())
        .ok_or_else(|| {
            Error::InvalidConfig(
                "no live holder up to the vault's owners runs this standing question".into(),
            )
        })?;
    Ok(WriteActor::new(
        holder.actor,
        match holder.kind {
            HolderKind::Person => crate::EdgeActorClass::Human,
            HolderKind::Agent => crate::EdgeActorClass::Agent,
        },
    ))
}

/// Every due question, run by the writer `runner` names for its principal,
/// through the answerer `answerer_for` makes once per question, until
/// `may_start` says no before one starts (FIX 7376).
pub(super) fn refresh_due_as<A: GraphAnswerer>(
    vault: &Vault,
    now: u64,
    may_start: &mut impl FnMut() -> bool,
    mut runner: impl FnMut(EntityId) -> Result<WriteActor>,
    mut answerer_for: impl FnMut(&QuestionRecord, WriteActor) -> Result<A>,
) -> Result<RefreshBatch> {
    let mut batch = RefreshBatch::default();
    for (principal, question, trigger) in due_work(vault, now)? {
        if !may_start() {
            break;
        }
        let answered = runner(principal).and_then(|chosen| {
            let mut answerer: Option<A> = None;
            let writer = asker::RefreshWriter::Runner(chosen);
            refresh_with(
                vault,
                writer,
                principal,
                question,
                trigger,
                now,
                &mut |record, unit, kind, body| {
                    if answerer.is_none() {
                        answerer = Some(answerer_for(record, writer.for_record(record))?);
                    }
                    let answerer = answerer.as_mut().expect("made above");
                    graph_proposal(vault, record, answerer, unit, kind, body)
                },
            )
        });
        match answered {
            Ok(answers) => batch.answers.extend(answers),
            Err(error) => {
                hold_failed(vault, question, now);
                batch.failures.push(RefreshFailure {
                    question,
                    trigger,
                    error,
                });
            }
        }
    }
    Ok(batch)
}

/// Holds a failed question's work until [`FAILED_REFRESH_HOLD_SECS`] after
/// `now`. A hold that cannot be written leaves the question due: the failure
/// is already the caller's to report.
pub(in crate::llm::decision::questions) fn hold_failed(
    vault: &Vault,
    question: EntityId,
    now: u64,
) {
    let held = vault.with_write_txn_grouped(|txn| {
        let Some(mut head) = QUESTION_HEAD.get(&vault.store, txn, &HeadKey(question))? else {
            return Ok(());
        };
        head.retry_at = Some(now.saturating_add(FAILED_REFRESH_HOLD_SECS));
        QUESTION_HEAD.put(&vault.store, txn, &HeadKey(question), &head)
    });
    if let Err(error) = held {
        tracing::warn!(kind = ?error.kind(), "a failed standing question was not held");
    }
}

impl Vault {
    /// When the next standing question falls due, in unix seconds; `None`
    /// when none has work. A past instant is due now. Paused questions,
    /// arrivals on a unit awaiting its owner's answer and questions inside a
    /// failure's hold arm nothing until their hold ends or a write changes
    /// them, so a deadline timer armed from this never spins on them.
    pub fn next_question_refresh_at(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        let mut next: Option<u64> = None;
        let mut arm = |at: u64| {
            if next.is_none_or(|current| at < current) {
                next = Some(at);
            }
        };
        for row in QUESTION_HEAD.iter_raw_from(&self.store, &txn, &[])? {
            let (key, _) = row?;
            let Some(HeadKey(id)) = HeadKey::decode_key(&key) else {
                continue;
            };
            let Some(head) = QUESTION_HEAD.get(&self.store, &txn, &HeadKey(id))? else {
                continue;
            };
            if head.paused {
                continue;
            }
            let record = QUESTION_VERSION
                .get(
                    &self.store,
                    &txn,
                    &VersionKey {
                        id,
                        version: head.version,
                    },
                )?
                .ok_or(Error::CorruptedIndex("question version"))?;
            // An artifact question's asks are polled by its own pump.
            if record.definition.adapter == ARTIFACT_ADAPTER {
                continue;
            }
            if let Some(interval) = record.definition.refresh.every_seconds {
                let due = head
                    .last_refresh
                    .unwrap_or(record.created_at)
                    .saturating_add(interval);
                arm(due.max(head.retry_at.unwrap_or(0)));
            }
            if let Some(backfill) =
                QUESTION_BACKFILL_AT.get(&self.store, &txn, &BackfillAtKey(id))?
                && backfill.version == head.version
            {
                arm(backfill.due_at.max(head.retry_at.unwrap_or(0)));
            }
        }
        for row in arrival::PENDING.iter_from(&self.store, &txn, &[])? {
            let ((question, unit), _) = row?;
            let Some(head) = QUESTION_HEAD.get(&self.store, &txn, &HeadKey(question))? else {
                continue;
            };
            if head.paused {
                continue;
            }
            let Some(record) = QUESTION_VERSION.get(
                &self.store,
                &txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
            )?
            else {
                continue;
            };
            // A held unit keeps its marker; its owner's answer is a claim
            // write, which wakes the timer again.
            if !record.definition.refresh.on_arrival
                || !record.definition.units.contains(&unit)
                || !crate::gate::claim_consolidation_eligible_in_txn(
                    &self.store,
                    &txn,
                    &unit,
                    crate::gate::ConsolidationReader::QuestionRefreshSource,
                )?
            {
                continue;
            }
            arm(head.retry_at.unwrap_or(0));
        }
        Ok(next)
    }
}

/// The scheduled, backfill and materialized-arrival work due at `now`, with
/// each question's principal. A question's arrivals wait while its scheduled
/// refresh or backfill runs.
pub(super) fn due_work(
    vault: &Vault,
    now: u64,
) -> Result<Vec<(EntityId, EntityId, RefreshTrigger)>> {
    let work = {
        let txn = vault.store.env.read_txn()?;
        let mut work = Vec::new();
        // Four row families share the declaration; decode only exact head keys.
        for row in QUESTION_HEAD.iter_raw_from(&vault.store, &txn, &[])? {
            let (key, _) = row?;
            let Some(HeadKey(id)) = HeadKey::decode_key(&key) else {
                continue;
            };
            let Some(head) = QUESTION_HEAD.get(&vault.store, &txn, &HeadKey(id))? else {
                continue;
            };
            if head.paused || head.retry_at.is_some_and(|at| at > now) {
                continue;
            }
            let record = QUESTION_VERSION
                .get(
                    &vault.store,
                    &txn,
                    &VersionKey {
                        id,
                        version: head.version,
                    },
                )?
                .ok_or(Error::CorruptedIndex("question version"))?;
            if record.definition.adapter == ARTIFACT_ADAPTER {
                continue;
            }
            if let Some(interval) = record.definition.refresh.every_seconds
                && now
                    >= head
                        .last_refresh
                        .unwrap_or(record.created_at)
                        .saturating_add(interval)
            {
                // A scheduled refresh answers every unit, so a due backfill
                // waits a pass and then finds nothing left to answer.
                work.push((record.principal, id, RefreshTrigger::Schedule));
            } else if let Some(backfill) =
                QUESTION_BACKFILL_AT.get(&vault.store, &txn, &BackfillAtKey(id))?
                && backfill.version == head.version
                && backfill.due_at <= now
            {
                work.push((record.principal, id, RefreshTrigger::Backfill));
            }
        }
        for row in arrival::PENDING.iter_from(&vault.store, &txn, &[])? {
            let ((question, unit), _) = row?;
            let Some(head) = QUESTION_HEAD.get(&vault.store, &txn, &HeadKey(question))? else {
                continue;
            };
            if head.paused || head.retry_at.is_some_and(|at| at > now) {
                continue;
            }
            let Some(record) = QUESTION_VERSION.get(
                &vault.store,
                &txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
            )?
            else {
                continue;
            };
            if !work.iter().any(|(_, id, trigger)| {
                *id == question
                    && matches!(trigger, RefreshTrigger::Schedule | RefreshTrigger::Backfill)
            }) {
                work.push((record.principal, question, RefreshTrigger::Arrival(unit)));
            }
        }
        work
    };
    Ok(work)
}
