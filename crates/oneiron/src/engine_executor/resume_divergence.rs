//! One run's resume-divergence ask and the owner's answer to it (L8-23): a resumed pending step
//! whose re-entered program changed an effect step holds with its walk's report, and the hold asks
//! the owner once whether to re-fire the changed effect steps or leave them. The next entry applies
//! the answer.
//!
//! A run has at most one pending step, so at most one ask: one row per run, keyed by the run id,
//! holding the step, the report, the report's effect digest, when asked and the answer. A hold
//! whose step and digest match the row's unanswered ask asks nothing again; a hold an answer did
//! not clear asks again. An answer records only when the row still waits on that step and digest;
//! anything else finds the ask settled. The ask's inbox rows offer the answer verb's two taps.
//! Entry: `raise_resume_divergence_ask_in_txn`, `Vault::answer_code_run_resume_divergence`.

use serde::{Deserialize, Serialize};

use super::ResumePreflightReport;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::side_table::{self, Named, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use oneiron_verb_wire::verbs::code_run_resume_divergence::ResumeDivergenceAnswerOutcome;

pub(crate) use oneiron_verb_wire::verbs::code_run_resume_divergence::ResumeDivergenceChoice;

/// Producer name of a resume-divergence owner ask (L8-23).
pub(crate) const RESUME_DIVERGENCE_NOTIFICATION_PRODUCER: &str = "code_run.resume_divergence";

/// The verb the ask's taps call (L8-23).
pub(crate) const RESUME_DIVERGENCE_ANSWER_VERB: &str = "vault.code_run.resume_divergence.answer";

/// One run's resume-divergence ask (L8-23): the held step, what its walk met, and the owner's
/// answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResumeDivergenceAsk {
    /// The held step's seq.
    pub(crate) step_seq: u64,
    /// The hold's walk report, for the next entry's entry-by-entry approval.
    pub(crate) report: ResumePreflightReport,
    /// The report's effect digest, cached so a hold asks once per drift.
    pub(crate) effect_digest: String,
    /// When the ask was raised, vault clock seconds: part of its identity.
    pub(crate) asked_at: u64,
    /// The owner's answer; `None` while it waits.
    pub(crate) answer: Option<ResumeDivergenceChoice>,
}

/// Every run's resume-divergence ask, by run id (L8-23). Only this module writes it.
const ASKS: SideTable<EntityId, ResumeDivergenceAsk, Named> =
    SideTable::new(&side_table::CODE_RUN_RESUME_DIVERGENCE);

/// The ask's identity for `owner` (L8-23): the run, the step, the effect digest, when asked, the
/// owner.
pub(crate) fn resume_divergence_ask_source(
    run: EntityId,
    step_seq: u64,
    effect_digest: &str,
    asked_at: u64,
    owner: EntityId,
) -> NotificationSource {
    let run_hex = run.to_hex();
    let owner_hex = owner.to_hex();
    NotificationSource {
        producer: RESUME_DIVERGENCE_NOTIFICATION_PRODUCER.to_owned(),
        event: format!("{run_hex}:{step_seq}:{effect_digest}:{asked_at}:{owner_hex}"),
        result: Some(run_hex),
        ..NotificationSource::default()
    }
}

/// The run, step and effect digest an ask of this producer names (L8-23), read from its `result`
/// and `event`; `None` for any other shape.
pub(crate) fn resume_divergence_ask_target(
    source: &NotificationSource,
) -> Option<(EntityId, u64, String)> {
    let run = EntityId::from_hex(source.result.as_deref()?).ok()?;
    let run_hex = run.to_hex();
    let mut parts = source.event.split(':');
    if parts.next()? != run_hex.as_str() {
        return None;
    }
    let step_seq = parts.next()?.parse::<u64>().ok()?;
    let digest = parts.next()?;
    let valid = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !valid {
        return None;
    }
    parts.next()?.parse::<u64>().ok()?;
    EntityId::from_hex(parts.next()?).ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((run, step_seq, digest.to_owned()))
}

/// The ask's words (L8-23): the walk's report line and the two choices, never a request body.
fn resume_divergence_ask_detail(report: &ResumePreflightReport) -> String {
    format!("{report} Re-fire the changed effect steps once, or leave them?")
}

/// One run's resume-divergence ask, read in `txn` (L8-23).
pub(crate) fn read_resume_divergence_ask_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
) -> Result<Option<ResumeDivergenceAsk>> {
    ASKS.get(&vault.store, txn, &run)
}

/// Raises the owner's ask on `report`'s drift, in the caller's writer (L8-23): a hold whose step
/// and digest match the run's unanswered ask asks nothing again; any other hold, an answered one
/// included, clears the old row's ask rows, puts the new row unanswered, and records one inbox ask
/// per live owner. The run id is no live entity, so the ask names no subject.
pub(crate) fn raise_resume_divergence_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    run: EntityId,
    report: &ResumePreflightReport,
) -> Result<()> {
    let digest = report.effect_digest();
    if let Some(known) = ASKS.get(&vault.store, &*wtxn, &run)? {
        // An answered ask whose drift holds again did not apply (a refire the walk could not
        // run live): the owner is asked again.
        if known.step_seq == report.step_seq
            && known.effect_digest == digest
            && known.answer.is_none()
        {
            return Ok(());
        }
        clear_resume_divergence_ask_in_txn(
            vault,
            wtxn,
            run,
            known.step_seq,
            &known.effect_digest,
            known.asked_at,
        )?;
    }
    let asked_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    ASKS.put(
        &vault.store,
        wtxn,
        &run,
        &ResumeDivergenceAsk {
            step_seq: report.step_seq,
            report: report.clone(),
            effect_digest: digest.clone(),
            asked_at,
            answer: None,
        },
    )?;
    let detail = resume_divergence_ask_detail(report);
    for owner in crate::policy_model::owners_in_txn(vault, &*wtxn)? {
        vault.record_notification_in_txn(
            wtxn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    detail: Some(detail.clone()),
                    ..resume_divergence_ask_source(run, report.step_seq, &digest, asked_at, owner)
                },
                subject_refs: Vec::new(),
                recipient: Some(owner),
                created_at: asked_at,
                origin_conversation: None,
            },
        )?;
    }
    Ok(())
}

/// Marks the ask raised at `asked_at` on `run`'s step and digest seen and acked for each live
/// owner, in the caller's write (L8-23): an answered or replaced ask offers no tap any more.
fn clear_resume_divergence_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    run: EntityId,
    step_seq: u64,
    effect_digest: &str,
    asked_at: u64,
) -> Result<()> {
    for owner in crate::policy_model::owners_in_txn(vault, &*wtxn)? {
        let ask = crate::inbox::notification_id(&resume_divergence_ask_source(
            run,
            step_seq,
            effect_digest,
            asked_at,
            owner,
        ))?;
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*wtxn, &ask)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = crate::inbox::decode_notification_body(&body)?;
        let Some(recipient) = body.recipient.clone() else {
            continue;
        };
        if body.acked_by.get(&recipient) == Some(&true) {
            continue;
        }
        body.seen_by.insert(recipient.clone(), true);
        body.acked_by.insert(recipient, true);
        vault.put_notification_in_txn(wtxn, &ask, &body)?;
    }
    Ok(())
}

impl Vault {
    /// The owner's answer to the ask a resumed pending step raised (L8-23): `refire` releases the
    /// changed effect steps to run live once at their own seqs, which the run does at its next
    /// entry; `leave` makes them answer the step `effect_changed_left`, and the run goes on without
    /// them. The proof is the vault owner's, rechecked in the writer; the first answer settles the
    /// ask and clears its rows, and a later one finds it settled.
    ///
    /// # Errors
    ///
    /// A proof that is not a live owner's.
    pub fn answer_code_run_resume_divergence(
        &self,
        owner: &AuthenticatedOwner,
        run: EntityId,
        step_seq: u64,
        effect_digest: &str,
        choice: ResumeDivergenceChoice,
    ) -> Result<ResumeDivergenceAnswerOutcome> {
        self.with_write_txn_grouped(|wtxn| {
            owner.revalidate_in_txn(self, &*wtxn)?;
            let Some(mut answered) = ASKS.get(&self.store, &*wtxn, &run)? else {
                return Ok(ResumeDivergenceAnswerOutcome::AlreadySettled);
            };
            if answered.step_seq != step_seq
                || answered.effect_digest.as_str() != effect_digest
                || answered.answer.is_some()
            {
                return Ok(ResumeDivergenceAnswerOutcome::AlreadySettled);
            }
            answered.answer = Some(choice);
            ASKS.put(&self.store, wtxn, &run, &answered)?;
            clear_resume_divergence_ask_in_txn(
                self,
                wtxn,
                run,
                step_seq,
                effect_digest,
                answered.asked_at,
            )?;
            Ok(match choice {
                ResumeDivergenceChoice::Refire => ResumeDivergenceAnswerOutcome::RefireReleased,
                ResumeDivergenceChoice::Leave => ResumeDivergenceAnswerOutcome::Left,
            })
        })
    }

    /// Whether the ask on `run`'s step `step_seq` and `effect_digest` waits for the owner's answer
    /// now (L8-23), read in `txn`: the inbox offers the ask's taps only then.
    pub(crate) fn resume_divergence_awaits_owner_in(
        &self,
        txn: &heed::RoTxn<'_>,
        run: EntityId,
        step_seq: u64,
        effect_digest: &str,
    ) -> Result<bool> {
        Ok(ASKS.get(&self.store, txn, &run)?.is_some_and(|ask| {
            ask.step_seq == step_seq
                && ask.effect_digest.as_str() == effect_digest
                && ask.answer.is_none()
        }))
    }
}
