//! Projection of judged amendments — attributed shares into the shared
//! `learning.edit_cost` cells, the skill's reliability record, actor lessons —
//! and their retraction.

use std::collections::BTreeMap;

use super::cells::{charge_judgment_in_txn, charges_subject, withdraw_receipt_in_txn};
use super::evidence_judge::{amendment_judgment_in_txn, amendment_judgments_in_txn};
use super::stored::{ROW_VERSION, StoredTarget, TARGET, TARGET_ROW_LABEL, TargetKey, hex_entity};
use super::taxonomy::{AmendmentClass, AmendmentJudgment};
use crate::Vault;
use crate::actor_claims::{
    ActorClaimEvidence, ActorClaimRow, PREDICATE_ACTOR_LESSON, ground_actor_claim,
    write_actor_claim_in_txn,
};
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::PREDICATE_LEARNING_EDIT_COST;
use crate::ports::EntityStoreRead;
use crate::side_table::HexId;
use crate::skill_reliability::{AmendedOutcome, reconcile_amended_outcomes_in_txn};
use crate::temporal::TimeRange;

// ---------------------------------------------------------------------------
// The edit-cost write door
// ---------------------------------------------------------------------------

/// Lands each judged amendment's attributed shares in the shared
/// `learning.edit_cost` cells, returning the cell heads this pass stands on.
///
/// **Judgments, never deltas.** The argument type is the guard the ticket asks
/// for: there is no path from a raw `d_norm` to a cell that does not pass a
/// class first.
///
/// **Every judgment is re-grounded, not trusted.** [`AmendmentJudgment`] is a
/// public type with public fields and this function feeds projector-only
/// state, so a row counts only if it IS the row this module persisted for that
/// receipt (the ONE-1738/ONE-1739 posture), checked under the writer that
/// lands its evidence. Ungrounded rows are SKIPPED rather than fatal — one
/// forged row must not deny a whole pass.
///
/// **One family, one write path** (FIX 9797). Each charging share is one
/// evidence row per receipt per cell: the subject's cell at its executor, in
/// the receipt's consent scope and task type. The learning projector
/// recomputes the cell's estimate — mean edit mass and spread, own runs,
/// prior, labels with the untouched / amended / rejected counts, window and
/// estimator version — from every row the cell holds, so a replay overwrites
/// its own rows and the pass is idempotent. No parallel scalar head is kept.
///
/// **Every pass reconciles before it writes.** The judgment ledger is
/// overwrite-by-receipt, so a re-judgment can move a receipt off the subject
/// it used to charge — and nothing in the new judgment names the old one. The
/// subjects each receipt has charged are therefore kept as their own ledger,
/// and a receipt's evidence on a subject no judgment charges any more is
/// WITHDRAWN here. A re-judgment onto another executor, scope or task type
/// moves the receipt's row off the old cell as it lands the new one.
///
/// # Errors
///
/// Storage errors, and whatever the learning door refuses.
pub fn project_edit_cost_claims(
    vault: &Vault,
    judgments: &[AmendmentJudgment],
) -> Result<Vec<EntityId>> {
    retract_unsupported_targets(vault)?;
    vault.with_write_txn_grouped(|wtxn| {
        let mut heads = Vec::new();
        for judgment in judgments {
            // Grounded is not authorization: this row must also BE the row
            // this module routed for that receipt.
            if amendment_judgment_in_txn(vault, wtxn, &judgment.receipt_id)?.as_ref()
                != Some(judgment)
            {
                continue;
            }
            for cell in charge_judgment_in_txn(vault, wtxn, judgment)? {
                for (head, _, _) in
                    crate::learning::project::active_heads_in_txn(vault, wtxn, &cell)?
                {
                    if !heads.contains(&head) {
                        heads.push(head);
                    }
                }
            }
        }
        Ok(heads)
    })
}

// ---------------------------------------------------------------------------
// skill_defect → skill.reliability
// ---------------------------------------------------------------------------

/// Lands each judged amendment's `skill_defect` share on the reliability record
/// of the attempt whose proposal was amended, returning the skills whose
/// `skill.reliability` was reprojected (ARCH-0056 §5).
///
/// **One record per attempt, the later verdict holding.** The attempt already
/// has an outcome row in the skill's ledger, often a contributing win. The
/// amendment is a later verdict on that same attempt, so it REPLACES the row
/// rather than adding a loss beside it: the attempt counts once, as a loss
/// weighted by the defect share. Two amendments of one attempt leave the later
/// one standing. A later amendment that charges the skill nothing hands the
/// attempt back its own record.
///
/// The join is the attempt the evidence named when the amendment was judged,
/// grounded at the door and kept on the judgment row. An amendment judged
/// without one names no attempt, so its share reaches `learning.edit_cost`
/// alone.
///
/// Recomputed from the whole judgment ledger on every pass, like the cost rows,
/// and in ONE write transaction with the rows it derives: a re-judged or
/// withdrawn amendment takes its share back on the next pass, a pass that read
/// an older ledger cannot land over a newer one, and a pass with nothing new
/// reprojects nothing.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn project_amendment_reliability(vault: &Vault) -> Result<Vec<EntityId>> {
    vault.with_write_txn_grouped(|wtxn| {
        let mut verdicts = Vec::new();
        for (judgment, attempt) in amendment_judgments_in_txn(vault, wtxn)? {
            let Some((attempt_receipt, skill)) = attempt else {
                continue;
            };
            // A verdict that charges this skill nothing is still a verdict on
            // the attempt: it is what lets a later amendment stand over an
            // earlier one.
            let defect_share = judgment
                .split
                .iter()
                .filter(|share| {
                    share.class == AmendmentClass::SkillDefect && share.subject == Some(skill)
                })
                .map(|share| share.share)
                .sum();
            verdicts.push(AmendedOutcome {
                skill,
                attempt_receipt,
                amendment_receipt: judgment.receipt_id,
                defect_share,
                at: judgment.at,
            });
        }
        reconcile_amended_outcomes_in_txn(vault, wtxn, &verdicts)
    })
}

// ---------------------------------------------------------------------------
// execution_lapse → actor.lesson
// ---------------------------------------------------------------------------

/// Lands one `actor.lesson` per judged amendment whose split charges the actor
/// an `execution_lapse` share, citing that amendment's receipt, and returns the
/// lesson ids (ARCH-0056 §5).
///
/// A lesson is a SET row with no weight, so the share does not size it: any
/// lapse share records the lapse, once. The entry names the label and the
/// amendment receipt, `execution_lapse:<receipt>` — the receipt resolves the Δ,
/// which is what the decider corrected, and the engine writes no prose about it
/// (a distiller may turn the entry into one later). Naming the receipt is also
/// what keeps two lapses two entries: the SET key is the note, so one bare
/// token would fold every lapse into the first.
///
/// Every judgment is re-grounded, not trusted: a row counts only if it IS the
/// row this module persisted for that receipt, checked again under the writer
/// that lands the lesson and its retraction target together, so a re-judgment
/// cannot slip between the check and the lesson. Every pass reconciles first,
/// so an amendment judged again without its lapse share retracts the lesson it
/// earned. A replay re-returns the standing lesson rather than writing another.
/// An ungrounded row is skipped rather than fatal to the pass.
///
/// # Errors
///
/// Storage errors, and whatever the `actor.*` write door rejects.
pub fn project_amendment_lessons(
    vault: &Vault,
    judgments: &[AmendmentJudgment],
) -> Result<Vec<EntityId>> {
    retract_unsupported_targets(vault)?;
    let mut written = Vec::new();
    for judgment in judgments {
        let Some(actor) = lapse_actor(judgment) else {
            continue;
        };
        let row = ActorClaimRow::Lesson {
            actor,
            text: lapse_lesson(&judgment.receipt_id),
        };
        let Ok(evidence) = ActorClaimEvidence::amendment(
            judgment.evidence_receipts.clone(),
            judgment.engine_ver.clone(),
            judgment.at,
        ) else {
            continue;
        };
        // The door's own reads, before the writer opens.
        if ground_actor_claim(vault, &row, &evidence).is_err() {
            continue;
        }
        let landed = vault.with_write_txn_grouped(|wtxn| {
            if amendment_judgment_in_txn(vault, wtxn, &judgment.receipt_id)?.as_ref()
                != Some(judgment)
            {
                return Ok(None);
            }
            let receipt = judgment.receipt_id.as_str();
            record_target_in_txn(vault, wtxn, PREDICATE_ACTOR_LESSON, &actor, receipt)?;
            write_actor_claim_in_txn(vault, wtxn, &row, &evidence).map(Some)
        })?;
        written.extend(landed);
    }
    Ok(written)
}

/// The actor an amendment's `execution_lapse` share charges, if it charges one.
fn lapse_actor(judgment: &AmendmentJudgment) -> Option<EntityId> {
    judgment
        .split
        .iter()
        .find(|share| share.class == AmendmentClass::ExecutionLapse && share.share > 0.0)
        .and_then(|share| share.subject)
}

/// The lesson entry a lapse on `receipt` leaves: the label, then the receipt.
fn lapse_lesson(receipt: &str) -> String {
    format!("{}:{receipt}", AmendmentClass::ExecutionLapse.as_str())
}

// ---------------------------------------------------------------------------
// The landed-target ledger (retraction)
// ---------------------------------------------------------------------------

/// Records that this projector holds a live row for `(predicate, subject,
/// scope)` in the caller's transaction, so a later pass can find it again
/// after the judgments that earned it have moved elsewhere. Both kinds key on
/// the receipt they were learned from: a `learning.edit_cost` target's scope
/// is the receipt whose evidence the subject's cell holds, an `actor.lesson`
/// target's is the amendment receipt.
pub(super) fn record_target_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    predicate: &'static str,
    subject: &EntityId,
    scope: &str,
) -> Result<()> {
    let row = StoredTarget {
        v: ROW_VERSION,
        predicate: predicate.to_owned(),
        subject: subject.to_hex(),
        scope: scope.to_owned(),
    };
    TARGET.put(
        &vault.store,
        wtxn,
        &target_key(predicate, subject, scope),
        &row,
    )?;
    Ok(())
}

/// Every tuple this projector has landed a head for, on the caller's snapshot.
fn recorded_targets_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(&'static str, EntityId, String)>> {
    let mut out = Vec::new();
    for (_, row) in TARGET.scan(&vault.store, txn)? {
        let predicate = known_target_predicate(&row.predicate)
            .ok_or(Error::CorruptedIndex(TARGET_ROW_LABEL))?;
        out.push((
            predicate,
            hex_entity(&row.subject, TARGET_ROW_LABEL)?,
            row.scope,
        ));
    }
    Ok(out)
}

/// Withdraws every landed row the judgment ledger no longer supports.
///
/// A receipt re-judged onto another class or subject, or withdrawn, orphans
/// what it was holding up: without this the old charge would stand in the
/// subject's cell forever, and an old lesson would keep standing. A lesson is
/// retracted, not deleted, so it stays readable as history; an edit-cost row
/// is withdrawn from its cell, which the learning projector recomputes.
///
/// Support is read first and decided again under the writer that retracts: a
/// pass with nothing to withdraw — the common case — costs no write
/// transaction, and a tuple a concurrent pass has just earned is not retracted
/// on a stale read.
fn retract_unsupported_targets(vault: &Vault) -> Result<()> {
    {
        let rtxn = vault.store.env.read_txn()?;
        if unsupported_targets_in_txn(vault, &rtxn)?.is_empty() {
            return Ok(());
        }
    }
    let now = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|wtxn| {
        for (predicate, subject, scope) in unsupported_targets_in_txn(vault, wtxn)? {
            retract_target_in_txn(vault, wtxn, predicate, &subject, &scope, now)?;
        }
        Ok(())
    })
}

/// The landed tuples no persisted judgment supports any more.
fn unsupported_targets_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(&'static str, EntityId, String)>> {
    let persisted: BTreeMap<String, AmendmentJudgment> = amendment_judgments_in_txn(vault, txn)?
        .into_iter()
        .map(|(judgment, _)| (judgment.receipt_id.clone(), judgment))
        .collect();
    let mut unsupported = recorded_targets_in_txn(vault, txn)?;
    // Both kinds of target key on the receipt they were learned from.
    unsupported.retain(|(predicate, subject, scope)| {
        let judgment = persisted.get(scope);
        if *predicate == PREDICATE_ACTOR_LESSON {
            judgment.is_none_or(|row| lapse_actor(row) != Some(*subject))
        } else {
            judgment.is_none_or(|row| !charges_subject(row, subject))
        }
    });
    Ok(unsupported)
}

/// Withdraws one tuple's rows and forgets the tuple, in the caller's
/// transaction.
///
/// An edit-cost target withdraws its receipt's evidence from every
/// `learning.edit_cost` cell of the subject. A lesson target retracts its
/// active heads: the `actor.*` namespace owns its own lifecycle mechanics —
/// the generic [`crate::Vault::retract_claim`] refuses a reserved predicate by
/// design — so the closed body is re-put through the same engine-owned door
/// that wrote it, exactly as the reserved supersession path does.
fn retract_target_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    predicate: &'static str,
    subject: &EntityId,
    scope: &str,
    now: u64,
) -> Result<()> {
    if predicate == PREDICATE_LEARNING_EDIT_COST {
        withdraw_receipt_in_txn(vault, wtxn, subject, scope, None, now)?;
        TARGET.delete(&vault.store, wtxn, &target_key(predicate, subject, scope))?;
        return Ok(());
    }
    let heads = active_lesson_heads_in_txn(vault, wtxn, subject, &lapse_lesson(scope))?;
    for (id, mut body) in heads {
        let header = {
            let Some(raw) = vault
                .store
                .port_entity_record(&*wtxn, &id)?
                .map(|row| row.encode())
            else {
                continue;
            };
            EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("edit cost claim entity"))?
        };
        // The clamp mirrors the supersession path: a withdrawal stamped
        // BEFORE the row it closes would make the re-Put range invalid and
        // roll the whole transaction back.
        let at = now.max(header.occurred_start);
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(at);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &id,
            &body,
            TimeRange {
                start: header.occurred_start,
                end: at,
            },
            header.learned_at,
        )?;
    }
    TARGET.delete(&vault.store, wtxn, &target_key(predicate, subject, scope))?;
    Ok(())
}

/// The key of one landed tuple. The scope goes LAST: it is the only field a
/// caller supplies, so nothing it can contain shifts another.
fn target_key(predicate: &str, subject: &EntityId, scope: &str) -> TargetKey {
    TargetKey {
        predicate: predicate.to_owned(),
        subject: HexId(*subject),
        scope: scope.to_owned(),
    }
}

/// The `'static` predicate a stored token names, if it names one this
/// projector lands.
fn known_target_predicate(token: &str) -> Option<&'static str> {
    [PREDICATE_LEARNING_EDIT_COST, PREDICATE_ACTOR_LESSON]
        .into_iter()
        .find(|predicate| *predicate == token)
}

/// The active `actor.lesson` heads of `actor` that carry exactly `text`.
fn active_lesson_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor: &EntityId,
    text: &str,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut heads = Vec::new();
    for id in vault.claims_for_subject_in_txn(rtxn, actor)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_ACTOR_LESSON
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.source != Some(ClaimSource::Observed)
            || body.approval != ClaimApprovalStatus::Auto
            || body.value.as_str() != Some(text)
        {
            continue;
        }
        heads.push((id, body));
    }
    Ok(heads)
}
