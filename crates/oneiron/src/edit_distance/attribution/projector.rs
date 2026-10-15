//! Projection of judged amendments — edit-cost claims, the skill's reliability
//! record, actor lessons — and their retraction.

use super::evidence_judge::{
    amendment_judgment_in_txn, amendment_judgments, amendment_judgments_in_txn,
};
use super::stored::{
    MAX_CITED_RECEIPTS, ROW_VERSION, StoredTarget, TARGET, TARGET_ROW_LABEL, TargetKey, hex_entity,
    invalid, normalized_scope,
};
use super::taxonomy::{AmendmentClass, AmendmentJudgment, cost_predicate};
use crate::Vault;
use crate::actor_claims::{
    ActorClaimEvidence, ActorClaimRow, PREDICATE_ACTOR_LESSON, edit_cost_scope,
    edit_cost_scope_name, ground_actor_claim, write_actor_claim, write_actor_claim_in_txn,
};
use crate::batch::EntityMetadataHeader;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    PREDICATE_ACTOR_EDIT_COST, PREDICATE_SKILL_EDIT_COST,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::side_table::HexId;
use crate::skill_reliability::{AmendedOutcome, reconcile_amended_outcomes_in_txn};
use crate::temporal::TimeRange;

// ---------------------------------------------------------------------------
// The claim write door
// ---------------------------------------------------------------------------

/// Projects judged amendments into `*.edit_cost` rows, returning the claim ids
/// this pass landed.
///
/// **Judgments, never deltas.** The argument type is the guard the ticket asks
/// for: there is no path from a raw `d_norm` to a claim that does not pass a
/// class first.
///
/// **Every judgment is re-grounded, not trusted.** [`AmendmentJudgment`] is a
/// public type with public fields and this function authors reserved truth, so
/// a row counts only if it IS the row this module persisted for that receipt
/// (the ONE-1738/ONE-1739 posture). Ungrounded rows are SKIPPED rather than
/// fatal — one forged row must not deny a whole pass.
///
/// The value written is RECOMPUTED from the whole judgment ledger for the row's
/// `(subject, scope)` pair, so the pass is idempotent and an interrupted one
/// leaves a stale row rather than a double-counted one. A pass that would write
/// the row already standing writes nothing and re-returns it.
///
/// **Every pass reconciles before it writes.** The judgment ledger is
/// overwrite-by-receipt, so a re-judgment can move a receipt off the tuple it
/// used to charge — and nothing in the new judgment names the old one. The
/// tuples this projector has landed are therefore kept as their own ledger, and
/// one that has lost every supporting judgment is RETRACTED here rather than
/// left charging a verdict no judge stands behind.
///
/// # Errors
///
/// Storage errors, and whatever the `actor.*` write door rejects.
pub fn project_edit_cost_claims(
    vault: &Vault,
    judgments: &[AmendmentJudgment],
) -> Result<Vec<EntityId>> {
    retract_unsupported_targets(vault)?;
    let persisted = amendment_judgments(vault)?;
    let mut targets: Vec<(&'static str, EntityId, String)> = Vec::new();
    for judgment in judgments {
        // Grounded is not authorization: this row must also BE the row this
        // module routed for that receipt.
        if !persisted
            .iter()
            .any(|row| row.receipt_id == judgment.receipt_id && row == judgment)
        {
            continue;
        }
        for share in &judgment.split {
            let Some(predicate) = cost_predicate(share.class) else {
                continue;
            };
            let Some(subject) = share.subject else {
                continue;
            };
            let target = (predicate, subject, judgment.scope.clone());
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
    }

    let mut written = Vec::with_capacity(targets.len());
    for (predicate, subject, scope) in targets {
        let Some(aggregate) = aggregate_for(&persisted, predicate, subject, &scope) else {
            continue;
        };
        // Recorded BEFORE the head it describes: the write door owns its own
        // transaction, so the two cannot land atomically, and a tuple recorded
        // without a head is reconciled away harmlessly while a head landed
        // without its tuple would be unreachable for the rest of time.
        record_target(vault, predicate, &subject, &scope)?;
        written.push(write_cost_head(
            vault, predicate, subject, &scope, &aggregate,
        )?);
    }
    Ok(written)
}

/// Lands one tuple's cost head — or re-returns the head that already says
/// exactly this.
///
/// The no-op arm is what makes a replay a replay. Both writers mint
/// `EntityId::now()` and supersede whatever head they find, so an unchanged
/// pass without this check forks a fresh claim entity every run: unbounded
/// phantom supersession history, sync traffic for a number that did not move,
/// and a different id back from a function whose contract is idempotence.
///
/// ONE head, and only one: two active heads for a tuple is a post-sync fork
/// that must collapse even when the surviving value is unchanged, so that case
/// falls through to the writers on purpose.
fn write_cost_head(
    vault: &Vault,
    predicate: &'static str,
    subject: EntityId,
    scope: &str,
    aggregate: &CostAggregate,
) -> Result<EntityId> {
    let evidence = ActorClaimEvidence::amendment(aggregate.receipts.clone(), aggregate.at)?;
    let value = rmpv::Value::F32(aggregate.cost);
    let cited = if predicate == PREDICATE_ACTOR_EDIT_COST {
        evidence.to_value()
    } else {
        skill_cost_evidence(aggregate)
    };
    {
        let rtxn = vault.store.env.read_txn()?;
        let heads = active_cost_heads_in_txn(vault, &rtxn, predicate, &subject, scope)?;
        if let [(head_id, head)] = heads.as_slice()
            && head.value == value
            && head.valid_from == Some(aggregate.at)
            && head.evidence.as_ref() == Some(&cited)
        {
            return Ok(*head_id);
        }
    }
    if predicate == PREDICATE_ACTOR_EDIT_COST {
        write_actor_claim(
            vault,
            ActorClaimRow::EditCost {
                actor: subject,
                scope: scope.to_owned(),
                cost: aggregate.cost,
            },
            &evidence,
        )
    } else {
        write_skill_edit_cost(vault, &subject, scope, aggregate)
    }
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
/// without one names no attempt, so its share reaches `skill.edit_cost` alone.
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
        let Ok(evidence) =
            ActorClaimEvidence::amendment(judgment.evidence_receipts.clone(), judgment.at)
        else {
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

/// Records that this projector holds a live head for `(predicate, subject,
/// scope)`, so a later pass can find it again after the judgments that earned
/// it have moved elsewhere.
fn record_target(
    vault: &Vault,
    predicate: &'static str,
    subject: &EntityId,
    scope: &str,
) -> Result<()> {
    vault
        .with_write_txn_grouped(|wtxn| record_target_in_txn(vault, wtxn, predicate, subject, scope))
}

/// [`record_target`] in the caller's transaction.
fn record_target_in_txn(
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

/// Closes every landed head the judgment ledger no longer supports.
///
/// A receipt re-judged onto another class, subject or scope orphans the head
/// its old tuple was holding up: the aggregate is only ever recomputed for
/// tuples some judgment still points at, so without this the old charge would
/// stand forever and [`edit_cost_for`] would keep reporting it. Retraction —
/// not deletion — is the withdrawal: the row stays readable as history.
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
    let persisted: Vec<AmendmentJudgment> = amendment_judgments_in_txn(vault, txn)?
        .into_iter()
        .map(|(judgment, _)| judgment)
        .collect();
    let mut unsupported = recorded_targets_in_txn(vault, txn)?;
    unsupported.retain(|(predicate, subject, scope)| {
        if *predicate == PREDICATE_ACTOR_LESSON {
            // A lesson's scope is the amendment it was learned from.
            !persisted
                .iter()
                .any(|row| row.receipt_id == *scope && lapse_actor(row) == Some(*subject))
        } else {
            aggregate_for(&persisted, predicate, *subject, scope).is_none()
        }
    });
    Ok(unsupported)
}

/// Retracts one tuple's active heads and forgets the tuple, in the caller's
/// transaction.
///
/// The `skill.*`/`actor.*` namespaces own their own lifecycle mechanics — the
/// generic [`crate::Vault::retract_claim`] refuses a reserved predicate by
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
    let heads = if predicate == PREDICATE_ACTOR_LESSON {
        active_lesson_heads_in_txn(vault, wtxn, subject, &lapse_lesson(scope))?
    } else {
        active_cost_heads_in_txn(vault, wtxn, predicate, subject, scope)?
    };
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
    [
        PREDICATE_ACTOR_EDIT_COST,
        PREDICATE_SKILL_EDIT_COST,
        PREDICATE_ACTOR_LESSON,
    ]
    .into_iter()
    .find(|predicate| *predicate == token)
}

/// One `(subject, scope)` pair's folded cost.
struct CostAggregate {
    cost: f32,
    /// The newest cited receipts, oldest-first, bounded.
    receipts: Vec<String>,
    /// The newest judged amendment's stamp — the row's event time.
    at: u64,
}

/// Folds every persisted judgment charging `(predicate, subject, scope)`.
///
/// Each judgment charges only its SHARE of the edit: the class that earns this
/// predicate holds `share` of the amendment, so the subject's charge is
/// `share · d_norm`, and a single verdict (share 1) charges the whole edit.
/// The mean of those charges is the aggregate, taken over the CLASS that earns
/// this predicate only: a `discovery` names the same SKILL a `skill_defect`
/// does, and folding both would charge a skill for content it never claimed
/// to have.
fn aggregate_for(
    persisted: &[AmendmentJudgment],
    predicate: &'static str,
    subject: EntityId,
    scope: &str,
) -> Option<CostAggregate> {
    let mut rows: Vec<(&AmendmentJudgment, f64)> = persisted
        .iter()
        .filter(|row| row.scope == scope)
        .filter_map(|row| {
            let share: f32 = row
                .split
                .iter()
                .filter(|share| {
                    share.subject == Some(subject) && cost_predicate(share.class) == Some(predicate)
                })
                .map(|share| share.share)
                .sum();
            (share > 0.0).then(|| (row, f64::from(share) * f64::from(row.d_norm)))
        })
        .collect();
    if rows.is_empty() {
        return None;
    }
    rows.sort_by(|(left, _), (right, _)| {
        left.at
            .cmp(&right.at)
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
    let total: f64 = rows.iter().map(|(_, charge)| charge).sum();
    // Precision loss is intended: this is a reported estimate over a bounded
    // unit-interval fold, not an accumulator.
    #[expect(
        clippy::cast_precision_loss,
        reason = "reported aggregate over unit-interval judgments"
    )]
    let mean = (total / rows.len() as f64).clamp(0.0, 1.0) as f32;
    let at = rows.last().map_or(0, |(row, _)| row.at);
    // The NEWEST citations survive the bound: a row's trace should point at the
    // evidence nearest the estimate it carries.
    let first = rows.len().saturating_sub(MAX_CITED_RECEIPTS);
    let receipts = rows[first..]
        .iter()
        .flat_map(|(row, _)| row.evidence_receipts.iter().cloned())
        .take(MAX_CITED_RECEIPTS)
        .collect();
    Some(CostAggregate {
        cost: mean,
        receipts,
        at,
    })
}

/// Writes the `skill.edit_cost` head for one `(skill, scope)` pair, superseding
/// every active head that shares it.
///
/// The `skill.*` mirror of [`write_actor_claim`]: the body is built HERE, never
/// by a caller, and rides `put_reserved_claim_in_txn` — the same engine-owned
/// door `skill.reliability` and the scan verdicts author through.
fn write_skill_edit_cost(
    vault: &Vault,
    skill: &EntityId,
    scope: &str,
    aggregate: &CostAggregate,
) -> Result<EntityId> {
    if vault.get_skill_record(skill)?.is_none() {
        return Err(Error::EntityNotFound);
    }
    let scope = normalized_scope(scope)?.to_owned();
    let at = aggregate.at;
    let value = rmpv::Value::F32(aggregate.cost);
    let evidence = skill_cost_evidence(aggregate);
    vault.with_write_txn_grouped(|wtxn| {
        let heads =
            active_cost_heads_in_txn(vault, wtxn, PREDICATE_SKILL_EDIT_COST, skill, &scope)?;
        let claim_id = vault.store.clock.entity_id()?;
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_EDIT_COST,
            ClaimSubject::Entity(*skill),
            value.clone(),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.evidence = Some(evidence.clone());
        body.scope = Some(edit_cost_scope(&scope));
        body.valid_from = Some(at);
        body.source = Some(ClaimSource::Observed);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &claim_id,
            &body,
            TimeRange { start: at, end: at },
            at,
        )?;
        // EVERY active head closes, not just the first found: `EntityId::now()`
        // is per-replica unique, so two replicas that both projected this pair
        // hold two distinct claims, and closing one would leave the other live
        // forever. The `max` mirrors the sibling clamp — an out-of-order event
        // time makes the re-Put range invalid and rolls the transaction back.
        for (head_id, head) in &heads {
            let head_start = head.valid_from.unwrap_or(0);
            vault.supersede_reserved_claim_in_txn(wtxn, &claim_id, head_id, at.max(head_start))?;
        }
        Ok(claim_id)
    })
}

/// The citation array a `skill.edit_cost` row carries — the `skill.*` shape,
/// beside the lane envelope its `actor.*` sibling's own ledger builds.
fn skill_cost_evidence(aggregate: &CostAggregate) -> rmpv::Value {
    rmpv::Value::Array(
        aggregate
            .receipts
            .iter()
            .map(|receipt| rmpv::Value::from(receipt.as_str()))
            .collect(),
    )
}

/// The active heads of one `(predicate, subject, scope)` tuple.
///
/// One scan for both predicates: an entity is an ACTOR or a SKILL, never both,
/// so the tuple already says which ledger is being read.
fn active_cost_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    predicate: &str,
    subject: &EntityId,
    scope: &str,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut heads = Vec::new();
    for id in vault.claims_for_subject_in_txn(rtxn, subject)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != predicate
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.source != Some(ClaimSource::Observed)
            || body.approval != ClaimApprovalStatus::Auto
            || edit_cost_scope_name(body.scope.as_ref()) != Some(scope)
        {
            continue;
        }
        heads.push((id, body));
    }
    Ok(heads)
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

/// The live `*.edit_cost` estimate for `(subject, scope)`, or `None`.
///
/// One read for both predicates: an entity is an ACTOR or a SKILL, never both,
/// so the subject already says which row is being asked about. Two active heads
/// for one pair is a legitimate post-sync convergence state, so the newest wins
/// deterministically — by event time, then claim id — rather than bricking the
/// read.
///
/// # Errors
///
/// Storage errors.
pub fn edit_cost_for(vault: &Vault, subject: &EntityId, scope: &str) -> Result<Option<f32>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut best: Option<(u64, EntityId, f32)> = None;
    for id in vault.claims_for_subject_in_txn(&rtxn, subject)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if !matches!(
            body.predicate.as_str(),
            PREDICATE_SKILL_EDIT_COST | PREDICATE_ACTOR_EDIT_COST
        ) || body.lifecycle != ClaimLifecycleStatus::Active
            || body.source != Some(ClaimSource::Observed)
            || body.approval != ClaimApprovalStatus::Auto
            || edit_cost_scope_name(body.scope.as_ref()) != Some(scope)
        {
            continue;
        }
        let rmpv::Value::F32(cost) = body.value else {
            return Err(invalid("edit_cost value must be a cost in 0..=1"));
        };
        let valid_from = body.valid_from.unwrap_or(0);
        let newer = match &best {
            None => true,
            Some((best_from, best_id, _)) => {
                valid_from > *best_from || (valid_from == *best_from && id > *best_id)
            }
        };
        if newer {
            best = Some((valid_from, id, cost));
        }
    }
    Ok(best.map(|(_, _, cost)| cost))
}
