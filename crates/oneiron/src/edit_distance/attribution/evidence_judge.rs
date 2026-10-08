//! Amendment evidence doors and the judging pass.

use super::stored::{
    EVIDENCE, EVIDENCE_ROW_LABEL, JUDGMENT, JUDGMENT_ROW_LABEL, PREFERENCE, ROW_VERSION,
    StoredEvidence, StoredJudgment, StoredPreference, StoredShare, hex_entity, invalid,
    normalized_scope,
};
use super::taxonomy::{
    AmendmentCause, AmendmentClass, AmendmentEvidence, AmendmentJudgment, AmendmentShare,
    PreferenceProposal, class_subject, classify_amendment, cost_predicate,
};
use crate::Vault;
use crate::actor_claims::require_actor_entity;
use crate::edit_distance::delta::amendment_delta;
use crate::error::{Error, Result};
use crate::skill_attribution::{
    AttributionJudge, AttributionLane, EditHunk, RuleAttributionJudge, UnclearAttribution,
    delete_unclear_in_txn, put_unclear_in_txn, unclear_floor,
};

// ---------------------------------------------------------------------------
// Evidence door
// ---------------------------------------------------------------------------

/// Records the routing facts behind one amendment, for a later judging pass.
///
/// Recording never classifies — the same split SK-04 keeps, and for the same
/// reason: facts can be captured where they are observed, and a fixed judge can
/// re-route them afterwards.
///
/// Everything the row asserts is RESOLVED here, at the door: the receipt must
/// carry a Δ this engine measured, any skill must exist, the scope must be a
/// usable key, and the actor must be an entity that can ACT. A judgment is only
/// as good as its inputs, and the classes it feeds author reserved truth.
///
/// The actor check is the DOWNSTREAM door's own (`require_actor_entity`, the
/// D13 matrix), asked here rather than three passes later: an
/// [`AmendmentClass::ExecutionLapse`] on a TURN would be recorded, judged and
/// persisted before [`project_edit_cost_claims`](crate::edit_distance::attribution::project_edit_cost_claims) hit the refusal, wedging every
/// later pass on durable state the engine had already accepted.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when a reference does not resolve, names an
/// entity that cannot act, or the scope is unusable; storage errors.
pub fn record_amendment_evidence(vault: &Vault, evidence: &AmendmentEvidence) -> Result<()> {
    let scope = normalized_scope(&evidence.scope)?.to_owned();
    if amendment_delta(vault, &evidence.receipt_id)?.is_none() {
        return Err(invalid("amendment evidence cites an unmeasured receipt"));
    }
    require_actor_entity(vault, &evidence.actor)?;
    if let Some(skill) = evidence.skill
        && vault.get_skill_record(&skill)?.is_none()
    {
        return Err(invalid("amendment evidence names an unknown skill"));
    }
    let row = StoredEvidence {
        v: ROW_VERSION,
        actor: evidence.actor.to_hex(),
        skill: evidence.skill.map(|id| id.to_hex()),
        scope,
        cause: evidence.cause.map(|cause| cause.as_str().to_owned()),
        followed_skill: evidence.followed_skill,
        skill_covered_step: evidence.skill_covered_step,
        at: evidence.at,
    };
    vault.with_write_txn(|wtxn| {
        EVIDENCE.put(&vault.store, wtxn, &evidence.receipt_id, &row)?;
        Ok(())
    })
}

/// The routing facts recorded for `receipt_id`, if any.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an undecodable row; storage errors.
pub fn amendment_evidence(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentEvidence>> {
    let rtxn = vault.store.env.read_txn()?;
    amendment_evidence_in_txn(vault, &rtxn, receipt_id)
}

/// Transaction-composable [`amendment_evidence`], for a reader that must see
/// the evidence ledger on the SAME snapshot as the rows it is tagging.
pub(in crate::edit_distance) fn amendment_evidence_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt_id: &str,
) -> Result<Option<AmendmentEvidence>> {
    let Some(row) = EVIDENCE.get(&vault.store, rtxn, &receipt_id.to_owned())? else {
        return Ok(None);
    };
    Ok(Some(AmendmentEvidence {
        receipt_id: receipt_id.to_owned(),
        actor: hex_entity(&row.actor, EVIDENCE_ROW_LABEL)?,
        skill: row
            .skill
            .as_deref()
            .map(|hex| hex_entity(hex, EVIDENCE_ROW_LABEL))
            .transpose()?,
        scope: row.scope,
        cause: row
            .cause
            .as_deref()
            .map(|token| {
                AmendmentCause::parse(token).ok_or(Error::CorruptedIndex(EVIDENCE_ROW_LABEL))
            })
            .transpose()?,
        followed_skill: row.followed_skill,
        skill_covered_step: row.skill_covered_step,
        at: row.at,
    }))
}

// ---------------------------------------------------------------------------
// The judging pass
// ---------------------------------------------------------------------------

/// Judges the amendment recorded against `receipt_id` with the deterministic
/// tier, persisting and returning the judgment — or `None` when the judge
/// abstains, no facts were recorded, or no Δ was measured.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn judge_amendment(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentJudgment>> {
    judge_amendment_with(vault, receipt_id, &RuleAttributionJudge)
}

/// [`judge_amendment`] with an explicit tier — the seam the model judge and the
/// audit harness both use. The amendment is judged as one region:
/// [`judge_amendment_hunks`] with no hunks.
///
/// # Errors
///
/// Storage errors, and whatever `judge` returns.
pub fn judge_amendment_with(
    vault: &Vault,
    receipt_id: &str,
    judge: &dyn AttributionJudge,
) -> Result<Option<AmendmentJudgment>> {
    judge_amendment_hunks(vault, receipt_id, judge, &[])
}

/// Judges the amendment recorded against `receipt_id` hunk by hunk
/// (ARCH-0056 §5 #attribution-split), persisting and returning its label +
/// share split — or `None` when the judge abstains, no facts were recorded,
/// or no Δ was measured.
///
/// `hunks` are the changed regions as the host that holds both texts cut
/// them. Each weighs its own measured edit mass, so the split says which part
/// of the edit each label explains; no hunks is one region, one class at 100%.
/// Each route then takes only its share: a `preference_shift` share files a
/// preference note carrying it, an `unclear` share files a row in the unclear
/// ledger for the Dreamer, and [`project_edit_cost_claims`](crate::edit_distance::attribution::project_edit_cost_claims) charges the
/// skill and the actor their shares alone.
///
/// Re-judging OVERWRITES the receipt's judgment row rather than freezing the
/// first answer. A deterministic judge re-derives the same row, so the pass is
/// idempotent; a judge that has since been FIXED is exactly what the audit
/// exists to provoke, and a ledger that refused its correction would keep the
/// wrong verdict forever. The claim rows follow on the next
/// [`project_edit_cost_claims`](crate::edit_distance::attribution::project_edit_cost_claims) pass, which recomputes from this ledger.
///
/// ABSTENTION is a correction like any other. A re-judging pass whose honest
/// answer is silence WITHDRAWS whatever the previous pass persisted rather than
/// leaving it queryable: this ledger is what the projector recomputes from, so
/// a row nobody now stands behind would keep charging by itself.
///
/// # Errors
///
/// Storage errors, and whatever `judge` returns.
pub fn judge_amendment_hunks(
    vault: &Vault,
    receipt_id: &str,
    judge: &dyn AttributionJudge,
    hunks: &[EditHunk<'_>],
) -> Result<Option<AmendmentJudgment>> {
    let Some(evidence) = amendment_evidence(vault, receipt_id)? else {
        return Ok(None);
    };
    // No measurement, no judgment: a cost with nothing behind it is the number
    // this module refuses to invent.
    let Some(delta) = amendment_delta(vault, receipt_id)? else {
        return withdraw_judgment(vault, receipt_id).map(|()| None);
    };
    let floor = unclear_floor(vault)?;
    let Some(split) = classify_amendment(&evidence, judge, hunks, floor)? else {
        return withdraw_judgment(vault, receipt_id).map(|()| None);
    };
    let shares: Vec<AmendmentShare> = split
        .shares
        .iter()
        .map(|share| AmendmentShare {
            class: share.verdict,
            share: share.share,
            subject: class_subject(share.verdict, &evidence),
        })
        .collect();
    // A class that charges somebody but names nobody is not a judgment, it is a
    // routing bug wearing one. Recorded as an abstention rather than landed.
    if shares
        .iter()
        .any(|share| cost_predicate(share.class).is_some() && share.subject.is_none())
    {
        return withdraw_judgment(vault, receipt_id).map(|()| None);
    }
    let judgment = AmendmentJudgment {
        receipt_id: receipt_id.to_owned(),
        split: shares,
        scope: normalized_scope(&evidence.scope)?.to_owned(),
        evidence_receipts: vec![receipt_id.to_owned()],
        d_norm: delta.d_norm,
        at: evidence.at,
    };

    let row = StoredJudgment {
        v: ROW_VERSION,
        class: None,
        subject: None,
        split: judgment
            .split
            .iter()
            .map(|share| StoredShare {
                class: share.class.as_str().to_owned(),
                share: share.share,
                subject: share.subject.map(|id| id.to_hex()),
            })
            .collect(),
        scope: judgment.scope.clone(),
        evidence_receipts: judgment.evidence_receipts.clone(),
        d_norm: judgment.d_norm,
        at: judgment.at,
    };
    let preference_share = judgment.share_of(AmendmentClass::PreferenceShift);
    let preference_row = (preference_share > 0.0).then(|| StoredPreference {
        v: ROW_VERSION,
        scope: judgment.scope.clone(),
        evidence_receipts: judgment.evidence_receipts.clone(),
        share: preference_share,
        at: judgment.at,
    });
    let unclear_row = (!split.unclear.is_empty()).then(|| UnclearAttribution {
        lane: AttributionLane::Amendment,
        reference: receipt_id.to_owned(),
        evidence_receipts: judgment.evidence_receipts.clone(),
        notes: split.unclear.clone(),
        at: judgment.at,
    });

    let receipt_id_owned = receipt_id.to_owned();
    vault.with_write_txn(|wtxn| {
        JUDGMENT.put(&vault.store, wtxn, &receipt_id_owned, &row)?;
        // A note and the judgment that demanded it land together, and a
        // re-judgment that no longer carries the share withdraws the note it
        // no longer stands behind.
        match preference_row.as_ref() {
            Some(row) => {
                PREFERENCE.put(&vault.store, wtxn, &receipt_id_owned, row)?;
            }
            None => {
                PREFERENCE.delete(&vault.store, wtxn, &receipt_id_owned)?;
            }
        }
        match unclear_row.as_ref() {
            Some(row) => put_unclear_in_txn(vault, wtxn, row)?,
            None => {
                delete_unclear_in_txn(vault, wtxn, AttributionLane::Amendment, &receipt_id_owned)?;
            }
        }
        Ok(())
    })?;
    Ok(Some(judgment))
}

/// Deletes whatever a previous pass persisted for `receipt_id` — its judgment
/// and, with it, any preference note or unclear row that judgment filed.
///
/// The withdrawal is the whole correction on this side: the cost head the row
/// was holding up loses its ledger support, and the next
/// [`project_edit_cost_claims`] pass retracts it.
fn withdraw_judgment(vault: &Vault, receipt_id: &str) -> Result<()> {
    let receipt_id = receipt_id.to_owned();
    {
        // A receipt that never landed an answer has none to withdraw, and an
        // abstention is the common case — it must not cost a write transaction.
        // Every note rides its judgment, so no judgment means no note.
        let rtxn = vault.store.env.read_txn()?;
        if !JUDGMENT.contains(&vault.store, &rtxn, &receipt_id)?
            && !PREFERENCE.contains(&vault.store, &rtxn, &receipt_id)?
        {
            return Ok(());
        }
    }
    vault.with_write_txn(|wtxn| {
        JUDGMENT.delete(&vault.store, wtxn, &receipt_id)?;
        PREFERENCE.delete(&vault.store, wtxn, &receipt_id)?;
        delete_unclear_in_txn(vault, wtxn, AttributionLane::Amendment, &receipt_id)?;
        Ok(())
    })
}

/// Every persisted amendment judgment, in receipt-id order.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn amendment_judgments(vault: &Vault) -> Result<Vec<AmendmentJudgment>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (receipt_id, row) in JUDGMENT.scan(&vault.store, &rtxn)? {
        out.push(AmendmentJudgment {
            receipt_id,
            split: stored_split(&row)?,
            scope: row.scope,
            evidence_receipts: row.evidence_receipts,
            d_norm: row.d_norm,
            at: row.at,
        });
    }
    Ok(out)
}

/// A stored row's split; a row written before split verdicts reads back as
/// its one class at 100%.
fn stored_split(row: &StoredJudgment) -> Result<Vec<AmendmentShare>> {
    let share = |class: &str, share: f32, subject: Option<&str>| -> Result<AmendmentShare> {
        Ok(AmendmentShare {
            class: AmendmentClass::parse(class).ok_or(Error::CorruptedIndex(JUDGMENT_ROW_LABEL))?,
            share,
            subject: subject
                .map(|hex| hex_entity(hex, JUDGMENT_ROW_LABEL))
                .transpose()?,
        })
    };
    match (&row.split[..], row.class.as_deref()) {
        ([], Some(class)) => Ok(vec![share(class, 1.0, row.subject.as_deref())?]),
        ([], None) => Err(Error::CorruptedIndex(JUDGMENT_ROW_LABEL)),
        (split, _) => split
            .iter()
            .map(|stored| share(&stored.class, stored.share, stored.subject.as_deref()))
            .collect(),
    }
}

/// Every preference proposal awaiting ED-04's miner, in receipt-id order.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn pending_preference_proposals(vault: &Vault) -> Result<Vec<PreferenceProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (receipt_id, row) in PREFERENCE.scan(&vault.store, &rtxn)? {
        out.push(PreferenceProposal {
            receipt_id,
            scope: row.scope,
            evidence_receipts: row.evidence_receipts,
            share: row.share,
            at: row.at,
        });
    }
    Ok(out)
}
