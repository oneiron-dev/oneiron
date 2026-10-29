//! A rejection goes through the judge before it charges anyone (ARCH-0056
//! §5, §11; FIX 7823).
//!
//! A rejection carries no Δ and no hunks, so the judge gives it one label at
//! 100% — the path a failed attempt with no edit takes. Only a `skill_defect`
//! share charges the skill and only an `execution_lapse` share charges the
//! actor; `environment`, `preference_shift` and `unclear` charge nobody, and
//! an `unclear` share files its note in the unclear ledger for the Dreamer.
//! The judgment row is the record either way, and a charged share lands on
//! its subject's `learning.edit_cost` cell counted rejected. The generating
//! actor's cell, and the skill's when the proposal rode one, count the
//! rejection even where no share charges them (FIX 9797).
//!
//! The inbox states no cause, so that first judgment holds `unclear`. When
//! a cause is stated later, [`judge_rejection_with_cause`] re-judges the
//! same rejection through this same path (FIX 11621): the judgment row and
//! the evidence row are overwritten under the same keys, the stale unclear
//! note is withdrawn when nothing is left unclear, and the charge settles
//! the receipt's rows rather than counting them twice.

use super::cells::{charge_judgment_in_txn, learning_scope};
use super::evidence_judge::{amendment_judgment_in_txn, judgment_row};
use super::stored::{EVIDENCE, JUDGMENT, ROW_VERSION, StoredEvidence, normalized_scope};
use super::taxonomy::{
    AmendmentCause, AmendmentEvidence, AmendmentJudgment, AmendmentShare, charges_edit_cost,
    class_subject, classify_amendment_traced,
};
use crate::Vault;
use crate::edit_distance::delta::MEASUREMENT_ENGINE_VERSION;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning_setting::{ATTRIBUTION_UNCLEAR_FLOOR, setting_value_in_txn};
use crate::skill_attribution::{
    AttributionLane, UnclearAttribution, delete_unclear_in_txn, put_unclear_in_txn,
};

/// The edit mass a rejection carries: the decider discarded the whole
/// proposal. Canon gives a rejection no Δ; the whole proposal's mass is the
/// cost the inbox's direct write used to record.
const REJECTION_EDIT_MASS: f32 = 1.0;

/// One rejected proposal, as the inbox decision captured it.
pub(in crate::edit_distance) struct Rejection<'a> {
    /// The decision receipt.
    pub(in crate::edit_distance) receipt: &'a str,
    /// The actor whose proposal was rejected.
    pub(in crate::edit_distance) actor: EntityId,
    /// The skill the proposal rode, when it rode one.
    pub(in crate::edit_distance) skill: Option<EntityId>,
    pub(in crate::edit_distance) scope: &'a str,
    /// The reviewed claim's project; `None` is the vault's (FIX 6038).
    pub(in crate::edit_distance) project: Option<EntityId>,
    pub(in crate::edit_distance) at: u64,
}

/// Judges `rejection` with the rule tier in the deciding write's transaction,
/// persists the judgment, files any unclear note, and lands each charged
/// share on its subject's cell. Returns the judgment, or `None` when the
/// judge abstains or a charging class names nobody.
///
/// The inbox knows no cause for a rejection, so the rule tier holds it
/// `unclear` with a missing-cause note: it charges nobody until a judge with
/// facts says otherwise.
///
/// # Errors
///
/// Storage errors, an unusable scope, and whatever the decision path or the
/// learning door refuses.
pub(in crate::edit_distance) fn judge_rejection_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    rejection: &Rejection<'_>,
) -> Result<Option<AmendmentJudgment>> {
    judge_rejection_cause_in_txn(vault, wtxn, rejection, None)
}

/// [`judge_rejection_in_txn`] with the rejection's cause stated (FIX 11621):
/// the cause rides the evidence into the same classify path an amendment
/// takes, so a settled cause labels the rejection instead of holding it
/// `unclear`, and `proposal_wrong` reaches the judge with facts.
///
/// # Errors
///
/// Storage errors, an unusable scope, and whatever the decision path or the
/// learning door refuses.
pub(in crate::edit_distance) fn judge_rejection_with_cause_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    rejection: &Rejection<'_>,
    cause: AmendmentCause,
) -> Result<Option<AmendmentJudgment>> {
    judge_rejection_cause_in_txn(vault, wtxn, rejection, Some(cause))
}

/// Re-judges the rejection recorded against `receipt_id` with `cause`
/// stated, in one write transaction (FIX 11621) — the intake for facts the
/// inbox did not have. The facts it replays (actor, skill, scope, project,
/// decision time) are the stored judgment's own; the stored scope is
/// already the first pass's normalized form, which the shared path
/// re-normalizes unchanged. Returns the new judgment, or `None` when no
/// rejection judgment stands for `receipt_id` or the judge abstains.
///
/// Re-judging overwrites rather than freezes, as
/// [`judge_amendment_hunks`](super::judge_amendment_hunks) does: the charge
/// settles the receipt's rows onto the new split, so nothing counts twice.
///
/// # Errors
///
/// Storage errors, an unusable stored scope, a judge revision the
/// displacement fence refuses (FIX 11638), and whatever the decision
/// path or the learning door refuses.
pub fn judge_rejection_with_cause(
    vault: &Vault,
    receipt_id: &str,
    cause: AmendmentCause,
) -> Result<Option<AmendmentJudgment>> {
    let judged = {
        let rtxn = vault.store.env.read_txn()?;
        amendment_judgment_in_txn(vault, &rtxn, receipt_id)?
    };
    let Some(judged) = judged else {
        return Ok(None);
    };
    if !judged.rejected {
        return Ok(None);
    }
    let Some(actor) = judged.actor else {
        return Ok(None);
    };
    vault.with_write_txn_grouped(|wtxn| {
        // The standing check runs again in the writing transaction, and
        // the replayed facts are that check's own: a withdrawal or
        // re-judgment since the snapshot above is never clobbered by
        // facts read from it.
        let Some(standing) = amendment_judgment_in_txn(vault, &*wtxn, receipt_id)? else {
            return Ok(None);
        };
        if !standing.rejected || standing.actor != Some(actor) {
            return Ok(None);
        }
        let rejection = Rejection {
            receipt: receipt_id,
            actor,
            skill: standing.skill,
            scope: &standing.scope,
            project: standing.project,
            at: standing.at,
        };
        judge_rejection_with_cause_in_txn(vault, wtxn, &rejection, cause)
    })
}

/// [`judge_rejection_in_txn`]'s one path, with the cause the door stated.
fn judge_rejection_cause_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    rejection: &Rejection<'_>,
    cause: Option<AmendmentCause>,
) -> Result<Option<AmendmentJudgment>> {
    let scope = normalized_scope(&learning_scope(rejection.scope))?.to_owned();
    let mut evidence =
        AmendmentEvidence::new(rejection.receipt, rejection.actor, scope.as_str()).at(rejection.at);
    evidence.skill = rejection.skill;
    evidence.cause = cause;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a unit-interval setting narrowed to the judge's f32 confidence"
    )]
    let floor = setting_value_in_txn(&vault.store, &*wtxn, &ATTRIBUTION_UNCLEAR_FLOOR)? as f32;
    let (split, trace) = classify_amendment_traced(&evidence, None, &[], floor)?;
    let Some(split) = split else {
        return Ok(None);
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
    // A class that charges somebody but names nobody is a routing bug, not a
    // judgment: nothing lands.
    if shares
        .iter()
        .any(|share| charges_edit_cost(share.class) && share.subject.is_none())
    {
        return Ok(None);
    }
    // A rejection keeps the routing facts the inbox truthfully has, in the same
    // row and under the same key the amendment door writes (FIX 11633): the
    // decision names no attempt, executor or task type, so those stay unset;
    // the cause rides the row when the intake stated one (FIX 11621).
    let evidence_row = StoredEvidence {
        v: ROW_VERSION,
        actor: rejection.actor.to_hex(),
        skill: rejection.skill.map(|id| id.to_hex()),
        attempt: None,
        executor: None,
        type_ref: None,
        project: rejection.project.map(|id| id.to_hex()),
        scope: scope.clone(),
        cause: cause.map(|cause| cause.as_str().to_owned()),
        followed_skill: None,
        skill_covered_step: None,
        at: rejection.at,
    };
    let judgment = AmendmentJudgment {
        receipt_id: rejection.receipt.to_owned(),
        split: shares,
        scope,
        evidence_receipts: vec![rejection.receipt.to_owned()],
        d_norm: REJECTION_EDIT_MASS,
        engine_ver: MEASUREMENT_ENGINE_VERSION.to_owned(),
        at: rejection.at,
        hunks: Vec::new(),
        executor: None,
        type_ref: None,
        project: rejection.project,
        attempt_receipt: None,
        judge: trace.revision,
        judge_model: trace.model,
        actor: Some(rejection.actor),
        skill: rejection.skill,
        rejected: true,
    };
    // A displaced judge's answers no longer land (FIX 11638): the fence
    // the attempt lane checks before its judgment put, checked here
    // before any of this door's rows land.
    if let Some(revision) = judgment.judge.as_deref() {
        crate::skill_attribution::ensure_current_attribution_judge_in_txn(vault, &*wtxn, revision)?;
    }
    EVIDENCE.put(&vault.store, wtxn, &judgment.receipt_id, &evidence_row)?;
    JUDGMENT.put(
        &vault.store,
        wtxn,
        &judgment.receipt_id,
        &judgment_row(&judgment),
    )?;
    // The labels settle their write-once cause row beside the judgment.
    super::causes::put_amendment_cause_in_txn(vault, wtxn, &judgment)?;
    // A rejection has no Δ to mine, so a `preference_shift` share files no
    // preference note, and a `discovery` share mints no edit proposal here. A
    // re-judgment that left nothing unclear withdraws the note the first
    // pass filed.
    if !split.unclear.is_empty() {
        put_unclear_in_txn(
            vault,
            wtxn,
            &UnclearAttribution {
                lane: AttributionLane::Amendment,
                reference: judgment.receipt_id.clone(),
                evidence_receipts: judgment.evidence_receipts.clone(),
                notes: split.unclear.clone(),
                at: judgment.at,
            },
        )?;
    } else {
        delete_unclear_in_txn(
            vault,
            wtxn,
            AttributionLane::Amendment,
            &judgment.receipt_id,
        )?;
    }
    charge_judgment_in_txn(vault, wtxn, &judgment)?;
    Ok(Some(judgment))
}
