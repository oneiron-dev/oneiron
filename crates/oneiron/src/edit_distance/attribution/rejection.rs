//! A rejection goes through the judge before it charges anyone (ARCH-0056
//! §5, §11; FIX 7823).
//!
//! A rejection carries no Δ and no hunks, so the judge gives it one label at
//! 100% — the path a failed attempt with no edit takes. Only a `skill_defect`
//! share charges the skill and only an `execution_lapse` share charges the
//! actor; `environment`, `preference_shift` and `unclear` charge nobody, and
//! an `unclear` share files its note in the unclear ledger for the Dreamer.
//! The judgment row is the record either way, and a charged share lands on
//! its subject's `learning.edit_cost` cell counted rejected.

use super::cells::{charge_judgment_in_txn, learning_scope};
use super::evidence_judge::judgment_row;
use super::stored::{JUDGMENT, normalized_scope};
use super::taxonomy::{
    AmendmentEvidence, AmendmentJudgment, AmendmentShare, charges_edit_cost, class_subject,
    classify_amendment_traced,
};
use crate::Vault;
use crate::edit_distance::delta::MEASUREMENT_ENGINE_VERSION;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning_setting::{ATTRIBUTION_UNCLEAR_FLOOR, setting_value_in_txn};
use crate::skill_attribution::{AttributionLane, UnclearAttribution, put_unclear_in_txn};

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
    let scope = normalized_scope(&learning_scope(rejection.scope))?.to_owned();
    let mut evidence =
        AmendmentEvidence::new(rejection.receipt, rejection.actor, scope.as_str()).at(rejection.at);
    evidence.skill = rejection.skill;
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
        attempt_receipt: None,
        judge: trace.revision,
        rejected: true,
    };
    JUDGMENT.put(
        &vault.store,
        wtxn,
        &judgment.receipt_id,
        &judgment_row(&judgment, rejection.skill),
    )?;
    // A rejection has no Δ to mine, so a `preference_shift` share files no
    // preference note, and a `discovery` share mints no edit proposal here.
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
    }
    charge_judgment_in_txn(vault, wtxn, &judgment)?;
    Ok(Some(judgment))
}
