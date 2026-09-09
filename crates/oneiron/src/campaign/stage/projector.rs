//! The single `crm.stage` writer plus shared claim-scan and error helpers.

use rmpv::Value;

use super::ladder::PromotionMode;
use super::outcome::NoShowRecoveryPlan;
use super::reentry::ReentryPlan;
use crate::campaign::claims::{
    CrmStageValue, EvidenceBasis, PREDICATE_CRM_STAGE, StageKey, decode_crm_stage_value,
    encode_crm_stage_value, supersede_crm_stage_in_txn,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::error::Error;
use crate::temporal::TimeRange;
use crate::{EntityId, Result, Vault};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// The only CA-04 ingress permitted to write a `crm.stage` head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageProjectorInput {
    /// PERSON the head is written on.
    pub party_ref: EntityId,
    /// The head being replaced, or `None` for the FIRST head.
    pub previous_stage_claim_ref: Option<EntityId>,
    /// CA-01's canonical value. This module defines no second stage wire shape.
    pub value: CrmStageValue,
}

/// What one ladder call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageProjectResult {
    /// The stage head moved.
    Advanced {
        /// The new live `crm.stage` head.
        new_claim_ref: EntityId,
    },
    /// A proposed head landed for the existing approval machinery to rule on.
    Proposed {
        /// The proposed `crm.stage` claim.
        proposed_claim_ref: EntityId,
    },
    /// Something happened that is not a stage move.
    Routed(StageRoute),
    /// Nothing to do. Silence, an unrouted code, and an unconfigured transition
    /// all land here — none of them is an error.
    NoChange,
}

/// A non-promoting route the ladder took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageRoute {
    /// The membership is paused with a wake condition.
    Snoozed(ReentryPlan),
    /// A no-show earned a recovery plan.
    Reengage(NoShowRecoveryPlan),
    /// Referral routing owns the next step.
    Referral,
    /// The membership left the cohort.
    Exited,
    /// The membership is held out of the cohort.
    Suppressed,
}

// ---------------------------------------------------------------------------
// The projector - the ONE `crm.stage` writer
// ---------------------------------------------------------------------------

/// Writes one `crm.stage` head through CA-01's transition door.
///
/// Crate-visible on purpose: every CA-04 ingress routes here, and there is no
/// public back door that could put or supersede a `crm.stage` claim without the
/// head compare-and-swap.
///
/// Under [`PromotionMode::Auto`] the replacement head and the prior head's
/// supersession share ONE write transaction through
/// [`supersede_crm_stage_in_txn`], which verifies predicate, subject, campaign
/// scope, and current head before superseding — so a stale
/// `previous_stage_claim_ref` rolls the replacement back instead of leaving two
/// live heads.
///
/// Under [`PromotionMode::Propose`] the same canonical value lands as a
/// PROPOSED head and nothing is superseded, because nothing has been decided
/// yet. Resolving it belongs to the crate's existing claim-approval machinery;
/// this module mints no second approval mechanism. The COMPARE half of the CAS
/// still runs, in the same write transaction as the proposal: a proposal planned
/// against a head that has since been superseded is refused rather than landed
/// beside the head that replaced it, because a torn pair of live heads wedges
/// every later transition on this `(party, campaign)` — the dial changes who
/// decides, never whether the head check holds.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the value carries no evidence references, or
/// when the head the transition was planned against is no longer the current
/// one. Claim-validation, supersession, and storage errors propagate.
pub(super) fn project_stage_transition(
    vault: &Vault,
    input: &StageProjectorInput,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    // Defence in depth against the ONE law a stage cannot be written without:
    // CA-01's decoder rejects an empty list at the write door too, but this door
    // names the caller rather than the wire.
    if input.value.evidence_refs.is_empty() {
        return Err(invalid("crm.stage transition requires evidence"));
    }
    let body = stage_claim_body(input, mode);
    let new_id = EntityId::now();
    let recorded_at = input.value.recorded_at;
    match mode {
        PromotionMode::Propose => {
            vault.with_write_txn(|wtxn| {
                require_current_stage_head(vault, wtxn, input)?;
                vault.put_claim_in_txn(wtxn, &new_id, &body, at(recorded_at), recorded_at)?;
                Ok(())
            })?;
            Ok(StageProjectResult::Proposed {
                proposed_claim_ref: new_id,
            })
        }
        PromotionMode::Auto => {
            vault.with_write_txn(|wtxn| {
                vault.put_claim_in_txn(wtxn, &new_id, &body, at(recorded_at), recorded_at)?;
                supersede_crm_stage_in_txn(
                    vault,
                    wtxn,
                    &new_id,
                    input.previous_stage_claim_ref.as_ref(),
                    recorded_at,
                )
            })?;
            Ok(StageProjectResult::Advanced {
                new_claim_ref: new_id,
            })
        }
    }
}

fn stage_claim_body(input: &StageProjectorInput, mode: PromotionMode) -> ClaimBody {
    let mut body = ClaimBody::new(
        PREDICATE_CRM_STAGE,
        ClaimSubject::Entity(input.party_ref),
        encode_crm_stage_value(&input.value),
        1.0,
        match mode {
            PromotionMode::Auto => ClaimApprovalStatus::Approved,
            PromotionMode::Propose => ClaimApprovalStatus::Proposed,
        },
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(match input.value.basis {
        EvidenceBasis::Machine => ClaimSource::Observed,
        EvidenceBasis::OwnerAttested => ClaimSource::UserStated,
    });
    body.evidence = Some(evidence_value(&input.value.evidence_refs));
    body
}

/// The compare half of the head CAS, without the swap.
///
/// [`supersede_crm_stage_in_txn`] carries this check for a promotion, as the
/// first half of replacing the head. A proposal replaces nothing, so it has no
/// supersession to hang the check on — but it still lands a live head, and a
/// second live head is exactly what the check exists to prevent. Reading through
/// the caller's write txn is what makes it a compare-and-swap rather than a
/// suggestion.
fn require_current_stage_head(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    input: &StageProjectorInput,
) -> Result<()> {
    let current = live_stage_head_in(vault, wtxn, &input.party_ref, &input.value.campaign_ref)?
        .map(|(id, _)| id);
    if current != input.previous_stage_claim_ref {
        return Err(invalid("crm.stage expected head is not current"));
    }
    Ok(())
}

// Shared claim-scan and tiny helpers.

/// The live `crm.stage` head for one `(party, campaign)`, read through the
/// caller's transaction.
///
/// Two live heads is a TORN pipeline, not a merge problem — the rows can
/// disagree about stage, evidence, and basis — so it is rejected here for the
/// same reason CA-01's transition door rejects it. Decoding runs through CA-01's
/// decoder; this module defines no second stage wire shape.
pub(super) fn live_stage_head_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: &EntityId,
    campaign_ref: &EntityId,
) -> Result<Option<(EntityId, CrmStageValue)>> {
    let mut head = None;
    for id in vault.claims_for_subject_in_txn(rtxn, party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CRM_STAGE || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let value = decode_crm_stage_value(&body.value)?;
        if value.campaign_ref != *campaign_ref {
            continue;
        }
        if head.is_some() {
            return Err(invalid("crm.stage has more than one live head"));
        }
        head = Some((id, value));
    }
    Ok(head)
}

/// The live head as a transition needs it: the claim the projector will
/// supersede, and the stage the transition leaves. `(None, None)` means no live
/// head yet — `campaign.member` is not a stage.
pub(super) fn stage_position(
    vault: &Vault,
    party_ref: &EntityId,
    campaign_ref: &EntityId,
) -> Result<(Option<EntityId>, Option<StageKey>)> {
    let rtxn = vault.store.env.read_txn()?;
    let Some((id, value)) = live_stage_head_in(vault, &rtxn, party_ref, campaign_ref)? else {
        return Ok((None, None));
    };
    Ok((Some(id), Some(value.stage)))
}

/// Evidence is a reference list, matching the crate's claim-evidence shape.
pub(super) fn evidence_value(evidence_refs: &[EntityId]) -> Value {
    Value::Array(
        evidence_refs
            .iter()
            .map(|id| Value::from(id.to_hex()))
            .collect(),
    )
}

pub(super) fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

pub(super) fn elapsed(now: u64, then: u64) -> u64 {
    now.saturating_sub(then)
}

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::claims::StageEvidenceClass;
    use crate::config::VaultConfig;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::test_util::{entity, open_test_vault_with};

    // Seeds, all outside `PINNED_ID_BYTES`.
    const PARTY_SEED: u8 = 0x71;
    const CAMPAIGN_SEED: u8 = 0x72;
    const EVIDENCE_SEED: u8 = 0x73;
    const RECORDED_AT: u64 = 1_754_400_000;

    /// The projector's own door is crate-visible, so the stale-head plan a
    /// concurrent pair of requests produces is only expressible from inside the
    /// crate. The cross-module laws stay in
    /// `tests/campaign_stage_ladder_oracle.rs`.
    fn stage_vault() -> (tempfile::TempDir, Vault) {
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let (dir, vault) = open_test_vault_with(config);
        vault
            .put_entity(
                &entity(PARTY_SEED),
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"stage projector party",
            )
            .expect("put person");
        (dir, vault)
    }

    fn transition_to(stage: &str, previous: Option<EntityId>) -> StageProjectorInput {
        StageProjectorInput {
            party_ref: entity(PARTY_SEED),
            previous_stage_claim_ref: previous,
            value: CrmStageValue {
                campaign_ref: entity(CAMPAIGN_SEED),
                stage: StageKey(stage.to_owned()),
                evidence_class: StageEvidenceClass::MeaningfulReply,
                evidence_refs: vec![entity(EVIDENCE_SEED)],
                basis: EvidenceBasis::Machine,
                recorded_at: RECORDED_AT,
            },
        }
    }

    fn advance(vault: &Vault, input: &StageProjectorInput) -> EntityId {
        match project_stage_transition(vault, input, PromotionMode::Auto) {
            Ok(StageProjectResult::Advanced { new_claim_ref }) => new_claim_ref,
            other => panic!("expected an advanced stage, got {other:?}"),
        }
    }

    /// Every live `crm.stage` claim on the party, counted WITHOUT the one-head
    /// rule — the point of the test is whether a second head can exist at all.
    fn live_heads(vault: &Vault) -> Vec<EntityId> {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .claims_for_subject_in_txn(&rtxn, &entity(PARTY_SEED))
            .expect("claims for subject")
            .into_iter()
            .filter(|id| {
                vault
                    .get_claim_in_txn(&rtxn, id)
                    .expect("claim body")
                    .is_some_and(|body| {
                        body.predicate == PREDICATE_CRM_STAGE
                            && body.lifecycle == ClaimLifecycleStatus::Active
                    })
            })
            .collect()
    }

    #[test]
    fn a_proposal_against_a_stale_head_is_refused() {
        let (_dir, vault) = stage_vault();

        // Two requests plan from the same head. One of them advances first.
        let planned_from = advance(&vault, &transition_to("replied", None));
        let current = advance(&vault, &transition_to("call_booked", Some(planned_from)));

        // The other now lands its PROPOSAL against a head that no longer exists.
        // Beside the head that replaced it, it would be a second live head, and
        // a torn pair wedges every later transition on this (party, campaign).
        let stale = transition_to("call_held", Some(planned_from));
        let proposed = project_stage_transition(&vault, &stale, PromotionMode::Propose);
        assert!(
            matches!(proposed, Err(Error::InvalidClaimBody(_))),
            "{proposed:?}"
        );
        assert_eq!(
            live_heads(&vault),
            vec![current],
            "a refused proposal leaves the current head alone",
        );

        // The dial decides WHO rules on the transition, never whether the head
        // check holds: AUTO refuses the same stale plan.
        let advanced = project_stage_transition(&vault, &stale, PromotionMode::Auto);
        assert!(
            matches!(advanced, Err(Error::InvalidClaimBody(_))),
            "{advanced:?}"
        );
        assert_eq!(live_heads(&vault), vec![current]);
    }

    #[test]
    fn a_proposal_against_the_current_head_lands_proposed() {
        let (_dir, vault) = stage_vault();
        let current = advance(&vault, &transition_to("replied", None));

        let result = project_stage_transition(
            &vault,
            &transition_to("call_booked", Some(current)),
            PromotionMode::Propose,
        );
        let Ok(StageProjectResult::Proposed { proposed_claim_ref }) = result else {
            panic!("propose mode must return a proposed head, got {result:?}");
        };

        // Nothing was superseded: the proposal is a question, not a decision.
        let body = vault
            .get_claim(&proposed_claim_ref)
            .expect("read proposal")
            .expect("proposal exists");
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(
            vault
                .get_claim(&current)
                .expect("read head")
                .expect("head exists")
                .lifecycle,
            ClaimLifecycleStatus::Active,
        );
    }
}
