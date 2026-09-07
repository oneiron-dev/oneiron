//! Engine-only invocation boundary. A healer never receives a stamp or a minting API.

use std::collections::BTreeSet;

use crate::claim::ClaimSource;
use crate::error::{Error, Result};
use crate::gate::{
    PolicyApprovalCeiling, PolicyManifestResolution, evaluate_repair_consent, repair_criticality,
};
use crate::write_envelope::WriteActor;

use super::super::{MAX_EVENTS_PER_RUN, validate_ref, validate_token, validate_working_set};
use super::{
    DiagnosticEvent, DiagnosticWorkingSet, Healer, RepairActor, RepairBundle, ReviewedRepair,
    validate_repair_proposal,
};

/// Engine registration binds a specific implementation to its maintenance actor.
///
/// Only engine call sites construct this. Never fill these fields from a
/// proposal, diagnostic, external request, or healer-authored descriptor.
/// The definition ceiling must be resolved from current engine state for this
/// invocation; a missing agent definition must be supplied as Proposed.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct RegisteredHealer<'a> {
    pub(crate) healer_id: &'a str,
    pub(crate) actor: WriteActor,
    pub(crate) agent_definition_ceiling: Option<PolicyApprovalCeiling>,
    pub(crate) healer: &'a dyn Healer,
}

/// Engine-minted identity, created BEFORE the registered healer runs.
///
/// Public read access is for disclosure only. There is no public constructor,
/// deserializer, or mutable field. All healer output is Generated, even when a
/// proposal claims UserStated or an owner actor.
///
/// Healer implementations outside the engine cannot mint invocation authority:
///
/// ```compile_fail
/// use oneiron::self_heal::HealerInvocationStamp;
/// let mint = HealerInvocationStamp::mint;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealerInvocationStamp {
    healer_id: String,
    actor: RepairActor,
    run_ref: String,
    session_tag: String,
    agent_definition_ceiling: Option<PolicyApprovalCeiling>,
}

impl HealerInvocationStamp {
    pub(crate) fn mint(
        registration: &RegisteredHealer<'_>,
        run_ref: &str,
        session_tag: &str,
    ) -> Result<Self> {
        validate_token(registration.healer_id, "healer id is not a bounded token")?;
        validate_ref(run_ref)?;
        validate_ref(session_tag)?;
        crate::claim::validate_session_tag(session_tag)?;
        Ok(Self {
            healer_id: registration.healer_id.to_owned(),
            actor: RepairActor {
                actor_class: registration
                    .actor
                    .actor_class()
                    .gate_actor_class()
                    .to_owned(),
                actor_ref: registration.actor.entity_ref(),
            },
            run_ref: run_ref.to_owned(),
            session_tag: session_tag.to_owned(),
            agent_definition_ceiling: registration.agent_definition_ceiling,
        })
    }

    /// Registered engine identity, not a name returned by the healer.
    #[must_use]
    pub fn healer_id(&self) -> &str {
        &self.healer_id
    }

    /// Registered maintenance actor used for the Gate's authority and provenance.
    #[must_use]
    pub fn actor(&self) -> &RepairActor {
        &self.actor
    }

    /// Engine classification of healer output. Proposal disclosure cannot change it.
    #[must_use]
    pub const fn source(&self) -> ClaimSource {
        ClaimSource::Generated
    }

    /// Engine-supplied run coordinate, never taken from the triggering diagnostic.
    #[must_use]
    pub fn run_ref(&self) -> &str {
        &self.run_ref
    }

    /// Session chosen by the engine invocation boundary.
    #[must_use]
    pub fn session_tag(&self) -> &str {
        &self.session_tag
    }

    pub(crate) const fn agent_definition_ceiling(&self) -> Option<PolicyApprovalCeiling> {
        self.agent_definition_ceiling
    }
}

/// Runs one registered healer and returns only reviewed proposals.
///
/// The caller supplies a CURRENT manifest resolution and a bounded diagnostic
/// working set. This function does no reads or writes outside those values.
/// Invalid output rejects the whole bundle, never silently drops a poisoned
/// member. Diagnostic refs remain disclosure: resolving them is not authority.
/// There is no scheduler or execution path in this layer.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn run_healer_proposals(
    policy: &PolicyManifestResolution,
    registration: &RegisteredHealer<'_>,
    run_ref: &str,
    session_tag: &str,
    working_set: &DiagnosticWorkingSet<'_>,
    diagnostics: &[DiagnosticEvent],
) -> Result<RepairBundle> {
    validate_working_set(working_set)?;
    let invocation = HealerInvocationStamp::mint(registration, run_ref, session_tag)?;
    let mut proposals = registration.healer.propose(working_set, diagnostics);
    if proposals.len() > MAX_EVENTS_PER_RUN {
        return Err(Error::InvariantViolation("repair proposal ceiling"));
    }
    let mut ids = BTreeSet::new();
    for proposal in &mut proposals {
        proposal.session_tag = invocation.session_tag().to_owned();
        validate_repair_proposal(proposal, invocation.session_tag())?;
        if !ids.insert(proposal.proposal_id) {
            return Err(Error::InvariantViolation("duplicate repair proposal id"));
        }
    }
    let proposals = proposals
        .into_iter()
        .map(|proposal| {
            let criticality = repair_criticality(policy, &invocation, &proposal);
            let (route, decision) = evaluate_repair_consent(policy, &invocation, &proposal);
            ReviewedRepair {
                proposal,
                invocation: invocation.clone(),
                criticality,
                route,
                reason_codes: decision
                    .reason_codes()
                    .iter()
                    .map(|reason| reason.as_str().to_owned())
                    .collect(),
            }
        })
        .collect();
    Ok(RepairBundle {
        session_tag: invocation.session_tag().to_owned(),
        proposals,
    })
}
