//! A run's browser sends under the owner's consent (FIX 10422).
//!
//! A standing action grant of a browser effect class (`send`, `publish`,
//! ...) covers a send only inside the scope its owner gave it: its actor,
//! the project it names (its `project:` selectors and its target) and the
//! audience it names (its `audience:` selectors), each matched by the bound's
//! own containment ([`GrantBound::contains`]). An axis a grant leaves open
//! covers every send on it, so a grant that names no project or audience
//! covers every send of its class by its actor. Where a send runs
//! ([`super::EffectPlace`]) is never enough on its own.
//!
//! An owner's press on one send names [`browser_approve_once_digest`]: the
//! Gate's own composer over the send's facts, pinned as an
//! `ApprovalTarget::Browser`, the same builder for the digest the owner is
//! shown and the one the send spends.

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::gate::{
    ApprovalTarget, BrowserSendTarget, ExternalEffectGateInput, GateActor, GateProvenanceHandles,
    GateReasonCode,
};

use super::bound::{
    ActionClass, ActionEnvelope, ActorBound, BoundClass, BoundEnvelope, GrantBound,
};
use super::doors::ConsentEvaluation;
use super::effect::{ConsentDecision, EffectDigest};
use super::grant::StandingConsentGrant;

/// The channel a browser send's Gate input names.
const BROWSER_CHANNEL: &str = "browser";

/// The selector a grant names its project by, before the project's id.
const PROJECT_SELECTOR: &str = "project:";

/// The selector a grant names one audience member by, before the member.
const AUDIENCE_SELECTOR: &str = "audience:";

/// Who sends from a run's browser, and where: the axes a standing browser
/// grant is scoped on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSendScope {
    /// The call's verified caller.
    pub actor: EntityId,
    pub actor_class: EdgeActorClass,
    /// The project the run sends in, when its host knows one.
    pub project: Option<EntityId>,
    /// The audience or recipient the send reaches, when its host knows one.
    pub audience: Option<String>,
}

/// One classified browser send, as its host observed it (FIX 10422): who
/// sends and where, the run, the call it belongs to and its stable position
/// there, the effect class and act, the page and the read of it the row came
/// from, the row's locator, and the act's own input. Handles only, never a
/// secret's bytes: a secret the act types is named by its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserConsentFacts {
    pub scope: BrowserSendScope,
    pub run: EntityId,
    /// The call the send belongs to.
    pub attempt: EntityId,
    /// The send's position in that call, the same on every replay of it.
    pub ordinal: u64,
    /// The effect class the row's name marks.
    pub class: String,
    /// The act: `self.browser.click`, `self.browser.click_at`, ...
    pub verb: String,
    /// The page the act began on.
    pub page: Option<String>,
    /// The read of the page the row came from.
    pub revision: Option<String>,
    /// The row's locator.
    pub target: String,
    /// The act's own input, as JSON text.
    pub operands: String,
}

impl BrowserSendScope {
    /// Whether standing `grant` covers a send of `class` from this scope
    /// (FIX 10422): an action grant of that class whose whole bound holds
    /// the send. Its actor must be this scope's actor, of its class where
    /// the grant names one; a project it names must be this scope's, where
    /// it knows one; an audience it names must hold this scope's audience,
    /// where it knows one. A run whose host knows no project keeps today's
    /// cover on that axis (restriction rubric 1, FIX 11906). Its budget is
    /// not read here: that is the reviewed batch its caller runs the class
    /// under.
    #[must_use]
    pub fn covered_by(&self, grant: &StandingConsentGrant, class: &str) -> bool {
        let StandingConsentGrant::Action(_) = grant else {
            return false;
        };
        let bound = grant.bound();
        let BoundEnvelope::Action(envelope) = bound.envelope() else {
            return false;
        };
        self.send_bound(class, envelope)
            .is_some_and(|send| bound.contains(&send))
    }

    /// The bound one send of `class` from this scope is, against a grant
    /// whose envelope is `envelope`: that envelope's own selectors, its
    /// `project:` ones standing for this scope's project and its
    /// `audience:` ones for this scope's audience where it knows one; the
    /// project as its target; and the envelope's own budget, so the budget
    /// never decides cover. Where this scope knows no project or audience,
    /// the envelope's own selectors and target stand on that axis.
    fn send_bound(&self, class: &str, envelope: &ActionEnvelope) -> Option<GrantBound> {
        let names = |prefix: &str| {
            envelope
                .selectors()
                .iter()
                .any(|selector| selector.starts_with(prefix))
        };
        let project = self.project.map(|project| project.to_hex());
        let mut selectors: Vec<String> = envelope
            .selectors()
            .iter()
            .filter(|selector| {
                !(project.is_some() && selector.starts_with(PROJECT_SELECTOR))
                    && !(self.audience.is_some() && selector.starts_with(AUDIENCE_SELECTOR))
            })
            .cloned()
            .collect();
        if names(PROJECT_SELECTOR)
            && let Some(project) = &project
        {
            selectors.push(format!("{PROJECT_SELECTOR}{project}"));
        }
        if names(AUDIENCE_SELECTOR)
            && let Some(audience) = &self.audience
        {
            selectors.push(format!("{AUDIENCE_SELECTOR}{audience}"));
        }
        let mut send = ActionEnvelope::new(selectors).ok()?;
        if let Some(target) = project.or_else(|| envelope.target().map(str::to_owned)) {
            send = send.with_target(target).ok()?;
        }
        if let Some(budget) = envelope.budget() {
            send = send.with_budget(budget);
        }
        let actor = ActorBound::new(self.actor.to_hex())
            .and_then(|actor| actor.with_actor_class(self.actor_class.gate_actor_class()))
            .ok()?;
        GrantBound::action(actor, ActionClass::new(class).ok()?, send).ok()
    }
}

/// The approve-once digest an owner's press on one browser send names (FIX
/// 10422): the Gate's own composer over the send's pinned input, the one
/// builder for the digest the owner is shown and the one the send spends.
///
/// # Errors
/// Facts no consent bound can be built from (an empty class).
pub fn browser_approve_once_digest(facts: &BrowserConsentFacts) -> Result<EffectDigest> {
    crate::gate::external_effect_approval_digest(&browser_pinned_gate_input(facts)).ok_or(
        Error::Gate(GateError::InvalidConsentBound(
            "a browser send's facts compose no approve-once digest",
        )),
    )
}

/// The Gate input of one browser send of `facts`: its actor sending on the
/// browser channel under its effect class, with the send's typed target
/// beside it. The one place a browser send's pinned input is built.
fn browser_pinned_gate_input(facts: &BrowserConsentFacts) -> ExternalEffectGateInput {
    let scope = &facts.scope;
    let target = BrowserSendTarget {
        actor_class: scope.actor_class.gate_actor_class(),
        run: facts.run,
        attempt: facts.attempt,
        ordinal: facts.ordinal,
        verb: facts.verb.clone(),
        project: scope.project,
        audience: scope.audience.clone(),
        page: facts.page.clone(),
        revision: facts.revision.clone(),
        target: facts.target.clone(),
        operands_digest: *blake3::hash(facts.operands.as_bytes()).as_bytes(),
    };
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: scope.actor_class.gate_actor_class().to_owned(),
            actor_ref: Some(scope.actor.to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(scope.actor),
            approval_target: Some(ApprovalTarget::Browser(target)),
            ..GateProvenanceHandles::default()
        },
        verb: facts.class.clone(),
        channel: BROWSER_CHANNEL.to_owned(),
        channel_identity_ref: None,
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: false,
        has_permission: false,
        policy_risk: crate::gate::ExternalEffectPolicyRisk::Normal,
        send_autonomy: None,
    }
}

impl Vault {
    /// The consent verdict on one browser send (FIX 10422), read from the
    /// active standing grants of its class: `Auto` when one covers it whole
    /// ([`BrowserSendScope::covered_by`]) with no budget, a send that runs
    /// with no press; else `Ask`, naming a bound exceeded where a grant of
    /// its class stands but none covers it. A budgeted grant's reviewed
    /// batch is a press over the batch, so it answers `Ask` here. It spends
    /// and records nothing.
    ///
    /// # Errors
    /// Storage errors.
    pub fn evaluate_browser_send(&self, facts: &BrowserConsentFacts) -> Result<ConsentEvaluation> {
        let grants = self.active_standing_consent_grants()?;
        let of_class: Vec<&StandingConsentGrant> = grants
            .iter()
            .filter(|grant| {
                matches!(
                    grant.bound().class(),
                    BoundClass::Action(class) if class.as_str() == facts.class
                )
            })
            .collect();
        let covered = of_class.iter().any(|grant| {
            let unbudgeted = match grant.bound().envelope() {
                BoundEnvelope::Action(envelope) => envelope.budget().is_none(),
                BoundEnvelope::Disclosure(_) => false,
            };
            unbudgeted && facts.scope.covered_by(grant, &facts.class)
        });
        if covered {
            return Ok(ConsentEvaluation {
                decision: ConsentDecision::Auto,
                reason_codes: Vec::new(),
                bypassed_by: None,
            });
        }
        let reason = if of_class.is_empty() {
            GateReasonCode::PendingConsentIrreversibleEffect
        } else {
            GateReasonCode::PendingConsentBoundExceeded
        };
        Ok(ConsentEvaluation {
            decision: ConsentDecision::Ask,
            reason_codes: vec![reason.as_str().to_owned()],
            bypassed_by: None,
        })
    }

    /// The project run `run`'s browser sends in (FIX 10422): a pumped agent
    /// run is its dispatch's leased try, and sends in the project that
    /// dispatch was given. `None` for a run that is no agent dispatch's try
    /// (a credential's or a turn program's), or one given no project.
    ///
    /// # Errors
    /// Storage errors.
    pub fn browser_run_project(&self, run: EntityId) -> Result<Option<EntityId>> {
        let attempt = crate::attempt_queue::AttemptId::from_bytes(run.as_bytes())?;
        Ok(crate::attempt_queue::AttemptQueue::new(self)
            .get(attempt)?
            .as_ref()
            .and_then(crate::agent_dispatch::record_dispatch_input)
            .and_then(|input| input.project_ref))
    }
}
