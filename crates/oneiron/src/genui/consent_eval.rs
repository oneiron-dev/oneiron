//! DEC-0006 action vocabulary, request/decision/intent types and evaluation helpers.

use super::protocol::{Of336ActionDescriptor, Of336ComponentKind};
use crate::booking::DisclosureRung;
use crate::consent::AuthenticatedOwner;
use crate::error::GateError;
use crate::receipt::{ReceiptKind, ReceiptRecord};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[doc(hidden)]
pub use oneiron_records::genui::consent_eval::{
    CONSENT_ACTION_APPROVE_ONCE, CONSENT_ACTION_DECLINE, CONSENT_ACTION_ESCALATE_PREFIX,
    CONSENT_BUNDLE_ACTION_DECLINE, CONSENT_BUNDLE_ACTION_ID_PREFIX,
    CONSENT_NOOP_NON_PRINCIPAL_REASON, ConsentActionDecision, ConsentActionKind,
    ConsentConfirmOutcome, ConsentSurface, GrantMintIntent, GrantMintIntentScope,
};
#[doc(hidden)]
pub(super) use oneiron_records::genui::consent_eval::{
    ensure_principal_ref, lens_text, non_empty, required_scope_ref,
    widening_grant_surface_is_eligible,
};

/// Whether an emitted ask action id offers a duration/expiry choice.
///
/// Invariant 9 kills duration pickers everywhere the owner answers an ask; the
/// one named exception is a mint-time field on the ARCH-0071 delegation
/// record, which is not an ask option and never reaches this vocabulary.
#[must_use]
pub fn consent_action_id_offers_duration(action_id: &str) -> bool {
    const DURATION_TOKENS: [&str; 6] = ["duration", "expire", "expiry", "ttl", "until", "days"];
    DURATION_TOKENS
        .iter()
        .any(|token| action_id.contains(token))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "identity", rename_all = "snake_case")]
pub enum ConsentActorIdentity {
    SurfaceActor { actor_ref: String },
    VoicePath { speaker_ref: String },
}

impl ConsentActorIdentity {
    #[must_use]
    pub fn actor_ref(&self) -> &str {
        match self {
            Self::SurfaceActor { actor_ref } => actor_ref,
            Self::VoicePath { speaker_ref, .. } => speaker_ref,
        }
    }

    /// A voice label is never a principal credential, even when the engine
    /// matched an enrolled print. Only an authenticated account/device actor
    /// can confirm a widening grant.
    #[must_use]
    pub fn authenticates_principal(&self, principal_ref: &str) -> bool {
        !principal_ref.trim().is_empty()
            && matches!(self, Self::SurfaceActor { actor_ref } if !actor_ref.trim().is_empty() && actor_ref == principal_ref)
    }

    /// A store-authenticated owner handle and an account/device actor are both
    /// necessary. A voice claim cannot borrow a handle from another channel.
    /// The handle is revalidated on `vault`: it decides an act, so a proof
    /// another vault authenticated, or a revoked one, names no principal here.
    ///
    /// # Errors
    /// The proof does not revalidate on `vault`, or a storage error.
    pub fn authenticates_owner(
        &self,
        vault: &crate::Vault,
        principal_ref: &str,
        authenticated_owner: &AuthenticatedOwner,
    ) -> Result<bool> {
        Ok(
            authenticated_owner.revalidate_principal_ref(vault)? == principal_ref
                && self.authenticates_principal(principal_ref),
        )
    }

    /// [`Self::authenticates_owner`] on the person tier, for the asked
    /// person's own refusal: a decline decides no act, so the person need not
    /// own this vault.
    ///
    /// # Errors
    /// The proof does not revalidate on `vault`, or a storage error.
    pub fn authenticates_person(
        &self,
        vault: &crate::Vault,
        principal_ref: &str,
        authenticated_owner: &AuthenticatedOwner,
    ) -> Result<bool> {
        Ok(
            authenticated_owner.revalidate_person_principal_ref(vault)? == principal_ref
                && self.authenticates_principal(principal_ref),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentActionRequest {
    pub component_id: String,
    pub action_id: String,
    pub action: ConsentActionKind,
    pub actor: ConsentActorIdentity,
    pub surface: ConsentSurface,
    pub occurred_at: u64,
}

impl ConsentActionRequest {
    pub fn new(
        component_id: impl Into<String>,
        action_id: impl Into<String>,
        action: ConsentActionKind,
        actor: ConsentActorIdentity,
        surface: ConsentSurface,
        occurred_at: u64,
    ) -> Result<Self> {
        Ok(Self {
            component_id: non_empty("consent action component_id", component_id.into())?,
            action_id: non_empty("consent action action_id", action_id.into())?,
            action,
            actor,
            surface,
            occurred_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentActionEvaluation {
    pub decision: ConsentActionDecision,
    pub receipt: ReceiptRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_mint_intent: Option<GrantMintIntent>,
}

/// Converts one bounded calendar-sharing sentence into exactly one
/// [`GrantMintIntent`].
///
/// The agent-facing input is a sentence — "share my work calendar fully with
/// Yuki" — already resolved upstream to typed refs and a rung. This seam turns
/// that into a single `(calendar_ref, audience, rung)` grant intent, where the
/// audience is the intent's `principal_ref`. It never fans the sentence out
/// into a settings matrix: one sentence mints one scope, or it errors.
pub fn calendar_grant_mint_intent(
    principal_ref: &str,
    origin_component_id: &str,
    origin_action_id: &str,
    origin_receipt_ref: Option<&str>,
    calendar_ref: &str,
    rung: DisclosureRung,
) -> Result<GrantMintIntent> {
    Ok(GrantMintIntent {
        principal_ref: non_empty("calendar grant principal_ref", principal_ref.to_owned())?,
        origin_component_id: non_empty(
            "calendar grant origin_component_id",
            origin_component_id.to_owned(),
        )?,
        origin_action_id: non_empty(
            "calendar grant origin_action_id",
            origin_action_id.to_owned(),
        )?,
        origin_receipt_ref: origin_receipt_ref.map(str::to_owned),
        scope: GrantMintIntentScope::Calendar {
            calendar_ref: non_empty("calendar grant calendar_ref", calendar_ref.to_owned())?,
            rung,
        },
    })
}

pub(super) fn consent_evaluation(
    component_kind: Of336ComponentKind,
    component_id: &str,
    principal_ref: &str,
    request: &ConsentActionRequest,
    decision: ConsentActionDecision,
    grant_mint_intent: Option<GrantMintIntent>,
) -> ConsentActionEvaluation {
    ConsentActionEvaluation {
        decision,
        receipt: consent_receipt(
            component_kind,
            component_id,
            principal_ref,
            request,
            decision,
            None,
        ),
        grant_mint_intent,
    }
}

pub(super) fn ensure_authenticated_actor(
    vault: &crate::Vault,
    principal_ref: &str,
    request: &ConsentActionRequest,
    authenticated_owner: &AuthenticatedOwner,
) -> Result<()> {
    // A decline is the asked person's own refusal; every other action
    // decides an act, so it takes the owner tier.
    let authenticated = if matches!(request.action, ConsentActionKind::Decline) {
        request
            .actor
            .authenticates_person(vault, principal_ref, authenticated_owner)?
    } else {
        request
            .actor
            .authenticates_owner(vault, principal_ref, authenticated_owner)?
    };
    if authenticated {
        return Ok(());
    }
    Err(Error::Gate(GateError::ConsentUnauthenticatedActor(
        "the action actor is not bound to the card's store-authenticated principal",
    )))
}

/// Whether the tapping actor is the card's principal (FIX 9859). The proof
/// is revalidated on the person tier first, so a live person who is not the
/// principal answers `false`, for a receipted no-op, whatever tier their
/// credential has. The principal's own decline is a person-tier act; any
/// other action the principal takes decides an act, so it still takes the
/// owner tier, as [`ensure_authenticated_actor`] asks.
///
/// # Errors
/// The proof does not revalidate on `vault` (revoked, foreign or not a live
/// person), the principal lacks the owner tier for an act, or a storage
/// error.
pub(super) fn actor_is_card_principal(
    vault: &crate::Vault,
    principal_ref: &str,
    request: &ConsentActionRequest,
    authenticated_owner: &AuthenticatedOwner,
) -> Result<bool> {
    if !request
        .actor
        .authenticates_person(vault, principal_ref, authenticated_owner)?
    {
        return Ok(false);
    }
    ensure_authenticated_actor(vault, principal_ref, request, authenticated_owner)?;
    Ok(true)
}

pub(super) fn noop_policy_rejection(
    component_kind: Of336ComponentKind,
    component_id: &str,
    principal_ref: &str,
    request: &ConsentActionRequest,
    decision: ConsentActionDecision,
    reason: &str,
) -> ConsentActionEvaluation {
    ConsentActionEvaluation {
        decision,
        receipt: consent_receipt(
            component_kind,
            component_id,
            principal_ref,
            request,
            decision,
            Some(reason),
        ),
        grant_mint_intent: None,
    }
}

fn consent_receipt(
    component_kind: Of336ComponentKind,
    component_id: &str,
    principal_ref: &str,
    request: &ConsentActionRequest,
    decision: ConsentActionDecision,
    reason: Option<&str>,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(
        "component_kind".to_owned(),
        component_kind.as_str().to_owned(),
    );
    fields.insert("component_id".to_owned(), component_id.to_owned());
    fields.insert("action_id".to_owned(), request.action_id.clone());
    fields.insert("surface".to_owned(), request.surface.as_str().to_owned());
    fields.insert(
        "expected_principal_ref".to_owned(),
        principal_ref.to_owned(),
    );
    if let Some(reason) = reason {
        fields.insert("reason".to_owned(), reason.to_owned());
    }

    ReceiptRecord {
        receipt_id: format!(
            "consent:{}:{}:{}",
            component_id, request.action_id, request.occurred_at
        ),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: request.occurred_at,
        actor: Some(request.actor.actor_ref().to_owned()),
        on_behalf_of: Some(principal_ref.to_owned()),
        outcome: decision.outcome().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("of336:{component_id}")),
        policy_trace: reason.map_or_else(
            || vec!["principal_auth:principal_bound".to_owned()],
            |reason| vec![reason.to_owned()],
        ),
        fields,
    }
}

pub(super) fn ensure_component_request(
    card_id: &str,
    request: &ConsentActionRequest,
) -> Result<()> {
    if request.component_id == card_id {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "consent action targets component {:?}, expected {:?}",
        request.component_id, card_id
    )))
}

pub(super) fn ensure_declared_action(
    actions: &[Of336ActionDescriptor],
    request: &ConsentActionRequest,
) -> Result<()> {
    let Some(action) = actions
        .iter()
        .find(|action| action.action_id == request.action_id)
    else {
        return Err(Error::InvalidConfig(format!(
            "consent action {:?} was not declared by component {:?}",
            request.action_id, request.component_id
        )));
    };
    if action.action == request.action {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "consent action {:?} payload does not match declared typed action",
        request.action_id
    )))
}
