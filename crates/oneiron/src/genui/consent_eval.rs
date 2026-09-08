//! DEC-0006 action vocabulary, request/decision/intent types and evaluation helpers.

use super::consent_cards::{BundleApprovalScope, ConsentScopeEscalator};
use super::protocol::{Of336ActionDescriptor, Of336ComponentKind};
use crate::booking::DisclosureRung;
use crate::consent::AuthenticatedOwner;
use crate::lens::{
    ButtonControl, LensAtom, LensAtomId, LensNode, LensText, MetaLineAtom, SelfUiAction,
    SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiValue,
};
use crate::receipt::{ReceiptKind, ReceiptRecord};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// DEC-0006 invariant 9 arming — surface (a), the in-moment ask
// ---------------------------------------------------------------------------

/// Action id of the approve-once outcome — the DEFAULT of the confirm trio.
pub const CONSENT_ACTION_APPROVE_ONCE: &str = "approve_once";

/// Action id of the deny outcome.
pub const CONSENT_ACTION_DECLINE: &str = "decline";

/// Action id prefix of the approve-and-stop-asking outcome. The suffix names
/// WHICH bound the owner is stamping ([`ConsentScopeEscalator::as_str`]), so a
/// stop-asking tap is always bound to one row rather than a blanket "yes".
pub const CONSENT_ACTION_ESCALATE_PREFIX: &str = "escalate_";

/// Action id prefix of the BATCH form of the same ask — the ARCH-0072
/// admission slate. It is surface (a) in batch form, not a third surface.
pub const CONSENT_BUNDLE_ACTION_ID_PREFIX: &str = "approve_bundle_";

/// Action id of the batch decline.
pub const CONSENT_BUNDLE_ACTION_DECLINE: &str = "decline_bundle";

/// The three outcomes DEC-0006 invariant 2 pins for EVERY manual confirm,
/// including a scope-exceed escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentConfirmOutcome {
    /// Approve once — the default.
    ApproveOnce,
    /// Approve and stop asking: the in-moment path into
    /// `Vault::create_standing_grant`, bounded to one grant row under the same
    /// owner stamp.
    ApproveAndStopAsking,
    /// Deny.
    Deny,
}

impl ConsentConfirmOutcome {
    /// The trio, in offer order — approve once is first because it is the
    /// default. There is deliberately no fourth outcome and no duration
    /// option: the registry replaces expiry-guessing (invariant 9).
    #[must_use]
    pub const fn trio() -> [Self; 3] {
        [Self::ApproveOnce, Self::ApproveAndStopAsking, Self::Deny]
    }

    /// Which outcome an emitted ask action id maps to.
    ///
    /// The escalator ids are the approve-and-stop-asking outcome: each one
    /// stamps ONE bound (contact / verb-class / channel), which is what makes
    /// stop-asking an owner act on a row rather than an inference.
    /// `escalate_just_once` is the escalator vocabulary's own restatement of
    /// approve-once and maps there.
    #[must_use]
    pub fn from_action_id(action_id: &str) -> Option<Self> {
        match action_id {
            CONSENT_ACTION_APPROVE_ONCE => Some(Self::ApproveOnce),
            CONSENT_ACTION_DECLINE | CONSENT_BUNDLE_ACTION_DECLINE => Some(Self::Deny),
            _ => {
                if let Some(scope) = action_id.strip_prefix(CONSENT_ACTION_ESCALATE_PREFIX) {
                    return Some(if scope == ConsentScopeEscalator::JustOnce.as_str() {
                        Self::ApproveOnce
                    } else {
                        Self::ApproveAndStopAsking
                    });
                }
                // A bundle approve is the batch form of approve-and-stop-asking:
                // one tap accepts the slate's drafted rows.
                action_id
                    .starts_with(CONSENT_BUNDLE_ACTION_ID_PREFIX)
                    .then_some(Self::ApproveAndStopAsking)
            }
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentSurface {
    EiriConversation,
    Dashboard,
    SharedSlack,
    McpUi,
    Voice,
}

impl ConsentSurface {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EiriConversation => "eiri_conversation",
            Self::Dashboard => "dashboard",
            Self::SharedSlack => "shared_slack",
            Self::McpUi => "mcp_ui",
            Self::Voice => "voice",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "identity", rename_all = "snake_case")]
pub enum ConsentActorIdentity {
    SurfaceActor {
        actor_ref: String,
    },
    VoicePath {
        speaker_ref: String,
        owner_voice_print_verified: bool,
    },
}

impl ConsentActorIdentity {
    #[must_use]
    pub fn actor_ref(&self) -> &str {
        match self {
            Self::SurfaceActor { actor_ref } => actor_ref,
            Self::VoicePath { speaker_ref, .. } => speaker_ref,
        }
    }

    #[must_use]
    pub fn authenticates_principal(&self, principal_ref: &str) -> bool {
        if principal_ref.trim().is_empty() || self.actor_ref().trim().is_empty() {
            return false;
        }
        match self {
            Self::SurfaceActor { actor_ref } => actor_ref == principal_ref,
            Self::VoicePath {
                speaker_ref,
                owner_voice_print_verified,
            } => *owner_voice_print_verified && speaker_ref == principal_ref,
        }
    }

    /// Whether this claimed actor matches a store-authenticated owner handle.
    ///
    /// Consent action evaluation uses this door: neither actor text nor the
    /// caller-deserialized voice boolean is authority. The handle can only come
    /// from [`crate::Vault::authenticate_owner`].
    #[must_use]
    pub fn authenticates_owner(
        &self,
        principal_ref: &str,
        authenticated_owner: &AuthenticatedOwner,
    ) -> bool {
        !principal_ref.trim().is_empty()
            && !self.actor_ref().trim().is_empty()
            && authenticated_owner.principal_ref() == principal_ref
            && self.actor_ref() == principal_ref
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentActionKind {
    Approve,
    Decline,
    Escalate(ConsentScopeEscalator),
    BundleApprove(BundleApprovalScope),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentActionDecision {
    ApprovedOnce,
    Declined,
    GrantMintIntent,
    NoopNonPrincipal,
    NoopSurfaceIneligible,
    NoopBeneficiaryConfirm,
}

impl ConsentActionDecision {
    #[must_use]
    pub const fn outcome(self) -> &'static str {
        match self {
            Self::ApprovedOnce => "approved",
            Self::Declined => "declined",
            Self::GrantMintIntent => "grant_mint_intent",
            Self::NoopNonPrincipal => "no_op_non_principal",
            Self::NoopSurfaceIneligible => "no_op_surface_ineligible",
            Self::NoopBeneficiaryConfirm => "no_op_beneficiary_confirm",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentActionEvaluation {
    pub decision: ConsentActionDecision,
    pub receipt: ReceiptRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_mint_intent: Option<GrantMintIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantMintIntent {
    pub principal_ref: String,
    pub origin_component_id: String,
    pub origin_action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_receipt_ref: Option<String>,
    pub scope: GrantMintIntentScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum GrantMintIntentScope {
    JustOnce {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        effect_ref: Option<String>,
    },
    Contact {
        contact_ref: String,
    },
    VerbClass {
        verb_class: String,
    },
    Channel {
        channel: String,
    },
    BundleExactSends {
        send_refs: Vec<String>,
    },
    BriefVerbClass {
        brief_ref: String,
        verb_class: String,
    },
    /// One calendar shared at one rung with the intent's `principal_ref`.
    Calendar {
        calendar_ref: String,
        rung: DisclosureRung,
    },
}

/// Converts one bounded calendar-sharing sentence into exactly one
/// [`GrantMintIntent`].
///
/// The agent-facing input is a sentence — "share my work calendar fully with
/// Yura" — already resolved upstream to typed refs and a rung. This seam turns
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

pub(super) fn append_eirispec_actions(
    elements: &mut serde_json::Map<String, Value>,
    root_children: &mut Vec<String>,
    actions: &[Of336ActionDescriptor],
) {
    for action in actions {
        let id = action.action_id.clone();
        root_children.push(id.clone());
        elements.insert(
            id,
            json!({
                "type": "button",
                "props": {
                    "label": action.label,
                    "action": {
                        "kind": "agentCallback",
                        "name": action.action_id,
                        "typedAction": action.action
                    }
                },
                "children": [],
                "fallbackText": action.label
            }),
        );
    }
}

pub(super) fn action_button_node(action: Of336ActionDescriptor) -> Result<LensNode> {
    Ok(LensNode::new(
        atom_id(format!("action-{}", action.action_id))?,
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: control_id(&action.action_id)?,
            label: lens_text(action.label)?,
            action: SelfUiAction {
                command: action_id(action_command(&action.action))?,
                args: vec![SelfUiValue::Text(lens_text(action.action_id)?)],
            },
        })),
    ))
}

fn action_command(action: &ConsentActionKind) -> &'static str {
    match action {
        ConsentActionKind::Approve => "consent_approve",
        ConsentActionKind::Decline => "consent_decline",
        ConsentActionKind::Escalate(_) => "consent_grant_mint",
        ConsentActionKind::BundleApprove(_) => "bundle_grant_mint",
    }
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
    principal_ref: &str,
    request: &ConsentActionRequest,
    authenticated_owner: &AuthenticatedOwner,
) -> Result<()> {
    if request
        .actor
        .authenticates_owner(principal_ref, authenticated_owner)
    {
        return Ok(());
    }
    Err(Error::ConsentUnauthenticatedActor(
        "the action actor is not bound to the card's store-authenticated principal",
    ))
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

pub(super) const fn widening_grant_surface_is_eligible(surface: ConsentSurface) -> bool {
    matches!(
        surface,
        ConsentSurface::EiriConversation | ConsentSurface::Dashboard | ConsentSurface::McpUi
    )
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

pub(super) fn ensure_principal_ref(principal_ref: &str) -> Result<()> {
    if principal_ref.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "consent principal_ref must not be empty".to_string(),
        ));
    }
    Ok(())
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

pub(super) fn required_scope_ref<'a>(scope: &str, value: Option<&'a str>) -> Result<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::InvalidConfig(format!("{scope} requires a bound scope ref")))
}

pub(super) fn non_empty(context: &str, value: String) -> Result<String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(Error::InvalidConfig(format!("{context} must not be empty")));
    }
    Ok(value)
}

pub(super) fn lens_text(value: impl Into<String>) -> Result<LensText> {
    LensText::new(value)
}

pub(super) fn atom_id(value: impl Into<String>) -> Result<LensAtomId> {
    LensAtomId::new(value)
}

fn control_id(value: &str) -> Result<SelfUiControlId> {
    SelfUiControlId::new(value)
}

fn action_id(value: &str) -> Result<SelfUiActionId> {
    SelfUiActionId::new(value)
}

pub(super) fn meta_line(label: &str, value: &str) -> Result<MetaLineAtom> {
    Ok(MetaLineAtom {
        label: lens_text(label)?,
        value: lens_text(value)?,
    })
}
