//! Moved from `crates/oneiron/src/genui/consent_eval.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::disclosure_rung::DisclosureRung;
use crate::genui::consent_cards::BundleApprovalScope;
use crate::genui::consent_cards::ConsentScopeEscalator;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_lens_wire::lens::atom::LensText;
use serde::Deserialize;
use serde::Serialize;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentSurface {
    CompanionConversation,
    Dashboard,
    SharedSlack,
    McpUi,
    Voice,
}

impl ConsentSurface {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompanionConversation => "companion_conversation",
            Self::Dashboard => "dashboard",
            Self::SharedSlack => "shared_slack",
            Self::McpUi => "mcp_ui",
            Self::Voice => "voice",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentActionKind {
    Approve,
    Decline,
    Escalate(ConsentScopeEscalator),
    BundleApprove(BundleApprovalScope),
    ProjectMint,
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
    /// Allows publishing updates to exactly one artifact.
    ArtifactPublish {
        artifact: String,
    },
    /// One calendar shared at one rung with the intent's `principal_ref`.
    Calendar {
        calendar_ref: String,
        rung: DisclosureRung,
    },
}

/// The reason a consent card's receipt names for a valid tap by someone
/// other than its principal (FIX 9859): it decides nothing and mints no
/// authority.
pub const CONSENT_NOOP_NON_PRINCIPAL_REASON: &str = "consent_actor:non_principal";

pub const fn widening_grant_surface_is_eligible(surface: ConsentSurface) -> bool {
    matches!(
        surface,
        ConsentSurface::CompanionConversation | ConsentSurface::Dashboard | ConsentSurface::McpUi
    )
}

pub fn ensure_principal_ref(principal_ref: &str) -> Result<()> {
    if principal_ref.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "consent principal_ref must not be empty".to_string(),
        ));
    }
    Ok(())
}

pub fn required_scope_ref<'a>(scope: &str, value: Option<&'a str>) -> Result<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::InvalidConfig(format!("{scope} requires a bound scope ref")))
}

pub fn non_empty(context: &str, value: String) -> Result<String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(Error::InvalidConfig(format!("{context} must not be empty")));
    }
    Ok(value)
}

pub fn lens_text(value: impl Into<String>) -> Result<LensText> {
    LensText::new(value)
}
