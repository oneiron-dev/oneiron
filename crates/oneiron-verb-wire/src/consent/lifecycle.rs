//! Moved from `crates/oneiron/src/consent/lifecycle.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::AudienceBound;
use oneiron_store::consent_bound::DisclosureClass;
use oneiron_store::consent_bound::DisclosureEnvelope;
use oneiron_store::consent_bound::GrantBound;
use oneiron_store::consent_bound::normalized_ref;
use serde::Deserialize;
use serde::Serialize;

/// Approve the exact engine-emitted effect digest, never a caller's description.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveOnceRequest {
    pub effect_digest: String,
}

/// Deny the exact effect the engine emitted, with the same digest grammar as approval.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenyConsentRequest {
    pub effect_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateStandingGrantRequest {
    pub bound: StandingGrantBound,
}

/// Action and disclosure bounds are disjoint, including on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum StandingGrantBound {
    Action(ActionBoundRequest),
    Disclosure(DisclosureBoundRequest),
}

/// Actor (a lineage for stop-asking), action class and bounded envelope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionBoundRequest {
    pub actor: String,
    pub class: String,
    pub envelope: ActionEnvelopeRequest,
}

/// Project and audience selectors, pinned to that project, with a per-use cap.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionEnvelopeRequest {
    pub project: String,
    pub audience: Vec<String>,
    /// A reviewed batch's count; absent for a standing no-press grant.
    /// Zero leaves every send needing the person's press.
    #[serde(default)]
    pub budget: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureBoundRequest {
    pub audience: Vec<String>,
    pub class: String,
    pub envelope: DisclosureEnvelopeRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureEnvelopeRequest {
    pub selectors: Vec<String>,
}

impl StandingGrantBound {
    fn into_bound(self) -> oneiron_base::error::Result<GrantBound> {
        match self {
            Self::Action(bound) => {
                let project = normalized_ref("project", bound.envelope.project)?;
                let mut selectors = vec![format!("project:{project}")];
                for member in bound.envelope.audience {
                    let member = normalized_ref("action audience member", member)?;
                    selectors.push(format!("audience:{member}"));
                }
                let mut envelope = ActionEnvelope::new(selectors)?.with_target(project)?;
                if let Some(budget) = bound.envelope.budget {
                    envelope = envelope.with_budget(budget);
                }
                GrantBound::action(
                    ActorBound::new(bound.actor)?,
                    ActionClass::new(bound.class)?,
                    envelope,
                )
            }
            Self::Disclosure(bound) => GrantBound::disclosure(
                AudienceBound::new(bound.audience)?,
                DisclosureClass::new(bound.class)?,
                DisclosureEnvelope::new(bound.envelope.selectors)?,
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrantRequest {
    /// The standing grant's bound digest, as emitted by its receipt or registry.
    pub grant: String,
}
