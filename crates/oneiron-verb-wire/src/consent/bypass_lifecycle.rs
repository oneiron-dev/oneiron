//! Moved from `crates/oneiron/src/consent/bypass_lifecycle.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_consent_state::consent::bypass::BypassScope;
use oneiron_consent_state::consent::effect::CatastropheClass;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::GrantBound;
use serde::Deserialize;
use serde::Serialize;

/// The actor and catastrophe classes, inside exactly one project or thread.
/// The action envelope retains every engine restriction; scope does not erase it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassGrantBoundRequest {
    pub actor: String,
    #[serde(default)]
    pub actor_class: Option<String>,
    pub classes: Vec<CatastropheClass>,
    pub scope: BypassScope,
    pub envelope: BypassActionEnvelopeRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassActionEnvelopeRequest {
    pub selectors: Vec<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub budget: Option<u64>,
    #[serde(default)]
    pub receipt_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassGrantWarningRequest {
    pub bound: BypassGrantBoundRequest,
}

/// What the owner acknowledges: their identity, the complete bound, the
/// versioned floor and the exact engine-computed per-class bound digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassGrantWarningView {
    pub owner: String,
    pub bound: BypassGrantBoundRequest,
    pub floor_version: u16,
    pub bound_digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateBypassGrantRequest {
    /// Pass the warning returned by bypass_grant_warning unchanged.
    pub warning: BypassGrantWarningView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveBypassGrantsRequest {}

/// One live engine row. Revoking `grant` through vault.consent.revoke ends
/// it; a multi-class creation returns a separate reference for every class.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassActiveState {
    pub active: bool,
    pub grant: String,
    pub bound: BypassGrantBoundRequest,
    pub floor_version: u16,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassedEffectReceiptsRequest {
    /// The reference emitted by creation, active state or the registry.
    pub grant: String,
}

/// A projection of an existing Gate receipt, never a caller-authored effect.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BypassedEffectReceipt {
    pub decision_ref: String,
    pub grant_ref: String,
    pub effect_digest: String,
    pub reason_code: String,
    pub created_at: u64,
}

impl BypassGrantBoundRequest {
    fn grant_bounds(&self) -> MemoryResult<Vec<GrantBound>> {
        if self.classes.is_empty() {
            return Err(MemoryError::bad_request(
                "a bypass names at least one catastrophe class",
            ));
        }
        let mut actor = ActorBound::new(self.actor.clone())?;
        if let Some(class) = &self.actor_class {
            actor = actor.with_actor_class(class.clone())?;
        }
        let mut envelope = ActionEnvelope::new(self.envelope.selectors.clone())?;
        if let Some(target) = &self.envelope.target {
            envelope = envelope.with_target(target.clone())?;
        }
        if let Some(budget) = self.envelope.budget {
            envelope = envelope.with_budget(budget);
        }
        envelope = envelope.with_receipt_required(self.envelope.receipt_required);
        let mut bounds = Vec::new();
        for (index, class) in self.classes.iter().enumerate() {
            if self.classes[..index].contains(class) {
                return Err(MemoryError::bad_request(
                    "a bypass class may appear only once",
                ));
            }
            bounds.push(GrantBound::action(
                actor.clone(),
                ActionClass::new(class.as_str())?,
                envelope.clone(),
            )?);
        }
        Ok(bounds)
    }
}
