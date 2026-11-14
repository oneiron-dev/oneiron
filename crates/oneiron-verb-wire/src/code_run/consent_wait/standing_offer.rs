//! Moved from `crates/oneiron/src/code_run/consent_wait/standing_offer.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::BoundEnvelope;
use oneiron_store::consent_bound::GrantBound;
use serde::Deserialize;
use serde::Serialize;

/// A server-wide standing send offer. This is a proposal, not authority;
/// only the authenticated owner's first answer mints the native grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeConsentStandingOffer {
    /// The exact actor reference of the native requirement.
    pub actor_ref: String,
    /// The native action class, `send`.
    pub verb_class: String,
    /// The complete native selector set, `["verb:send"]`.
    pub selectors: Vec<String>,
    /// The native server-wide target, `mcp:<server>`.
    pub target: Option<String>,
}

impl CodeConsentStandingOffer {
    /// Copies every fact of the supported scoped-MCP native requirement.
    /// A different requirement is not silently projected into this offer.
    pub fn from_bound(bound: &GrantBound) -> Option<Self> {
        let actor = bound.actor()?;
        let BoundEnvelope::Action(envelope) = bound.envelope() else {
            return None;
        };
        if actor.actor_class().is_some()
            || bound.class().as_str() != "send"
            || envelope.selectors() != ["verb:send"]
            || !envelope
                .target()
                .is_some_and(|target| target.starts_with("mcp:"))
            || envelope.budget().is_some()
            || envelope.receipt_required()
        {
            return None;
        }
        Some(Self {
            actor_ref: actor.actor_ref().to_owned(),
            verb_class: bound.class().as_str().to_owned(),
            selectors: envelope.selectors().to_vec(),
            target: envelope.target().map(str::to_owned),
        })
    }

    /// Reconstructs through the native validating constructors; there is
    /// no independent grant format or persistence path.
    pub fn bound(&self) -> Result<GrantBound> {
        let mut envelope = ActionEnvelope::new(self.selectors.clone())?;
        if let Some(target) = &self.target {
            envelope = envelope.with_target(target.clone())?;
        }
        GrantBound::action(
            ActorBound::new(self.actor_ref.clone())?,
            ActionClass::new(self.verb_class.clone())?,
            envelope,
        )
    }

    /// Full scope text shared by the frozen question and its option. No
    /// actor, selector or server target is clipped or inferred from a tool.
    pub fn scope_description(&self) -> String {
        format!(
            "server-wide sends (actor: {:?}, action class: {:?}, selectors: {:?}, target: {:?}); \
             this is not limited to this tool or these arguments",
            self.actor_ref, self.verb_class, self.selectors, self.target,
        )
    }
}
