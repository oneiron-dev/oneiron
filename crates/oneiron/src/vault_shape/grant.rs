//! A standing grant's bound as a seed writes it (DEC-0006): who, which class,
//! which envelope. The wire form holds no authority of its own. It builds a
//! [`GrantBound`] only through the consent constructors, which check it, and
//! a grant only lands through the consent doors: the owner's mint, or an
//! agent's proposal to the owner's widen inbox.
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, BoundClass, BoundEnvelope,
    BoundSubject, DisclosureClass, DisclosureEnvelope, GrantBound,
};
use crate::error::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A bound, `(actor or audience × class × envelope)`, as plain fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "domain", rename_all = "snake_case")]
pub enum ShapeGrantBound {
    /// Actor → verb class → target envelope.
    Action {
        /// The actor the grant lets act, by reference.
        actor: String,
        /// Narrows the grant to one class of that actor.
        #[serde(default)]
        actor_class: Option<String>,
        /// The verb class, never a raw verb alone.
        class: String,
        /// The target selectors; at least one.
        selectors: Vec<String>,
        /// Narrows the envelope to one exact target.
        #[serde(default)]
        target: Option<String>,
        /// Caps each use's draw.
        #[serde(default)]
        budget: Option<u64>,
        /// Every use inside the envelope emits a receipt.
        #[serde(default)]
        receipt_required: bool,
    },
    /// Audience → data class → data envelope.
    Disclosure {
        /// Who may hear it; at least one member.
        audience: Vec<String>,
        /// The data class, e.g. `health`.
        class: String,
        /// The data selectors; at least one.
        selectors: Vec<String>,
    },
}

impl ShapeGrantBound {
    /// The bound these fields state, as the consent constructors build it.
    ///
    /// # Errors
    ///
    /// The constructors' own refusal: an empty or oversized reference, an
    /// empty audience or envelope, or too many members or selectors.
    pub fn bound(&self) -> Result<GrantBound> {
        match self {
            Self::Action {
                actor,
                actor_class,
                class,
                selectors,
                target,
                budget,
                receipt_required,
            } => {
                let mut subject = ActorBound::new(actor.as_str())?;
                if let Some(actor_class) = actor_class {
                    subject = subject.with_actor_class(actor_class.as_str())?;
                }
                let mut envelope = ActionEnvelope::new(selectors.iter().cloned())?
                    .with_receipt_required(*receipt_required);
                if let Some(target) = target {
                    envelope = envelope.with_target(target.as_str())?;
                }
                if let Some(budget) = budget {
                    envelope = envelope.with_budget(*budget);
                }
                GrantBound::action(subject, ActionClass::new(class.as_str())?, envelope)
            }
            Self::Disclosure {
                audience,
                class,
                selectors,
            } => GrantBound::disclosure(
                AudienceBound::new(audience.iter().cloned())?,
                DisclosureClass::new(class.as_str())?,
                DisclosureEnvelope::new(selectors.iter().cloned())?,
            ),
        }
    }

    /// The fields of `bound`, when they state it whole. A contact clearance's
    /// typed Scope envelope has no plain form, so it reads as none: such a
    /// grant lands through the clearance door, never from a seed.
    #[must_use]
    pub fn of(bound: &GrantBound) -> Option<Self> {
        let wire = match (bound.subject(), bound.class(), bound.envelope()) {
            (
                BoundSubject::Actor(actor),
                BoundClass::Action(class),
                BoundEnvelope::Action(envelope),
            ) => Self::Action {
                actor: actor.actor_ref().to_owned(),
                actor_class: actor.actor_class().map(str::to_owned),
                class: class.as_str().to_owned(),
                selectors: envelope.selectors().to_vec(),
                target: envelope.target().map(str::to_owned),
                budget: envelope.budget(),
                receipt_required: envelope.receipt_required(),
            },
            (
                BoundSubject::Audience(audience),
                BoundClass::Disclosure(class),
                BoundEnvelope::Disclosure(envelope),
            ) => Self::Disclosure {
                audience: audience.members().to_vec(),
                class: class.as_str().to_owned(),
                selectors: envelope.selectors().to_vec(),
            },
            _ => return None,
        };
        // Only a form that builds back to the same bound states it whole.
        wire.bound()
            .ok()
            .filter(|built| built == bound)
            .map(|_| wire)
    }

    /// Whether a mint of this bound is an action widening, else a disclosure
    /// one.
    #[must_use]
    pub const fn is_action(&self) -> bool {
        matches!(self, Self::Action { .. })
    }
}
