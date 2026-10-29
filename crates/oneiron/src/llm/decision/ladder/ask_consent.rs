//! An ask about one consent effect (DEC-0006 "the confirm card carries an optional
//! reason", FIX 2975). The caller that composed the effect binds it to the ask from
//! trusted context, never from model-authored state, as it binds who the ask goes to. It
//! grants nothing: the owner's reason on the answer drafts the standing grant of its bound,
//! Proposed, which turns live only on the owner's confirm; and the ask is queued with the
//! owner's nearest reason on record pre-filled.

use super::{HumanDecisionQueue, HumanDecisionRequest};
use crate::consent::{
    CatastropheClass, ComposedEffect, EffectFacts, EffectPlace, GrantBound, UndoFidelity,
};
use crate::llm::decision::types::invalid;
use crate::vault_shape::ShapeGrantBound;
use crate::{EntityId, Result};
use serde::{Deserialize, Serialize};

/// The host's undo-fidelity finding, as an ask carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskUndoFidelity {
    Full,
    Partial,
    None,
    Unknown,
}

impl From<UndoFidelity> for AskUndoFidelity {
    fn from(fidelity: UndoFidelity) -> Self {
        match fidelity {
            UndoFidelity::Full => Self::Full,
            UndoFidelity::Partial => Self::Partial,
            UndoFidelity::None => Self::None,
            UndoFidelity::Unknown => Self::Unknown,
        }
    }
}

impl From<AskUndoFidelity> for UndoFidelity {
    fn from(fidelity: AskUndoFidelity) -> Self {
        match fidelity {
            AskUndoFidelity::Full => Self::Full,
            AskUndoFidelity::Partial => Self::Partial,
            AskUndoFidelity::None => Self::None,
            AskUndoFidelity::Unknown => Self::Unknown,
        }
    }
}

/// One composed effect as plain fields: the engine-owned facts, where it runs, and the
/// requirements it must be covered by. It rebuilds to the same effect, digest included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskEffect {
    /// What kind of operation it is (e.g. `channel.send`).
    pub operation_kind: String,
    pub fires_hooks: bool,
    pub triggers_publish: bool,
    pub external_observers: bool,
    pub undo_fidelity: AskUndoFidelity,
    pub blast_radius: u64,
    /// The catastrophe class the host matched, when it matched one.
    #[serde(default)]
    pub catastrophe: Option<CatastropheClass>,
    /// The project it acts inside, by entity id hex.
    #[serde(default)]
    pub project: Option<String>,
    /// The conversation thread it acts inside, by entity id hex.
    #[serde(default)]
    pub thread: Option<String>,
    /// Whether it is an erase.
    #[serde(default)]
    pub erase: bool,
    /// The action requirement, when it acts.
    #[serde(default)]
    pub action: Option<ShapeGrantBound>,
    /// The disclosure requirement, when it discloses.
    #[serde(default)]
    pub disclosure: Option<ShapeGrantBound>,
}

/// What an ask about one consent effect carries: the effect, and the bound an owner's
/// reason drafts a standing grant of, one of the effect's own requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskConsent {
    pub effect: AskEffect,
    pub bound: ShapeGrantBound,
}

/// A requirement's plain form; one with no plain form (a contact clearance's Scope
/// envelope) cannot ride an ask.
fn plain(bound: &GrantBound) -> Result<ShapeGrantBound> {
    ShapeGrantBound::of(bound)
        .ok_or_else(|| invalid("an ask carries a requirement only in its plain form"))
}

/// `hex` as an entity id, when it is one.
fn entity(hex: Option<&str>) -> Result<Option<EntityId>> {
    hex.map(|hex| {
        EntityId::from_hex(hex).map_err(|_| invalid("an ask names a place by entity id hex"))
    })
    .transpose()
}

impl AskConsent {
    /// The consent `effect` asks for, drafting `bound` on an owner's reason.
    ///
    /// # Errors
    ///
    /// A `bound` that is none of the effect's requirements, or a requirement with no
    /// plain form.
    pub fn of(effect: &ComposedEffect, bound: &GrantBound) -> Result<Self> {
        if ![effect.action_requirement(), effect.disclosure_requirement()]
            .into_iter()
            .flatten()
            .any(|required| required == bound)
        {
            return Err(invalid("an ask's bound is one of its effect's requirements"));
        }
        let facts = effect.facts();
        let place = effect.place();
        Ok(Self {
            effect: AskEffect {
                operation_kind: facts.operation_kind.clone(),
                fires_hooks: facts.fires_hooks,
                triggers_publish: facts.triggers_publish,
                external_observers: facts.external_observers,
                undo_fidelity: facts.undo_fidelity.into(),
                blast_radius: facts.blast_radius,
                catastrophe: facts.catastrophe,
                project: place.project.map(|id| id.to_hex()),
                thread: place.thread.map(|id| id.to_hex()),
                erase: effect.is_erase(),
                action: effect.action_requirement().map(plain).transpose()?,
                disclosure: effect.disclosure_requirement().map(plain).transpose()?,
            },
            bound: plain(bound)?,
        })
    }

    /// The effect, rebuilt through the consent constructors.
    ///
    /// # Errors
    ///
    /// Fields the constructors refuse.
    pub fn composed(&self) -> Result<ComposedEffect> {
        let fields = &self.effect;
        let mut facts = EffectFacts::new(fields.operation_kind.as_str())?
            .with_hooks(fields.fires_hooks)
            .with_publish_trigger(fields.triggers_publish)
            .with_external_observers(fields.external_observers)
            .with_undo_fidelity(fields.undo_fidelity.into())
            .with_blast_radius(fields.blast_radius);
        if let Some(class) = fields.catastrophe {
            facts = facts.with_catastrophe(class);
        }
        let mut effect = ComposedEffect::new(facts).in_place(EffectPlace {
            project: entity(fields.project.as_deref())?,
            thread: entity(fields.thread.as_deref())?,
        });
        if fields.erase {
            effect = effect.as_erase();
        }
        if let Some(action) = &fields.action {
            effect = effect.with_action_requirement(action.bound()?)?;
        }
        if let Some(disclosure) = &fields.disclosure {
            effect = effect.with_disclosure_requirement(disclosure.bound()?)?;
        }
        Ok(effect)
    }

    /// The bound an owner's reason drafts, rebuilt through the consent constructors.
    ///
    /// # Errors
    ///
    /// Fields the constructors refuse.
    pub fn grant_bound(&self) -> Result<GrantBound> {
        self.bound.bound()
    }

    /// Both halves rebuilt, the bound one of the effect's requirements.
    ///
    /// # Errors
    ///
    /// Fields the constructors refuse, or a bound that is none of the effect's
    /// requirements.
    pub fn validate(&self) -> Result<(ComposedEffect, GrantBound)> {
        let effect = self.composed()?;
        let bound = self.grant_bound()?;
        if ![effect.action_requirement(), effect.disclosure_requirement()]
            .into_iter()
            .flatten()
            .any(|required| *required == bound)
        {
            return Err(invalid("an ask's bound is one of its effect's requirements"));
        }
        Ok((effect, bound))
    }
}

/// A person queue whose every ask is about `consent`: a ladder whose caller composed the
/// effect it decides runs with this as its person queue, so the ask its person rung
/// queues carries the effect and the owner's nearest reason on record.
pub struct ConsentAskQueue<'a> {
    queue: &'a dyn HumanDecisionQueue,
    consent: &'a AskConsent,
}

impl<'a> ConsentAskQueue<'a> {
    #[must_use]
    pub const fn new(queue: &'a dyn HumanDecisionQueue, consent: &'a AskConsent) -> Self {
        Self { queue, consent }
    }
}

impl HumanDecisionQueue for ConsentAskQueue<'_> {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()> {
        self.queue
            .queue_with_consent(request, None, self.consent)
            .map(drop)
    }

    fn queue_with_state(
        &self,
        request: HumanDecisionRequest,
        state: &serde_json::Value,
    ) -> Result<Option<u64>> {
        self.queue
            .queue_with_consent(request, Some(state), self.consent)
    }
}
