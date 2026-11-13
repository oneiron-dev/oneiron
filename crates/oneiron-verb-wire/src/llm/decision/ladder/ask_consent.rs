//! Moved from `crates/oneiron/src/llm/decision/ladder/ask_consent.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_consent_state::consent::effect::CatastropheClass;
use oneiron_consent_state::consent::effect::UndoFidelity;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::consent_bound::GrantBound;
use oneiron_store::model_decision::invalid;
use serde::Deserialize;
use serde::Serialize;

/// The host's undo-fidelity finding, as an ask carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

/// One composed effect as plain fields: the engine-owned facts, where it runs, and the
/// requirements it must be covered by. It rebuilds to the same effect, digest included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    pub catastrophe: Option<CatastropheClass>,
    /// The project it acts inside, by entity id hex.
    pub project: Option<String>,
    /// The conversation thread it acts inside, by entity id hex.
    pub thread: Option<String>,
    /// Whether it is an erase.
    pub erase: bool,
    /// The action requirement, when it acts.
    pub action: Option<ShapeGrantBound>,
    /// The disclosure requirement, when it discloses.
    pub disclosure: Option<ShapeGrantBound>,
}

/// A requirement's plain form; one with no plain form (a contact clearance's Scope
/// envelope) cannot ride an ask.
pub fn plain(bound: &GrantBound) -> Result<ShapeGrantBound> {
    ShapeGrantBound::of(bound)
        .ok_or_else(|| invalid("an ask carries a requirement only in its plain form"))
}

/// `hex` as an entity id, when it is one.
pub fn entity(hex: Option<&str>) -> Result<Option<EntityId>> {
    hex.map(|hex| {
        EntityId::from_hex(hex).map_err(|_| invalid("an ask names a place by entity id hex"))
    })
    .transpose()
}
