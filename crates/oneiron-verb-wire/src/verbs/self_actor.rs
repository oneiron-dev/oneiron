//! Moved from `crates/oneiron/src/verbs/self_actor.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `self.actor`'s answer: the actor the caller's credential binds, its
/// class, and the person it acts for, each a 32-hex entity ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfActorRefs {
    /// The actor every write of the caller is attributed to.
    pub actor_ref: String,
    /// `human`, `agent` or `system`.
    pub actor_class: String,
    /// The person the caller acts for: a person himself; an agent or system
    /// actor on a personal vault, the vault's live owner, who mints its
    /// credential; an agent on a shared vault, the one live member its
    /// credentials' mints name as their minting member. `None` where the
    /// vault records no such person: a shared vault's system actor, or an
    /// agent whose mints name no member, name two, or name one who left.
    /// An identifier, never a permission.
    pub person_ref: Option<String>,
}
