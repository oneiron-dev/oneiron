//! Moved from `crates/oneiron/src/memory/voice_actor.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Whose voice a banked identity is (FIX 4393). Its owner/subject id is that
/// entity either way; the kind is bound when the bank first holds the voice
/// and never relabelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceRefSubjectKind {
    /// A real person's own voice: its subject consents to its rendering on
    /// their own person proof, under a consent basis.
    Person,
    /// A designed (synthetic) voice: it belongs to the entity that created
    /// it, the owner by default. No real person is its subject, so no person
    /// proof or consent basis is asked of it.
    Designed,
}

impl VoiceRefSubjectKind {
    /// The kind a render decision's input names when it names none: a
    /// person's. Only an input wire defaults it; a stored row never does.
    #[must_use]
    pub const fn input_default() -> Self {
        Self::Person
    }
}
