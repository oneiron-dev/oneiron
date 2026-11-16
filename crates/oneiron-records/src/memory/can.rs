//! Moved from `crates/oneiron/src/memory/can.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One verb's gate for one actor, dated (FIX [UI-GATE-PREVIEW];
/// GENUI-WIRE-GAPS section 4 item 1): what the app shows on an affordance
/// before anyone presses it. The call itself is judged again when it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanVerbAnswer {
    /// The verb's catalog name.
    pub verb: String,
    /// The actor whose call was judged.
    pub actor_ref: EntityId,
    /// That actor's class.
    pub actor_kind: EdgeActorClass,
    pub gate: CanVerbGate,
    /// Why the call would not run now: the refusal the call itself answers,
    /// or the person rule its verb row states. Empty for `auto` and
    /// `unchecked`.
    pub reasons: Vec<String>,
    /// The recording time the judgment read, Unix seconds.
    pub checked_at: u64,
}

/// The word a verb's gate answers. Check-in's words (ARCH-0082, designed,
/// not built) map as Go = `auto`, Wait = `proposed`, Absent = `person` or
/// `refused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanVerbGate {
    /// The actor's call would run now.
    Auto,
    /// The actor's call would wait for a person's yes. No verb answers it
    /// yet: none of the previewed verbs proposes.
    Proposed,
    /// The verb is a person's act and the actor is not a person: the call is
    /// refused, and a person may act instead.
    Person,
    /// The actor's call would be refused for another reason, each in
    /// `reasons`.
    Refused,
    /// No preview reads this verb's gate yet. It says nothing about who may
    /// call it.
    Unchecked,
}
