//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/identity.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::IdentityActNow;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::IdentityActNowRequest;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::IdentityAnswerRequest;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::IdentityEffect;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::IdentitySettled;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::MentionProvenance;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::evidence::IdentityAnswerEvidenceRequest;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::evidence::IdentityMentionState;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::evidence::IdentityMentionView;
pub use oneiron_verb_wire::dreamer_runner::maintenance::identity::evidence::IdentityResolutionView;
use serde::Deserialize;
use serde::Serialize;

/// Why an ask is open (ask rule B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAskReason {
    /// An agent must act on this person now.
    ActNow { effect: IdentityEffect },
    /// The Dreamer's pass could not settle it.
    Unsettled,
}

/// One saved mention whose person is not settled, and where its ask stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAsk {
    pub kind: u8,
    /// The span's text.
    pub name: String,
    pub turn: EntityId,
    pub message: EntityId,
    pub start: usize,
    pub end: usize,
    /// The entities it may be, real or provisional, every one: a decision
    /// lists as many as its Choice takes and carries the rest by id.
    pub candidates: Vec<EntityId>,
    /// The mention's own provisional entity, when it named only that one and
    /// the name now keys to real people: "someone new" confirms it.
    pub provisional: Option<EntityId>,
    /// The words around the mention, as a hint keeps them.
    pub context: Vec<String>,
    /// The complete source message, for the decision; `start..end` selects
    /// the mention.
    pub excerpt: String,
    pub reason: IdentityAskReason,
    pub opened_at: u64,
    /// No decision before this; 0 asks at once.
    pub retry_at: u64,
    /// When the decision abstained and the ask went to the person.
    pub escalated_at: Option<u64>,
    /// The newest turn the ask was sent to the person from.
    pub surfaced_turn: Option<EntityId>,
    /// When a nightly decision abstained and the names were kept separate
    /// for now: the ask is not due until its candidates change.
    pub kept_separate_at: Option<u64>,
}

/// The words answers about a name were given in, summed over the saved
/// contributions a read counts, once each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityHint {
    pub name: String,
    pub context: Vec<String>,
    pub saved_at: u64,
}

/// One option of an ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityOption {
    /// The Choice token: `is:<id>`, or [`SOMEONE_NEW`].
    pub choice: String,
    /// The candidate, as 32 hex; none for someone new.
    pub entity: Option<String>,
    /// Its stored name; empty for someone new.
    pub label: String,
    pub provisional: bool,
    /// When a provisional candidate was first said, store-clock seconds.
    pub first_said: Option<u64>,
}

/// An open ask as the owner reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityAskView {
    /// The ask, as 64 hex.
    pub ask: String,
    pub name: String,
    pub turn: String,
    pub conversation: Option<String>,
    pub excerpt: String,
    pub options: Vec<IdentityOption>,
    pub reason: IdentityAskReason,
    pub opened_at: u64,
    pub escalated_at: Option<u64>,
    /// When the names were kept separate for now; the ask still takes an
    /// answer.
    pub kept_separate_at: Option<u64>,
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("identity ask: {message}"))
}

/// The key of the ask for the span of `turn` at `message`, `start`..`end`.
pub fn ask_key(turn: &EntityId, message: &EntityId, start: usize, end: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.identity_ask.v1");
    hasher.update(turn.as_bytes());
    hasher.update(message.as_bytes());
    hasher.update(&u64::try_from(start).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(&u64::try_from(end).unwrap_or(u64::MAX).to_be_bytes());
    *hasher.finalize().as_bytes()
}

pub fn key_hex(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut key = [0_u8; 32];
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(key)
}
pub mod erase;
pub mod hints;
pub mod settle_undo;
