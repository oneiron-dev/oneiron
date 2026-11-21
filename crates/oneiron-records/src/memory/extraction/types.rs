//! Moved from `crates/oneiron/src/memory/extraction/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::extraction_work::ExtractionWork;
pub use oneiron_verb_wire::memory::extraction::types::ContextLink;
pub use oneiron_verb_wire::memory::extraction::types::CorefLink;
pub use oneiron_verb_wire::memory::extraction::types::EncoderExecution;
pub use oneiron_verb_wire::memory::extraction::types::ExecutionCompute;
pub use oneiron_verb_wire::memory::extraction::types::ExecutionPick;
pub use oneiron_verb_wire::memory::extraction::types::ExecutionRuntime;
pub use oneiron_verb_wire::memory::extraction::types::NerSpan;
pub use oneiron_verb_wire::memory::extraction::types::SpeakerLink;
pub use oneiron_verb_wire::memory::extraction::types::SpeakerTarget;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EncoderMessage {
    pub id: String,
    pub text: String,
}

/// Which side of the conversation a turn is on, read from its messages'
/// stored author: a role, never a guess from turn order or ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpeakerRole {
    /// The user side: the owner or another human.
    #[serde(rename = "A")]
    User,
    /// The companion side: the vault's own agents.
    #[serde(rename = "B")]
    Companion,
}

/// One earlier turn the tagger reads for context and tags nothing in.
#[derive(Debug, Clone, Serialize)]
pub struct EncoderTurn {
    pub turn: String,
    pub messages: Vec<EncoderMessage>,
    /// The turn's side, when its stored authors name one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker: Option<SpeakerRole>,
}

/// Which register of its conversation a call reads (FIX 9520, 10167).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncoderRegister {
    /// The live register: the turn and a bounded window of earlier text,
    /// never a later turn. A live call reads it.
    #[default]
    Live,
    /// The whole conversation as it is authorized and stored now: every
    /// earlier turn whole, the turn, then every later turn, in conversation
    /// order, with where it stops short of that. An import, backfill or
    /// other bulk marker reads it. Spans still index the turn's own messages
    /// alone.
    Conversation(RegisterReach),
}

impl EncoderRegister {
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}

/// Where a conversation register stops short of its conversation (FIX
/// 10705): neither, for one read whole. A side stops at its bound of turns,
/// keeping the nearest; walking down a DAG it also stops at a branch, whose
/// lines it does not choose between.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterReach {
    /// Turns older than the first of `context` were not read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub earlier_cut: bool,
    /// Turns later than the last of `following` were not read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub later_cut: bool,
}

impl RegisterReach {
    /// Whether the register reads its whole conversation.
    pub const fn is_whole(&self) -> bool {
        !self.earlier_cut && !self.later_cut
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EncoderInput {
    pub turn: String,
    pub messages: Vec<EncoderMessage>,
    /// Earlier turns of the same conversation, oldest first: the live
    /// register's window, or every earlier turn of the conversation
    /// register. Empty for a turn read alone. Spans index `messages` only.
    pub context: Vec<EncoderTurn>,
    /// Later turns of the same conversation, oldest first: only the
    /// conversation register carries them ([`EncoderRegister`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub following: Vec<EncoderTurn>,
    /// The register this input reads.
    #[serde(skip_serializing_if = "EncoderRegister::is_live")]
    pub register: EncoderRegister,
    /// The input's language as a lowercase ISO 639 code, only when a stored
    /// or configured fact names it; without it the tagger detects it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// The current turn's side, when its stored authors name one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker: Option<SpeakerRole>,
}
