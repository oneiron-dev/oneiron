//! Moved from `crates/oneiron/src/dreamer_runner/program/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

pub const PIN_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-pin:v1";

pub const OCCURRENCE_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-occurrence:v1";

/// The executable one armed program runs (DOOR-141 §3): a callable SKILL's
/// JS entry at an exact version and content hash, the digest of its call
/// contract, the executor revision that runs it and the arguments it is
/// called with, all pinned when it is armed. Prose is never the program, and
/// nothing here is regenerated: the stored code is the truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgramRecipePin {
    /// The callable SKILL entity.
    pub skill: EntityId,
    /// The SKILL revision armed.
    pub version: String,
    /// That revision's content hash, 64 lowercase hex.
    pub content_hash: String,
    /// The call contract's JS entry in the stored skill tree.
    pub entry: String,
    /// BLAKE3 over the call contract: its entry, arguments and returns, 64
    /// lowercase hex on the wire.
    #[schemars(with = "String")]
    #[serde(with = "hex32")]
    pub contract_digest: [u8; 32],
    /// The executor revision (`id@revision`) that runs it.
    pub executor: String,
    /// The arguments, as the JSON text armed.
    pub args: String,
}

impl ProgramRecipePin {
    /// The definition revision: BLAKE3 over every pinned field. Two armings
    /// of one definition share it; any change to the program moves it.
    #[must_use]
    pub fn revision(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PIN_DOMAIN);
        hasher.update(self.skill.as_bytes());
        for part in [
            self.version.as_bytes(),
            self.content_hash.as_bytes(),
            self.entry.as_bytes(),
            self.executor.as_bytes(),
            self.args.as_bytes(),
        ] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        hasher.update(&self.contract_digest);
        *hasher.finalize().as_bytes()
    }
}

/// What an actor arms: a callable SKILL, the executor revision that runs it,
/// the arguments it is called with, what wakes it (its own turns unless
/// `trigger` says otherwise), and, for a turn program, the conversation
/// whose turns wake it (any of the actor's own when `None`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmTurnProgram {
    /// The callable SKILL entity to arm.
    pub skill: EntityId,
    /// The executor revision (`id@revision`) that runs it.
    pub executor: String,
    /// The arguments it is called with, as its call contract takes them.
    pub args: serde_json::Value,
    /// The conversation whose turns wake it; any of the actor's own when
    /// absent. Only a turn program names one.
    #[serde(default)]
    pub conversation: Option<EntityId>,
    /// What wakes it: the actor's own turns when absent, or a due time, the
    /// host turning idle, or one of the actor's own change feed
    /// subscriptions moving (untangle slice 6.8).
    #[serde(default, skip_serializing_if = "ProgramTrigger::is_turn")]
    pub trigger: ProgramTrigger,
}

/// Which of the caller's own armed programs to disarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisarmTurnProgram {
    /// The registration arming returned.
    pub registration: EntityId,
}

/// What wakes one armed program (untangle slice 6.8c). Each wake is admitted by the same writer,
/// which judges the sealed authority again, as a turn's wake is.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProgramTrigger {
    /// Each turn its own actor lands, in the armed conversation or any of the actor's own.
    #[default]
    Turn,
    /// A due time: first at `first_at` (the vault's recording clock, seconds), then every
    /// `every_secs` after it; once when `every_secs` is 0. A due time missed while no node
    /// released wakes it once, never once per missed time.
    Timer { first_at: u64, every_secs: u64 },
    /// The host turning idle: once per idle stretch, when no inbound has arrived for
    /// `quiet_secs`.
    Idle { quiet_secs: u64 },
    /// A change feed subscription of its own actor: once per source head while the
    /// subscription's cursor stands behind it.
    Feed { subscription: EntityId },
}

impl ProgramTrigger {
    /// Whether this is the turn trigger, which every arming before slice 6.8c had.
    #[must_use]
    pub const fn is_turn(&self) -> bool {
        matches!(self, Self::Turn)
    }

    /// The kind of occurrence this trigger wakes on, `None` for a turn.
    pub const fn occurrence_kind(&self) -> Option<OccurrenceKind> {
        match self {
            Self::Turn => None,
            Self::Timer { .. } => Some(OccurrenceKind::Timer),
            Self::Idle { .. } => Some(OccurrenceKind::Idle),
            Self::Feed { .. } => Some(OccurrenceKind::Feed),
        }
    }
}

/// The kind of occurrence that woke a program whose trigger is not a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceKind {
    Timer,
    Idle,
    Feed,
}

impl OccurrenceKind {
    /// The one-byte tag the trigger index keys by.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Timer => 1,
            Self::Idle => 2,
            Self::Feed => 3,
        }
    }

    /// The occurrence's identity: the registration, the kind and the mark that names one
    /// occurrence (the due time, the idle stretch's start, the feed heads). Recording the same
    /// occurrence again gives the same id, so it wakes the program once.
    pub fn occurrence_id(
        self,
        registration: EntityId,
        mark: &[u8],
    ) -> oneiron_base::error::Result<EntityId> {
        let digest = blake3::Hasher::new()
            .update(OCCURRENCE_DOMAIN)
            .update(registration.as_bytes())
            .update(&[self.tag()])
            .update(&(mark.len() as u64).to_be_bytes())
            .update(mark)
            .finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        // A digest prefix is never a reserved id in practice; one would be refused, not used.
        EntityId::from_bytes(bytes).map_err(|_| {
            oneiron_base::error::Error::CorruptedIndex(
                "a turn program occurrence id is a reserved id",
            )
        })
    }
}

/// One armed program as its actor reads it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnProgramRegistration {
    pub registration: EntityId,
    pub actor: EntityId,
    pub conversation: Option<EntityId>,
    pub definition: ProgramRecipePin,
    /// [`ProgramRecipePin::revision`] of `definition`, 64 lowercase hex on
    /// the wire.
    #[schemars(with = "String")]
    #[serde(with = "hex32")]
    pub revision: [u8; 32],
    /// When it was armed (the vault's recording clock, seconds): only a turn
    /// that lands from then on wakes it.
    pub armed_at: u64,
    /// `false` when an identical arming already stood: arming is idempotent.
    pub newly_armed: bool,
}

/// A 32-byte digest as 64 lowercase hex, the crate's byte-hash wire form.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(blake3::Hash::from_bytes(*bytes).to_hex().as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        blake3::Hash::from_hex(value)
            .map(|hash| *hash.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
