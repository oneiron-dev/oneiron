//! The memory arms (ARCH-0042 #action-bench): no memory, raw-history
//! retrieval, derived only, raw plus derived, and gold-memory injection.
//!
//! The vault arms read through the agent's own read, `Memory::recall` (the
//! `vault.recall` verb), with `RecallScope::kinds` naming what the arm may
//! see. The bench renders the context from the typed items, one line each:
//! recall's `rendered` text puts owner claims in an l2_base prefix whatever
//! `kinds` says, so it would hand the raw arm derived memory.

use std::time::Instant;

use oneiron::memory::{
    ClaimInput, Effort, Memory, RecallScope, WitnessAssertions, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde::{Deserialize, Serialize};

use super::super::{BeamError, BeamResult};
use super::elapsed_us;
use super::tasks::{FollowUp, History, TurnAuthor};

/// Registry kinds of the raw history: a witnessed turn and its messages.
const RAW_KINDS: [&str; 2] = ["TURN", "MESSAGE"];
/// Registry kind of the derived memory.
const DERIVED_KINDS: [&str; 1] = ["CLAIM"];
/// A derived claim states what its history said; it is no guess.
const DERIVED_CLAIM_CONFIDENCE: f32 = 0.9;
/// The owner said it, as the turns it stands for show.
const DERIVED_CLAIM_SOURCE: &str = "user_stated";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MemoryArm {
    /// No memory: an empty context; the vault is never read.
    None,
    /// Raw-history retrieval: witnessed turns only.
    Raw,
    /// Derived memory only: claims.
    Derived,
    /// Raw history and derived memory in one recall.
    RawPlusDerived,
    /// The follow-up's gold memory as the context; the vault is never read.
    Gold,
}

impl MemoryArm {
    /// The registry kinds this arm's recall names; `None` for an arm that
    /// never reads the vault.
    fn kinds(self) -> Option<Vec<&'static str>> {
        match self {
            Self::None | Self::Gold => None,
            Self::Raw => Some(RAW_KINDS.to_vec()),
            Self::Derived => Some(DERIVED_KINDS.to_vec()),
            Self::RawPlusDerived => Some(RAW_KINDS.iter().chain(&DERIVED_KINDS).copied().collect()),
        }
    }
}

/// One history's vault: fresh, its embedded owner the one writer, holding
/// the history's turns and claims from before its freeze.
pub(super) struct HistoryVault {
    // Field order is drop order: the vault closes before its folder goes.
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
    pub(super) turns_witnessed: usize,
    pub(super) claims_written: usize,
    pub(super) items_after_freeze: usize,
    pub(super) ingest_elapsed_us: u64,
}

impl HistoryVault {
    pub(super) fn seed(history: &History) -> BeamResult<Self> {
        let dir = tempfile::tempdir()?;
        let started = Instant::now();
        let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(|error| memory_failure(&history.id, &error.to_string()))?;
        let memory = vault.memory(owner, EdgeActorClass::Human);
        let conversation = EntityId::now().to_hex();
        let mut seeded = Ingest::default();
        // Turns and claims enter in time order, so a later claim on the same
        // predicate supersedes the earlier one as a correction does.
        let mut events: Vec<Event<'_>> = history
            .turns
            .iter()
            .map(Event::Turn)
            .chain(history.claims.iter().map(Event::Claim))
            .collect();
        events.sort_by_key(|event| event.at());
        for event in events {
            if event.at() >= history.frozen_at {
                seeded.after_freeze += 1;
                continue;
            }
            match event {
                Event::Turn(turn) => {
                    witness(&memory, &conversation, turn.author, &turn.text, turn.at)
                        .map_err(|reason| memory_failure(&history.id, &reason))?;
                    seeded.turns += 1;
                }
                Event::Claim(claim) => {
                    upsert(&memory, owner, &claim.predicate, &claim.value, claim.at)
                        .map_err(|reason| memory_failure(&history.id, &reason))?;
                    seeded.claims += 1;
                }
            }
        }
        let ingest_elapsed_us = elapsed_us(started);
        Ok(Self {
            vault,
            owner,
            _dir: dir,
            turns_witnessed: seeded.turns,
            claims_written: seeded.claims,
            items_after_freeze: seeded.after_freeze,
            ingest_elapsed_us,
        })
    }

    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }
}

#[derive(Default)]
struct Ingest {
    turns: usize,
    claims: usize,
    after_freeze: usize,
}

enum Event<'a> {
    Turn(&'a super::tasks::Turn),
    Claim(&'a super::tasks::DerivedClaim),
}

impl Event<'_> {
    fn at(&self) -> u64 {
        match self {
            Self::Turn(turn) => turn.at,
            Self::Claim(claim) => claim.at,
        }
    }
}

fn witness(
    memory: &Memory<'_>,
    conversation: &str,
    author: TurnAuthor,
    text: &str,
    at: u64,
) -> Result<(), String> {
    memory
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_owned(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: match author {
                    TurnAuthor::User => WitnessAuthor::User,
                    TurnAuthor::Companion => WitnessAuthor::Companion,
                },
                message_type: "dialogue".to_owned(),
                content: text.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: at,
            assertions: WitnessAssertions::default(),
        })
        .map(drop)
        .map_err(|error| error.to_string())
}

fn upsert(
    memory: &Memory<'_>,
    owner: EntityId,
    predicate: &str,
    value: &str,
    at: u64,
) -> Result<(), String> {
    memory
        .claim_upsert(&ClaimInput {
            id: None,
            predicate: predicate.to_owned(),
            subject_ref: owner.to_hex(),
            value: serde_json::Value::from(value),
            confidence: DERIVED_CLAIM_CONFIDENCE,
            source: DERIVED_CLAIM_SOURCE.to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: Some(at),
            learned_at: None,
            salience: None,
            confidence_details: None,
        })
        .map(drop)
        .map_err(|error| error.to_string())
}

fn memory_failure(history: &str, reason: &str) -> BeamError {
    BeamError::InvalidFixture {
        fixture_id: history.to_owned(),
        reason: format!("action bench history write refused: {reason}"),
    }
}

/// What one arm hands the reader for one follow-up.
pub(super) struct ArmContext {
    pub(super) text: String,
    pub(super) lines: usize,
    pub(super) items_off_arm: usize,
    pub(super) recall_elapsed_us: u64,
}

pub(super) fn context(
    seeded: &HistoryVault,
    arm: MemoryArm,
    follow_up: &FollowUp,
    recall_limit: usize,
) -> BeamResult<ArmContext> {
    let Some(kinds) = arm.kinds() else {
        let lines: Vec<String> = match arm {
            MemoryArm::Gold => follow_up
                .gold_memory
                .iter()
                .map(|line| format!("- {line}"))
                .collect(),
            _ => Vec::new(),
        };
        return Ok(ArmContext {
            lines: lines.len(),
            text: lines.join("\n"),
            items_off_arm: 0,
            recall_elapsed_us: 0,
        });
    };
    let scope = RecallScope {
        kinds: Some(kinds.iter().map(|kind| (*kind).to_owned()).collect()),
        ..RecallScope::default()
    };
    let started = Instant::now();
    let pack = seeded
        .memory()
        .recall(
            &follow_up.prompt,
            Effort::Light,
            &scope,
            recall_limit,
            None,
            None,
        )
        .map_err(|error| BeamError::InvalidFixture {
            fixture_id: follow_up.id.clone(),
            reason: format!("action bench recall refused: {error}"),
        })?;
    let recall_elapsed_us = elapsed_us(started);
    let (on_arm, off_arm): (Vec<_>, Vec<_>) = pack
        .items
        .iter()
        .partition(|item| kinds.iter().any(|kind| *kind == item.kind));
    let lines: Vec<String> = on_arm
        .iter()
        .map(|item| match &item.predicate {
            Some(predicate) => format!("- {} {predicate}: {}", item.kind, item.value_text),
            None => format!("- {}: {}", item.kind, item.value_text),
        })
        .collect();
    Ok(ArmContext {
        lines: lines.len(),
        text: lines.join("\n"),
        items_off_arm: off_arm.len(),
        recall_elapsed_us,
    })
}
