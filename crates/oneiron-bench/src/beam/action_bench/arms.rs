//! The memory arms (ARCH-0042 #action-bench): no memory, raw-history
//! retrieval, derived only, raw plus derived, and gold-memory injection.
//!
//! The vault arms read through the agent's own read, `Memory::recall` (the
//! `vault.recall` verb), with `RecallScope::kinds` naming what the arm may
//! see. The bench renders the context from the typed items, one line each:
//! recall's `rendered` text puts owner claims in an l2_base prefix whatever
//! `kinds` says, so it would hand the raw arm derived memory.

use std::{collections::BTreeMap, sync::Arc, time::Instant};

use oneiron::memory::{
    ClaimInput, Effort, Memory, RecallScope, WitnessAssertions, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron::store::GateDecisionId;
use oneiron::{DeleteReason, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use serde::{Deserialize, Serialize};

use super::super::{BeamError, BeamResult};
use super::elapsed_us;
use super::tasks::{DerivedClaim, FollowUp, History, Turn, TurnAuthor};

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
/// the history's worlds and the turns and claims from before its freeze
/// that the user did not delete.
pub(super) struct HistoryVault {
    // Field order is drop order: the vault closes before its folder goes.
    vault: Vault,
    owner: EntityId,
    /// The history's worlds by name.
    worlds: BTreeMap<String, EntityId>,
    _dir: tempfile::TempDir,
    pub(super) turns_witnessed: usize,
    pub(super) claims_written: usize,
    pub(super) items_after_freeze: usize,
    pub(super) items_deleted: usize,
    pub(super) ingest_elapsed_us: u64,
}

impl HistoryVault {
    pub(super) fn seed(history: &History) -> BeamResult<Self> {
        let dir = tempfile::tempdir()?;
        let started = Instant::now();
        let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
        // A host installs a keystore after each open; a delete signs its
        // receipt with this install's key (FIX [BENCH-VECTOR-RUN-KEYSTORE]).
        // The vault is a temp dir dropped with the run, so a keystore in
        // process memory holds the whole of its custody.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault.prepare_install_signing()?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(|error| memory_failure(&history.id, &error.to_string()))?;
        let worlds = create_worlds(&vault, owner, &history.worlds)
            .map_err(|reason| memory_failure(&history.id, &reason))?;
        let counts = {
            let mut ingest = Ingest::new(&vault, owner, &worlds, history);
            ingest
                .run(history)
                .map_err(|reason| memory_failure(&history.id, &reason))?;
            ingest.counts
        };
        let ingest_elapsed_us = elapsed_us(started);
        Ok(Self {
            vault,
            owner,
            worlds,
            _dir: dir,
            turns_witnessed: counts.turns,
            claims_written: counts.claims,
            items_after_freeze: counts.after_freeze,
            items_deleted: counts.deleted,
            ingest_elapsed_us,
        })
    }

    pub(super) fn worlds_created(&self) -> usize {
        self.worlds.len()
    }

    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The follow-up's world as a recall names it; none for base reality.
    fn world_ref(&self, follow_up: &FollowUp) -> BeamResult<Option<String>> {
        follow_up
            .world
            .as_ref()
            .map(|name| {
                self.worlds.get(name).map(EntityId::to_hex).ok_or_else(|| {
                    BeamError::InvalidFixture {
                        fixture_id: follow_up.id.clone(),
                        reason: format!("action bench world `{name}` is not in the vault"),
                    }
                })
            })
            .transpose()
    }
}

/// Creates the history's worlds as its owner, with the proof the server's
/// `local_owner` builds: the embedded owner, authenticated on this open.
fn create_worlds(
    vault: &Vault,
    owner: EntityId,
    names: &[String],
) -> Result<BTreeMap<String, EntityId>, String> {
    if names.is_empty() {
        return Ok(BTreeMap::new());
    }
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .map_err(|error| error.to_string())?;
    let now = vault.now_recorded_at();
    names
        .iter()
        .map(|name| {
            let world = vault
                .create_world(&proof, name, now)
                .map_err(|error| error.to_string())?;
            Ok((name.clone(), world))
        })
        .collect()
}

#[derive(Default, Clone, Copy)]
struct IngestCounts {
    turns: usize,
    claims: usize,
    deleted: usize,
    after_freeze: usize,
}

/// One history's ingest: its turns and claims in time order, and each
/// deletion when the user made it; nothing at or after the freeze.
struct Ingest<'v> {
    vault: &'v Vault,
    memory: Memory<'v>,
    owner: EntityId,
    worlds: &'v BTreeMap<String, EntityId>,
    /// The history's one conversation: the first witness mints it at this id.
    conversation: EntityId,
    /// Each witnessed turn's message id, by the turn's place in the history.
    turns: Vec<Option<EntityId>>,
    /// Each written claim's id, by the claim's place in the history.
    claims: Vec<Option<EntityId>>,
    counts: IngestCounts,
}

impl<'v> Ingest<'v> {
    fn new(
        vault: &'v Vault,
        owner: EntityId,
        worlds: &'v BTreeMap<String, EntityId>,
        history: &History,
    ) -> Self {
        Self {
            vault,
            memory: vault.memory(owner, EdgeActorClass::Human),
            owner,
            worlds,
            conversation: EntityId::now(),
            turns: vec![None; history.turns.len()],
            claims: vec![None; history.claims.len()],
            counts: IngestCounts::default(),
        }
    }

    fn run(&mut self, history: &History) -> Result<(), String> {
        for event in events(history) {
            if event.at() >= history.frozen_at {
                self.counts.after_freeze += 1;
                continue;
            }
            self.apply(event)?;
        }
        Ok(())
    }

    fn apply(&mut self, event: Event<'_>) -> Result<(), String> {
        match event {
            Event::Turn(index, turn) => {
                let message = witness(&self.memory, self.conversation, turn)?;
                if let Some(slot) = self.turns.get_mut(index) {
                    *slot = Some(message);
                }
                self.counts.turns += 1;
            }
            Event::Claim(index, claim) => {
                let world = claim
                    .world
                    .as_ref()
                    .map(|name| {
                        self.worlds
                            .get(name)
                            .copied()
                            .ok_or("a claim names a world the vault lacks")
                    })
                    .transpose()?;
                let id = upsert(&self.memory, self.owner, claim, world)?;
                if let Some(slot) = self.claims.get_mut(index) {
                    *slot = Some(id);
                }
                self.counts.claims += 1;
            }
            Event::DeleteTurn(index, _) => {
                let Some(Some(message)) = self.turns.get(index).copied() else {
                    return Err("a deleted turn was never witnessed".to_owned());
                };
                // The user deletes what they said: the turn's message, as its
                // author, through the room door (the plain delete refuses a
                // room record). The TURN stays as its container; the
                // message's erase refreshes the TURN's search state.
                if !delete_message(self.vault, self.conversation, message, self.owner)? {
                    return Err("a deleted turn's message did not stand".to_owned());
                }
                self.counts.deleted += 1;
            }
            Event::DeleteClaim(index, _) => {
                let Some(Some(id)) = self.claims.get(index).copied() else {
                    return Err("a deleted claim was never written".to_owned());
                };
                if !delete(self.vault, &id)? {
                    return Err("a deleted claim did not stand".to_owned());
                }
                self.counts.deleted += 1;
            }
        }
        Ok(())
    }
}

enum Event<'a> {
    Turn(usize, &'a Turn),
    Claim(usize, &'a DerivedClaim),
    DeleteTurn(usize, u64),
    DeleteClaim(usize, u64),
}

impl Event<'_> {
    fn at(&self) -> u64 {
        match self {
            Self::Turn(_, turn) => turn.at,
            Self::Claim(_, claim) => claim.at,
            Self::DeleteTurn(_, at) | Self::DeleteClaim(_, at) => *at,
        }
    }
}

/// The history's writes and deletions in time order. The sort is stable, so
/// a later claim on one predicate supersedes the earlier one as a correction
/// does; a deletion comes after the write it deletes, which the trace check
/// puts earlier in time.
fn events(history: &History) -> Vec<Event<'_>> {
    let turns = history.turns.iter().enumerate().flat_map(|(index, turn)| {
        std::iter::once(Event::Turn(index, turn))
            .chain(turn.deleted_at.map(|at| Event::DeleteTurn(index, at)))
    });
    let claims = history
        .claims
        .iter()
        .enumerate()
        .flat_map(|(index, claim)| {
            std::iter::once(Event::Claim(index, claim))
                .chain(claim.deleted_at.map(|at| Event::DeleteClaim(index, at)))
        });
    let mut events: Vec<Event<'_>> = turns.chain(claims).collect();
    events.sort_by_key(Event::at);
    events
}

/// Witnesses one turn of one message: the message's id.
fn witness(memory: &Memory<'_>, conversation: EntityId, turn: &Turn) -> Result<EntityId, String> {
    let message = EntityId::now();
    memory
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: match turn.author {
                    TurnAuthor::User => WitnessAuthor::User,
                    TurnAuthor::Companion => WitnessAuthor::Companion,
                },
                message_type: "dialogue".to_owned(),
                content: turn.text.clone(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: turn.at,
            assertions: WitnessAssertions::default(),
        })
        .map_err(|error| error.to_string())?;
    Ok(message)
}

fn upsert(
    memory: &Memory<'_>,
    owner: EntityId,
    claim: &DerivedClaim,
    world: Option<EntityId>,
) -> Result<EntityId, String> {
    let id = EntityId::now();
    memory
        .claim_upsert(&ClaimInput {
            id: Some(id.to_hex()),
            predicate: claim.predicate.clone(),
            subject_ref: owner.to_hex(),
            value: serde_json::Value::from(claim.value.as_str()),
            confidence: DERIVED_CLAIM_CONFIDENCE,
            source: DERIVED_CLAIM_SOURCE.to_owned(),
            world_ref: world.as_ref().map(EntityId::to_hex),
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: Some(claim.at),
            learned_at: None,
            salience: None,
            confidence_details: None,
        })
        .map_err(|error| error.to_string())?;
    Ok(id)
}

/// The owner's plain delete, as a user's delete of one memory runs: whether
/// the item stood.
fn delete(vault: &Vault, id: &EntityId) -> Result<bool, String> {
    vault.delete_entity(id).map_err(|error| error.to_string())
}

/// The owner's delete of a message they wrote, as a user's delete of what
/// they said runs: whether the message stood.
fn delete_message(
    vault: &Vault,
    conversation: EntityId,
    message: EntityId,
    owner: EntityId,
) -> Result<bool, String> {
    vault
        .delete_room_record(
            conversation,
            message,
            WriteActor::new(owner, EdgeActorClass::Human),
            DeleteReason::UserDelete,
        )
        .map(|outcome| outcome.existed)
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
    // A follow-up in a world reads that world and base reality, as an agent
    // acting in it does; one with no world reads base reality only.
    let scope = RecallScope {
        world_ref: seeded.world_ref(follow_up)?,
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
