//! Continue and Retry on an assistant turn (owner ruling 10-17): a reply
//! interrupted by a crash or a dropped stream stays one MESSAGE that reads
//! incomplete, and gets these two typed actions.
//!
//! Each verb resolves the assistant TURN as its caller, checks it, and queues
//! one attempt for a host worker; the receipt names the queued attempt, never
//! text. Continue resumes generation on the same MESSAGE from its saved text;
//! Retry answers the same user turn again in a new assistant TURN and leaves
//! the interrupted MESSAGE as it is. The request is rebuilt from the ledger:
//! the agent is the MESSAGE's author, the source is the latest user turn
//! before it, and the history is the transcript before that. No model call
//! and no prompt text live here.
//!
//! On a conversation that adopted the DAG the transcript is the branch that
//! leads to the turn, and Retry's TURN is a sibling of the old one at its
//! parent, never moving HEAD; a thread's Retry stays in its thread.
//!
//! An action stands while its requester does. One asked through a transport
//! carries the capability slip its request was admitted on, and runs only
//! while that slip verifies and still binds the requester: revoking it stops
//! the queued action. Only the in-process host queues one without a slip.
use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptQueue, AttemptRecord, EnqueueAttempt, EnqueueOutcome};
use crate::authority::{InvocationSlipBinding, VerifiedSlip};
use crate::claim::CallerLocality;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::Result;
use crate::memory::{
    MAX_TRANSCRIPT_PAGE_TURNS, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    WitnessAuthor, resolve_entity_ref,
};
use crate::{EntityId, Error, Vault};

/// The attempt kind a host's turn-action worker claims.
pub const TURN_ACTION_ATTEMPT_KIND: &str = "conversation.turn_action";

/// Names the assistant TURN an action acts on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnActionRequest {
    /// The assistant TURN: a short ref or a 32-hex id.
    pub turn_id: String,
}

/// What a queued turn action does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TurnAction {
    /// Resume generation on the same MESSAGE from its saved text.
    Continue,
    /// Answer the same user turn again in a new assistant TURN.
    Retry,
}

/// A queued action: the attempt that will run it, never a claim that text
/// exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnActionReceipt {
    pub action: TurnAction,
    /// 32-hex id of the assistant TURN acted on.
    pub turn_id: String,
    /// 32-hex id of its generated MESSAGE.
    pub message_id: String,
    /// 32-hex id of the queued attempt.
    pub attempt_id: String,
}

/// The payload of a [`TURN_ACTION_ATTEMPT_KIND`] attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnActionAttempt {
    pub action: TurnAction,
    pub conversation: EntityId,
    /// The latest user turn before the assistant turn: what the reply answers.
    pub user_turn: EntityId,
    pub assistant_turn: EntityId,
    pub message: EntityId,
    /// Who asked. The worker reads the conversation again as this actor, and
    /// the reply's turn is a run on this actor's budget line.
    pub actor: EntityId,
    pub actor_class: u8,
    /// The slip the request was admitted on, verified again whenever the
    /// action's standing is judged. `None` only on a native attempt.
    pub invocation_slip: Option<InvocationSlipBinding>,
    /// The in-process host asked, with no transport and no slip: the
    /// actor's binding alone is its standing.
    pub native: bool,
    /// The requester read from off this device; the run reads there too.
    pub off_device: bool,
}

/// One earlier line of the conversation, as a chat request carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnActionLine {
    /// `User` or `Companion`.
    pub author: WitnessAuthor,
    pub text: String,
}

/// What a host needs to run one queued action, read again as its requester
/// when it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnActionContext {
    /// The agent definition that wrote the reply; it answers again.
    pub agent: EntityId,
    /// The conversation before the user turn, oldest first, at most the
    /// number of lines the host asked for.
    pub history: Vec<TurnActionLine>,
    /// What the user turn says.
    pub user_text: String,
    /// What the reply says now: exactly its saved text.
    pub saved: String,
}

impl TurnActionAttempt {
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("turn action payload encode failed"))
    }

    /// Decodes a claimed attempt of [`TURN_ACTION_ATTEMPT_KIND`].
    pub fn decode(attempt: &AttemptRecord) -> Result<Self> {
        if attempt.kind != TURN_ACTION_ATTEMPT_KIND {
            return Err(Error::InvariantViolation("not a turn action attempt"));
        }
        rmp_serde::from_slice(&attempt.payload)
            .map_err(|_| Error::CorruptedIndex("turn action payload"))
    }

    /// The requester's actor and class.
    pub fn requester(&self) -> Result<(EntityId, EdgeActorClass)> {
        let class = EdgeActorClass::try_from_u8(self.actor_class)
            .ok_or(Error::CorruptedIndex("turn action actor class"))?;
        Ok((self.actor, class))
    }

    /// Whether the action still stands, in `txn`: the requester's actor
    /// binding holds and, unless the attempt is native, the slip it was
    /// asked with does too. The action's standing, as a credential's
    /// liveness is a request's.
    #[must_use]
    pub fn requester_live_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> bool {
        self.requester_proof_in(vault, txn).is_ok()
    }

    /// The requester's standing in `txn`, and the slip's proof as it stands
    /// there: verified at this snapshot's fold and clock, every caveat
    /// included, still held by the requester at its class and granting a
    /// write. A native attempt stands on the actor binding, with no proof.
    fn requester_proof_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<Option<VerifiedSlip>> {
        let (actor, class) = self.requester()?;
        crate::memory::verify_actor_binding_in_txn(vault, txn, actor, class)?;
        let binding = match (&self.invocation_slip, self.native) {
            (None, true) => return Ok(None),
            (Some(binding), false) => binding,
            // No attempt is queued native with a slip, or slip-less without
            // being native.
            _ => return Err(standing_lost()),
        };
        let proof = vault
            .invocation_slip_in_txn(txn, binding)
            .map_err(|_| standing_lost())?;
        let claims = proof.claims();
        if claims.holder_ref != actor.to_hex()
            || claims.actor_class.as_deref() != Some(class.gate_actor_class())
            || !(proof.allows_verb("write") || proof.allows_verb("core:write"))
        {
            return Err(standing_lost());
        }
        Ok(Some(proof))
    }

    /// [`Self::requester_live_in`] in a snapshot of its own.
    #[must_use]
    pub fn requester_live(&self, vault: &Vault) -> bool {
        vault
            .store
            .env
            .read_txn()
            .is_ok_and(|txn| self.requester_live_in(vault, &txn))
    }
}

/// The turn an action acts on, resolved and checked as its caller.
struct Resolved {
    conversation: EntityId,
    user_turn: EntityId,
    message: EntityId,
    context: TurnActionContext,
}

fn invalid_state(message: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        message,
        &["Read the conversation's transcript again before acting on the turn."],
    )
}

/// The slip a turn action was asked with no longer stands for its requester.
fn standing_lost() -> MemoryError {
    MemoryError::new(
        crate::memory::MEMORY_CODE_FORBIDDEN,
        "the slip this turn action was asked with no longer stands for its requester",
        &["Ask for the action again with a live credential."],
    )
}

impl Memory<'_> {
    /// `vault.conversations.turn.continue`: queues generation that resumes
    /// an incomplete reply on its own MESSAGE, from exactly its saved text.
    pub fn conversations_turn_continue(
        &self,
        request: &TurnActionRequest,
    ) -> MemoryResult<TurnActionReceipt> {
        self.queue_turn_action(TurnAction::Continue, request)
    }

    /// `vault.conversations.turn.retry`: queues a new answer to the user
    /// turn an assistant turn answered, in a new assistant TURN. The old
    /// reply stays as it is.
    pub fn conversations_turn_retry(
        &self,
        request: &TurnActionRequest,
    ) -> MemoryResult<TurnActionReceipt> {
        self.queue_turn_action(TurnAction::Retry, request)
    }

    /// The context a queued `attempt` runs with, resolved and checked again
    /// as its requester: this handle must be bound to that actor. The
    /// attempt's standing is judged first, so a revoked slip reads nothing;
    /// the reads then run where the requester sat, under the slip's current
    /// proof. `history` caps the earlier lines it carries.
    pub fn turn_action_context(
        &self,
        attempt: &TurnActionAttempt,
        history: usize,
    ) -> MemoryResult<TurnActionContext> {
        if attempt.requester()? != (self.actor(), self.actor_class()) {
            return Err(MemoryError::bad_request(
                "a turn action runs as the actor that asked for it",
            ));
        }
        let proof = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            attempt.requester_proof_in(self.vault(), &txn)?
        };
        let reader = self.clone().at(if attempt.off_device {
            CallerLocality::OffDevice
        } else {
            CallerLocality::OnDevice
        });
        let reader = match &proof {
            Some(proof) => reader.with_read_proof(proof),
            None => reader,
        };
        let resolved =
            reader.resolve_turn_action(attempt.action, attempt.assistant_turn, history)?;
        if resolved.conversation != attempt.conversation
            || resolved.user_turn != attempt.user_turn
            || resolved.message != attempt.message
        {
            return Err(invalid_state(
                "the turn's conversation changed after its action was queued",
            ));
        }
        Ok(resolved.context)
    }

    /// The new assistant TURN a Retry `action` answers in on a DAG
    /// conversation, appended as the answering agent: a sibling of the old
    /// turn at its parent, replying to the user turn, with HEAD left where it
    /// is. A thread's Retry is a reply in that thread. `None` on a
    /// conversation that has not adopted the DAG, where the reply's stream
    /// mints its own TURN. The action is resolved and checked again as its
    /// requester first, so this handle must be bound to that actor.
    pub fn turn_action_retry_turn(
        &self,
        action: &TurnActionAttempt,
    ) -> MemoryResult<Option<EntityId>> {
        if action.action != TurnAction::Retry {
            return Err(MemoryError::bad_request(
                "only Retry appends a new assistant turn",
            ));
        }
        let context = self.turn_action_context(action, 0)?;
        let vault = self.vault();
        let (parent, session, thread) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            if !crate::conversation_dag::keeps_dag_topology(
                &vault.store,
                &txn,
                &action.conversation,
            )? {
                return Ok(None);
            }
            (
                crate::conversation_dag::retained_parent(
                    &vault.store,
                    &txn,
                    &action.assistant_turn,
                )?,
                crate::compaction::turn_session_membership_in_txn(
                    &vault.store,
                    &txn,
                    &action.assistant_turn,
                )?,
                crate::conversation_dag::is_thread_record(
                    &vault.store,
                    &txn,
                    &action.assistant_turn,
                )?,
            )
        };
        let now = vault.now_recorded_at();
        let writer = vault.memory(context.agent, EdgeActorClass::Agent);
        // The TURN carries only its speaker: the reply's words are its
        // MESSAGE's, added under it by the reply's stream.
        let body = rmp_serde::to_vec_named(&serde_json::json!({ "speaker": "assistant" }))
            .map_err(|_| Error::InvariantViolation("retry turn body encode failed"))?;
        let input = crate::conversation_dag::AppendRecord {
            conversation: action.conversation,
            parent,
            reply_to: Some(action.user_turn),
            quote: None,
            address: crate::conversation_dag::AddressMode::Broadcast,
            recipients: Vec::new(),
            advance: false,
            kind: crate::registry::ENTITY_TYPE_TURN,
            occurred: crate::TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            body,
            text: Vec::new(),
            session,
            thread_audience: None,
            actor: crate::WriteActor::new(context.agent, EdgeActorClass::Agent),
        };
        let appended = if thread {
            vault.reply_in_thread(&writer, action.assistant_turn, &input)?
        } else {
            vault.append_dag_record(&writer, &input)?
        };
        Ok(Some(appended.id))
    }

    fn queue_turn_action(
        &self,
        action: TurnAction,
        request: &TurnActionRequest,
    ) -> MemoryResult<TurnActionReceipt> {
        // A transport's caller acts on the slip its request was admitted
        // on; only the in-process host acts with none.
        let native = self.native_invocation();
        if !native && self.invocation_slip().is_none() {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "a turn action over a transport needs the slip its request was admitted on",
                &["Present a capability slip with its holder proof."],
            ));
        }
        let assistant_turn = resolve_entity_ref(self.vault(), &request.turn_id)?;
        // The history is read again when the action runs; none is kept here.
        let resolved = self.resolve_turn_action(action, assistant_turn, 0)?;
        let payload = TurnActionAttempt {
            action,
            conversation: resolved.conversation,
            user_turn: resolved.user_turn,
            assistant_turn,
            message: resolved.message,
            actor: self.actor(),
            actor_class: self.actor_class() as u8,
            invocation_slip: self.invocation_slip().cloned(),
            native,
            off_device: self.locality() == CallerLocality::OffDevice,
        };
        // Queued only while the slip it carries stands for this actor.
        {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            payload.requester_proof_in(self.vault(), &txn)?;
        }
        // One live action per MESSAGE: a second while one is queued or
        // running returns that one.
        let outcome = AttemptQueue::new(self.vault()).enqueue(EnqueueAttempt {
            kind: TURN_ACTION_ATTEMPT_KIND.to_owned(),
            payload: payload.encode()?,
            dedupe_key: Some(resolved.message.to_hex()),
            run_id: None,
            now: self.vault().now_recorded_at(),
        })?;
        let (EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record)) = outcome;
        let queued = TurnActionAttempt::decode(&record)?;
        Ok(TurnActionReceipt {
            action: queued.action,
            turn_id: queued.assistant_turn.to_hex(),
            message_id: queued.message.to_hex(),
            attempt_id: crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
        })
    }

    /// Resolves `assistant_turn` for `action` as the bound actor: a readable
    /// assistant TURN of a conversation the actor may write, holding one
    /// MESSAGE a stream generated, authored by a readable agent, with a user
    /// turn before it. No stream may be open on the MESSAGE, and Continue
    /// needs it incomplete. Retry on a project room's indexed turn is
    /// refused: a second answer there needs the room's regeneration door.
    fn resolve_turn_action(
        &self,
        action: TurnAction,
        assistant_turn: EntityId,
        history: usize,
    ) -> MemoryResult<Resolved> {
        let vault = self.vault();
        let conversation = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            crate::memory::verify_actor_binding_in_txn(
                vault,
                &txn,
                self.actor(),
                self.actor_class(),
            )?;
            let conversation = crate::memory::sole_edge_target(
                &vault.store,
                &txn,
                &assistant_turn,
                EdgeKind::ChildOf,
                "turn",
            )?
            .ok_or_else(|| MemoryError::not_found("turn not found"))?;
            // A person erased from a room writes nothing more there.
            let person = vault
                .get_raw_in(&txn, &self.actor())?
                .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
                .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_PERSON);
            if person
                && !super::room_person_write_allowed(
                    &vault.store,
                    &txn,
                    conversation,
                    self.actor(),
                )?
            {
                return Err(MemoryError::new(
                    crate::memory::MEMORY_CODE_FORBIDDEN,
                    "an erased person cannot act on a turn in this room",
                    &[],
                ));
            }
            // A room answers a claimed turn once; its second answer waits on
            // the room's own regeneration door, so none is queued here.
            if action == TurnAction::Retry
                && crate::workspace_roster::replicated_turn_in(vault, &txn, assistant_turn)?
                    .is_some()
            {
                return Err(invalid_state(
                    "indexed-room Retry requires the room regeneration door",
                ));
            }
            conversation
        };
        let walk = self.walk_to_turn(&conversation, &assistant_turn, history)?;
        let turn = walk
            .turn
            .ok_or_else(|| MemoryError::not_found("turn not found"))?;
        let (user_turn, user_text) = walk
            .user
            .ok_or_else(|| invalid_state("no user turn comes before this turn"))?;
        // The turn's one generated MESSAGE: a companion reply a stream wrote.
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let mut generated = Vec::new();
        for message in turn
            .messages
            .iter()
            .filter(|message| message.role == WitnessAuthor::Companion.as_str())
        {
            let id = EntityId::from_hex(&message.id)?;
            if crate::memory::message_stream_finality_in_txn(vault, &txn, &id)?.is_some() {
                generated.push((id, message));
            }
        }
        let (message, reply) = match generated.as_slice() {
            [only] => *only,
            _ => {
                return Err(MemoryError::bad_request(
                    "the turn is not an assistant turn holding one generated reply",
                ));
            }
        };
        let agent = crate::memory::sole_edge_target(
            &vault.store,
            &txn,
            &message,
            EdgeKind::AuthoredBy,
            "message",
        )?
        .ok_or_else(|| MemoryError::bad_request("the reply names no agent"))?;
        drop(txn);
        if reply.generating {
            return Err(invalid_state("the reply is being generated now"));
        }
        if action == TurnAction::Continue && !reply.incomplete {
            return Err(invalid_state(
                "the reply is complete; only Retry acts on it",
            ));
        }
        // Its instructions reach the model, so the caller must be able to
        // read the agent's definition, as chat requires.
        if self.get_entity(&agent.to_hex())?.value.is_none() {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "the answering agent's definition is not readable by this actor",
                &[],
            ));
        }
        Ok(Resolved {
            conversation,
            user_turn,
            message,
            context: TurnActionContext {
                agent,
                history: walk.history.into(),
                user_text,
                saved: reply.text.clone(),
            },
        })
    }

    /// Reads `conversation`'s transcript in order up to `target`, as the
    /// bound actor: the target turn, the latest user turn before it, and up
    /// to `history` lines before that user turn.
    fn walk_to_turn(
        &self,
        conversation: &EntityId,
        target: &EntityId,
        history: usize,
    ) -> MemoryResult<Walk> {
        // A DAG conversation's history is the branch that leads to the turn,
        // read on one page; any other's is its time order.
        let mut branch = self.turn_action_branch_transcript(conversation, target)?;
        let target = target.to_hex();
        let mut walk = Walk {
            turn: None,
            user: None,
            history: VecDeque::new(),
        };
        // Lines of the latest user turn and of the turns after it so far:
        // they join the history once a later user turn takes its place.
        let mut since: Vec<TurnActionLine> = Vec::new();
        let mut after = None;
        loop {
            let page = match branch.take() {
                Some(page) => page,
                None => {
                    self.conversation_transcript(
                        conversation,
                        after.as_deref(),
                        MAX_TRANSCRIPT_PAGE_TURNS,
                    )?
                    .value
                }
            };
            for turn in page.turns {
                if turn.id == target {
                    walk.turn = Some(turn);
                    return Ok(walk);
                }
                let lines: Vec<TurnActionLine> = turn
                    .messages
                    .iter()
                    .filter_map(|message| {
                        let author = WitnessAuthor::parse(&message.role)?;
                        (author != WitnessAuthor::System && !message.text.is_empty()).then(|| {
                            TurnActionLine {
                                author,
                                text: message.text.clone(),
                            }
                        })
                    })
                    .collect();
                let user: Vec<&str> = lines
                    .iter()
                    .filter(|line| line.author == WitnessAuthor::User)
                    .map(|line| line.text.as_str())
                    .collect();
                if user.is_empty() {
                    since.extend(lines);
                    continue;
                }
                let text = user.join("\n\n");
                walk.history.extend(std::mem::replace(&mut since, lines));
                while walk.history.len() > history {
                    walk.history.pop_front();
                }
                walk.user = Some((EntityId::from_hex(&turn.id)?, text));
            }
            match page.next {
                Some(next) => after = Some(next),
                None => return Ok(walk),
            }
        }
    }
}

/// What [`Memory::walk_to_turn`] found.
struct Walk {
    turn: Option<crate::memory::TranscriptTurn>,
    user: Option<(EntityId, String)>,
    history: VecDeque<TurnActionLine>,
}
