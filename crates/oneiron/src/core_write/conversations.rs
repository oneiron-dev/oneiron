//! `vault.conversations.create` and `vault.conversations.turns.create`
//! (OF-181): a conversation, and a TURN under one. `POST
//! /v1/core/conversations` and `POST /v1/core/conversations/{c}/turns` run
//! these same Vault doors, so a button, an agent's call and the REST write
//! make one write.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::batch::CoreWriteLane;
use super::shape::{
    AnnouncementAuthority, CoreWriteTextField, core_body_for_write, core_text_pairs,
    core_write_times, entity_id, stage_core_put, text_pairs, write_id,
};
use crate::authority::VerifiedSlip;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::conversation::ConversationBody;
use crate::edge::EdgeActorClass;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault, WriteActor};

/// A conversation to create. A body that names members also authors the
/// room's membership ledger, its creator and its role grants, as the
/// writing actor; a body with none is a plain put.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConversationCreateInput {
    /// The conversation's id; a fresh one when omitted.
    #[serde(default)]
    pub id: Option<String>,
    /// Unix seconds; defaults to `learned_at`.
    #[serde(default, alias = "occurredStart")]
    pub occurred_start: Option<u64>,
    /// Unix seconds; defaults to `occurred_start`.
    #[serde(default, alias = "occurredEnd")]
    pub occurred_end: Option<u64>,
    /// Unix seconds; defaults to now.
    #[serde(default, alias = "learnedAt")]
    pub learned_at: Option<u64>,
    /// The conversation body: kind, members, roles, title and the rest.
    pub body: Value,
    /// Explicit text-index fields; when omitted, the body's top-level strings.
    #[serde(default)]
    pub text: Option<Vec<CoreWriteTextField>>,
}

/// One TURN to put under a conversation, with its checked ChildOf edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConversationTurnCreateInput {
    /// The CONVERSATION the TURN belongs to.
    pub conversation: String,
    /// The TURN's id; a fresh one when omitted.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, alias = "occurredStart")]
    pub occurred_start: Option<u64>,
    #[serde(default, alias = "occurredEnd")]
    pub occurred_end: Option<u64>,
    #[serde(default, alias = "learnedAt")]
    pub learned_at: Option<u64>,
    pub body: Value,
    #[serde(default)]
    pub text: Option<Vec<CoreWriteTextField>>,
}

/// The entity a core write stored: its id, its type, the learned time it
/// sampled and the body as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreEntityWriteReceipt {
    pub id: String,
    pub entity_type: u8,
    pub learned_at: u64,
    pub body: Value,
}

impl CoreEntityWriteReceipt {
    fn new(id: EntityId, entity_type: u8, learned_at: u64, body: Value) -> Self {
        Self {
            id: id.to_hex(),
            entity_type,
            learned_at,
            body,
        }
    }
}

impl Vault {
    /// Creates a conversation, held to `lane` (FIX 10781): an id a stored
    /// row holds is judged against that row in the write's own transaction
    /// first, so the caller puts over only a row its lane admits
    /// ([`CoreWriteLane::admits_puts_in`]); an unbound lane puts as before.
    /// One naming members is authored by `actor` in one transaction with its
    /// membership ledger, text, creator and role grants; one naming none is
    /// a plain put, which no actor needs.
    /// # Errors
    /// A body that is no conversation, a bad id or interval, a memberful
    /// create with no actor, a named stored row outside `lane` as missing,
    /// or the vault's refusal.
    pub fn write_core_conversation(
        &self,
        input: &ConversationCreateInput,
        actor: Option<WriteActor>,
        lane: &CoreWriteLane<'_>,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        let body: ConversationBody = serde_json::from_value(input.body.clone())
            .map_err(|_| MemoryError::bad_request("invalid conversation body"))?;
        let id = write_id(input.id.as_deref())?;
        let times = core_write_times(input.occurred_start, input.occurred_end, input.learned_at)?;
        let admitted = |txn: &heed::RoTxn<'_>| -> crate::Result<()> {
            if lane.admits_puts_in(txn, &[id])? {
                return Ok(());
            }
            // As missing: the row's kind, body and scope stay unsaid.
            Err(crate::Error::EntityNotFound)
        };
        if !body.member_ids.is_empty() {
            let actor = actor.ok_or_else(|| {
                MemoryError::bad_request("a conversation with members is created by an actor")
            })?;
            let fields = core_text_pairs(input.text.as_deref().map(text_pairs), &input.body);
            let fields: Vec<(&str, &str)> = fields
                .iter()
                .map(|(field, value)| (field.as_str(), value.as_str()))
                .collect();
            // `Vault::create_conversation_with_text`, its id judged first in
            // the same transaction.
            self.with_write_txn_grouped(|txn| {
                admitted(txn)?;
                crate::conversation::create_in_txn(
                    self,
                    txn,
                    id,
                    &body,
                    actor,
                    times.occurred,
                    times.learned_at,
                    &fields,
                )
            })?;
            return Ok(CoreEntityWriteReceipt::new(
                id,
                ENTITY_TYPE_CONVERSATION,
                times.learned_at,
                input.body.clone(),
            ));
        }
        // A container body is never a TURN, so no announcement shapes it.
        stage_core_put(
            self.batch(),
            &id,
            ENTITY_TYPE_CONVERSATION,
            times,
            &input.body,
            AnnouncementAuthority::Writer,
            input.text.as_deref().map(text_pairs),
        )?
        .commit_with_target_guard(admitted)?;
        Ok(CoreEntityWriteReceipt::new(
            id,
            ENTITY_TYPE_CONVERSATION,
            times.learned_at,
            input.body.clone(),
        ))
    }

    /// Puts one TURN, its text index and its checked ChildOf edge to the
    /// conversation, in one batch, for `writer`'s caller. It wakes nothing:
    /// the served door that calls it lands the turn. `announcement` is the
    /// writer's, which its caller resolved: only the owner's TURN may be a
    /// platform announcement. A caller the TURN doors do not serve as the
    /// owner ([`Vault::turn_doors_owner`]) writes only into a conversation
    /// its own lane reads, judged in the batch's own writer (FIX 5939); the
    /// owner writes as before. Such a TURN sits in no private thread: its
    /// thread keys are refused here, and its one edge is to the
    /// conversation, which no thread holds. Nor does it put over a row its
    /// lane does not read: an id it names that a stored row holds is judged
    /// against that row first, in the same writer, before the put or its
    /// ChildOf lands (FIX 6068).
    /// # Errors
    /// A target that is no conversation, a bad id, interval or body, a
    /// conversation or a named stored row outside `writer`'s read, or the
    /// batch's ChildOf refusal.
    pub fn write_core_conversation_turn(
        &self,
        input: &ConversationTurnCreateInput,
        writer: &ScopedRead<'_>,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        self.write_core_conversation_turn_admitted(
            input,
            announcement,
            |txn, conversation, turn| {
                if self.turn_doors_owner_in(writer, txn)? {
                    return Ok(true);
                }
                Ok(writer.is_entity_readable_in(txn, conversation)?
                    && crate::batch::put_target_admitted_in(writer, txn, turn)?)
            },
        )?
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the conversation is outside this credential's read",
                &["Write the turn into a conversation this credential reads."],
            )
        })
    }

    /// [`Self::write_core_conversation_turn`] for the owner's own credential
    /// that grants no read (FIX 6066, Engine 10-20): it writes as the owner
    /// while `proof` is the live vault owner's own, judged in the batch's own
    /// writer. `None`, with nothing written, for any other credential.
    /// # Errors
    /// As [`Self::write_core_conversation_turn`], or a broken owner check.
    pub fn write_core_conversation_turn_as_owner(
        &self,
        input: &ConversationTurnCreateInput,
        proof: &VerifiedSlip,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<Option<CoreEntityWriteReceipt>> {
        self.write_core_conversation_turn_admitted(input, announcement, |txn, _, _| {
            self.slip_is_owner_in(txn, proof)
        })
    }

    /// Whether `proof` is the vault owner's own credential in `txn`, by the
    /// owner rule a credential's read key follows
    /// ([`Self::credential_read_key_in_txn`]): a person's, untransferred,
    /// live, and held by the owner the binding proves.
    fn slip_is_owner_in(&self, txn: &heed::RoTxn<'_>, proof: &VerifiedSlip) -> crate::Result<bool> {
        let claims = proof.claims();
        if !matches!(claims.actor_class.as_deref(), None | Some("human")) || proof.is_transferred()
        {
            return Ok(false);
        }
        let Ok(holder) = EntityId::from_hex(&claims.holder_ref) else {
            return Ok(false);
        };
        let owner =
            crate::memory::actor_is_vault_owner_in_txn(self, txn, holder, EdgeActorClass::Human)
                .map_err(|refusal| {
                    crate::Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(Box::new(
                        refusal,
                    )))
                })?;
        Ok(owner && self.capability_slip_is_live_in_txn(txn, proof)?)
    }

    /// One TURN under a conversation, written only when `admits` passes the
    /// conversation and the TURN's id in the batch's own writer; `None`,
    /// nothing written, when it does not.
    fn write_core_conversation_turn_admitted(
        &self,
        input: &ConversationTurnCreateInput,
        announcement: AnnouncementAuthority,
        admits: impl FnOnce(&heed::RoTxn<'_>, &EntityId, &EntityId) -> crate::Result<bool>,
    ) -> MemoryResult<Option<CoreEntityWriteReceipt>> {
        let conversation = entity_id(&input.conversation, "conversation")?;
        match self.get_entity_type(&conversation)? {
            Some(ENTITY_TYPE_CONVERSATION) => {}
            Some(_) => {
                return Err(MemoryError::bad_request(
                    "conversation id does not reference a conversation entity",
                ));
            }
            None => return Err(MemoryError::not_found("conversation not found")),
        }
        // A thread binding is its room door's to stamp (FIX 2951), and an
        // audience edit its thread's audience door's (FIX 5545).
        if [
            crate::workspace_roster::ROOM_THREAD_KEY,
            crate::workspace_roster::ROOM_THREAD_AUDIENCE_KEY,
        ]
        .iter()
        .any(|key| input.body.get(*key).is_some())
        {
            return Err(MemoryError::bad_request(
                "a TURN's room_thread and room_thread_audience are stamped by its room's thread doors",
            ));
        }
        let id = write_id(input.id.as_deref())?;
        let times = core_write_times(input.occurred_start, input.occurred_end, input.learned_at)?;
        let outside = std::cell::Cell::new(false);
        let committed = stage_core_put(
            self.batch(),
            &id,
            ENTITY_TYPE_TURN,
            times,
            &input.body,
            announcement,
            input.text.as_deref().map(text_pairs),
        )?
        .edge_checked(&id, &conversation, 1.0)
        .commit_with_target_guard(|txn| {
            if admits(txn, &conversation, &id)? {
                return Ok(());
            }
            outside.set(true);
            Err(crate::Error::EntityNotFound)
        });
        if outside.get() {
            return Ok(None);
        }
        committed?;
        Ok(Some(CoreEntityWriteReceipt::new(
            id,
            ENTITY_TYPE_TURN,
            times.learned_at,
            core_body_for_write(ENTITY_TYPE_TURN, &input.body, announcement).into_owned(),
        )))
    }
}

impl Memory<'_> {
    /// `vault.conversations.create`: a conversation, its membership
    /// authored as the bound actor, held to this handle's write lane (FIX
    /// 10781): its read, or the bounds of what a credential that grants no
    /// read may write to.
    /// # Errors
    /// As [`Vault::write_core_conversation`], and the write lane's refusal.
    pub fn conversations_create(
        &self,
        input: &ConversationCreateInput,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        let actor = self.write_actor();
        let lane = self.core_write_lane()?;
        self.vault()
            .write_core_conversation(input, Some(actor), &lane)
    }

    /// `vault.conversations.turns.create`: one TURN under a conversation,
    /// held to this handle's own read lane (FIX 5939), a platform
    /// announcement only while the bound actor is a live owner.
    /// # Errors
    /// As [`Vault::write_core_conversation_turn`].
    pub fn conversations_turns_create(
        &self,
        input: &ConversationTurnCreateInput,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let announcement = AnnouncementAuthority::of_actor(self.vault(), &self.actor())?;
        self.vault()
            .write_core_conversation_turn(input, &lane, announcement)
    }
}
