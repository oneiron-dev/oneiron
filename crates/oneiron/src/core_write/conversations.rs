//! `vault.conversations.create` and `vault.conversations.turns.create`
//! (OF-181): a conversation, and a TURN under one. `POST
//! /v1/core/conversations` and `POST /v1/core/conversations/{c}/turns` run
//! these same Vault doors, so a button, an agent's call and the REST write
//! make one write.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shape::{
    CoreWriteTextField, core_body_for_write, core_text_pairs, core_write_times, entity_id,
    stage_core_put, text_pairs, write_id,
};
use crate::conversation::ConversationBody;
use crate::memory::{Memory, MemoryError, MemoryResult};
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
    /// Creates a conversation. One naming members is authored by `actor`
    /// in one transaction with its membership ledger, text, creator and
    /// role grants; one naming none is a plain put, which no actor needs.
    /// # Errors
    /// A body that is no conversation, a bad id or interval, a memberful
    /// create with no actor, or the vault's refusal.
    pub fn write_core_conversation(
        &self,
        input: &ConversationCreateInput,
        actor: Option<WriteActor>,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        let body: ConversationBody = serde_json::from_value(input.body.clone())
            .map_err(|_| MemoryError::bad_request("invalid conversation body"))?;
        let id = write_id(input.id.as_deref())?;
        let times = core_write_times(input.occurred_start, input.occurred_end, input.learned_at)?;
        if !body.member_ids.is_empty() {
            let actor = actor.ok_or_else(|| {
                MemoryError::bad_request("a conversation with members is created by an actor")
            })?;
            let fields = core_text_pairs(input.text.as_deref().map(text_pairs), &input.body);
            let fields: Vec<(&str, &str)> = fields
                .iter()
                .map(|(field, value)| (field.as_str(), value.as_str()))
                .collect();
            self.create_conversation_with_text(
                id,
                &body,
                actor,
                times.occurred,
                times.learned_at,
                &fields,
            )?;
            return Ok(CoreEntityWriteReceipt::new(
                id,
                ENTITY_TYPE_CONVERSATION,
                times.learned_at,
                input.body.clone(),
            ));
        }
        stage_core_put(
            self.batch(),
            &id,
            ENTITY_TYPE_CONVERSATION,
            times,
            &input.body,
            input.text.as_deref().map(text_pairs),
        )?
        .commit()?;
        Ok(CoreEntityWriteReceipt::new(
            id,
            ENTITY_TYPE_CONVERSATION,
            times.learned_at,
            input.body.clone(),
        ))
    }

    /// Puts one TURN, its text index and its checked ChildOf edge to the
    /// conversation, in one batch. It wakes nothing: the served door that
    /// calls it lands the turn.
    /// # Errors
    /// A target that is no conversation, a bad id, interval or body, or
    /// the batch's ChildOf refusal.
    pub fn write_core_conversation_turn(
        &self,
        input: &ConversationTurnCreateInput,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
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
        let id = write_id(input.id.as_deref())?;
        let times = core_write_times(input.occurred_start, input.occurred_end, input.learned_at)?;
        stage_core_put(
            self.batch(),
            &id,
            ENTITY_TYPE_TURN,
            times,
            &input.body,
            input.text.as_deref().map(text_pairs),
        )?
        .edge_checked(&id, &conversation, 1.0)
        .commit()?;
        Ok(CoreEntityWriteReceipt::new(
            id,
            ENTITY_TYPE_TURN,
            times.learned_at,
            core_body_for_write(ENTITY_TYPE_TURN, &input.body).into_owned(),
        ))
    }
}

impl Memory<'_> {
    /// `vault.conversations.create`: a conversation, its membership
    /// authored as the bound actor.
    /// # Errors
    /// As [`Vault::write_core_conversation`].
    pub fn conversations_create(
        &self,
        input: &ConversationCreateInput,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        let actor = WriteActor::new(self.actor(), self.actor_class());
        self.vault().write_core_conversation(input, Some(actor))
    }

    /// `vault.conversations.turns.create`: one TURN under a conversation.
    /// # Errors
    /// As [`Vault::write_core_conversation_turn`].
    pub fn conversations_turns_create(
        &self,
        input: &ConversationTurnCreateInput,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        self.vault().write_core_conversation_turn(input)
    }
}
