//! `vault.conversations.records.append` (OF-181): one DAG record and its
//! topology, the write `POST /v1/core/conversations/{c}/records` makes. The
//! byline is the writer's own: the row takes no actor, and the append door
//! checks every reference it names on the writer's read lane, in the
//! append's own transaction.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shape::{
    CoreWriteTextField, core_body_for_write, core_text_pairs, core_write_times, encode_core_body,
    entity_id, optional_entity_id, text_pairs,
};
use crate::WriteActor;
use crate::conversation_dag::{AddressMode, AppendRecord, AppendedRecord, QuoteSpan};
use crate::memory::{Memory, MemoryResult};
use crate::registry::ENTITY_TYPE_TURN;

/// Who a record addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoreDagAddressMode {
    Broadcast,
    Direct,
}

/// A quoted span of a MESSAGE: half-open Unicode scalar offsets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreDagQuoteInput {
    pub message: String,
    pub start: u32,
    pub end: u32,
}

/// One TURN to append to a conversation's DAG.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DagRecordAppendInput {
    /// The CONVERSATION appended to.
    pub conversation: String,
    /// The record continued; absent only for the first root.
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub reply_to: Option<String>,
    /// Broadcast when omitted.
    #[serde(default)]
    pub addr: Option<CoreDagAddressMode>,
    /// Named recipients.
    #[serde(default)]
    pub to: Option<Vec<String>>,
    /// Advance HEAD; the parent must then be HEAD.
    pub advance: bool,
    pub body: Value,
    #[serde(default)]
    pub text: Option<Vec<CoreWriteTextField>>,
    #[serde(default)]
    pub occurred_start: Option<u64>,
    #[serde(default)]
    pub occurred_end: Option<u64>,
    #[serde(default)]
    pub learned_at: Option<u64>,
    /// The sitting or sub-session the record belongs to.
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub quote: Option<CoreDagQuoteInput>,
}

/// The appended record, HEAD after the append and the record's parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DagRecordAppendReceipt {
    pub id: String,
    pub head: Option<String>,
    pub parent: Option<String>,
}

impl From<AppendedRecord> for DagRecordAppendReceipt {
    fn from(appended: AppendedRecord) -> Self {
        Self {
            id: appended.id.to_hex(),
            head: appended.head.map(|id| id.to_hex()),
            parent: appended.parent.map(|id| id.to_hex()),
        }
    }
}

impl DagRecordAppendInput {
    /// The append door's input, bylined `actor`.
    /// # Errors
    /// A bad id, interval or body.
    pub fn append_record(&self, actor: WriteActor) -> MemoryResult<AppendRecord> {
        let times = core_write_times(self.occurred_start, self.occurred_end, self.learned_at)?;
        let body = core_body_for_write(ENTITY_TYPE_TURN, &self.body);
        Ok(AppendRecord {
            conversation: entity_id(&self.conversation, "conversation")?,
            parent: optional_entity_id(self.parent.as_deref(), "parent")?,
            reply_to: optional_entity_id(self.reply_to.as_deref(), "reply_to")?,
            quote: self
                .quote
                .as_ref()
                .map(|quote| {
                    Ok::<_, crate::memory::MemoryError>(QuoteSpan {
                        message: entity_id(&quote.message, "quote.message")?,
                        start: quote.start,
                        end: quote.end,
                    })
                })
                .transpose()?,
            address: match self.addr {
                Some(CoreDagAddressMode::Direct) => AddressMode::Direct,
                Some(CoreDagAddressMode::Broadcast) | None => AddressMode::Broadcast,
            },
            recipients: self
                .to
                .iter()
                .flatten()
                .map(|id| entity_id(id, "to"))
                .collect::<MemoryResult<Vec<_>>>()?,
            advance: self.advance,
            kind: ENTITY_TYPE_TURN,
            occurred: times.occurred,
            learned_at: times.learned_at,
            body: encode_core_body(&body)?,
            text: core_text_pairs(self.text.as_deref().map(text_pairs), &body),
            session: optional_entity_id(self.session.as_deref(), "session")?,
            actor,
        })
    }
}

impl Memory<'_> {
    /// `vault.conversations.records.append`: one TURN on the DAG, bylined
    /// the bound actor, through the append door that checks each named
    /// reference on this handle's read lane.
    /// # Errors
    /// A bad input, or the append door's refusal.
    pub fn conversations_records_append(
        &self,
        input: &DagRecordAppendInput,
    ) -> MemoryResult<DagRecordAppendReceipt> {
        let append = input.append_record(WriteActor::new(self.actor(), self.actor_class()))?;
        Ok(self.vault().append_dag_record(self, &append)?.into())
    }
}
