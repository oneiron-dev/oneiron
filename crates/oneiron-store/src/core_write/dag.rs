//! The `vault.conversations.records.append` row's input and receipt types
//! (OF-181) and the append door's input they make. The Memory door that
//! appends is the engine's (`core_write` in `oneiron`).

use oneiron_base::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use oneiron_contracts::memory::MemoryResult;
use oneiron_contracts::write_envelope::WriteActor;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shape::{
    AnnouncementAuthority, CoreWriteTextField, core_body_for_write, core_text_pairs,
    core_write_times, encode_core_body, entity_id, optional_entity_id, text_pairs,
};
use crate::conversation_record::{
    AddressMode, AppendRecord, AppendedRecord, DagReplyTarget, QuoteSpan,
};

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

/// One TURN to append to a conversation's DAG, or one MESSAGE of a TURN.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DagRecordAppendInput {
    /// The CONVERSATION appended to.
    pub conversation: String,
    /// The record continued; absent only for the first root. A MESSAGE
    /// continues only a MESSAGE of its own TURN.
    #[serde(default)]
    pub parent: Option<String>,
    /// The record answered: a TURN, or one MESSAGE of a TURN.
    #[serde(default)]
    pub reply_to: Option<String>,
    /// The TURN the appended MESSAGE is part of (FIX 9771). Set, the record
    /// is a MESSAGE whose `body` names its author, type, content, optional
    /// metadata, visibility and order; absent, it is a TURN. A MESSAGE never
    /// enters HEAD.
    #[serde(default)]
    pub containing_turn: Option<String>,
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
    /// A private thread's audience (FIX 2951). This row appends on the
    /// trunk, which names none, so a record that sets it is refused; a
    /// thread opens through its own reply door.
    #[serde(default)]
    pub thread_audience: Option<Vec<String>>,
}

/// The appended record, HEAD after the append and the record's parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DagRecordAppendReceipt {
    pub id: String,
    pub head: Option<String>,
    pub parent: Option<String>,
    /// The stored record's type: TURN or MESSAGE.
    pub entity_type: u8,
    /// The TURN a MESSAGE record is part of; absent for a TURN.
    #[serde(default)]
    pub containing_turn: Option<String>,
    /// What the record answers, at the revision it answered.
    #[serde(default)]
    pub reply_target: Option<DagReplyTarget>,
}

impl From<AppendedRecord> for DagRecordAppendReceipt {
    fn from(appended: AppendedRecord) -> Self {
        Self {
            id: appended.id.to_hex(),
            head: appended.head.map(|id| id.to_hex()),
            parent: appended.parent.map(|id| id.to_hex()),
            entity_type: appended.kind,
            containing_turn: appended.containing_turn.map(|id| id.to_hex()),
            reply_target: appended.reply_target,
        }
    }
}

impl DagRecordAppendInput {
    /// The append door's input, bylined `actor`, a platform announcement
    /// only at the owner's `announcement`.
    /// # Errors
    /// A bad id, interval or body.
    pub fn append_record(
        &self,
        actor: WriteActor,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<AppendRecord> {
        let times = core_write_times(self.occurred_start, self.occurred_end, self.learned_at)?;
        let containing_turn =
            optional_entity_id(self.containing_turn.as_deref(), "containing_turn")?;
        let kind = if containing_turn.is_some() {
            ENTITY_TYPE_MESSAGE
        } else {
            ENTITY_TYPE_TURN
        };
        let body = core_body_for_write(kind, &self.body, announcement);
        Ok(AppendRecord {
            conversation: entity_id(&self.conversation, "conversation")?,
            parent: optional_entity_id(self.parent.as_deref(), "parent")?,
            reply_to: optional_entity_id(self.reply_to.as_deref(), "reply_to")?,
            quote: self
                .quote
                .as_ref()
                .map(|quote| {
                    Ok::<_, oneiron_contracts::memory::MemoryError>(QuoteSpan {
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
            kind,
            containing_turn,
            occurred: times.occurred,
            learned_at: times.learned_at,
            body: encode_core_body(&body)?,
            text: core_text_pairs(self.text.as_deref().map(text_pairs), &body),
            session: optional_entity_id(self.session.as_deref(), "session")?,
            actor,
            thread_audience: self
                .thread_audience
                .as_ref()
                .map(|ids| {
                    ids.iter()
                        .map(|id| entity_id(id, "thread_audience"))
                        .collect::<MemoryResult<std::collections::BTreeSet<_>>>()
                })
                .transpose()?,
        })
    }
}
