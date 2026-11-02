//! What a reply answers (FIX 9771): a TURN, or one MESSAGE inside the TURN
//! that holds it, each at the content revision captured in the reply's own
//! write. A MESSAGE target keeps its TURN, against which the reply is placed
//! and read. A TURN reply's pointer `record` and its `RepliesTo` still name
//! that TURN, at its body's revision, and the pointer adds the MESSAGE and
//! its revision: MESSAGE rows never replicate, so a reply replicates as it
//! did. A MESSAGE the append door adds keeps the same pointer in its
//! metadata, and its `RepliesTo` names the exact target.

use super::super::DagReplyTarget;
use super::super::graph::{invalid, require_member, require_type};
use super::super::writes::value;
use super::{
    ProvenQuote, QuoteAnchor, RoomQuote, WITNESS_QUOTES_KEY, field, message_fields, owning_turn_in,
    quotes_value,
};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::RoTxn;
use rmpv::Value;
use std::collections::BTreeMap;

/// The metadata key under which a MESSAGE the append door adds keeps its
/// reply pointer. Only the door writes it.
pub(in crate::conversation_dag) const MESSAGE_REPLY_KEY: &str = "dag_reply_to";

/// The reply target an append names: `asked`, a TURN or a MESSAGE of
/// `conversation`, or the MESSAGE `quote` selects, each at its revision in
/// this transaction. A quote answers the MESSAGE it quotes; an `asked`
/// beside it names that MESSAGE or the TURN holding it.
pub(in crate::conversation_dag) fn append_target_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    conversation: EntityId,
    asked: Option<EntityId>,
    quote: Option<&ProvenQuote>,
) -> Result<Option<DagReplyTarget>> {
    match (asked, quote) {
        (asked, Some(quote)) => {
            let message = quote.anchor.message();
            if asked.is_some_and(|asked| asked != message && asked != quote.turn) {
                return Err(invalid("a quote answers the message it quotes"));
            }
            Ok(Some(message_target_in_txn(
                vault,
                txn,
                conversation,
                message,
                quote.turn,
            )?))
        }
        (Some(asked), None) => Ok(Some(target_in_txn(vault, txn, conversation, asked)?)),
        (None, None) => Ok(None),
    }
}

/// `record` as a reply target in `conversation`: a TURN of it at its body's
/// revision, or a MESSAGE of one of its TURNs at its text's revision.
fn target_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    conversation: EntityId,
    record: EntityId,
) -> Result<DagReplyTarget> {
    if let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_MESSAGE,
        ..
    } = live_entity_row_in_txn(&vault.store, txn, &record)?
    {
        let turn = owning_turn_in(&vault.store, txn, &record)?;
        return message_target_in_txn(vault, txn, conversation, record, turn);
    }
    require_member(&vault.store, txn, &conversation, &record)?;
    Ok(DagReplyTarget::Turn {
        record,
        revision: revision_in_txn(vault, txn, record)?,
    })
}

/// The MESSAGE `message` of `turn` as a reply target in `conversation`.
fn message_target_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    conversation: EntityId,
    message: EntityId,
    turn: EntityId,
) -> Result<DagReplyTarget> {
    require_member(&vault.store, txn, &conversation, &turn)?;
    if crate::conversation::room_message_owner_in(&vault.store, txn, message)? != Some(conversation)
    {
        return Err(invalid("reply target is outside conversation"));
    }
    Ok(DagReplyTarget::Message {
        record: message,
        revision: message_revision_in_txn(vault, txn, message)?,
        containing_turn: turn,
    })
}

/// The revision a reply captures of the TURN `target`: its body's hash.
fn revision_in_txn(vault: &Vault, txn: &RoTxn<'_>, target: EntityId) -> Result<String> {
    let body = require_type(&vault.store, txn, &target, ENTITY_TYPE_TURN)?;
    Ok(blake3::hash(&body).to_hex().to_string())
}

/// The content revision of `message`: the hash of its current text, its
/// document's once it has one.
fn message_revision_in_txn(vault: &Vault, txn: &RoTxn<'_>, message: EntityId) -> Result<String> {
    let row = require_type(&vault.store, txn, &message, ENTITY_TYPE_MESSAGE)?;
    let body = crate::entity_doc::resolve_record_body(&vault.store, txn, &message, &row)?;
    Ok(blake3::hash(message_text(&body)?.as_bytes())
        .to_hex()
        .to_string())
}

/// The text of a MESSAGE body.
pub(in crate::conversation_dag) fn message_text(body: &[u8]) -> Result<String> {
    field(&message_fields(body)?, "content")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::CorruptedIndex("message canonical content"))
}

/// The reply pointer for `target`: the TURN it is placed against at that
/// TURN's revision, then, for a MESSAGE target, the MESSAGE and its
/// revision, then a quote's `anchor`.
pub(in crate::conversation_dag) fn reply_pointer_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    target: &DagReplyTarget,
    anchor: Option<QuoteAnchor>,
) -> Result<Value> {
    let placement = target.placement();
    let mut pointer = vec![
        (Value::from("record"), Value::from(placement.to_hex())),
        (
            Value::from("revision"),
            Value::from(match target {
                DagReplyTarget::Turn { revision, .. } => revision.clone(),
                DagReplyTarget::Message { .. } => revision_in_txn(vault, txn, placement)?,
            }),
        ),
    ];
    if let DagReplyTarget::Message {
        record, revision, ..
    } = target
    {
        pointer.extend([
            (Value::from("message"), Value::from(record.to_hex())),
            (
                Value::from("message_revision"),
                Value::from(revision.clone()),
            ),
        ]);
    }
    if let Some(anchor) = anchor {
        pointer.push((Value::from("quote"), anchor.to_value()));
    }
    Ok(Value::Map(pointer))
}

/// The reply target a stored record's `body` keeps: a TURN's in its
/// `reply_to` pointer, a MESSAGE's in its metadata's door-owned pointer;
/// `None` for a record that answers nothing.
pub(in crate::conversation_dag) fn stored_target(
    kind: u8,
    body: &[u8],
) -> Result<Option<DagReplyTarget>> {
    let mut input = body;
    let value = rmpv::decode::read_value(&mut input).map_err(|_| invalid("invalid record body"))?;
    let Value::Map(fields) = value else {
        return Err(invalid("invalid record body"));
    };
    if !input.is_empty() {
        return Err(invalid("trailing record bytes"));
    }
    let pointer = if kind == ENTITY_TYPE_MESSAGE {
        let Some(Value::Map(metadata)) = field(&fields, "metadata") else {
            return Ok(None);
        };
        sole(metadata, MESSAGE_REPLY_KEY, "duplicate reply pointer")?
    } else {
        sole(&fields, "reply_to", "duplicate reply pointer")?
    };
    let Some(pointer) = pointer else {
        return Ok(None);
    };
    let Value::Map(pointer) = pointer else {
        return Err(invalid("invalid reply pointer"));
    };
    let get = |name| -> Result<&Value> {
        sole(pointer, name, "duplicate reply pointer field")?
            .ok_or_else(|| invalid("incomplete reply pointer"))
    };
    let id = |name| -> Result<EntityId> {
        EntityId::from_hex(
            get(name)?
                .as_str()
                .ok_or_else(|| invalid("invalid reply target"))?,
        )
    };
    let hash = |name| -> Result<String> {
        let revision = get(name)?
            .as_str()
            .ok_or_else(|| invalid("invalid reply revision"))?;
        if revision.len() != 64 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("invalid reply hash"));
        }
        Ok(revision.to_owned())
    };
    let record = id("record")?;
    let revision = hash("revision")?;
    Ok(Some(
        if sole(pointer, "message", "duplicate reply pointer field")?.is_some() {
            DagReplyTarget::Message {
                record: id("message")?,
                revision: hash("message_revision")?,
                containing_turn: record,
            }
        } else {
            DagReplyTarget::Turn { record, revision }
        },
    ))
}

/// The one value `fields` keeps under `name`; `duplicate` refuses a second.
fn sole<'a>(
    fields: &'a [(Value, Value)],
    name: &str,
    duplicate: &'static str,
) -> Result<Option<&'a Value>> {
    let mut values = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let first = values.next();
    if values.next().is_some() {
        return Err(invalid(duplicate));
    }
    Ok(first)
}

/// A quoted room turn's reply topology, fixed in the room witness's
/// transaction before its TURN is minted (OF-460, FIX 2028). The quotes are
/// its messages' own ([`super::ProvenRoomQuote`]); the witness mints the
/// TURN once, with the reply mode, a pointer answering `target`, its first
/// quoted MESSAGE inside that message's TURN, at the revisions captured in
/// this transaction, and `RepliesTo` to that TURN in its first body and
/// write; nothing patches it later. A project room's thread reply is also a
/// DAG thread record whose chain continues `parent`, the reply's own. An
/// ordinary room's quoted turn (FIX 2027) has no `parent`, so it stays an
/// opaque turn, classified as no thread and chained to nothing, and it has
/// no room row, so its first body keeps its messages' quotes by citing
/// MESSAGE.
pub(crate) struct QuotedReply {
    parent: Option<EntityId>,
    target: DagReplyTarget,
    pointer: Value,
    quotes: BTreeMap<EntityId, RoomQuote>,
}

impl QuotedReply {
    /// The topology of a project room thread reply that continues the thread
    /// chain at `parent` in `conversation` and answers `message`, its first
    /// quoted MESSAGE, of `turn`.
    pub(crate) fn thread_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        conversation: EntityId,
        parent: EntityId,
        (message, turn): (EntityId, EntityId),
    ) -> Result<Self> {
        require_member(&vault.store, txn, &conversation, &parent)?;
        require_type(&vault.store, txn, &parent, ENTITY_TYPE_TURN)?;
        let target = message_target_in_txn(vault, txn, conversation, message, turn)?;
        Ok(Self {
            parent: Some(parent),
            pointer: reply_pointer_in_txn(vault, txn, &target, None)?,
            target,
            quotes: BTreeMap::new(),
        })
    }

    /// The topology of an ordinary room `conversation`'s quoted turn (FIX
    /// 2027) answering `message`, its first quoted MESSAGE, of `turn`, whose
    /// first body keeps `quotes`, its messages' by citing MESSAGE.
    pub(crate) fn ordinary_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        conversation: EntityId,
        (message, turn): (EntityId, EntityId),
        quotes: BTreeMap<EntityId, RoomQuote>,
    ) -> Result<Self> {
        let target = message_target_in_txn(vault, txn, conversation, message, turn)?;
        Ok(Self {
            parent: None,
            pointer: reply_pointer_in_txn(vault, txn, &target, None)?,
            target,
            quotes,
        })
    }

    /// The door-owned fields the reply's first TURN body carries: a reply
    /// answering its target at its revisions, on a project thread reply the
    /// thread record kind, and on an ordinary room's turn its messages'
    /// quotes.
    pub(crate) fn body_fields(&self) -> Vec<(Value, Value)> {
        let mut fields = vec![
            (Value::from("addr"), Value::from("reply")),
            (Value::from("reply_to"), self.pointer.clone()),
        ];
        if self.parent.is_some() {
            fields.insert(
                0,
                (
                    Value::from("dag_kind"),
                    Value::from(super::super::topology::RecordKind::Thread.as_str()),
                ),
            );
        }
        if !self.quotes.is_empty() {
            let quotes = quotes_value(&self.quotes);
            fields.push((Value::from(WITNESS_QUOTES_KEY), quotes));
        }
        fields
    }

    /// Stages the minted reply's `RepliesTo` edge to the TURN it is placed
    /// against and, on a project thread reply, its `Parent`.
    pub(crate) fn edges<'v>(
        &self,
        mut batch: crate::BatchBuilder<'v>,
        record: &EntityId,
        learned_at: u64,
    ) -> crate::BatchBuilder<'v> {
        if let Some(parent) = self.parent {
            batch =
                batch.edge_with_value_fields(record, EdgeKind::Parent, &parent, value(learned_at));
        }
        batch.edge_with_value_fields(
            record,
            EdgeKind::RepliesTo,
            &self.target.placement(),
            value(learned_at),
        )
    }
}
