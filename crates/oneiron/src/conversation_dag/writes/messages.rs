//! A MESSAGE the append door adds to its TURN (FIX 9771): `PartOf` the TURN
//! its append names, a DAG TURN its own writer appended, with message-local
//! adjacency. Its `Parent` is an earlier MESSAGE of the same TURN; its
//! `RepliesTo` names the exact TURN or MESSAGE it answers, whose revision
//! its metadata's door-owned pointer keeps. It never enters HEAD or the
//! canonical line, and the TURN's own append and HEAD stay as they were.
//!
//! A MESSAGE row is the witness door's six-axis envelope, put only through
//! the witness ceiling: the append's body names the axes, the ceiling
//! authorizes the writer for them in this write, and the authorized bytes
//! are what lands.

use super::super::graph::{HEAD, counted_edge_ids, invalid, read_id, require_member, require_type};
use super::super::quote::{self, MESSAGE_REPLY_KEY};
use super::super::{AddressMode, AppendRecord, AppendedRecord};
use super::value;
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::gate::{WITNESS_AUTHOR_SYSTEM, WitnessMessageEnvelope};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use rmpv::Value;

/// The six axes a MESSAGE body holds, each once.
const MESSAGE_AXES: [&str; 6] = [
    "author",
    "type",
    "content",
    "metadata",
    "is_visible",
    "order",
];

/// Appends `input`, a MESSAGE of its `containing_turn`, at `id`. A thread
/// reply, a summary reply, HEAD, a session, recipients and an audience are
/// its TURN's, never a MESSAGE's.
pub(super) fn append_message_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    input: &AppendRecord,
    summary: Option<EntityId>,
    thread: bool,
    id: EntityId,
) -> Result<AppendedRecord> {
    let turn = input
        .containing_turn
        .ok_or_else(|| invalid("a MESSAGE names the TURN it is part of"))?;
    if thread || summary.is_some() {
        return Err(invalid("a MESSAGE joins its TURN through the append door"));
    }
    if input.advance {
        return Err(invalid("a MESSAGE never enters HEAD"));
    }
    if input.session.is_some() {
        return Err(invalid("a MESSAGE takes its TURN's session"));
    }
    if input.thread_audience.is_some() {
        return Err(invalid("only a thread's first record names its audience"));
    }
    if input.address != AddressMode::Broadcast || !input.recipients.is_empty() {
        return Err(invalid(
            "a MESSAGE names no recipients; its TURN addresses them",
        ));
    }
    require_type(
        &vault.store,
        txn,
        &input.conversation,
        ENTITY_TYPE_CONVERSATION,
    )?;
    let writer = input.actor.entity_ref();
    let turn_body = require_type(&vault.store, txn, &turn, ENTITY_TYPE_TURN)?;
    require_member(&vault.store, txn, &input.conversation, &turn)?;
    if super::super::topology::record_kind(&turn_body)?.is_none()
        || stamped_actor(&turn_body)? != Some(writer)
    {
        return Err(invalid(
            "a MESSAGE joins a DAG TURN its own writer appended",
        ));
    }
    // A private thread's TURN takes MESSAGEs from its audience now.
    if !crate::workspace_roster::record_thread_admits_in(vault, txn, turn, writer)? {
        return Err(invalid(
            "a private thread's TURN takes MESSAGEs from its audience",
        ));
    }
    if let Some(parent) = input.parent {
        require_type(&vault.store, txn, &parent, ENTITY_TYPE_MESSAGE)?;
        if containing_turn_in(vault, txn, parent)? != Some(turn) {
            return Err(invalid("a MESSAGE continues a MESSAGE of its own TURN"));
        }
    }
    // The record id is the citation a quote pins under; the writer reads
    // from its TURN's own chain.
    let quote = input
        .quote
        .map(|span| {
            quote::prove_quote_in_txn(
                vault,
                txn,
                input.conversation,
                Some(turn),
                input.actor,
                span,
                id,
            )
        })
        .transpose()?;
    if let Some(span) = &input.quote {
        let landing = crate::workspace_roster::thread_binding(&turn_body)?.map(|bound| bound.root);
        quote::require_quote_landing_in_txn(vault, txn, input.conversation, span.message, landing)?;
    }
    let target = quote::append_target_in_txn(
        vault,
        txn,
        input.conversation,
        input.reply_to,
        quote.as_ref(),
    )?;
    let pointer = target
        .as_ref()
        .map(|target| {
            let anchor = quote.as_ref().map(|quote| quote.anchor);
            quote::reply_pointer_in_txn(vault, txn, target, anchor)
        })
        .transpose()?;
    let decoded = decode_map(&input.body)?;
    let envelope = envelope_of(&decoded, pointer)?;
    require_free_order(vault, txn, turn, envelope.order)?;
    let bytes = envelope.encode_body()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let authorized = crate::gate::check_witness_message_ceiling(
        &vault.store,
        txn,
        input.actor,
        &envelope,
        &bytes,
        &policy,
    )?;
    super::super::policy::check_append_policy(vault, txn, &id, input, &bytes)?;
    if let Some(quote) = &quote {
        quote::pin_in_txn(vault, txn, quote, input.actor)?;
    }
    let birth = RowBirth::written(
        input.actor,
        MadeByClass::of_writer(input.actor.actor_class()),
        "conversations.records.append",
        &[],
        &[],
        input.learned_at,
    );
    let mut batch = vault
        .batch_in()
        .put_witness_message(&id, input.occurred, input.learned_at, &authorized)
        .made_by(&id, birth)
        .edge(&id, EdgeKind::PartOf, &turn, 1.0)
        .edge(&id, EdgeKind::BelongsTo, &input.conversation, 1.0);
    if envelope.author != WITNESS_AUTHOR_SYSTEM {
        batch = batch.edge(&id, EdgeKind::AuthoredBy, &writer, 1.0);
    }
    if let Some(parent) = input.parent {
        batch =
            batch.edge_with_value_fields(&id, EdgeKind::Parent, &parent, value(input.learned_at));
    }
    if let Some(target) = &target {
        batch = batch.edge_with_value_fields(
            &id,
            EdgeKind::RepliesTo,
            &target.record(),
            value(input.learned_at),
        );
    }
    // Its text is indexed as the witness door indexes a MESSAGE's.
    if !envelope.content.is_empty() {
        batch = batch.text(&id, &[("content", envelope.content)]);
    }
    batch.apply(txn)?;
    // The TURN's words changed: new work for consolidation and the sieve.
    crate::dreamer_consolidation::redirty::redirty_turn_in_txn(vault, txn, &turn)?;
    Ok(AppendedRecord {
        id,
        head: read_id(&vault.store, txn, HEAD, &input.conversation)?,
        parent: input.parent,
        kind: ENTITY_TYPE_MESSAGE,
        containing_turn: Some(turn),
        reply_target: target,
    })
}

/// The writer a DAG TURN's body stamps; `None` for a body that names none.
fn stamped_actor(body: &[u8]) -> Result<Option<EntityId>> {
    let fields = decode_map(body)?;
    let mut actors = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some("actor"))
        .map(|(_, value)| value);
    let actor = actors.next();
    if actors.next().is_some() {
        return Err(invalid("invalid room TURN author"));
    }
    actor
        .map(|value| {
            value
                .as_str()
                .and_then(|text| EntityId::from_hex(text).ok())
                .ok_or_else(|| invalid("invalid room TURN author"))
        })
        .transpose()
}

/// The TURN a live MESSAGE is part of; `None` for one no longer live.
fn containing_turn_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: EntityId,
) -> Result<Option<EntityId>> {
    if !matches!(
        live_entity_row_in_txn(&vault.store, txn, &message)?,
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE,
            ..
        }
    ) {
        return Ok(None);
    }
    let turns = counted_edge_ids(&vault.store, txn, &message, EdgeKind::PartOf, false)?;
    Ok(match turns[..] {
        [turn] => Some(turn),
        _ => None,
    })
}

/// Refuses `order` when a MESSAGE of `turn` already holds it: one position,
/// one MESSAGE, as the witness door keeps a TURN's messages.
fn require_free_order(vault: &Vault, txn: &RoTxn<'_>, turn: EntityId, order: u32) -> Result<()> {
    for message in counted_edge_ids(&vault.store, txn, &turn, EdgeKind::PartOf, true)? {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &message)?
        else {
            continue;
        };
        let held = decode_map(&body)?
            .iter()
            .find(|(key, _)| key.as_str() == Some("order"))
            .and_then(|(_, value)| value.as_u64());
        if held == Some(u64::from(order)) {
            return Err(invalid("a MESSAGE of this TURN holds that order"));
        }
    }
    Ok(())
}

/// A MessagePack map body, whole.
fn decode_map(body: &[u8]) -> Result<Vec<(Value, Value)>> {
    let mut input = body;
    let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut input) else {
        return Err(invalid("record body must be a map"));
    };
    if !input.is_empty() {
        return Err(invalid("trailing record body bytes"));
    }
    Ok(fields)
}

/// The envelope the append body `fields` names, each axis once and nothing
/// else, with `pointer`, the reply pointer, kept in its metadata under the
/// door's own key. A body whose metadata names that key is refused.
fn envelope_of(
    fields: &[(Value, Value)],
    pointer: Option<Value>,
) -> Result<WitnessMessageEnvelope<'_>> {
    let mut seen = std::collections::HashSet::new();
    for (key, _) in fields {
        let key = key
            .as_str()
            .filter(|key| MESSAGE_AXES.contains(key))
            .ok_or_else(|| invalid("a MESSAGE body holds its six axes alone"))?;
        if !seen.insert(key) {
            return Err(invalid("duplicate record body key"));
        }
    }
    let get = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    let text = |name: &str| {
        get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("a MESSAGE body names its author, type and content"))
    };
    let is_visible = get("is_visible")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("a MESSAGE body names whether it is visible"))?;
    let order = get("order")
        .and_then(Value::as_u64)
        .and_then(|order| u32::try_from(order).ok())
        .ok_or_else(|| invalid("a MESSAGE body names its order"))?;
    let mut metadata = get("metadata").cloned();
    if let Some(Value::Map(entries)) = &metadata
        && entries
            .iter()
            .any(|(key, _)| key.as_str() == Some(MESSAGE_REPLY_KEY))
    {
        return Err(invalid(
            "a MESSAGE body's metadata names the door's reply pointer",
        ));
    }
    if let Some(pointer) = pointer {
        match &mut metadata {
            None => {
                metadata = Some(Value::Map(vec![(Value::from(MESSAGE_REPLY_KEY), pointer)]));
            }
            Some(Value::Map(entries)) => entries.push((Value::from(MESSAGE_REPLY_KEY), pointer)),
            Some(_) => return Err(invalid("a reply MESSAGE's metadata is a map")),
        }
    }
    Ok(WitnessMessageEnvelope {
        author: text("author")?,
        message_type: text("type")?,
        content: text("content")?,
        metadata,
        is_visible,
        order,
    })
}
