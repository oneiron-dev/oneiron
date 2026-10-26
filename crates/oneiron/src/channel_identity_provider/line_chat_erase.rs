//! A LINE chat's observations go with the ChannelIdentity that routes the
//! chat (FIX 10807). Deleting or erasing an identity whose route key is a
//! group or room on a bot hard-deletes, in the delete's own write
//! transaction, every observation of that chat, and the archived `join`
//! event an observation names: nothing else holds a join's archive. A text
//! message's archive stays with the message it carries; the person and
//! room erase is the one that takes it. Each deleted row also gets the
//! `dt:` marker and `pt:` propagation intent a physical delete leaves out,
//! so every replica and a restore erase it too. An observation's id is
//! opaque, so its marker confirms nothing about the chat.

use super::line_chat_binding::provider_inbound_actor;
use super::{
    LINE_CHANNEL, LINE_CHAT_OBSERVATION_PREDICATE, LineChat, LineChatKind, LineChatObservation,
};
use crate::batch::{BatchOp, apply_ops};
use crate::counterparty_contact::ClaimHeadWriter;
use crate::deletion::{TombstoneReason, TombstoneValueV2, stage_engine_row_hard_erasure_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM};
use crate::store::Store;
use crate::surface_event::PROVIDER_EVENT_REF_PREFIX;

/// Hard-deletes the observations of the LINE chat the ChannelIdentity
/// `identity` routes, and the `join` events they archived, in the delete's
/// write transaction and before the identity's own rows go. The
/// chat is read from the identity's row and from its live address fact,
/// whichever stands. A row a legal hold covers stays: the hold decides, and
/// the identity's delete goes on. An identity of no LINE chat deletes
/// nothing.
///
/// # Errors
/// Storage errors, and a refusal of the batch delete door.
pub(crate) fn erase_line_chat_observations_for_delete_in_txn(
    writer: &ClaimHeadWriter<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    identity: &EntityId,
    now: u64,
) -> Result<()> {
    let store = writer.store;
    let mut chats = Vec::new();
    if let Some(row) = store.port_entity_record(&*wtxn, identity)?
        && let Ok(record) = crate::channel_identity::decode_channel_identity_body(&row.body)
        && record.channel() == LINE_CHANNEL
        && let Some(chat) = line_chat_of_address(record.address_or_handle())
    {
        chats.push(chat);
    }
    if let Ok(Some(facts)) =
        crate::channel_identity::channel_identity_facts_in_txn(store, &*wtxn, identity)
        && facts.channel == LINE_CHANNEL
        && let Some(chat) = line_chat_of_address(&facts.address_or_handle)
        && !chats.contains(&chat)
    {
        chats.push(chat);
    }
    if chats.is_empty() {
        return Ok(());
    }
    let subject = provider_inbound_actor()?;
    let mut rows_to_delete = Vec::new();
    for entry in crate::ports::EdgeStoreRead::port_edges(
        store,
        &*wtxn,
        &subject,
        crate::ports::EdgeDirection::In,
        Some(crate::edge::EdgeKind::ClaimOf),
        None,
    )? {
        let claim_id = entry?.target;
        let Some(raw) = store.port_entity_record(&*wtxn, &claim_id)? else {
            continue;
        };
        if raw.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let Ok(body) = crate::claim::decode_claim_body(&raw.body, true) else {
            continue;
        };
        if body.predicate != LINE_CHAT_OBSERVATION_PREDICATE {
            continue;
        }
        let Ok(observation) = rmpv::ext::from_value::<LineChatObservation>(body.value) else {
            continue;
        };
        if !chats.iter().any(|(destination, chat)| {
            observation.destination == *destination && observation.chat == *chat
        }) {
            continue;
        }
        rows_to_delete.push((claim_id, ENTITY_TYPE_CLAIM));
        if let Some((artifact, version)) = archived_version(&observation.payload_ref)
            && archives_line_join_in_txn(store, &*wtxn, &artifact, version)?
        {
            rows_to_delete.push((artifact, ENTITY_TYPE_BLOB_ARTIFACT));
        }
    }
    rows_to_delete.sort_unstable();
    rows_to_delete.dedup();
    for (id, kind) in rows_to_delete {
        hard_delete_row_in_txn(writer, wtxn, &id, kind, now)?;
    }
    Ok(())
}

/// One row's hard delete through the batch delete door, with the marker and
/// propagation intent that door leaves out. A row of another kind than
/// `kind`, one already gone, or one a legal hold covers stays.
fn hard_delete_row_in_txn(
    writer: &ClaimHeadWriter<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    now: u64,
) -> Result<()> {
    let store = writer.store;
    if crate::store::legal_hold::held_in_txn(store, &*wtxn, id.as_bytes())? {
        tracing::warn!(
            row = %id.to_hex(),
            "a legal hold keeps a LINE chat observation row its identity's delete would take"
        );
        return Ok(());
    }
    let Some(row) = store.port_entity_record(&*wtxn, id)? else {
        return Ok(());
    };
    if row.entity_type != kind {
        return Ok(());
    }
    apply_ops(
        store,
        writer.config,
        writer.analyzer,
        wtxn,
        vec![BatchOp::Delete { id: *id }],
        writer.text_index_trusted,
        false,
        true,
    )?;
    stage_engine_row_hard_erasure_in_txn(
        store,
        wtxn,
        id,
        row.learned_at,
        &TombstoneValueV2 {
            reason: TombstoneReason::UserHardDelete,
            deleted_at: now,
            request_id: *id.as_bytes(),
        },
    )
}

/// The bot and chat a LINE chat route key names
/// (`line:oa:<bot>:<group|room>:<chat id>`); `None` for a per-user or any
/// other key.
fn line_chat_of_address(address: &str) -> Option<(String, LineChat)> {
    let rest = address.strip_prefix("line:oa:")?;
    let (destination, rest) = rest.split_once(':')?;
    let (kind, id) = rest.split_once(':')?;
    Some((
        destination.to_owned(),
        LineChat::new(LineChatKind::parse(kind)?, id),
    ))
}

/// The artifact and version a provider event ref
/// (`blob:<artifact hex>@<version>`) names.
fn archived_version(payload_ref: &str) -> Option<(EntityId, u64)> {
    let (artifact, version) = payload_ref
        .strip_prefix(PROVIDER_EVENT_REF_PREFIX)?
        .split_once('@')?;
    Some((EntityId::from_hex(artifact).ok()?, version.parse().ok()?))
}

/// Whether `artifact` archives a LINE `join` and nothing else: its one
/// version is `version`, and that version's inline bytes are a
/// `{destination, event}` wrapper whose event is a join. A message's
/// archive, and one these bytes cannot show to be a join, is not.
fn archives_line_join_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    version: u64,
) -> Result<bool> {
    let Some(head) = crate::blob_artifact::read_blob_artifact_head_in_txn(store, txn, artifact)?
    else {
        return Ok(false);
    };
    if head.version != version {
        return Ok(false);
    }
    let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&head.content_hash)?;
    let Some(row) = store.port_entity_record(txn, &asset)? else {
        return Ok(false);
    };
    if row.entity_type != ENTITY_TYPE_ASSET
        || *blake3::hash(&row.body).as_bytes() != head.content_hash
    {
        return Ok(false);
    }
    Ok(serde_json::from_slice::<serde_json::Value>(&row.body)
        .ok()
        .is_some_and(|wrapper| {
            wrapper
                .pointer("/event/type")
                .and_then(serde_json::Value::as_str)
                == Some("join")
        }))
}
