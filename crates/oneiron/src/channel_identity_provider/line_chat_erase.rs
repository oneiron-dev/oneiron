//! A LINE chat's observations go with the ChannelIdentity that routes the
//! chat (FIX 10807). Deleting or erasing an identity whose route key is a
//! group or room on a bot hard-deletes, in the delete's own write
//! transaction, every observation of that chat and the archived provider
//! event each one names. Each row also gets the `dt:` marker and `pt:`
//! propagation intent a physical delete leaves out, so every replica and a
//! restore erase it too. An observation's id is opaque, so its marker
//! confirms nothing about the chat.

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
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM};
use crate::surface_event::PROVIDER_EVENT_REF_PREFIX;

/// Hard-deletes the observations of the LINE chat the ChannelIdentity
/// `identity` routes, and the provider events they archived, in the
/// delete's write transaction and before the identity's own rows go. The
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
        if let Some(artifact) = archived_artifact(&observation.payload_ref) {
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

/// The artifact a provider event ref (`blob:<artifact hex>@<version>`)
/// names.
fn archived_artifact(payload_ref: &str) -> Option<EntityId> {
    let (artifact, _) = payload_ref
        .strip_prefix(PROVIDER_EVENT_REF_PREFIX)?
        .split_once('@')?;
    EntityId::from_hex(artifact).ok()
}
