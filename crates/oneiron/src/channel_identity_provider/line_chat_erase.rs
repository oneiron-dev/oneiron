//! Native LINE observation cleanup for the ChannelIdentity that routes a
//! bot/chat. Exact private captures alone may release an archive version;
//! public observations lose only their own records. Accepted continuations
//! survive source graph teardown and holds, with native erase receipts and
//! instance custody proof before completion. Other version consumers keep
//! their bytes. Ordinary batch deletes retain their propagation markers.

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
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::surface_event::PROVIDER_EVENT_REF_PREFIX;

/// Deletes the observations selected by the identity's native route.
/// Only original private captures may release a join version. All accepted
/// native selectors are recorded before the first observation teardown;
/// held observations stay pending with their source identity attribution.
pub(crate) fn erase_line_chat_observations_for_delete_in_txn(
    writer: &ClaimHeadWriter<'_>,
    txn: &mut heed::RwTxn<'_>,
    identity: &EntityId,
    _now: u64,
) -> Result<()> {
    let store = writer.store;
    let write = crate::secret_custody::CustodyWrite {
        store,
        config: writer.config,
        analyzer: writer.analyzer,
        text_index_trusted: writer.text_index_trusted,
    };
    let observations = line_chat_observations_for_identity_in_txn(store, txn, identity)?;
    for (claim, _) in observations {
        super::line_chat_archive_pins::accept_line_chat_observation_erase_in_txn(
            store, txn, identity, &claim,
        )?;
    }
    super::line_chat_archive_pins::settle_line_chat_archive_releases_in_txn(&write, txn)
}

fn line_chat_observations_for_identity_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity: &EntityId,
) -> Result<Vec<(EntityId, LineChatObservation)>> {
    let mut chats = Vec::new();
    if let Some(row) = store.port_entity_record(txn, identity)?
        && let Ok(record) = crate::channel_identity::decode_channel_identity_body(&row.body)
        && record.channel() == LINE_CHANNEL
        && let Some(chat) = line_chat_of_address(record.address_or_handle())
    {
        chats.push(chat);
    }
    if let Ok(Some(facts)) =
        crate::channel_identity::channel_identity_facts_in_txn(store, txn, identity)
        && facts.channel == LINE_CHANNEL
        && let Some(chat) = line_chat_of_address(&facts.address_or_handle)
        && !chats.contains(&chat)
    {
        chats.push(chat);
    }
    if chats.is_empty() {
        return Ok(Vec::new());
    }
    let subject = provider_inbound_actor()?;
    let mut observations = Vec::new();
    for entry in crate::ports::EdgeStoreRead::port_edges(
        store,
        txn,
        &subject,
        crate::ports::EdgeDirection::In,
        Some(crate::edge::EdgeKind::ClaimOf),
        None,
    )? {
        let claim_id = entry?.target;
        let Some(raw) = store.port_entity_record(txn, &claim_id)? else {
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
        observations.push((claim_id, observation));
    }
    Ok(observations)
}

/// One row's hard delete through the batch delete door, with the marker and
/// propagation intent that door leaves out. A row of another kind than
/// `kind`, one already gone, or one a legal hold covers stays.
pub(super) fn hard_delete_row_in_txn(
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
            "a hold or selected storage-only restriction keeps a LINE chat observation row its identity's delete would take"
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
pub(super) fn archived_version(payload_ref: &str) -> Option<(EntityId, u64)> {
    let (artifact, version) = payload_ref
        .strip_prefix(PROVIDER_EVENT_REF_PREFIX)?
        .split_once('@')?;
    Some((EntityId::from_hex(artifact).ok()?, version.parse().ok()?))
}
