//! Capability-scoped outbound attempt enqueue; actual sends belong to adapters.
use super::codec::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation::visibility::message_room;
use crate::{EntityId, Error, Result, Vault};

pub(super) fn room_connector(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: &EntityId,
) -> Result<Option<String>> {
    let Some(raw) = vault.store.entities.get(txn, room.as_bytes())? else {
        return Ok(None);
    };
    let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("room header"))?;
    if h.entity_type != crate::registry::ENTITY_TYPE_CONVERSATION {
        return Ok(None);
    }
    let mut data = &raw[ENTITY_METADATA_HEADER_LEN..];
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut data) else {
        return Ok(None);
    };
    Ok(entries
        .iter()
        .find(|(k, _)| k.as_str() == Some("room_connector"))
        .and_then(|(_, v)| v.as_str())
        .map(str::to_owned))
}
fn capable(connector: &str) -> bool {
    crate::outbound::outbound_capability_manifest(connector).is_some_and(|m| {
        m.verbs.iter().any(|v| {
            v.kind == "react"
                && v.delivery_semantics.kind
                    == crate::outbound::OutboundDeliverySemanticsKind::ReactionTarget
        })
    })
}
pub(super) fn enqueue(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &ReactInput,
    id: &EntityId,
    state: ReactionState,
    now: u64,
) -> Result<()> {
    if input.ext.is_some() {
        return Ok(());
    }
    let Some(room) = message_room(&vault.store, txn, &input.message)? else {
        return Ok(());
    };
    let Some(connector) = room_connector(vault, txn, &room)? else {
        return Ok(());
    };
    if !capable(&connector) {
        return Ok(());
    }
    let payload=serde_json::to_vec(&serde_json::json!({"connector":connector,"conversation":room.to_hex(),"reaction":id.to_hex(),"message":input.message.to_hex(),"by":input.by.to_hex(),"glyph":input.glyph,"state":state})).map_err(|_|Error::InvariantViolation("reaction outbound encode"))?;
    crate::attempt_queue::AttemptQueue::new(vault).enqueue_in_txn(
        txn,
        crate::attempt_queue::EnqueueAttempt {
            kind: "reaction.outbound".into(),
            payload,
            dedupe_key: Some(format!("{}:{state:?}", id.to_hex())),
            run_id: None,
            now,
        },
    )?;
    Ok(())
}
impl Vault {
    /// Whether a room's adapter declares a reaction delivery capability.
    pub fn reactions_outbound(&self, conversation: &EntityId) -> Result<ReactionsOutbound> {
        let txn = self.store.env.read_txn()?;
        Ok(
            if room_connector(self, &txn, conversation)?.is_some_and(|c| capable(&c)) {
                ReactionsOutbound::Mirrored
            } else {
                ReactionsOutbound::FirstPartyOnly
            },
        )
    }
}
