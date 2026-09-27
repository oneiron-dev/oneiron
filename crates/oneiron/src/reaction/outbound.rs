//! Connector-neutral reaction attempts; connector workers own provider sends.
use super::ReactionBody;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt};
use crate::conversation::room_for_record_in;
use crate::error::Result;
use crate::outbound::{OutboundDeliverySemanticsKind, outbound_capability_manifest};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

pub const REACTION_OUTBOUND_ATTEMPT_KIND: &str = "reaction.outbound.v1";

/// What the connector lane receives; provider-specific message addresses are
/// resolved by the adapter, never invented in the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionOutboundAttempt {
    pub reaction: EntityId,
    pub message: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub room_external_id: String,
    pub connector: String,
    pub revoked: bool,
}

pub(super) fn outbound_target_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    msg: EntityId,
) -> Result<Option<(String, String)>> {
    let Some(room) = room_for_record_in(vault, txn, msg)? else {
        return Ok(None);
    };
    let room = crate::conversation::body_in(vault, txn, room)?;
    if room.kind != crate::conversation::ConversationKind::Mirror {
        return Ok(None);
    }
    let Some(external) = room.external_id else {
        return Ok(None);
    };
    let Some((connector, _)) = external.split_once(':') else {
        return Ok(None);
    };
    let supported = outbound_capability_manifest(connector).is_some_and(|manifest| {
        manifest.verbs.iter().any(|verb| {
            verb.kind == "react"
                && verb.delivery_semantics.kind == OutboundDeliverySemanticsKind::ReactionTarget
        })
    });
    let connector = connector.to_owned();
    Ok(supported.then_some((connector, external)))
}

pub(super) fn enqueue(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ReactionBody,
    revoked: bool,
) -> Result<()> {
    // Mirrored ingress never loops back to the provider.
    if body.ext.is_some() {
        return Ok(());
    }
    let Some((connector, room_external_id)) = outbound_target_in(vault, txn, body.msg)? else {
        return Ok(());
    };
    let payload = ReactionOutboundAttempt {
        reaction: id,
        message: body.msg,
        by: body.by,
        glyph: body.glyph.clone(),
        room_external_id,
        connector,
        revoked,
    };
    let bytes = rmp_serde::to_vec_named(&payload)
        .map_err(|_| crate::error::Error::CorruptedIndex("reaction outbound payload"))?;
    AttemptQueue::new(vault).enqueue_with_task_ref_and_dedupe_actor_in_txn(
        txn,
        EnqueueAttempt {
            kind: REACTION_OUTBOUND_ATTEMPT_KIND.to_owned(),
            payload: bytes,
            dedupe_key: Some(format!(
                "{}:{}",
                id.to_hex(),
                if revoked { "revoked" } else { "put" }
            )),
            run_id: None,
            now: vault.store.clock.now_recorded_at(),
        },
        None,
        None,
    )?;
    Ok(())
}

impl Vault {
    /// Room's capability posture, not a claim of connector delivery success.
    pub fn reactions_outbound(&self, room: EntityId) -> Result<&'static str> {
        let txn = self.store.env.read_txn()?;
        let body = crate::conversation::body_in(self, &txn, room)?;
        if body.kind != crate::conversation::ConversationKind::Mirror {
            return Ok("first_party_only");
        }
        let Some(external) = body.external_id else {
            return Ok("first_party_only");
        };
        let Some((connector, _)) = external.split_once(':') else {
            return Ok("first_party_only");
        };
        Ok(
            if outbound_capability_manifest(connector).is_some_and(|manifest| {
                manifest.verbs.iter().any(|verb| {
                    verb.kind == "react"
                        && verb.delivery_semantics.kind
                            == OutboundDeliverySemanticsKind::ReactionTarget
                })
            }) {
                "mirrored"
            } else {
                "first_party_only"
            },
        )
    }
}
