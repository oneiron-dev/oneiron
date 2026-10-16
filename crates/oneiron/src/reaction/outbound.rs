//! Connector-neutral outbound reactions (connector out). A first-party put or
//! remove in a mirror room is queued only when that room's connector declares
//! a `react` verb with `ReactionTarget` delivery semantics. Mirrored claims
//! never loop back to their provider. The payload names the claim, not its
//! content: the connector worker reads the claim when it sends, so erasing a
//! reaction leaves nothing behind in the queue.
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt};
use crate::error::{Error, Result};
use crate::outbound::{OutboundDeliverySemanticsKind, outbound_capability_manifest};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

pub const REACTION_OUTBOUND_ATTEMPT_KIND: &str = "reaction.outbound.v1";

/// What the connector lane receives. Provider message addresses are resolved
/// by the adapter, never invented in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionOutboundAttempt {
    pub reaction: EntityId,
    pub connector: String,
    pub room_external_id: String,
    pub remove: bool,
}

/// Whether `connector` can target a message with a reaction.
#[must_use]
pub fn connector_declares_reaction_target(connector: &str) -> bool {
    outbound_capability_manifest(connector).is_some_and(|manifest| {
        manifest.verbs.iter().any(|verb| {
            verb.kind == "react"
                && verb.delivery_semantics.kind == OutboundDeliverySemanticsKind::ReactionTarget
        })
    })
}

/// The (connector, room external id) of a mirror room whose connector
/// declares `ReactionTarget`.
fn outbound_target_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<(String, String)>> {
    let body = crate::conversation::body_in(vault, txn, room)?;
    if body.kind != crate::conversation::ConversationKind::Mirror {
        return Ok(None);
    }
    let Some(external) = body.external_id else {
        return Ok(None);
    };
    let Some((connector, _)) = external.split_once(':') else {
        return Ok(None);
    };
    Ok(connector_declares_reaction_target(connector)
        .then(|| (connector.to_owned(), external.clone())))
}

/// Mirrors a held reaction once its owner clears it (Engine ruling 4).
///
/// A reaction whose write attached a critical confirm is held, not mirrored:
/// nothing acts on a claim awaiting its owner (ARCH-0026 §G3). The Clear sends
/// the held put, once, under the reaction's own dedupe key. A decline or a
/// timeout demotion never reaches here, and a reaction removed meanwhile, or
/// one whose record has left its room, is not sent. Only a first-party
/// reaction is ever sent: a mirrored or machine-written one never loops back
/// to its provider, whoever cleared it.
pub(crate) fn release_cleared_reaction_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim_id: EntityId,
    body: &crate::claim::ClaimBody,
) -> Result<()> {
    if !crate::claim::claim_surfaceable(body)
        || super::value::machine_written(body)
        || super::value::decode_reaction(body).is_none_or(|value| value.external_id.is_some())
    {
        return Ok(());
    }
    let crate::claim::ClaimSubject::Entity(record) = body.subject else {
        return Ok(());
    };
    if !matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, &record)?,
        crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_MESSAGE | crate::registry::ENTITY_TYPE_TURN,
            ..
        }
    ) || vault.archive_tombstone_in_txn(txn, &record)?.is_some()
    {
        return Ok(());
    }
    let Some(room) = crate::conversation::room_for_record_in(vault, txn, record)? else {
        return Ok(());
    };
    enqueue_in_txn(vault, txn, claim_id, room, false)
}

pub(super) fn enqueue_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reaction: EntityId,
    room: EntityId,
    remove: bool,
) -> Result<()> {
    let Some((connector, room_external_id)) = outbound_target_in(vault, txn, room)? else {
        return Ok(());
    };
    if connector == "imessage_bridge"
        && let Some(body) = vault.get_claim_in_txn(txn, &reaction)?
        && let Some(value) = super::value::decode_reaction(&body)
    {
        super::channel_adapters::IMessageTapback::from_glyph(&value.glyph)?;
    }
    let payload = rmp_serde::to_vec_named(&ReactionOutboundAttempt {
        reaction,
        connector,
        room_external_id,
        remove,
    })
    .map_err(|_| Error::InvariantViolation("reaction outbound payload encode failed"))?;
    AttemptQueue::new(vault).enqueue_with_task_ref_and_dedupe_actor_in_txn(
        txn,
        EnqueueAttempt {
            kind: REACTION_OUTBOUND_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(format!(
                "{}:{}",
                reaction.to_hex(),
                if remove { "remove" } else { "put" }
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
    /// The room's reaction posture: `mirrored` when first-party reactions are
    /// sent to its connector, else `first_party_only`. Not a delivery claim.
    pub fn reactions_outbound(&self, room: EntityId) -> Result<&'static str> {
        let txn = self.store.env.read_txn()?;
        Ok(if outbound_target_in(self, &txn, room)?.is_some() {
            "mirrored"
        } else {
            "first_party_only"
        })
    }
}
