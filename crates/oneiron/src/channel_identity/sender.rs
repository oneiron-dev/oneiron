use super::decode_channel_identity_body;
use super::keys::ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND;
use super::record::ChannelIdentity;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::counterparty_contact::normalize_channel_class;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::class_policy::ActPosture;

use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;

/// Resolves the OF-347 channel identity a connector key sends through.
///
/// ONE-1868 leg 2, optional enrichment: the opt-out verdict rests on
/// `(counterparty, channel_class)`, never on this value. Nothing new is minted —
/// the governing connector key (OF-277) names the sending actor, and the
/// ChannelIdentity bound to that actor on the connector's channel is the
/// identity that will carry the send. Missing, unregistered, or inactive
/// identities resolve to `None`. Multiple eligible identities instead return
/// [`Error::InvalidConfig`]: automatic selection must not send without a unique sender.
pub(crate) fn resolve_channel_identity_ref_for_connector(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector_key: &str,
    actor_entity_ref: Option<&EntityId>,
) -> crate::Result<Option<EntityId>> {
    let connector = connector_key.trim().to_ascii_lowercase().replace('-', "_");
    let Some((_, key_record)) =
        crate::connector_key::governing_connector_key(store, txn, &connector, actor_entity_ref)?
    else {
        return Ok(None);
    };
    let Some(bound_actor) = key_record
        .actor_entity_ref
        .or_else(|| actor_entity_ref.copied())
    else {
        return Ok(None);
    };

    let channel_class = normalize_channel_class(connector_key);
    let mut resolved = None;
    for entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)? {
        let id = entry?;
        let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
            return Err(Error::CorruptedIndex("channel identity entity row"));
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("channel identity entity header"));
        };
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::CorruptedIndex("channel identity entity type"));
        }
        let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        // The posture comes from the vault's `act_policy` row for this
        // identity's subject class, resolved in THIS transaction — not from the
        // identity's class. A delegated row is denied by the row the default
        // manifest ships, and if the owner raises that row the capability check
        // behind `may_send_under` still refuses, because a read-only grant
        // carries no outbound scope.
        if !outbound_send_permitted(store, txn, &identity)?
            || normalize_channel_class(identity.channel()) != channel_class
            || identity.binding().actor_ref() != Some(bound_actor)
        {
            continue;
        }
        if resolved.is_some() {
            return Err(Error::InvalidConfig(
                "ambiguous outbound sender: multiple eligible channel identities; select an explicit channel_identity_ref"
                    .to_owned(),
            ));
        }
        resolved = Some(id);
    }
    Ok(resolved)
}

/// An explicit channel identity always wins; otherwise resolve it cheaply.
pub(crate) fn enrich_dispatch_channel_identity(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector_key: &str,
    actor_entity_ref: Option<&EntityId>,
    explicit: Option<EntityId>,
) -> crate::Result<Option<EntityId>> {
    match explicit {
        Some(id) => {
            let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
                return Ok(Some(id));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("channel identity sender header"))?;
            if header.entity_type == ENTITY_TYPE_CHANNEL_IDENTITY {
                let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                // A pinned identity on a different channel class is metadata,
                // not the sender for THIS effect. Keep the gate's counterparty
                // verdict independent of a stale cross-channel enrichment.
                // Provider email rails map to the email class here too.
                if normalize_channel_class(identity.channel())
                    == normalize_channel_class(connector_key)
                    && !outbound_send_permitted(store, txn, &identity)?
                {
                    return Err(refuse_outbound_send(&identity));
                }
            }
            Ok(Some(id))
        }
        None => {
            resolve_channel_identity_ref_for_connector(store, txn, connector_key, actor_entity_ref)
        }
    }
}

/// Whether `identity` may carry an outbound effect in this vault right now.
///
/// Two independent questions, asked in the order that keeps them honest:
///
/// 1. POLICY — does the manifest's `act_policy` row for
///    `channel_identity.outbound_send` permit this subject class, for this
///    holder? A missing row is [`ActPosture::Deny`]: silence about an outbound
///    act is not permission, and the default manifest is never silent here.
/// 2. SUBSTRATE — does the row hold the capability the act needs? For a
///    self-held row that is a live state; for a delegated row it is an outbound
///    scope on the grant, which no read-only scope class can express.
///
/// Raising the manifest row therefore cannot by itself enable a send. What it
/// changes is which of the two refusals the vault reports, and who owns the
/// decision: the vault's policy data rather than an engine class ban.
fn outbound_send_permitted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity: &ChannelIdentity,
) -> crate::Result<bool> {
    let posture = resolved_outbound_posture(store, txn, identity)?;
    Ok(identity.may_send_under(posture))
}

fn resolved_outbound_posture(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity: &ChannelIdentity,
) -> crate::Result<ActPosture> {
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    Ok(policy
        .resolved_act_posture(
            ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND,
            identity.outbound_subject_class(),
            identity.binding().actor_ref(),
        )
        .unwrap_or_default())
}

/// The refusal for an explicit sender the vault will not send through.
///
/// The two reasons are reported apart on purpose: "this vault's policy bars the
/// class" and "the grant we hold carries no outbound scope" are different facts
/// for the owner who has to decide what to change.
fn refuse_outbound_send(identity: &ChannelIdentity) -> Error {
    let reason = if identity.holds_outbound_capability() {
        "this vault's act_policy row bars outbound send for this channel identity's subject class"
    } else {
        "channel identity holds no outbound send capability: a self-held row must be active, and \
         a delegated grant must carry an outbound scope"
    };
    Error::Record(crate::error::RecordError::InvalidChannelIdentityBody(
        reason,
    ))
}
