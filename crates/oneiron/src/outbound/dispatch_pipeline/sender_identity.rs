use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::decode_channel_identity_body;
use crate::counterparty_contact::normalize_channel_class;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound::capability::normalize_key;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;
use crate::vault::entity_id_from_type_index_key;

/// Resolves the OF-347 channel identity a connector key sends through.
///
/// ONE-1868 leg 2, optional enrichment: the opt-out verdict rests on
/// `(counterparty, channel_class)`, never on this value. Nothing new is minted —
/// the governing connector key (OF-277) names the sending actor, and the
/// ChannelIdentity bound to that actor on the connector's channel is the
/// identity that will carry the send. Missing, unregistered, or inactive
/// identities resolve to `None`. Multiple eligible identities instead return
/// [`Error::InvalidConfig`]: automatic selection must not send without a unique sender.
pub(in crate::outbound) fn resolve_channel_identity_ref_for_connector(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector_key: &str,
    actor_entity_ref: Option<&EntityId>,
) -> crate::Result<Option<EntityId>> {
    let connector = normalize_key(connector_key);
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
    for entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("channel identity entity row"));
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("channel identity entity header"));
        };
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::CorruptedIndex("channel identity entity type"));
        }
        let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        // `may_send` rather than `state == Active`: a `delegated_grant` row is
        // a scoped-READ grant over a mailbox the product does not own, and it
        // reaches ACTIVE like any other row. Selecting one as the sender of an
        // outbound effect would be sending AS the member on an authority we
        // were never given.
        if !identity.may_send()
            || normalize_channel_class(&identity.channel) != channel_class
            || identity.binding.actor_ref() != Some(bound_actor)
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
pub(in crate::outbound) fn enrich_dispatch_channel_identity(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector_key: &str,
    actor_entity_ref: Option<&EntityId>,
    explicit: Option<EntityId>,
) -> crate::Result<Option<EntityId>> {
    match explicit {
        some @ Some(_) => Ok(some),
        None => {
            resolve_channel_identity_ref_for_connector(store, txn, connector_key, actor_entity_ref)
        }
    }
}
