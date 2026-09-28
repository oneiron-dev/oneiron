//! Sealed connector-key admission authority at the generic batch/replay door.
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::store::Store;
/// A replicated key body is a peer assertion, not host qualification or
/// owner re-consent: peers cannot replace an indexed Pending key with a
/// self-asserted Active body or rewrite an approved manifest. Local typed
/// lifecycle rewrites use the sealed port rather than this generic batch door,
/// so it preserves all locally qualified admission and manifest state.
pub(super) fn validate_connector_manifest_put(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    if entity_type != crate::registry::ENTITY_TYPE_CONNECTOR_KEY {
        return Ok(());
    }
    if replicated {
        return Err(Error::Record(RecordError::InvalidConnectorKeyBody(
            "replicated key cannot assert host-qualified manifest state",
        )));
    }
    let incoming = crate::connector_key::decode_connector_key_body(data)?;
    if let Some(previous) = store.entities.get(txn, id.as_bytes())? {
        let header = crate::batch::EntityMetadataHeader::parse(&previous)
            .ok_or(Error::CorruptedIndex("connector key entity header"))?;
        if header.entity_type == entity_type {
            let old = crate::connector_key::decode_connector_key_body(
                &previous[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )?;
            let leaves_pending = old.status == crate::connector_key::ConnectorKeyStatus::Pending
                && incoming.status != old.status;
            if leaves_pending
                || incoming.retained_manifest != old.retained_manifest
                || incoming.protocol_revision != old.protocol_revision
                || incoming.pending_manifest != old.pending_manifest
                || incoming.slate_ref != old.slate_ref
                || incoming.slate_revision != old.slate_revision
                || incoming.admission_epoch != old.admission_epoch
                || incoming.consent_required != old.consent_required
            {
                return Err(Error::Record(RecordError::InvalidConnectorKeyBody(
                    "admission transitions require qualified lifecycle doors",
                )));
            }
        }
    }
    Ok(())
}
