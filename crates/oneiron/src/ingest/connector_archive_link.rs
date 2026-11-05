//! Record-only occurrence of the provider-event archive an accepted inbound
//! MESSAGE landed from (FIX 10851).
//!
//! The witness that lands an inbound connector MESSAGE also records, in the
//! same transaction, which accepted provider-event archive version the
//! message carries: the conversation, the archive artifact and its exact
//! version, keyed by the MESSAGE. The row is provenance metadata only. It is
//! never authority to read or delete the archive, never text-integrity,
//! first-ever-source, refcount or cleanup proof, and never a hold. A hard
//! erase of the MESSAGE retires the row with it; a soft erase keeps it.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::blob_artifact::BlobVersionProvenance;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::{
    SURFACE_PROVIDER_EVENT_BLOB, SURFACE_PROVIDER_INBOUND_ACTOR,
};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::surface_event::{
    PROVIDER_EVENT_REF_PREFIX, SurfaceConnectorPayload, surface_event_run_id,
};

/// One accepted inbound MESSAGE's archive occurrence. Key: id16 (MESSAGE).
const CONNECTOR_MESSAGE_ARCHIVE: SideTable<EntityId, ConnectorMessageArchive, Named> =
    SideTable::new(&side_table::CONNECTOR_MESSAGE_ARCHIVE);

/// Which accepted archive version one MESSAGE landed from: ids and the exact
/// version only, never bytes or text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorMessageArchive {
    conversation: EntityId,
    artifact: EntityId,
    version: u64,
}

/// Records the accepted provider-event archive `origin` names against the
/// MESSAGE the inbound witness just landed, in that witness's transaction.
///
/// Infallible by contract: anything unproved or unreadable records nothing
/// and the witness stands as it did. Only the actual accepted inbound
/// witness calls this, after its own effect, with the stored MESSAGE id and
/// its conversation.
pub(super) fn record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    conversation: EntityId,
    message: EntityId,
    origin: &SurfaceConnectorPayload,
) {
    if let Err(error) = record_in_savepoint(vault, wtxn, conversation, message, origin) {
        tracing::warn!(
            kind = ?error.kind(),
            "a connector message archive occurrence did not record; the witness stands without it"
        );
    }
}

/// [`record_in_txn`] in a savepoint of the witness transaction: the metadata
/// commits only on a fully proved record, and any storage failure rolls back
/// only the savepoint.
fn record_in_savepoint(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    conversation: EntityId,
    message: EntityId,
    origin: &SurfaceConnectorPayload,
) -> Result<()> {
    let Some(payload_ref) = origin.payload_ref.as_deref() else {
        return Ok(());
    };
    let Some((artifact, version)) = parse_provider_event_ref(payload_ref) else {
        return Ok(());
    };
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    match record_proved_in_txn(
        vault,
        &mut savepoint,
        conversation,
        message,
        origin,
        artifact,
        version,
    ) {
        Ok(true) => savepoint.commit()?,
        Ok(false) => drop(savepoint),
        Err(error) => {
            drop(savepoint);
            return Err(error);
        }
    }
    Ok(())
}

/// Proves `artifact@version` is this origin's accepted provider-event archive
/// and pins it to `message`. `false` leaves the savepoint unwritten: a row
/// already stands, or the ref proves nothing. A row that reads back stands
/// as it is; a row that does not decode is not absence and fails the proof.
fn record_proved_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    conversation: EntityId,
    message: EntityId,
    origin: &SurfaceConnectorPayload,
    artifact: EntityId,
    version: u64,
) -> Result<bool> {
    if CONNECTOR_MESSAGE_ARCHIVE
        .get(&vault.store, &*txn, &message)?
        .is_some()
    {
        return Ok(false);
    }
    let expected_artifact = EntityId::derive(
        SURFACE_PROVIDER_EVENT_BLOB,
        &[
            origin.channel.as_bytes(),
            origin.surface_event_id.as_bytes(),
        ],
    )?;
    if artifact != expected_artifact {
        return Ok(false);
    }
    let Some(record) = vault.blob_artifact_version_metadata_in_txn(&*txn, &artifact, version)?
    else {
        return Ok(false);
    };
    let inbound = EntityId::derive(SURFACE_PROVIDER_INBOUND_ACTOR, &[])?;
    if record.made_by.process.actor != inbound {
        return Ok(false);
    }
    let run_ref = format!(
        "surface:{}:{}",
        origin.channel,
        surface_event_run_id(&origin.surface_event_id)
    );
    let expected_provenance = BlobVersionProvenance::AgentRun { run_ref };
    if record.provenance != expected_provenance {
        return Ok(false);
    }
    CONNECTOR_MESSAGE_ARCHIVE.put(
        &vault.store,
        txn,
        &message,
        &ConnectorMessageArchive {
            conversation,
            artifact,
            version,
        },
    )?;
    Ok(true)
}

/// The artifact and version a provider event ref
/// (`blob:<artifact hex>@<version>`) names.
fn parse_provider_event_ref(payload_ref: &str) -> Option<(EntityId, u64)> {
    let rest = payload_ref.strip_prefix(PROVIDER_EVENT_REF_PREFIX)?;
    let (artifact, version) = rest.split_once('@')?;
    Some((
        EntityId::from_hex(artifact).ok()?,
        version.parse::<u64>().ok()?,
    ))
}

/// Retires the archive occurrence `id` names, if one stands. No kind or
/// liveness check: the witness keys this table by actual MESSAGEs only, so a
/// hard replay or headerless delete retires the same private key. Runs in
/// the erase transaction's physical tail only; a soft erase keeps the row.
pub(crate) fn erase_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    CONNECTOR_MESSAGE_ARCHIVE.delete(store, wtxn, id)?;
    Ok(())
}
