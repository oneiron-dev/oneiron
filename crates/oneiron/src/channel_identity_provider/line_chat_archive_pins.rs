//! Native capture of a LINE observation's exact provider archive version.
//! Registration changes no current teardown or archive-retention behavior.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::surface_event::ProviderEventArchiveReceipt;
use crate::{EntityId, Vault};

#[derive(Serialize, Deserialize)]
struct LineChatArchivePin {
    artifact_id: EntityId,
    version: u64,
    content_hash: [u8; 32],
    version_claim: EntityId,
    own_join: bool,
}

const PINS: SideTable<EntityId, LineChatArchivePin, Named> =
    SideTable::new(&side_table::LINE_CHAT_ARCHIVE_PIN);

pub(super) fn register_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
    archive: &ProviderEventArchiveReceipt,
    own_join: bool,
) -> Result<()> {
    if archive.channel != super::LINE_CHANNEL {
        return Ok(());
    }
    let Some(version) = vault.blob_artifact_version_metadata_in_txn(
        txn,
        &archive.artifact_id,
        archive.version.version,
    )?
    else {
        return Ok(());
    };
    if version.content_hash != archive.version.content_hash
        || version.claim_id != archive.version.claim_id
    {
        return Ok(());
    }
    PINS.put(
        &vault.store,
        txn,
        claim,
        &LineChatArchivePin {
            artifact_id: archive.artifact_id,
            version: version.version,
            content_hash: version.content_hash,
            version_claim: version.claim_id,
            own_join,
        },
    )
}
