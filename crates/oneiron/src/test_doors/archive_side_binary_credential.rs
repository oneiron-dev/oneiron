//! Door for `tests/archive_side_family_binary_credential.rs`: plants one blob
//! head side row with a caller-chosen content hash, so the test's archive
//! carries a tree-form binary payload the nulling pass reads only as hex.

use crate::Vault;
use crate::batch::export::PortableSideTable;
use crate::blob_artifact::{
    BLOB_ARTIFACT_CONTENT_HASH_LEN, BlobArtifactVersion, BlobVersionProvenance,
    archive_version_tables,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{Raw, SideCodec, SideKey};
use crate::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};

/// Plants the blob head row of `artifact` with `content_hash` as its binary
/// payload: version 1, a user upload, no parent. The head table is the
/// second table [`archive_version_tables`] lends.
///
/// # Errors
///
/// The codec's and storage's refusals.
pub fn plant_blob_head_row(
    vault: &Vault,
    artifact: &EntityId,
    content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<()> {
    let record = BlobArtifactVersion {
        version: 1,
        content_hash,
        provenance: BlobVersionProvenance::UserUpload,
        calc_engine: None,
        claim_id: EntityId::now(),
        created_at: 100,
        parent_version: None,
        fork_of_version: None,
        export_name: "fixture export".to_owned(),
        export_media_type: "application/octet-stream".to_owned(),
        made_by: MadeBy {
            inputs: Vec::new(),
            process: MadeByProcess {
                actor: *artifact,
                class: MadeByClass::Stated,
                identity: "user_upload".to_owned(),
                version: "1".to_owned(),
                params_hash: "0".repeat(64),
            },
            at: 100,
            trigger: None,
        },
    };
    let value = <Raw as SideCodec<BlobArtifactVersion>>::encode(&record)
        .map_err(|_| Error::InvariantViolation("blob head fixture does not encode"))?;
    let mut key = Vec::new();
    artifact.encode_into(&mut key);
    let tables = archive_version_tables();
    let head = tables[1];
    vault.with_write_txn_grouped(|wtxn| head.restore(&vault.store, wtxn, &key, &value))
}
