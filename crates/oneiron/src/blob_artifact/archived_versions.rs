//! The version records of a blob artifact's chain as an archive reads them
//! (fix list row 15416): each row a record names, and the bytes it holds and
//! what made them, through the chain table's own codec.

use super::versions::{VERSIONS, blob_artifact_asset_entity_id};
use crate::entity_id::EntityId;

/// Each entity row a stored version record names, read through its table's
/// own codec (fix list row 15416): its ledger claim and each row its made_by
/// names. A head row is a version record in the same codec. `None` when the
/// record does not read.
pub(crate) fn archive_version_rows(value: &[u8]) -> Option<Vec<EntityId>> {
    let version = VERSIONS.decode_value(value).ok()?;
    let mut rows = super::made_by::made_by_rows(&version.made_by);
    rows.push(version.claim_id);
    Some(rows)
}

/// One version's bytes and what made them, as a record of it names them (fix
/// list row 15416): the version record of a chain, or a `blob.version` claim.
pub(crate) struct ArchivedVersionSource {
    /// The content-addressed ASSET its bytes are.
    pub(crate) asset: EntityId,
    /// Its `blob.version` ledger claim.
    pub(crate) claim: EntityId,
    /// Each row its made_by names; `None` when its made_by does not read.
    pub(crate) made_by: Option<Vec<EntityId>>,
}

/// The bytes a stored version record holds and what made them, read through
/// its table's own codec (fix list row 15416). A head row is a version record
/// in the same codec. `None` when the record does not read.
pub(crate) fn archive_version_source(value: &[u8]) -> Option<ArchivedVersionSource> {
    let version = VERSIONS.decode_value(value).ok()?;
    Some(ArchivedVersionSource {
        asset: blob_artifact_asset_entity_id(&version.content_hash).ok()?,
        claim: version.claim_id,
        made_by: Some(super::made_by::made_by_rows(&version.made_by)),
    })
}
