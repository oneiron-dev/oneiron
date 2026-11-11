//! Doors for `tests/primitive_a_policy_preflight.rs` (slice 6.4e): a row a
//! source landed, born stamped under a new source policy and bound to it in
//! one write, as a mail attachment lands (`mail_pack::attachments`).

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;

/// A source's row and the source policy it was born under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceBoundRow {
    /// The source policy.
    pub policy: EntityId,
    /// The BLOB_ARTIFACT row bound to it.
    pub row: EntityId,
}

/// Lands one BLOB_ARTIFACT row under a new source policy read by `readers`
/// (open to the vault when `open`), created by `by` at `at`: stamped with
/// the source-audience obligation and bound in the same write.
pub fn land_source_bound_artifact(
    vault: &Vault,
    readers: BTreeSet<EntityId>,
    open: bool,
    by: EntityId,
    at: u64,
) -> Result<SourceBoundRow> {
    let row = vault.store.clock.entity_id()?;
    let body = crate::blob_artifact::encode_blob_artifact_body(
        &crate::blob_artifact::BlobArtifactBody::new("source-row.txt", "text/plain"),
    )?;
    let occurred = crate::TimeRange { start: at, end: at };
    let policy = vault.with_write_txn_grouped(|txn| {
        let policy =
            crate::source_audience::create_source_policy_in_txn(vault, txn, readers, open, by, at)?;
        let birth = crate::source_audience::SourceAudienceBirth::mint_in(vault, txn, &policy)?;
        let stamped = birth.stamp_in_txn(vault, txn, &row, &body)?;
        vault
            .batch_in()
            .put_source_bound(
                &row,
                ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                at,
                &stamped,
                &birth,
            )
            .apply(txn)?;
        crate::source_audience::bind_record_in_txn(vault, txn, &row, &policy)?;
        Ok(policy)
    })?;
    Ok(SourceBoundRow { policy, row })
}
