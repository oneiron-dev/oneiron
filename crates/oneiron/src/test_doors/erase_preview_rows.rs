//! The record-erase preview rows the build before the shared preview kept
//! (`erase:preview:v1:`, FIX 12522), so the `one_way_confirm` test proves
//! that an actor erase takes the erased caller's and the next preview takes
//! the rest (review F2 on #7861). Raw rows under the prefix: one is planted as
//! that build wrote it, and the callers and records of the rows left are
//! listed undecoded, so the door reads the same whether or not this build
//! declares the table.

use serde::Serialize;

use crate::EntityId;
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;
use crate::vault::Vault;

/// The retired table's keyspace.
const PREFIX: &[u8] = b"erase:preview:v1:";

/// How long the old build kept a preview confirmable, in seconds.
const OLD_TTL_SECS: u64 = 600;

/// The old build's row, field for field.
#[derive(Serialize)]
struct ErasePreviewRow {
    preview_digest: String,
    issued_at: u64,
    expires_at: u64,
}

/// Plants the old build's preview of erasing `record`, shown to `caller` at
/// `issued_at`: key id16 (caller) + id16 (record), the row in the old build's
/// named MessagePack.
///
/// # Errors
///
/// Storage errors.
pub fn plant_retired_erase_preview(
    vault: &Vault,
    caller: &EntityId,
    record: &EntityId,
    issued_at: u64,
) -> Result<()> {
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(caller.as_bytes());
    key.extend_from_slice(record.as_bytes());
    let row = ErasePreviewRow {
        preview_digest: "0".repeat(64),
        issued_at,
        expires_at: issued_at + OLD_TTL_SECS,
    };
    let value = rmp_serde::to_vec_named(&row)
        .map_err(|_| Error::InvariantViolation("the old erase preview row does not encode"))?;
    vault.with_write_txn_grouped(|txn| {
        vault
            .store
            .side_vault_meta()
            .put(txn, key.as_slice(), value.as_slice())?;
        Ok(())
    })
}

/// The caller and record of every row left under the retired prefix, in key
/// order.
///
/// # Errors
///
/// Storage errors, or a row whose key is not two ids.
pub fn retired_erase_previews(vault: &Vault) -> Result<Vec<(EntityId, EntityId)>> {
    let id = |bytes: &[u8]| {
        <[u8; 16]>::try_from(bytes)
            .map(EntityId::from_bytes_unchecked)
            .map_err(|_| Error::InvariantViolation("an old erase preview key is not two ids"))
    };
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for row in vault.store.side_vault_meta().prefix_iter(&rtxn, PREFIX)? {
        let (key, _) = row?;
        let ids = &key[PREFIX.len()..];
        if ids.len() != 32 {
            return Err(Error::InvariantViolation(
                "an old erase preview key is not two ids",
            ));
        }
        rows.push((id(&ids[..16])?, id(&ids[16..])?));
    }
    Ok(rows)
}
