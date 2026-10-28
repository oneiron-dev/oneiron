//! Federation admission validators for AUTHORITY_LOG and pack-instance rows.
//! Each reads in the caller's read txn, never a reader or writer of its own:
//! admission holds that txn while it validates, and LMDB gives one thread one
//! read slot (FIX 10162).

use heed::RoTxn;

use crate::Vault;
use crate::authority::{
    AuthorityOp, authority_entry_hash, authority_log_entity_id, decode_authority_log_entry_body,
    genesis_vault_id, validate_authority_log_entry_body_bytes,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};

/// Federation admission door for a AUTHORITY_LOG carrier.
///
/// ONE-1604-D1 (fix-leg 4): the CRDT row's KEY is bound to the id derived
/// from the decoded body, exactly as `check_authority_log_store_key` binds it
/// at the write door. Without the bind, admission validated the body and the
/// vault root but never checked that the body belonged at `id` — so a
/// wrong-key authority row entered the ADMITTED doc and only failed later at
/// materialize. That is strictly worse than rejecting here: the admitted doc
/// is what the ordinary replay path imports, so the mismatch surfaced after
/// the row had already been copied into locally authored bytes, and anything
/// this door scopes off the same key operated on a row that could never be
/// admitted under it.
///
/// The bind is a REMOTE rejection, not a local failure:
/// `AuthorityLogStoreKeyMismatch` is already classified in
/// `quarantine::remote_rejection_reason`, so the replay sites quarantine the
/// row and continue rather than aborting the window (H2). Deriving the id
/// costs one hash over bytes this function has already decoded.
///
/// The local root, the adopted evidence and the retirement ancestry are all
/// read in `txn`, from the transaction-bound read-only fold.
pub(super) fn admit_federated_authority_log(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<()> {
    validate_authority_log_entry_body_bytes(body)?;
    let entry = decode_authority_log_entry_body(body)?;
    if authority_log_entity_id(&entry)? != *id {
        return Err(Error::Record(RecordError::AuthorityLogStoreKeyMismatch {
            id: *id,
        }));
    }
    let entry_vault_id = match &entry.op {
        AuthorityOp::Genesis { .. } => genesis_vault_id(&entry)?,
        _ => entry
            .vault_id
            .ok_or(Error::Record(RecordError::InvalidAuthorityLogBody(
                "missing authority vault id",
            )))?,
    };
    // Where the fold needs history this row supplies, the fold with the row
    // in judges it (FIX 2535).
    let hash = authority_entry_hash(&entry)?;
    let local = crate::authority::preflight_authority_rows_in_txn(
        &vault.store,
        vault.privacy_posture(),
        txn,
        &[(hash, &entry)],
    )?;
    let local_vault_id =
        local
            .vault_id
            .ok_or(Error::Record(RecordError::InvalidAuthorityLogBody(
                "missing local authority root",
            )))?;
    if entry_vault_id != local_vault_id {
        return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
            "foreign authority log vault id",
        )));
    }
    let evidence = crate::authority::adopted_evidence_in_txn(&vault.store, txn)?;
    if !crate::authority::authority_row_resident(&vault.store, txn, &entry)?
        && crate::authority::door_refuses_retired_standing(
            &vault.store,
            &local,
            &hash,
            &entry,
            &mut |hash| {
                crate::authority::door_ancestor_row(&vault.store, txn, evidence.as_deref(), hash)
            },
        )?
    {
        return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
            "authority row signed by a key a handoff retired",
        )));
    }
    Ok(())
}

/// A federated pack-instance row: remapped and validated in `txn`.
pub(super) fn validate_federated_pack(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    blob: &[u8],
) -> Result<()> {
    let source = crate::registry::pack_byte_map::PackInstanceEnvelope::from_bytes(
        &blob[ENTITY_METADATA_HEADER_LEN..],
    )?;
    let (handle, local) = store.remap_pack_instance_in_txn(txn, &source)?;
    store.validate_pack_instance_in_txn(txn, handle, &local.to_bytes()?)
}
