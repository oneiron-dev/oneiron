//! Stores queue-check output through the receipt-bound completion token.
//! The token authorizes only its actual bytes and fresh artifact. Ordinary
//! appends retain their actor authorization and share the same version core.
//!
//! Original input taint is attached at birth; the closed token settles the
//! artifact's input placement in the same writer. MadeBy records provenance,
//! not permission. Public family reads carry the current Owner proof and
//! retain the request's actual scoped reader.

use heed::RwTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::merge_queue::{QueueCheckFieldToken, QueueCheckOutputRef};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::write_envelope::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};

use super::super::body::{BlobArtifactBody, encode_blob_artifact_body};
use super::super::made_by::validate_version_made_by_in_txn;
use super::super::provenance::BlobVersionProvenance;
use super::{VersionAuthority, VersionBody};

/// Mint ONE fresh artifact id from the native clock (no authority in mint;
/// binding happens at birth+append under the completion token).
pub(crate) fn mint_queue_check_artifact_id(vault: &Vault) -> Result<EntityId> {
    EntityId::from_bytes(vault.store.clock.ulid()?)
}

/// Append ONE actual field's bytes as an immutable version under the
/// token's fresh artifact. Births the artifact via trusted no-actor batch
/// (public checks, no live-grant recheck) when missing, then appends the
/// version with honest QueueCheck provenance plus Concluded made_by carrying
/// the ORIGINAL repo input and inputs-digest params (no fake trigger).
/// Empty bytes are valid. Returns the EXACT committed version/hash.
pub(crate) fn append_queue_check_output_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    token: &QueueCheckFieldToken,
) -> Result<QueueCheckOutputRef> {
    // Clock in-writer (same pattern as the version core).
    let learned_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let occurred = crate::temporal::TimeRange {
        start: learned_at,
        end: learned_at,
    };

    // Native supporting birth under the closed completion token. The body
    // name is fixed, never a work key or user-supplied output path.
    if vault
        .get_blob_artifact_in_txn(txn, &token.artifact_id())?
        .is_none()
    {
        let body = BlobArtifactBody::new("queue-check-exhaust", "application/octet-stream")
            .with_secret_taint_refs(token.input_taint().to_vec());
        let data = encode_blob_artifact_body(&body)?;
        vault
            .batch_in()
            .put(
                &token.artifact_id(),
                ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                learned_at,
                &data,
            )
            .apply(txn)?;
    }

    // Honest provenance plus Concluded made_by (Root made_by proof).
    let provenance = BlobVersionProvenance::QueueCheck {
        check_ref: token.check_ref().to_owned(),
    };
    let made_by = MadeBy {
        inputs: vec![MadeByInput {
            row: token.repo(),
            role: MadeByInputRole::Input,
        }],
        process: MadeByProcess {
            actor: token.recorded_actor(),
            class: MadeByClass::Concluded,
            identity: provenance.as_str().to_owned(),
            version: "1".into(),
            params_hash: token.inputs_digest().to_owned(),
        },
        at: learned_at,
        trigger: None,
    };
    validate_version_made_by_in_txn(vault, txn, &made_by)?;

    // The completion token, not the recorded author, authorizes these
    // supporting effects. Ordinary appends keep their actor gates in the
    // same version algorithm.
    let version = vault.append_blob_artifact_version_body_with_authority_in_txn(
        txn,
        &token.artifact_id(),
        VersionBody::Bytes(token.bytes()),
        &provenance,
        VersionAuthority::QueueCheck(token),
        occurred,
        learned_at,
        None,
        None,
        Some(&made_by),
        false,
        true,
        None,
        crate::core_write::CoreWriteLaneRef::Unbound,
    )?;

    crate::federation::record_scope::stamp_queue_check_exhaust_birth(&vault.store, txn, token)?;

    Ok(QueueCheckOutputRef {
        artifact_id: token.artifact_id(),
        version: version.version,
        content_hash: version.content_hash,
    })
}
