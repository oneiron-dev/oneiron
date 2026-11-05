//! Queue-check exhaust versions (FIX 7227): fresh artifact birth via
//! trusted no-actor batch plus honest QueueCheck provenance/made_by.
//! Called ONLY with `QueueCheckFieldToken` (unforgeable, minted in finish
//! after SAME plus closed-approval validation). No arbitrary bytes/raw id
//! params; the parent core derives actor/clock inside from the token.
//!
//! Registration DONE (Root applied 17:12:15, A17:12:15+K17:15:20 YES):
//! `mod queue_check;` + `pub(crate) use queue_check::{...};` in versions.rs,
//! plus private `VersionAuthority::{Actor,QueueCheck(&token)}` with Actor
//! derived AT TOP and the ONE algorithm (all old gates for Actor, trusted
//! no-actor birth+claim for completion, NO live recheck). This child calls
//! the parent private `append_body_with_authority` naturally via `super::`;
//! it names the MQ token via the public parent alias, never the private
//! child path. L02-safe lapse case (no Held+late loss on revoked grant).
//!
//! P2 privacy (qualified): the fresh birth keeps the default stamp (base
//! world, own substrate facet, default project, Sensitive) via the store
//! `stamp_put` hook; it does NOT copy the repo project (that would broaden
//! the old owner-only exhaust read to Member where the repo project is
//! Member-readable). `MadeByInput(repo)` is provenance (structural,
//! births_row), NOT fresh-read authority; source IDs/proof grant nothing.
//! `token.repo()` is the ORIGINAL repo (frozen BEFORE exec via the receipt
//! inputs, NOT CURRENT work/config, via the TOKEN fix), so no CURRENT
//! re-read broadens. Sensitivity Restricted narrowing (original Restricted
//! vs fresh Sensitive default) needs an L02 positive pointer plus a port
//! read (15th path, beyond STOP14): named remainder, NOT faked as PASS.
//! Low-level trusted writer reads need no auth; the public Memory/facade
//! consumer reads the stored refs through the existing owner door.

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
    // ASSUMPTION A1 (Root to confirm 1-line): point TimeRange ctor shape.
    let occurred = crate::temporal::TimeRange {
        start: learned_at,
        end: learned_at,
    };

    // Birth when missing: fixed generic body (NEVER work key/user filename),
    // trusted no-actor batch (public put checks plus None-actor apply path
    // plus claim checks; NO live-grant refold by construction, NO
    // ACTIVE_ACTOR). The store `stamp_put` hook places the default stamp
    // (base/default/Sensitive, own facet); NO explicit project/world set
    // here, so the old owner-only exhaust read is NOT broadened to Member
    // via a repo-project copy. Sensitivity remainder (see module docs).
    if vault
        .get_blob_artifact_in_txn(txn, &token.artifact_id())?
        .is_none()
    {
        let body = BlobArtifactBody::new("queue-check-exhaust", "application/octet-stream");
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

    // Completion path (Root private authority, A+K YES): the parent core
    // derives Actor AT TOP from the token (frozen original approver as
    // Human), then reuses the ONE algorithm (validate/head/highwater/
    // dedupe/record/refs/changelog/fingerprint) with trusted no-actor
    // birth+claim (NO live auth, NO apply_actor). Same args as the made_by
    // door (fork None, no calc engine, made_by Some, preserve false,
    // reanchor true); only the authority differs. No raw-field enum, no new
    // pub raw API; the child accesses the parent private core naturally.
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
    )?;

    Ok(QueueCheckOutputRef {
        artifact_id: token.artifact_id(),
        version: version.version,
        content_hash: version.content_hash,
    })
}
