//! Re-admission over already-admitted bytes.
//! The entry point is `revalidate_admitted_federated_claims`.
//! Owned by `super`.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::validate_claim_body_and_decode;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
#[cfg(feature = "test-hooks")]
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::sync::loro_support::map_for_each_value_bytes;
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;

use super::FederationAdmissionRole;
use super::refuse_peer_agent_definition_widening;
#[cfg(feature = "sync")]
use super::super::edge::refuse_admitted_stamps;
#[cfg(feature = "sync")]
use super::super::validators::validate_federated_pack;

/// Re-runs federated claim admission over ALREADY-ADMITTED window bytes using
/// the policy resolved RIGHT NOW.
///
/// `admit_federated_window_update` evaluates claims against the policy that was
/// resolved at ADMISSION time. A staged vault import parks those bytes behind a
/// durable Pending receipt, and the human confirmation that releases them can
/// land arbitrarily later — so the policy the operator actually consented under
/// is the one in force at CONFIRM time, not the one that happened to be loaded
/// when the artifact was first staged. This door re-resolves the manifest with
/// the same resolver the stage leg uses and re-applies the same claim gate.
///
/// It deliberately re-checks the admitted bytes AS THEY ARE rather than
/// re-deriving a fresh admitted doc: the receipt pins their digest, so a
/// re-admission would produce different bytes and break the digest bind. The
/// claims inside are already restamped to `src=imported`, which is exactly the
/// source the gate must judge on the import path, so no restamp is repeated.
///
/// Non-claim rows were admitted by identity/kind rules that do not depend on
/// resolved policy, so they are left alone here, except an agent definition:
/// it is judged again against the definition stored now, so one turned off
/// since the stage does not come back on through the confirmation.
#[cfg(feature = "sync")]
pub(in crate::sync) fn revalidate_admitted_federated_claims(
    vault: &Vault,
    key: &WindowKey,
    admitted_update: &[u8],
    role: FederationAdmissionRole,
) -> Result<()> {
    let admitted = create_window_doc(role.origin(), key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;

    let policy = vault
        .with_write_txn_grouped(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    let rtxn = vault.store.env.read_txn()?;
    let mut result = Ok(());
    map_for_each_value_bytes(&admitted.get_map("entities"), |key, value| {
        if result.is_err() {
            return;
        }
        result = recheck_admitted_claim_blob(&vault.store, &rtxn, &policy, value).and_then(|()| {
            let id = EntityId::from_hex(key).map_err(|_| Error::InvalidKey)?;
            let blob = value.ok_or(Error::InvalidKey)?;
            refuse_peer_agent_definition_widening(&vault.store, &rtxn, &id, blob)
        });
    });
    result
}

/// Refuses ALREADY-ADMITTED window bytes that carry a facet stamp
/// ([`refuse_admitted_stamps`]), so a staged artifact an older door admitted
/// with its stamps in its bytes is not confirmed (non-terminal, as a claim
/// refusal is).
#[cfg(feature = "sync")]
pub(in crate::sync) fn revalidate_admitted_facet_stamps(
    key: &WindowKey,
    admitted_update: &[u8],
) -> Result<()> {
    let admitted = create_window_doc("federation-staged", key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;
    refuse_admitted_stamps(&admitted.get_map("edges"))
}

#[cfg(feature = "sync")]
fn recheck_admitted_claim_blob(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    value: Option<&[u8]>,
) -> Result<()> {
    let blob = value.ok_or(Error::InvalidKey)?;
    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if crate::sync::pack_sync::is_pack_handle(header.entity_type) {
        return validate_federated_pack(store, txn, blob);
    }
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(());
    }
    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    crate::gate::check_federated_claim_admission(store, &body, policy)
}

/// Test-only helper for downstream crates that need to seed a grant-backed
/// selector without opening the public maintenance-band write gate.
#[cfg(feature = "test-hooks")]
pub fn put_selector_test_federation_grant(
    vault: &Vault,
    grant_id: &EntityId,
    grant: &crate::federation::FederationGrant,
    learned_at: u64,
) -> Result<()> {
    let body = crate::federation::encode_federation_grant_body(grant)?;
    vault
        .batch()
        .put_replicated(
            grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            crate::temporal::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .commit()
}
