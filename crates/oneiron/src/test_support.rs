//! Doors for tests that drive the engine from another crate, such as the
//! seal organ's end-to-end check, which runs the engine's seal task over the
//! real organ host. Hidden and compiled only for tests or with
//! `test-support`; never API. The crate's own tests reach the same helpers
//! through `test_util`.

use crate::authority::HostSlipIssuer;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::blob_artifact::esign::EsignAuditActor;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Raw stored-entity record: the 25-byte metadata header (type byte,
/// occurred start/end, learned_at — all big-endian u64s, per the
/// `batch::ENTITY_*_OFFSET` layout) followed by `body`.
pub(crate) fn entity_record(
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    out.push(entity_type);
    out.extend_from_slice(&occurred.start.to_be_bytes());
    out.extend_from_slice(&occurred.end.to_be_bytes());
    out.extend_from_slice(&learned_at.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Stores `data` as a policy-manifest entity at `id` via a raw store put
/// (occurred `1..1`, learned_at `1`), bypassing the batch write path.
/// Seeding the *default* manifest slot must pass
/// `crate::gate::default_policy_manifest_id()` so the intent is explicit.
/// The `graph_fs` test copy deliberately stays local: it exercises the
/// real `apply_ops` write path instead of a raw put.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn put_policy_manifest_bytes(vault: &Vault, id: EntityId, data: &[u8]) -> crate::Result<()> {
    let payload = entity_record(
        ENTITY_TYPE_POLICY_MANIFEST,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    );
    vault.with_write_txn(|wtxn| {
        // This fixture represents local authoring, not replay. Preserve that
        // origin even though it bypasses batch to isolate the tested gate.
        crate::gate::manifest_authenticity::stamp_manifest_origin(
            &vault.store,
            wtxn,
            &id,
            data,
            false,
        )?;
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

/// The unit-test host root. Each test vault is its own trust domain, so one
/// fixed secret lets any fixture rebuild the issuer that rooted its vault.
#[doc(hidden)]
pub fn test_host_issuer() -> HostSlipIssuer {
    HostSlipIssuer::from_secret(b"oneiron unit test host root").expect("host issuer")
}

/// Roots the vault under the test host and provisions the engine's MACHINE
/// writers, as a host does at bootstrap. Returns the host issuer so a test can
/// provision its own MACHINE actors with `provision_host_machine_identity`.
#[doc(hidden)]
pub fn provision_engine_machines(vault: &Vault) -> HostSlipIssuer {
    let issuer = test_host_issuer();
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    issuer
}

/// Binds `person` as the human owner under the host root, so owner verbs
/// keep working once a fixture roots its vault.
///
/// # Errors
/// The authority log's.
#[doc(hidden)]
pub fn bind_host_owner(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    person: EntityId,
) -> crate::Result<()> {
    vault.bind_host_owner_for_test(issuer, person)
}

/// Appends `Sent` to an esign document's ledger, as sending it does.
///
/// # Errors
/// The ledger's: an unknown document, or a state that cannot be sent.
#[doc(hidden)]
pub fn mark_esign_sent(
    vault: &Vault,
    document: EntityId,
    actor: EsignAuditActor,
    now: u64,
) -> crate::Result<()> {
    crate::blob_artifact::esign::mark_sent_for_test(vault, document, actor, now)
}

/// The scope an effect grant names in a policy manifest.
#[doc(hidden)]
pub fn effect_preset() -> crate::federation::Scope {
    crate::federation::scope_codec::effect_preset()
}
