//! Fixture writes that every test build shares: the crate's unit tests
//! (`test_util`), dependent crates (`test_support`, feature `test-support`)
//! and the integration-test doors (`test_doors` and the gate fixture, cfg
//! `oneiron_test_support`). Compiled under any of those gates, so a door
//! built under the cfg alone never reaches the feature-gated `test_support`
//! module (#6908, 5a328cbaf6a). Not API.

use crate::authority::HostSlipIssuer;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Raw stored-entity record: the 33-byte metadata header (type byte,
/// occurred start/end, learned_at, row_version — all big-endian u64s, per
/// the `batch::ENTITY_*_OFFSET` layout) followed by `body`.
pub(crate) fn entity_record(
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    row_version: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    out.push(entity_type);
    out.extend_from_slice(&occurred.start.to_be_bytes());
    out.extend_from_slice(&occurred.end.to_be_bytes());
    out.extend_from_slice(&learned_at.to_be_bytes());
    out.extend_from_slice(&row_version.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Stores `data` as a policy-manifest entity at `id` via a raw store put
/// (occurred `1..1`, learned_at `1`), bypassing the batch write path; the
/// body of `test_support::put_policy_manifest_bytes`.
pub(crate) fn put_policy_manifest_bytes(
    vault: &Vault,
    id: EntityId,
    data: &[u8],
) -> crate::Result<()> {
    let payload = entity_record(
        ENTITY_TYPE_POLICY_MANIFEST,
        TimeRange { start: 1, end: 1 },
        1,
        0,
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
pub(crate) fn test_host_issuer() -> HostSlipIssuer {
    HostSlipIssuer::from_secret(b"oneiron unit test host root").expect("host issuer")
}

/// Roots the vault under the test host and provisions the engine's MACHINE
/// writers, as a host does at bootstrap; the body of
/// `test_support::provision_engine_machines`.
pub(crate) fn provision_engine_machines(vault: &Vault) -> HostSlipIssuer {
    let issuer = test_host_issuer();
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    issuer
}
