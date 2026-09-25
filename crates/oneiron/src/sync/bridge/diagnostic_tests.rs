//! Account-local diagnostic isolation at both replay paths and outbound packing.
use super::*;
use crate::self_heal::{
    ConsentDeniedDetector, DeterministicDetector, DiagnosticObservation, DiagnosticWorkingSet,
    diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::sync::{
    loro_support::map_insert_bytes,
    types::WindowKey,
    window::{forward_rematerialize, reverse_rematerialize},
};
use crate::test_util::open_test_vault_with;
use crate::{config::VaultConfig, registry::ENTITY_TYPE_DIAGNOSTIC};
fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}

fn diagnostic_fixture(seed: u8, valid_to: Option<u64>) -> Result<(EntityId, Vec<u8>)> {
    let observations = [DiagnosticObservation {
        source_ref: id(seed),
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [seed; 32],
        observed_at: 1_000,
    }];
    let mut event = ConsentDeniedDetector
        .detect(&DiagnosticWorkingSet {
            scope_ref: "scope.consent",
            observations: &observations,
        })
        .remove(0);
    event.valid_to = valid_to;
    let body = encode_diagnostic_event_body(&event)?;
    let entity = diagnostic_event_id(&event.detector_id, &body);
    let mut blob = vec![ENTITY_TYPE_DIAGNOSTIC];
    blob.extend_from_slice(&event.valid_from.to_be_bytes());
    blob.extend_from_slice(&valid_to.unwrap_or(u64::MAX).to_be_bytes());
    blob.extend_from_slice(&1_000_u64.to_be_bytes());
    blob.extend_from_slice(&body);
    Ok((entity, blob))
}

#[test]
fn peer_diagnostic_output_is_silent_at_live_and_forward_replay() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let (id, blob) = diagnostic_fixture(4, None)?;
    let doc = LoroDoc::new();
    vault.with_write_txn(|txn| {
        assert!(!materialize_entity_blob_in_txn(
            &vault,
            txn,
            &doc.get_map("tombstones"),
            "2026-03",
            &id.to_hex(),
            &blob,
            0
        )?);
        Ok(())
    })?;
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)?;
    doc.commit();
    assert_eq!(
        forward_rematerialize(
            &vault,
            &doc,
            &Materializer::new(),
            &WindowKey::new("2026-03")
        )?,
        0
    );
    assert!(vault.get(&id)?.is_none());
    assert!(crate::sync::quota::maintenance_ingest_quota_snapshots(&vault)?.is_empty());
    Ok(())
}
#[test]
fn local_diagnostic_is_not_packed_into_crdt() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let (id, blob) = diagnostic_fixture(4, None)?;
    let event =
        crate::self_heal::decode_diagnostic_event_body(&blob[ENTITY_METADATA_HEADER_LEN..])?;
    vault.emit_diagnostic_event(&id, &event)?;
    let doc = LoroDoc::new();
    let window = crate::sync::WindowKey::from_timestamp(crate::unix_seconds_now());
    reverse_rematerialize(&vault, &doc, &window)?;
    assert!(map_get_bytes(&doc.get_map("entities"), &id.to_hex()).is_none());
    assert!(vault.get(&id)?.is_some());
    Ok(())
}
