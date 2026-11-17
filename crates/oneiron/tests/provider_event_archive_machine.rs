//! FIX [PROVIDER-EVENT-ARCHIVE-MACHINE-UNSIGNED] (OF-519 custody): a served
//! host archives each verified provider event's body as the provider-inbound
//! MACHINE. A MACHINE author's claim needs a signed, enrolled software
//! identity, and the host enrolls and signs only for its engine MACHINE
//! writers. The provider-inbound MACHINE was not one of them, so on a vault
//! the host rooted and provisioned, every fresh archive was refused with
//! "machine write requires a signed enrolled software identity" and no
//! provider event body was kept.
//!
//! - On a rooted vault with the engine writers provisioned, as a host holds
//!   it, a provider event archives: its body and its `blob.version` claim
//!   read back, the claim names the provider-inbound MACHINE at class
//!   `system` and carries its machine signature, and it stays Proposed.
//! - The host provisions again on every open, so the next open still
//!   archives a new event.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! provider_event_archive_machine`.

use oneiron::edge::EdgeActorClass;
use oneiron::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
};
use oneiron::{ClaimApprovalStatus, EntityId, Vault, VaultConfig};
use rmpv::Value;

/// The provider-inbound MACHINE's derivation domain, the engine's
/// `derived_domains::SURFACE_PROVIDER_INBOUND_ACTOR`, spelled out as
/// `tests/claim_facet_birth.rs` spells it.
const SURFACE_PROVIDER_INBOUND_ACTOR: &[u8] = b"oneiron:surface-provider-inbound-actor:v1";
/// The claim evidence key of a MACHINE write signature (the engine's
/// `authority::machine_write::MACHINE_SIGNATURE_KEY`).
const MACHINE_SIGNATURE_KEY: &str = "machine_signature";
/// The fixture's fixed clock: no wall time.
const T0: u64 = 1_780_000_000;

/// A vault rooted under the test host with the engine's MACHINE writers
/// provisioned, as a host opens it.
fn open_as_host(dir: &tempfile::TempDir) -> Vault {
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let _issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
}

fn evidence_field<'a>(evidence: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = evidence else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// Archives one Slack event body and checks its body, version and claim.
fn archive_and_check(vault: &Vault, event_id: &str, body: &[u8], now: u64) {
    let archived = vault.archive_provider_event("slack", event_id, body, now);
    let payload_ref = match archived {
        Ok(payload_ref) => payload_ref,
        Err(error) => panic!("the provider event archive was refused: {error:?}"),
    };
    assert_eq!(
        vault.read_provider_event(&payload_ref).expect("read event"),
        Some(body.to_vec()),
        "the archived body reads back by its payload ref"
    );
    let (artifact, version) = payload_ref
        .strip_prefix(oneiron::surface_event::PROVIDER_EVENT_REF_PREFIX)
        .and_then(|rest| rest.split_once('@'))
        .expect("a provider event ref");
    let artifact = EntityId::from_hex(artifact).expect("artifact id");
    let version: u64 = version.parse().expect("version number");
    let metadata = vault
        .blob_artifact_version_metadata(&artifact, version)
        .expect("version metadata")
        .expect("the version is stored");
    let claim = vault
        .get_claim(&metadata.claim_id)
        .expect("claim read")
        .expect("the version's claim is stored");
    assert_eq!(claim.predicate, "blob.version");
    assert_eq!(
        claim.approval,
        ClaimApprovalStatus::Proposed,
        "an archived body stays a proposal"
    );
    let evidence = claim.evidence.as_ref().expect("claim evidence");
    let inbound =
        EntityId::derive(SURFACE_PROVIDER_INBOUND_ACTOR, &[]).expect("provider-inbound id");
    assert_eq!(
        evidence_field(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        Some(&Value::Binary(inbound.as_bytes().to_vec())),
        "the provider-inbound MACHINE wrote the version"
    );
    assert_eq!(
        evidence_field(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY).and_then(Value::as_u64),
        Some(EdgeActorClass::System as u64),
        "it wrote at class system"
    );
    assert!(
        evidence_field(evidence, MACHINE_SIGNATURE_KEY).is_some(),
        "the version claim carries the MACHINE's signature"
    );
}

#[test]
fn a_rooted_vault_archives_a_provider_event_as_the_provisioned_inbound_machine() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_as_host(&dir);
    let body = br#"{"event":{"type":"message","text":"verified inbound"}}"#;
    archive_and_check(&vault, "Ev-rooted-1", body, T0);

    // The provider retries the same event: the same bytes are the blob
    // store's own no-op, under the same ref.
    let first = vault
        .archive_provider_event("slack", "Ev-rooted-1", body, T0)
        .expect("first ref");
    let retry = vault
        .archive_provider_event("slack", "Ev-rooted-1", body, T0 + 1)
        .expect("a retry archives");
    assert_eq!(first, retry, "a retry keeps its ref");
}

#[test]
fn a_reopened_host_vault_still_archives_a_new_provider_event() {
    let dir = tempfile::tempdir().expect("temporary vault");
    {
        let vault = open_as_host(&dir);
        archive_and_check(
            &vault,
            "Ev-before-reopen",
            br#"{"event":{"text":"before"}}"#,
            T0,
        );
    }
    let vault = open_as_host(&dir);
    archive_and_check(
        &vault,
        "Ev-after-reopen",
        br#"{"event":{"text":"after"}}"#,
        T0 + 60,
    );
}
