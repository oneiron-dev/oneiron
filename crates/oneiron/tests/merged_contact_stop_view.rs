//! A key whose PERSON was merged into a different key keeps showing the STOP
//! it said before the merge on its contacts (F06 R4-F1; ARCH-0057 "fold a
//! merged key's own heads in the rebuild").
//!
//! The contact read folds the party's standing `comm.opt_out` heads into the
//! contact's own heads (OF-272). It resolved only an ACTIVE party, and a key
//! merged into another has none, so the fold read no head and the contact
//! showed no opt-out, while the send gate, which reads every PERSON carrying
//! the key whatever its lifecycle, still held the key's sends.
//!
//! The vault is unseeded, as the comm legs of the effect-spine oracle open it
//! (`tests/it/effect_spine_oracle.rs`), so the opener needs the test-support
//! feature.
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::comm::{record_comm_inbound_stop, resolve_or_create_comm_party, run_comm_projector};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::identity_topology::{
    EntityLifecycleState, IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite,
    IdentityTopologyOp, MergeOp, SurvivorshipPlan,
};
use oneiron::{ClaimSource, EntityId, Vault, VaultConfig};

const MERGED_KEY: &str = "merged-key@example.com";
const SURVIVOR_KEY: &str = "survivor-key@example.com";
const UNKNOWN_KEY: &str = "no-person@example.com";

/// An unseeded vault with this install's signing keys loaded: a topology op's
/// seal is signed with the install's machine key (P6c).
fn open_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("vault dir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(directory.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    (directory, vault)
}

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("entity id")
}

/// One contact for `counterparty`. Its identity row is absent, so its channel
/// class is unknown and every head of the party covers it.
fn create_contact(vault: &Vault, contact_id: EntityId, counterparty: &str) {
    let contact = CounterpartyContactRecord::user_introduction(id(0x51), counterparty, 1)
        .expect("contact record");
    vault
        .create_counterparty_contact(&contact_id, &contact)
        .expect("create contact");
}

/// Whether the public contact read shows the contact opted out.
fn contact_view_opted_out(vault: &Vault, contact_id: EntityId) -> bool {
    vault
        .get_counterparty_contact(&contact_id)
        .expect("read contact")
        .expect("contact exists")
        .is_opted_out()
}

/// Merges `source` into `survivor` read-through.
fn merge_read_through(vault: &Vault, source: EntityId, survivor: EntityId) {
    let outcome = vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![source],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: vec![survivor, source],
                    rationale: "one person, two addresses".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            vault.now_recorded_at(),
        )
        .expect("merge");
    assert!(
        matches!(outcome, IdentityOpOutcome::Applied { .. }),
        "the merge applies; got {outcome:?}"
    );
}

#[test]
fn a_merged_keys_contact_keeps_its_stop() {
    let (_directory, vault) = open_vault();
    let contact_id = id(0x5C);
    create_contact(&vault, contact_id, MERGED_KEY);
    record_comm_inbound_stop(&vault, MERGED_KEY, "email", 30).expect("record the STOP");
    run_comm_projector(&vault).expect("project the STOP");
    assert!(
        contact_view_opted_out(&vault, contact_id),
        "fixture: the STOP shows on the contact before the merge"
    );

    let merged = resolve_or_create_comm_party(&vault, MERGED_KEY).expect("merged key's party");
    let survivor = resolve_or_create_comm_party(&vault, SURVIVOR_KEY).expect("survivor's party");
    assert_ne!(merged, survivor, "fixture: two keys, two PERSONs");
    merge_read_through(&vault, merged, survivor);
    assert_eq!(
        vault.entity_lifecycle_state(&merged).expect("lifecycle"),
        EntityLifecycleState::Merged,
        "fixture: the merged key has no active party now"
    );

    assert!(
        contact_view_opted_out(&vault, contact_id),
        "the merged key's contact still shows the STOP it said before the merge"
    );
}

/// The fold reads heads only for PERSONs that carry the contact's key: a key
/// no PERSON carries folds nothing, beside a stopped key.
#[test]
fn a_key_no_person_carries_folds_no_stop() {
    let (_directory, vault) = open_vault();
    let stopped = id(0x5D);
    let unknown = id(0x5E);
    create_contact(&vault, stopped, MERGED_KEY);
    create_contact(&vault, unknown, UNKNOWN_KEY);
    record_comm_inbound_stop(&vault, MERGED_KEY, "email", 30).expect("record the STOP");
    run_comm_projector(&vault).expect("project the STOP");

    assert!(contact_view_opted_out(&vault, stopped));
    assert!(
        !contact_view_opted_out(&vault, unknown),
        "a contact whose key no PERSON carries shows no opt-out"
    );
}
