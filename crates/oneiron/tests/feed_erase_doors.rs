//! A hard delete leaves no change feed row naming the deleted entity (review #6942), read
//! through the test door `oneiron::test_doors::feeds`: a reader is told nothing of rows its lane
//! does not show (lead call K), and no lane shows a deleted entity, so the rows are counted there.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test feed_erase_doors`.
#![cfg(oneiron_test_support)]

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::deletion::DeleteReason;
use oneiron::edge::EdgeKind;
use oneiron::feeds::{FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::feeds::rows_naming;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

fn owner_key(vault: &Vault) -> ScopedReadActorKey {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let issuer = HostSlipIssuer::from_secret(b"feed-erase-test-host-secret").expect("issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    let issued_at = vault.capability_slip_now().expect("authority clock");
    let mut claims = root.claims.clone();
    claims.slip_id = [0x49; 32];
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the owner's slip");
    let challenge = b"feed-erase-test";
    let proof = issuer
        .binding_proof(&slip, challenge)
        .expect("binding proof");
    let verified = vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)
        .expect("verified slip");
    ScopedReadActorKey::from_verified_slip(&verified).expect("owner key")
}

fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("person");
    id
}

/// A hard delete scrubs the edge rows naming the deleted entity before its tear, and the tear's
/// cascade over the entity's edges writes none back: no edge row names it afterwards, though a
/// follower from the beginning has acknowledged nothing.
#[test]
fn a_hard_delete_leaves_no_edge_row_naming_the_deleted_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    // A hard delete needs this install's keystore, as a host installs it after each open.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    vault.prepare_install_signing().expect("install signing");
    vault
        .feed_subscribe(
            &vault.scoped_read(owner_key(&vault)),
            &FeedSubscribeRequest {
                selector: FeedSelector {
                    sources: vec![FeedSource::Edges],
                    kinds: Vec::new(),
                    entity_types: Vec::new(),
                    predicates: Vec::new(),
                },
                start: FeedStart::Beginning,
            },
        )
        .expect("follow edges");
    let (from, to) = (put_person(&vault), put_person(&vault));
    // A PERSON's put may write edges of its own: the count before the Supports edge is the base.
    let before = rows_naming(&vault, &to).expect("rows");
    vault
        .put_edge(&from, EdgeKind::Supports, &to, 0.5)
        .expect("edge");
    assert_eq!(
        rows_naming(&vault, &to).expect("rows"),
        before + 1,
        "the edge added"
    );

    vault
        .delete_entity_with_reason(&to, DeleteReason::UserHardDelete)
        .expect("hard delete of the edge's target");
    assert_eq!(
        rows_naming(&vault, &to).expect("rows"),
        0,
        "no feed row names the deleted end"
    );
}
