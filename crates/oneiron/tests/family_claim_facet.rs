//! [CHANNEL-IDENTITY-CLAIM-FACET] and [COUNTERPARTY-CONTACT-CLAIM-FACET]:
//! the two family doors write their `channel_identity.*` and
//! `counterparty_contact.*` heads in the vault default facet, so the CLAIM
//! birth gate admits them. Before the fix each head was born in its subject's
//! own substrate, which is no FACET, and both create doors failed with
//! `InvalidFacet { found: None }` for every record.
//!
//! This integration target builds the library and this file only, so it runs
//! independently of unrelated library test targets.

use oneiron::channel_identity::{ChannelIdentity, ChannelIdentityBinding, SelfHeldShape};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::{EntityId, Vault, VaultConfig};

fn entity(seed: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x7f;
    bytes[15] = seed;
    EntityId::from_bytes(bytes).expect("valid fixture id")
}

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("valid fixture dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("valid fixture vault");
    (dir, vault)
}

/// Every claim on `subject` is born in the vault default facet; answers the
/// predicates seen.
fn heads_in_default_facet(vault: &Vault, subject: &EntityId, family: &str) -> Vec<String> {
    let facet = vault.default_facet().expect("default facet");
    let mut predicates = Vec::new();
    for claim in vault.claims_for_subject(subject).expect("claims") {
        let body = vault
            .get_claim(&claim)
            .expect("claim read")
            .expect("claim present");
        if !body.predicate.starts_with(family) {
            continue;
        }
        assert_eq!(
            body.scope_facet, facet,
            "{} head is born outside the vault default facet",
            body.predicate
        );
        predicates.push(body.predicate);
    }
    predicates
}

#[test]
fn create_channel_identity_writes_heads_in_the_default_facet() {
    let (_dir, vault) = vault();
    let id = entity(0x01);
    let identity = ChannelIdentity::requested(
        "email",
        "agent@example.test",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(entity(0x02)),
        1_800_000_000,
    );
    vault
        .create_channel_identity(&id, &identity)
        .expect("create_channel_identity admits a valid requested identity");
    let stored = vault
        .get_channel_identity(&id)
        .expect("identity read")
        .expect("identity present");
    assert_eq!(stored.address_or_handle(), "agent@example.test");
    let predicates = heads_in_default_facet(&vault, &id, "channel_identity.");
    assert!(
        !predicates.is_empty(),
        "the create door wrote no channel_identity.* heads"
    );
}

#[test]
fn create_own_app_channel_identity_writes_heads_in_the_default_facet() {
    let (_dir, vault) = vault();
    let id = entity(0x03);
    vault
        .create_own_app_channel_identity(&id, entity(0x04), 1_800_000_000)
        .expect("create_own_app_channel_identity admits the home identity");
    assert!(!heads_in_default_facet(&vault, &id, "channel_identity.").is_empty());
}

#[test]
fn create_counterparty_contact_writes_heads_in_the_default_facet() {
    let (_dir, vault) = vault();
    let id = entity(0x05);
    let record =
        CounterpartyContactRecord::user_introduction(entity(0x06), "party@example.test", 1)
            .expect("valid contact record");
    vault
        .create_counterparty_contact(&id, &record)
        .expect("create_counterparty_contact admits a valid contact");
    let stored = vault
        .get_counterparty_contact(&id)
        .expect("contact read")
        .expect("contact present");
    assert_eq!(stored.counterparty, "party@example.test");
    let predicates = heads_in_default_facet(&vault, &id, "counterparty_contact.");
    assert!(
        !predicates.is_empty(),
        "the create door wrote no counterparty_contact.* heads"
    );
}

#[test]
fn revoke_counterparty_contact_writes_the_new_heads_in_the_default_facet() {
    let (_dir, vault) = vault();
    let id = entity(0x07);
    let record =
        CounterpartyContactRecord::user_introduction(entity(0x08), "other@example.test", 1)
            .expect("valid contact record");
    vault
        .create_counterparty_contact(&id, &record)
        .expect("create_counterparty_contact admits a valid contact");
    let revoked = vault
        .revoke_counterparty_contact(&id, 2)
        .expect("revoke_counterparty_contact supersedes the heads");
    assert_eq!(revoked.revoked_at, Some(2));
    assert!(!heads_in_default_facet(&vault, &id, "counterparty_contact.").is_empty());
}
