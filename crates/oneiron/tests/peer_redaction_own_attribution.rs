#![cfg(all(oneiron_test_support, feature = "sync"))]
//! A peer's redaction records the refusal before it erases this vault's own
//! attribution (ARCH-0055:162, author-carrier-open; census L7-35). A local
//! redaction signs a `RefusedActorClass` seal for an own author whose class
//! does not fit its entity before it scrubs the carrier; a peer's
//! `AuthorRedaction` scrubbed the same carrier with no refusal, so a decision
//! its wrong-class author kept out came into force once the author was gone.
//!
//! Red on origin/main: after the peer's redaction the merge is in the
//! effective fold, so the "never brings a wrong-class decision into force"
//! assertion fails. On the head the refusal is recorded first and the
//! decision stays out. The fitting-author control passes on both.

use oneiron::identity_topology::{
    AdmissionVerdict, IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp,
    MergeOp, StoredIdentityOpAction, SurvivorshipPlan,
};
use oneiron::registry::{ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_PERSON};
use oneiron::test_doors::peer_author_redaction as doors;
use oneiron::write_envelope::WriteActor;
use oneiron::{ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange {
    start: 100,
    end: 100,
};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault dir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    // An identity op and an integrity refusal are sealed with this install's
    // machine key, which a host loads from its keystore after each open.
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    (dir, vault)
}

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("fixture id")
}

fn put_person(vault: &Vault, byte: u8) -> EntityId {
    let person = id(byte);
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, AT, AT.start, b"person fixture")
        .expect("put person");
    person
}

/// An actorless merge of `source` into `survivor` under the engine's seal.
fn merge(vault: &Vault, source: EntityId, survivor: EntityId) -> EntityId {
    let op = IdentityTopologyOp::Merge(MergeOp {
        sources: vec![source],
        survivor,
        evidence: IdentityOpEvidence {
            refs: Vec::new(),
            rationale: "fixture rationale".to_owned(),
        },
        survivorship_plan: SurvivorshipPlan::ReadThrough,
    });
    match vault
        .apply_identity_topology_op(&op, &IdentityOpWrite::auto(ClaimSource::Inferred), 150)
        .expect("apply merge")
    {
        IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("expected the merge applied, got {other:?}"),
    }
}

fn in_force(vault: &Vault, event: EntityId) -> bool {
    doors::effective_identity_events(vault)
        .expect("effective identity fold")
        .contains(&event)
}

fn refused_actor_class(vault: &Vault, event: EntityId) -> bool {
    vault
        .entities_by_type(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
        .expect("type-76 rows")
        .into_iter()
        .filter_map(|row| {
            vault
                .identity_topology_event(&row)
                .expect("read type-76 row")
        })
        .any(|row| {
            matches!(row.action,
                StoredIdentityOpAction::AdmissionDisposition(fact)
                if fact.target == event && fact.verdict == AdmissionVerdict::RefusedActorClass)
        })
}

fn author(vault: &Vault, event: EntityId) -> Option<EntityId> {
    vault
        .identity_topology_event(&event)
        .expect("read the merge")
        .expect("the merge is held")
        .actor
        .map(WriteActor::entity_ref)
}

#[test]
fn a_peers_redaction_keeps_a_wrong_class_own_author_refused() {
    let (_dir, vault) = open_vault();
    let source = put_person(&vault, 0x51);
    let survivor = put_person(&vault, 0x52);
    let person = put_person(&vault, 0x53);
    let event = merge(&vault, source, survivor);
    assert!(in_force(&vault, event), "the sealed merge is in force");

    // A PERSON never acts as System: this vault's own carrier names an author
    // whose class does not fit, which the fold reads as an admission failure.
    doors::put_own_author_attribution(
        &vault,
        event,
        WriteActor::new(person, EdgeActorClass::System),
        160,
    )
    .expect("this vault's own carrier");
    assert_eq!(author(&vault, event), Some(person));
    assert!(
        !in_force(&vault, event),
        "an own author whose class does not fit keeps the merge out"
    );
    assert!(
        !refused_actor_class(&vault, event),
        "no refusal is recorded before a redaction"
    );

    assert!(
        doors::ingest_peer_author_redaction(&vault, event, 900, 170)
            .expect("land the peer's redaction"),
        "the peer's redaction lands fresh"
    );
    assert_eq!(
        author(&vault, event),
        None,
        "the peer's redaction still erases this vault's own attribution"
    );
    assert!(
        !in_force(&vault, event),
        "a peer's redaction never brings a wrong-class decision into force"
    );
    assert!(
        refused_actor_class(&vault, event),
        "the peer's redaction records the refusal a local redaction records first"
    );
}

#[test]
fn a_peers_redaction_of_a_fitting_own_author_refuses_nothing() {
    let (_dir, vault) = open_vault();
    let source = put_person(&vault, 0x61);
    let survivor = put_person(&vault, 0x62);
    let person = put_person(&vault, 0x63);
    let event = merge(&vault, source, survivor);
    doors::put_own_author_attribution(
        &vault,
        event,
        WriteActor::new(person, EdgeActorClass::Human),
        160,
    )
    .expect("this vault's own carrier");
    assert_eq!(author(&vault, event), Some(person));
    assert!(
        in_force(&vault, event),
        "a fitting own author keeps the merge in force"
    );

    assert!(
        doors::ingest_peer_author_redaction(&vault, event, 900, 170)
            .expect("land the peer's redaction"),
        "the peer's redaction lands fresh"
    );
    assert_eq!(
        author(&vault, event),
        None,
        "the peer's redaction erases the author"
    );
    assert!(in_force(&vault, event), "the merge stays in force");
    assert!(
        !refused_actor_class(&vault, event),
        "a fitting author earns no refusal"
    );
}
