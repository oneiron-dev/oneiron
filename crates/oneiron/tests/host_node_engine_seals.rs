//! The host's own merges count on a paired replica (census L7-34; ARCH-0055
//! `#seal-standing-open`: "The host's own merges stay parked on paired
//! replicas ... Ruled, not built. They count once a host self-profile flow
//! exists"; DEC-0005 `#will-sweep`). A managed host profiles its own node as
//! a hosted node, never mine (`Vault::provision_host_node`). An engine seal
//! counts on a replica when that replica wrote it or a machine mine there
//! signed it; the host's own node now counts too, and stays not mine. An
//! execution node's engine seal stays inert, as canon says.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test host_node_engine_seals`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::ClaimSource;
use oneiron::edge::EdgeKind;
use oneiron::identity_topology::{
    IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    SurvivorshipPlan,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::host_node_seals::{copy_authority_log, deliver_identity_topology_rows};
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

/// One install of a vault under the Hosted posture, with a keystore and its
/// install signing loaded. The vault drops first.
struct Install {
    vault: Vault,
    _dir: tempfile::TempDir,
}

fn hosted_install() -> Install {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("hosted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.prepare_install_signing().expect("install signing");
    Install { vault, _dir: dir }
}

/// The managed host's install: the vault rooted under the test host, and this
/// install's own node profiled in `role` by the host root, as managed start
/// does for `HostedNode`. Returns the install and its MACHINE row.
fn host_with_node(role: MachineRole) -> (Install, EntityId) {
    let host = hosted_install();
    host.vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault's owner, whom the node's profile names");
    let issuer = oneiron::test_support::provision_engine_machines(&host.vault);
    let profiled = if role == MachineRole::HostedNode {
        host.vault.provision_host_node(&issuer)
    } else {
        host.vault.ensure_serving_install_profile(&issuer, role)
    };
    let folded = profiled.expect("FIXTURE: the host root profiles this install's node");
    let node = folded
        .roster
        .as_ref()
        .expect("FIXTURE: the node's profile is a roster revision")
        .profile
        .machine;
    (host, node)
}

fn put_person(vault: &Vault, person: EntityId) {
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"person fixture",
        )
        .expect("FIXTURE: the person lands");
}

/// `install` merges `loser` into `survivor` through its own local door, on
/// the engine's authority (an auto merge, sealed by this install's key).
fn merge_locally(install: &Vault, loser: EntityId, survivor: EntityId) {
    put_person(install, loser);
    put_person(install, survivor);
    let outcome = install
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![loser],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "fixture rationale".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            200,
        )
        .expect("FIXTURE: the host's merge");
    assert!(
        matches!(outcome, IdentityOpOutcome::Applied { .. }),
        "FIXTURE: the host's merge applies"
    );
}

fn merged(vault: &Vault, loser: EntityId, survivor: EntityId) -> bool {
    vault
        .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
        .expect("edge read")
}

/// The host, with its node in `role`, merges two people; a paired replica of
/// the same vault takes the authority log, both people and the merge's rows.
/// Returns the replica, the host's node and the pair.
fn host_merge_reaches_a_replica(role: MachineRole) -> (Install, Install, EntityId, [EntityId; 2]) {
    let (host, node) = host_with_node(role);
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    merge_locally(&host.vault, loser, survivor);
    assert!(
        merged(&host.vault, loser, survivor),
        "FIXTURE: the merge is in force on the host that sealed it"
    );

    let replica = hosted_install();
    copy_authority_log(&host.vault, &replica.vault)
        .expect("FIXTURE: the replica takes the host's authority log");
    assert_eq!(
        replica
            .vault
            .authority_fold()
            .expect("replica fold")
            .vault_id,
        host.vault.authority_fold().expect("host fold").vault_id,
        "FIXTURE: the replica folds the host's vault"
    );
    put_person(&replica.vault, loser);
    put_person(&replica.vault, survivor);
    let landed = deliver_identity_topology_rows(&host.vault, &replica.vault)
        .expect("FIXTURE: the merge's rows reach the replica");
    assert!(landed > 0, "FIXTURE: the merge's rows land fresh");
    (host, replica, node, [loser, survivor])
}

#[test]
fn the_hosts_own_merge_counts_on_a_paired_replica() {
    let (_host, replica, node, [loser, survivor]) =
        host_merge_reaches_a_replica(MachineRole::HostedNode);
    assert!(
        replica
            .vault
            .authority_fold()
            .expect("replica fold")
            .trusted_machine(node)
            .is_none(),
        "the host's node is never mine on the replica"
    );
    assert!(
        merged(&replica.vault, loser, survivor),
        "the host's own merge is in force on a paired replica"
    );
}

#[test]
fn an_execution_nodes_merge_stays_parked_on_a_paired_replica() {
    let (_host, replica, _node, [loser, survivor]) =
        host_merge_reaches_a_replica(MachineRole::ExecutionNode);
    assert!(
        !merged(&replica.vault, loser, survivor),
        "an execution node's engine seal stays inert on a paired replica"
    );
}
