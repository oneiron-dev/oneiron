//! HOME-ELECTION-NEEDS-FULL-COPY (CROSS-ARCH-0024 `#my-network` item 04:
//! "Only a full copy can become home."): the MACRO home election ranks a
//! machine's declared candidacy only while that machine holds a full copy,
//! once any declaration it ranks does. With no full copy anywhere, the
//! election ranks as before. A home that marks its own copy keeps the home
//! on every machine, whatever that machine's host names as its own
//! candidate. An owner pick of a machine with no full copy waits for its
//! mark.
//!
//! The fixture is one owned vault: this install profiled as the owner's own
//! machine, and two enrolled machines that declare MACRO candidacies under
//! their own keys. It reaches the crate-private doors through
//! `oneiron::test_doors::full_copy_mark`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test home_election_full_copy`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{ConsolidationHomePickRequest, consolidation_home_pick_as};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::full_copy_mark::{
    declare_macro_candidacy_for, enroll_mine_machine, sign_full_copy_mark,
};
use oneiron::{DreamerHomeNodeCandidate, DreamerRunnerStore, EntityId, Vault, VaultConfig};

/// The node id the home declares: machine B, always on, which marks its own
/// copy as a served home does.
const HOME_NODE: u64 = 20;
/// Machine A's declared node id: below the home's, so the default order's
/// node-id tie-break ranks A first.
const A_NODE: u64 = 7;
/// Machine B's declared node id as a primary device.
const B_NODE: u64 = 9;

/// A fresh owned vault with this install profiled as the owner's own
/// machine, the authenticated owner, and two enrolled machines with the keys
/// that sign as them.
struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    a: EntityId,
    a_key: SigningKey,
    b: EntityId,
    b_key: SigningKey,
}

fn fixture() -> (Fixture, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("FIXTURE: a scratch directory");
    let vault =
        Vault::open_owned(dir.path(), VaultConfig::default()).expect("FIXTURE: a fresh vault");
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner actor");
    let issuer = HostSlipIssuer::from_secret(b"home election full copy test host")
        .expect("FIXTURE: the fixture host issuer");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_host_root_slip(&issuer)
        .expect("FIXTURE: the host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
        .expect("FIXTURE: this install's serving profile");
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the authenticated owner");
    let (a, a_key) =
        enroll_mine_machine(&vault, &owner, 0xA7).expect("FIXTURE: machine A enrols as mine");
    let (b, b_key) =
        enroll_mine_machine(&vault, &owner, 0xB7).expect("FIXTURE: machine B enrols as mine");
    (
        Fixture {
            vault,
            owner,
            a,
            a_key,
            b,
            b_key,
        },
        dir,
    )
}

/// Elects over `host`, the host's own candidacy, and the vault's declared
/// candidacies; answers the elected node.
fn elect(vault: &Vault, host: &[DreamerHomeNodeCandidate]) -> Option<u64> {
    DreamerRunnerStore::new(vault)
        .elect_home_node(host, 100)
        .expect("the election runs")
        .map(|home| home.node_id)
}

/// The designation as it stands, after the last landing re-elected it.
fn designated(vault: &Vault) -> Option<u64> {
    DreamerRunnerStore::new(vault)
        .home_node_designation()
        .expect("the designation reads")
        .map(|home| home.node_id)
}

#[test]
fn a_candidacy_with_a_full_copy_is_elected_over_one_without() {
    let (fixture, _dir) = fixture();
    let Fixture {
        vault,
        a,
        a_key,
        b,
        b_key,
        ..
    } = fixture;
    declare_macro_candidacy_for(&vault, a, &a_key, A_NODE, true, false)
        .expect("FIXTURE: A declares an always-on candidacy");
    declare_macro_candidacy_for(&vault, b, &b_key, B_NODE, false, true)
        .expect("FIXTURE: B declares a primary-device candidacy");
    assert_eq!(
        elect(&vault, &[]),
        Some(A_NODE),
        "with no full copy anywhere, the default order elects the always-on A"
    );
    assert!(
        sign_full_copy_mark(&vault, b, &b_key, true)
            .expect("B's held mark signs")
            .is_some(),
        "B's first held mark is written"
    );
    assert_eq!(
        designated(&vault),
        Some(B_NODE),
        "once B holds a full copy, the mark's landing re-elects B: A holds none"
    );
    assert!(
        sign_full_copy_mark(&vault, b, &b_key, false)
            .expect("B's withdrawn mark signs")
            .is_some(),
        "B's withdrawn mark is written"
    );
    assert_eq!(
        designated(&vault),
        Some(A_NODE),
        "with B's mark withdrawn, no full copy stands and the default order elects A again"
    );
}

#[test]
fn a_home_that_marks_its_own_copy_keeps_the_home_on_every_machine() {
    let (fixture, _dir) = fixture();
    let Fixture {
        vault,
        a,
        a_key,
        b: home,
        b_key: home_key,
        ..
    } = fixture;
    declare_macro_candidacy_for(&vault, a, &a_key, A_NODE, true, false)
        .expect("FIXTURE: A declares an always-on candidacy");
    declare_macro_candidacy_for(&vault, home, &home_key, HOME_NODE, true, false)
        .expect("FIXTURE: the home declares an always-on candidacy");
    assert!(
        sign_full_copy_mark(&vault, home, &home_key, true)
            .expect("the home's own mark signs")
            .is_some(),
        "FIXTURE: the home marks its own copy, as a served home does"
    );
    assert_eq!(
        elect(&vault, &[]),
        Some(HOME_NODE),
        "a machine whose host names no home elects the home: A holds no full copy, though its \
         node id ranks first"
    );
    assert_eq!(
        elect(
            &vault,
            &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE)]
        ),
        Some(HOME_NODE),
        "the home's own host elects the same home"
    );
    assert!(
        sign_full_copy_mark(&vault, a, &a_key, true)
            .expect("A's held mark signs")
            .is_some(),
        "A's first held mark is written"
    );
    assert_eq!(
        designated(&vault),
        Some(A_NODE),
        "once A holds a full copy it stands again, and the default order ranks it by node id"
    );
}

#[test]
fn an_owner_pick_without_a_full_copy_waits_for_its_mark() {
    let (fixture, _dir) = fixture();
    let Fixture {
        vault,
        owner,
        a,
        a_key,
        b: home,
        b_key: home_key,
    } = fixture;
    declare_macro_candidacy_for(&vault, a, &a_key, A_NODE, false, true)
        .expect("FIXTURE: A declares a primary-device candidacy");
    declare_macro_candidacy_for(&vault, home, &home_key, HOME_NODE, true, false)
        .expect("FIXTURE: the home declares an always-on candidacy");
    assert!(
        sign_full_copy_mark(&vault, home, &home_key, true)
            .expect("the home's own mark signs")
            .is_some(),
        "FIXTURE: the home marks its own copy, as a served home does"
    );
    assert_eq!(
        elect(&vault, &[]),
        Some(HOME_NODE),
        "the always-on home is elected"
    );
    let receipt = consolidation_home_pick_as(
        &vault,
        &owner,
        ActSurface::ThisInstall,
        ConsolidationHomePickRequest {
            node_id: Some(A_NODE.to_string()),
            seen: None,
        },
    )
    .expect("the owner's pick of A lands");
    assert_eq!(
        receipt.pick.as_deref(),
        Some("7"),
        "the pick is recorded although A holds no full copy"
    );
    assert_eq!(
        designated(&vault),
        Some(HOME_NODE),
        "the election passes over the pick of A while A holds no full copy"
    );
    assert!(
        sign_full_copy_mark(&vault, a, &a_key, true)
            .expect("A's held mark signs")
            .is_some(),
        "A's first held mark is written"
    );
    assert_eq!(
        designated(&vault),
        Some(A_NODE),
        "once A holds a full copy, the mark's landing elects the owner's pick"
    );
}
