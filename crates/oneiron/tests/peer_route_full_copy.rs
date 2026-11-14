//! L7-47 (CROSS-ARCH-0024 `#my-network` item 04: "A full copy earns
//! roles. It is a live backup and a standby home."): a machine's signed
//! full-copy mark leads the peer order of a device whose home is down, a
//! withdrawn mark falls back to the election's rank, a repeated mark writes
//! nothing, and a mark another machine signed is refused.
//!
//! The fixture is one owned vault: this install profiled as the owner's own
//! machine, and two enrolled peers. It reaches the crate-private doors
//! through `oneiron::test_doors::full_copy_mark`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test peer_route_full_copy`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::full_copy_mark::{
    declare_candidacy_for, enroll_mine_machine, holds_full_copy, rank_sync_peers,
    sign_full_copy_mark,
};
use oneiron::{EntityId, Vault, VaultConfig};

/// A fresh owned vault with this install profiled as the owner's own
/// machine, and two enrolled peers with the keys that sign as them.
struct Fixture {
    vault: Vault,
    local: EntityId,
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
    let issuer = HostSlipIssuer::from_secret(b"peer route full copy test host")
        .expect("FIXTURE: the fixture host issuer");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_host_root_slip(&issuer)
        .expect("FIXTURE: the host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
        .expect("FIXTURE: this install's serving profile");
    let local = vault
        .local_machine()
        .expect("FIXTURE: this install's machine reads")
        .expect("FIXTURE: this install has a machine once it is profiled")
        .id;
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the authenticated owner");
    let (a, a_key) =
        enroll_mine_machine(&vault, &owner, 0xA7).expect("FIXTURE: peer A enrols as mine");
    let (b, b_key) =
        enroll_mine_machine(&vault, &owner, 0xB7).expect("FIXTURE: peer B enrols as mine");
    (
        Fixture {
            vault,
            local,
            a,
            a_key,
            b,
            b_key,
        },
        dir,
    )
}

#[test]
fn a_full_copy_ranks_before_the_election_standby() {
    let (fixture, _dir) = fixture();
    let Fixture {
        vault,
        local,
        a,
        a_key,
        b,
        b_key,
    } = fixture;
    let home = EntityId::now();
    let granted = vec![a, b];
    declare_candidacy_for(&vault, a, &a_key, 7, true)
        .expect("FIXTURE: A declares an always-on candidacy");
    assert_eq!(
        rank_sync_peers(&vault, &granted, local, home).expect("the peer order reads"),
        vec![a, b],
        "with no full-copy mark, the election standby A ranks first"
    );
    assert!(
        sign_full_copy_mark(&vault, b, &b_key, true)
            .expect("B's held mark signs")
            .is_some(),
        "B's first held mark is written"
    );
    assert!(
        holds_full_copy(&vault, b).expect("the mark reads"),
        "B holds a full copy once its held mark lands"
    );
    assert_eq!(
        rank_sync_peers(&vault, &granted, local, home).expect("the peer order reads"),
        vec![b, a],
        "a machine that holds a full copy ranks before the election standby"
    );
}

#[test]
fn a_withdrawn_mark_ranks_by_election_again() {
    let (fixture, _dir) = fixture();
    let Fixture {
        vault,
        local,
        a,
        a_key,
        b,
        b_key,
    } = fixture;
    let home = EntityId::now();
    let granted = vec![a, b];
    declare_candidacy_for(&vault, a, &a_key, 7, true)
        .expect("FIXTURE: A declares an always-on candidacy");
    sign_full_copy_mark(&vault, b, &b_key, true).expect("FIXTURE: B's held mark lands");
    assert!(
        sign_full_copy_mark(&vault, b, &b_key, false)
            .expect("B's withdrawn mark signs")
            .is_some(),
        "withdrawing a held mark writes"
    );
    assert!(
        !holds_full_copy(&vault, b).expect("the mark reads"),
        "B holds no full copy once its mark says so"
    );
    assert_eq!(
        rank_sync_peers(&vault, &granted, local, home).expect("the peer order reads"),
        vec![a, b],
        "a withdrawn mark ranks by the election again"
    );
}

#[test]
fn a_repeated_mark_writes_nothing() {
    let (fixture, _dir) = fixture();
    let Fixture { vault, local, .. } = fixture;
    assert!(
        vault
            .declare_full_copy(true)
            .expect("this install writes its first held mark")
            .is_some(),
        "this install's first held mark is written"
    );
    assert!(
        vault
            .declare_full_copy(true)
            .expect("a repeated mark reads back")
            .is_none(),
        "repeating a held mark writes nothing"
    );
    assert!(
        holds_full_copy(&vault, local).expect("the mark reads"),
        "this install holds a full copy once its held mark lands"
    );
    assert!(
        vault
            .declare_full_copy(false)
            .expect("this install withdraws its mark")
            .is_some(),
        "withdrawing the mark writes"
    );
    assert!(
        vault
            .declare_full_copy(false)
            .expect("a repeated withdrawal reads back")
            .is_none(),
        "repeating a withdrawn mark writes nothing"
    );
    assert!(
        !holds_full_copy(&vault, local).expect("the mark reads"),
        "this install holds no full copy once its mark says so"
    );
    let (fresh, _fresh_dir) = fixture();
    assert!(
        fresh
            .vault
            .declare_full_copy(false)
            .expect("a fresh vault answers")
            .is_none(),
        "a fresh vault's first held=false writes nothing: no mark means not held"
    );
}

#[test]
fn a_mark_signed_by_another_machine_is_refused() {
    let (fixture, _dir) = fixture();
    let Fixture {
        vault,
        local,
        a,
        a_key,
        b,
        ..
    } = fixture;
    let home = EntityId::now();
    let granted = vec![a, b];
    declare_candidacy_for(&vault, a, &a_key, 7, true)
        .expect("FIXTURE: A declares an always-on candidacy");
    assert!(
        sign_full_copy_mark(&vault, b, &a_key, true).is_err(),
        "a mark naming B signed by A's key is refused"
    );
    assert!(
        !holds_full_copy(&vault, b).expect("the mark reads"),
        "B holds no full copy after a refused mark"
    );
    assert_eq!(
        rank_sync_peers(&vault, &granted, local, home).expect("the peer order reads"),
        vec![a, b],
        "a refused mark leaves the election order alone"
    );
}
