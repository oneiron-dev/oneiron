//! Floors from rows fold a log of single-chain signers as the arrival floors
//! did (Engine RULING SEQ-FLOOR-SHAPE = A, 15 Nov 16:37; FIX
//! [SEQUENCE-FLOOR-DELIVERY-ORDER]).
//!
//! Before the ruling each install floored a row at the highest sequence of
//! its signer's same-scope rows it had observed before that row, and a later
//! row of the signer that descends from it vouched for it (the arrival-order
//! lift). Now a row's floor comes from the rows: the highest sequence among
//! its signer's same-scope rows that do not have it among their ancestors.
//! Where every signer signs one chain, no row has such a row, so no row is
//! floored, whatever order the rows arrived in.
//!
//! The test builds one vault's log from its own doors (the host root, this
//! install, an admitted machine's chain, two worlds' settings and key
//! records), with one more row on the machine's chain that is well signed
//! but that the fold refuses, then folds it by the rows' floors and by the
//! arrival floors of many orders through `test_doors::authority_sequence_floor`:
//! - every order that delivers each row after its parents floors no row, and
//!   both folds are equal, field for field;
//! - on every order, the fold by the rows' floors equals that in-order fold;
//! - every other order whose floors the old lift cleared folds equal too;
//! - the refused row vouches for nothing, so an order that delivers it before
//!   the rows below it leaves their arrival floors past the old lift (Astra
//!   round 1 E5): there the old fold may differ, and the rows' floors still
//!   fold as in order.
//!
//! Each order prints one `EQUIV` line; an order whose floors the old lift
//! left in place prints whether its fold still matched (the delivery-order
//! divergence the ruling removes). Green on the head only: the door is new.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test sequence_floor_equivalence`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerAct, OwnerActKind, ReadLocation,
    WorldPrivacy, WorldPrivacyEdit, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::authority_sequence_floor::fold_both_ways;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// Random orders of each kind the test folds.
const ORDERS_PER_KIND: u64 = 12;

struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
}

fn rooted() -> Rooted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Rooted {
        _dir: dir,
        vault,
        owner,
        proof,
        vault_id,
    }
}

/// The owner admits a machine whose install key the test holds, and returns
/// its id, its key and the entry that carried the admission.
fn admit_machine(rooted: &Rooted, seed: u8) -> (EntityId, SigningKey, AuthorityEntryHash) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let machine = EntityId::now();
    let machine_key = signing.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = signing
        .sign(&machine_profile_proof_transcript(
            &rooted.vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    let request = MachineEnrolmentRequest {
        vault_id: rooted.vault_id,
        machine,
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        machine_proof,
    };
    let folded = rooted
        .vault
        .enroll_machine(
            &rooted.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner admits the machine");
    let admission = folded
        .chains()
        .map(|(_, head)| head)
        .max_by_key(|head| head.profile.revision)
        .expect("the admission's revision")
        .entry;
    (machine, signing, admission)
}

/// The admitted machine's own world edit to `settings` at `seq` on
/// `parent`, signed by its install key: one link of its chain.
fn machine_row(
    rooted: &Rooted,
    machine: EntityId,
    signing: &SigningKey,
    (world, settings): (EntityId, WorldPrivacy),
    seq: u64,
    parent: AuthorityEntryHash,
) -> AuthorityLogEntry {
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: vec![parent],
        op: AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
            world,
            act: OwnerAct::by_owner(
                rooted.owner,
                OwnerActKind::WorldPrivacy,
                world,
                ActSurface::ThisInstall,
                [0; 32],
            ),
            machine,
            settings,
        }),
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

/// One vault's log from its own doors: the host root and the engine's
/// machines, this install marked the owner's, two worlds kept here (each
/// edit mints the world's key in its own scope), two admitted machines, one
/// of them removed, and the other's own three-row chain; then a fourth row
/// on that chain, well signed, whose one-machine pick names no machine the
/// vault admits, so every fold refuses it and it vouches for nothing.
fn log_of_single_chain_signers() -> Vec<AuthorityLogEntry> {
    let rooted = rooted();
    let here = rooted
        .vault
        .local_machine()
        .expect("this install")
        .expect("this install's machine")
        .id;
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            here,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner marks this install yours");
    for name in ["Kept here", "Also kept here"] {
        let world = rooted
            .vault
            .create_world(&rooted.proof, name, rooted.vault.now_recorded_at())
            .expect("the owner's world");
        rooted
            .vault
            .set_world_privacy_as(
                &rooted.proof,
                ActSurface::ThisInstall,
                world,
                WorldPrivacy {
                    read: ReadLocation::OneMachine(here),
                    ..WorldPrivacy::default()
                },
                None,
            )
            .expect("the owner keeps the world on this install");
    }
    let (removed, _, _) = admit_machine(&rooted, 0xA1);
    let (machine, signing, admission) = admit_machine(&rooted, 0xA2);
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            removed,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the first machine");
    let world = EntityId::now();
    let mut parent = admission;
    for seq in 1..=3 {
        let row = machine_row(
            &rooted,
            machine,
            &signing,
            (world, WorldPrivacy::default()),
            seq,
            parent,
        );
        rooted
            .vault
            .put_authority_log_entry(&row, AT, 1)
            .expect("the admitted machine's row lands");
        parent = authority_entry_hash(&row).expect("hash");
    }
    let mut entries: Vec<AuthorityLogEntry> = rooted
        .vault
        .export_signed_authority_history()
        .expect("the vault's history")
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a stored row"))
        .collect();
    let nowhere = WorldPrivacy {
        read: ReadLocation::OneMachine(EntityId::now()),
        ..WorldPrivacy::default()
    };
    entries.push(machine_row(
        &rooted,
        machine,
        &signing,
        (world, nowhere),
        4,
        parent,
    ));
    entries
}

/// A small deterministic generator (xorshift64).
struct Orders(u64);

impl Orders {
    fn next(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % bound as u64).expect("an index")
    }

    /// Any order of `count` rows.
    fn shuffled(&mut self, count: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (0..count).collect();
        for index in (1..count).rev() {
            order.swap(index, self.next(index + 1));
        }
        order
    }

    /// An order that delivers each row after every parent the log holds.
    fn topological(&mut self, entries: &[AuthorityLogEntry]) -> Vec<usize> {
        let hashes: Vec<AuthorityEntryHash> = entries
            .iter()
            .map(|entry| authority_entry_hash(entry).expect("hash"))
            .collect();
        let held: BTreeSet<AuthorityEntryHash> = hashes.iter().copied().collect();
        let mut delivered = BTreeSet::new();
        let mut order = Vec::with_capacity(entries.len());
        let mut left: Vec<usize> = (0..entries.len()).collect();
        while !left.is_empty() {
            let ready: Vec<usize> = left
                .iter()
                .copied()
                .filter(|index| {
                    entries[*index]
                        .parent_hashes
                        .iter()
                        .all(|parent| delivered.contains(parent) || !held.contains(parent))
                })
                .collect();
            assert!(!ready.is_empty(), "the log's parents form no cycle");
            let pick = ready[self.next(ready.len())];
            left.retain(|index| *index != pick);
            delivered.insert(hashes[pick]);
            order.push(pick);
        }
        order
    }
}

#[test]
fn rows_floors_fold_a_log_of_single_chain_signers_as_its_arrival_floors_did() {
    let entries = log_of_single_chain_signers();
    let signers: BTreeSet<&AuthorityKey> =
        entries.iter().map(AuthorityLogEntry::signer_key).collect();
    assert!(
        signers.len() >= 3,
        "the log has several signers: {}",
        signers.len()
    );
    let mut orders: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    orders.insert("stored".into(), (0..entries.len()).collect());
    orders.insert("reversed".into(), (0..entries.len()).rev().collect());
    let mut generator = Orders(0x9E37_79B9_7F4A_7C15);
    for round in 0..ORDERS_PER_KIND {
        orders.insert(
            format!("topological-{round}"),
            generator.topological(&entries),
        );
        orders.insert(format!("any-{round}"), generator.shuffled(entries.len()));
    }
    let in_order = fold_both_ways(&entries, &orders["topological-0"]).by_arrival;
    let mut lifted_short = 0;
    let mut diverged = 0;
    let mut floored_orders = 0;
    for (name, order) in &orders {
        let both = fold_both_ways(&entries, order);
        let same = both.by_arrival == both.by_rows;
        println!(
            "EQUIV order={name} rows={} topological={} rows_floored={} arrival_floored={} \
             after_lift={} same={same} valid={}",
            entries.len(),
            both.topological,
            both.rows_floored,
            both.arrival_floored,
            both.arrival_floored_after_lift,
            both.by_rows.valid_entries.len(),
        );
        assert!(both.single_chain, "every signer signs one chain per scope");
        assert_eq!(both.rows_floored, 0, "no row of a single chain is floored");
        assert_eq!(
            both.by_rows, in_order,
            "order {name}: the rows' floors fold as the in-order install did"
        );
        if both.topological {
            assert_eq!(
                both.arrival_floored, 0,
                "order {name} delivers parents first and floors no row"
            );
        }
        if both.arrival_floored > 0 {
            floored_orders += 1;
        }
        if both.arrival_floored_after_lift == 0 {
            assert_eq!(
                both.by_arrival, both.by_rows,
                "order {name}: the old lift cleared every floor, so the folds agree"
            );
        } else {
            lifted_short += 1;
            diverged += usize::from(!same);
        }
    }
    println!(
        "EQUIV-SUMMARY orders={} floored_orders={floored_orders} lift_left_floors={lifted_short} \
         old_fold_diverged={diverged}",
        orders.len()
    );
    assert!(
        floored_orders > 0,
        "some order floors rows, so the old lift is exercised"
    );
    assert!(
        lifted_short > 0,
        "the reversed order delivers the refused row first, so the old lift leaves floors"
    );
}
