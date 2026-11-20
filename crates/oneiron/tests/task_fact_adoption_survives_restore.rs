//! An adopted ACK still counts after a checkpoint restore drops its twin (REVIEW-9976
//! round 2 P1, `task_authority/mod.rs:1484`). A rooted vault reopened with no signer writes
//! its task facts unsigned; the next pass that loads the signer writes each a twin under
//! this install's carrier signature. The fix keeps the unsigned row's written-here mark at
//! adoption, so a restore of a checkpoint taken before the twin, which drops the twin and
//! carries the mark from the live vault, still counts the fact here, and the next pass
//! twins it again.
//!
//! `an_adopted_ack_still_counts_after_a_restore_drops_its_twin` is the red/green pair: red
//! at f1ed0eb198e (adoption deleted the ack's mark, so after the restore the ack row has
//! neither proof nor mark and the task reads unacked), green at 32a754b90e7 (the mark is
//! kept and carried from the live vault, so the task still reads acked).
//!
//! An adopted Owner fact does not refuse a restore of a checkpoint taken before its twin
//! (blind review round 1 P1, REVIEW-10064, `authority_plane.rs:701`). The twin is a live-only
//! fact row, and the restore compare read every live-only Owner, cancellation or assignment
//! fact on a task the checkpoint holds as moved authority, though the checkpoint holds the
//! same fact on the unsigned row the live fold still counts. Red on #10064's head
//! 8d4b25c54e6d with this test: the restore in
//! `an_adopted_owner_fact_does_not_refuse_a_restore_of_the_checkpoint_before_its_twin` is
//! refused for "task authority". Green on the head: the restore drops the twin, the carried
//! mark counts the unsigned Owner fact on the copy, and a cancel written since the
//! checkpoint still refuses the restore.
//! `adoption_twins_an_unsigned_fact_once_and_keeps_its_owner` (part 1) guards the head's
//! twin check instead: green on both commits, red only if the head lost `twinned_here_in`
//! (a second pass would twin the fact again).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_fact_adoption_survives_restore` (`--all-features` carries
//! the `test-support` feature `restore_tempdir` needs).
#![cfg(oneiron_test_support)]
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::authority::LocalOpenProfile;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::task_fact_actor::mint_fact;
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind, Vault,
    VaultConfig,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;

/// The carrier signature key in a signed fact body. The engine's key
/// (`task_authority/mod.rs:101`) is private, so the test matches its literal.
const CARRIER_SIGNATURE_KEY: &str = "carrier_signature";

/// A TASK `owner` creates through the task door, which writes its Owner fact.
fn owner_task(vault: &Vault, owner: EntityId, label: &str) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some(label.into()),
            Some(owner),
            Some(vault.now_recorded_at()),
        ))
        .expect("the task door")
        .task_ref
        .expect("the TASK creation took effect")
}

/// The authority fact rows linked to `task`, as `(id, body)`.
fn fact_rows(vault: &Vault, task: EntityId) -> Vec<(EntityId, Vec<u8>)> {
    vault
        .edges_in(&task)
        .expect("the task's links")
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::ScopedTo)
        .filter_map(|edge| {
            let raw = vault.get_raw(&edge.target).expect("the linked row")?;
            let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
            String::from_utf8_lossy(&body)
                .contains(TASK_AUTHORITY_FACT_SUBKIND)
                .then_some((edge.target, body))
        })
        .collect()
}

/// Whether a fact body carries this install's signature.
fn is_signed(body: &[u8]) -> bool {
    String::from_utf8_lossy(body).contains(CARRIER_SIGNATURE_KEY)
}

/// The kind key in a fact body. The engine's key (`task_authority/mod.rs:92`) is private,
/// so the test matches its literal.
const FACT_KIND_KEY: &str = "kind";

/// The authority fact kind a fact body states, as its stored byte.
fn fact_kind(body: &[u8]) -> u8 {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).expect("a fact body decodes");
    value
        .as_map()
        .expect("a fact body is a map")
        .iter()
        .find(|entry| entry.0.as_str() == Some(FACT_KIND_KEY))
        .and_then(|entry| entry.1.as_u64())
        .expect("a fact body names its kind") as u8
}

/// Whether a fact body states an acknowledgement.
fn is_acked(body: &[u8]) -> bool {
    fact_kind(body) == TaskAuthorityFactKind::Acked.as_byte()
}

#[test]
fn adoption_twins_an_unsigned_fact_once_and_keeps_its_owner() {
    // One keystore held across opens: the adopting reopen must load the same machine's
    // seed. A fresh empty keystore with `prepare_install_signing` would forget the machine
    // and join as new.
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let dir = tempfile::tempdir().expect("tempdir");

    // Root the vault with the signer loaded, then drop it so the same path can reopen.
    let owner = {
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("a new vault");
        vault.install_device_keystore(Arc::clone(&keystore));
        assert_eq!(
            vault
                .profile_local_open(Some(b"task-fact-adoption-survives-restore"), true)
                .expect("the root door"),
            LocalOpenProfile::RootedAndProfiled,
        );
        vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner")
    };

    // Reopen the same path with no keystore and no signer: a start with no signer
    // loaded. The task door still succeeds, and its Owner fact stores unsigned.
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen without a keystore");
    let task = owner_task(&vault, owner, "adopted after a signer-less start");
    let here = vault
        .task_authority_state(task)
        .expect("the task reads here")
        .expect("the unproved fact still counts where it was written");
    assert_eq!(here.owner_ref, owner);
    let rows = fact_rows(&vault, task);
    assert_eq!(rows.len(), 1, "the task door wrote one Owner fact");
    assert!(
        !is_signed(&rows[0].1),
        "the fact written with no signer loaded stores unsigned"
    );

    // Install the same keystore and load the signer without profiling: neither step
    // adopts. The next adoption pass twins the unsigned fact.
    vault.install_device_keystore(Arc::clone(&keystore));
    vault
        .prepare_install_signing()
        .expect("the install signer loads");
    assert_eq!(
        vault
            .adopt_unsigned_task_facts()
            .expect("the adoption pass"),
        1,
        "the unsigned post-root fact gets one twin"
    );
    let rows = fact_rows(&vault, task);
    assert_eq!(rows.len(), 2, "the unsigned row and its twin stand");
    assert_eq!(
        rows.iter().filter(|(_, body)| is_signed(body)).count(),
        1,
        "one of the two fact rows carries this install's signature"
    );
    let here = vault
        .task_authority_state(task)
        .expect("the task reads after adoption")
        .expect("the adopted fact still names an owner here");
    assert_eq!(here.owner_ref, owner);
    assert_eq!(
        vault
            .adopt_unsigned_task_facts()
            .expect("a second adoption pass"),
        0,
        "the twin stands, so a second pass twins nothing"
    );
}

#[test]
fn an_adopted_ack_still_counts_after_a_restore_drops_its_twin() {
    // One keystore held across opens: the adopting reopen must load the same machine's
    // seed. A fresh empty keystore with `prepare_install_signing` would forget the machine
    // and join as new.
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let dir = oneiron::test_support::restore_tempdir();
    let path = dir.path().join("vault");

    // Root the vault with the signer loaded, and create the task in this rooted session,
    // so its Owner fact is signed: the later adoption must twin the ack alone, since an
    // unsigned Owner twin would make the restore refuse. Drop the vault so the path can
    // reopen.
    let (owner, task) = {
        let vault = Vault::open_owned(&path, VaultConfig::device()).expect("a new vault");
        vault.install_device_keystore(Arc::clone(&keystore));
        assert_eq!(
            vault
                .profile_local_open(Some(b"task-fact-adoption-keeps-ack"), true)
                .expect("the root door"),
            LocalOpenProfile::RootedAndProfiled,
        );
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let task = owner_task(&vault, owner, "acked while no signer was loaded");
        let rows = fact_rows(&vault, task);
        assert_eq!(rows.len(), 1, "the task door wrote one Owner fact");
        assert!(
            is_signed(&rows[0].1),
            "the Owner fact written with the signer loaded stores signed"
        );
        (owner, task)
    };

    // Reopen the same path with no keystore and no signer: a start with no signer
    // loaded. The owner's ack goes through the mint door, which writes it unsigned with
    // its written-here mark.
    let vault = Vault::open(&path, VaultConfig::device()).expect("reopen without a keystore");
    mint_fact(&vault, task, TaskAuthorityFactKind::Acked, owner, None).expect("the owner's ack");
    let here = vault
        .task_authority_state(task)
        .expect("the task reads here")
        .expect("the Owner fact still proves an owner");
    assert!(here.acked, "the unproved ack counts where it was written");
    let rows = fact_rows(&vault, task);
    assert_eq!(rows.len(), 2, "the Owner fact and the ack stand");
    let unsigned: Vec<&(EntityId, Vec<u8>)> =
        rows.iter().filter(|(_, body)| !is_signed(body)).collect();
    assert_eq!(unsigned.len(), 1, "only the ack stores unsigned");
    assert_eq!(
        fact_kind(&unsigned[0].1),
        TaskAuthorityFactKind::Acked.as_byte(),
        "the unsigned row is the ack"
    );

    // Install the same keystore and load the signer without profiling: neither step
    // adopts. Then take the checkpoint the restore replays: it holds the unsigned ack
    // row, not its mark.
    vault.install_device_keystore(Arc::clone(&keystore));
    vault
        .prepare_install_signing()
        .expect("the install signer loads");
    vault.ensure_vault_key().expect("the vault data key");
    let key = vault.checkpoint_key().expect("the checkpoint key");
    let image = dir.path().join("image");
    vault
        .snapshot_checkpoint(&image, 100)
        .expect("a checkpoint holding the unsigned ack");

    assert_eq!(
        vault
            .adopt_unsigned_task_facts()
            .expect("the adoption pass"),
        1,
        "only the unsigned ack adopts; the Owner fact is signed"
    );
    let rows = fact_rows(&vault, task);
    assert_eq!(rows.len(), 3, "the Owner fact, the ack and its twin stand");
    assert_eq!(
        rows.iter().filter(|(_, body)| is_acked(body)).count(),
        2,
        "the ack and its twin stand"
    );
    assert_eq!(
        rows.iter().filter(|(_, body)| is_signed(body)).count(),
        2,
        "the Owner fact and the twin carry signatures"
    );
    assert_eq!(
        rows.iter()
            .filter(|(_, body)| is_acked(body) && is_signed(body))
            .count(),
        1,
        "one of the two Acked rows carries this install's signature"
    );

    // Restore the checkpoint over the live vault. The ack's twin is live-only, and an
    // acknowledgement moves no task authority, so the restore goes through and drops it,
    // carrying the live vault's written-here marks.
    let (copy, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &dir.path().join("restored"),
        VaultConfig::device(),
        &vault,
        200,
    )
    .expect("the restore drops the ack's twin instead of refusing");

    let rows = fact_rows(&copy, task);
    assert_eq!(
        rows.len(),
        2,
        "the twin row is gone; the Owner fact and the ack stand"
    );
    let unsigned: Vec<&(EntityId, Vec<u8>)> =
        rows.iter().filter(|(_, body)| !is_signed(body)).collect();
    assert_eq!(unsigned.len(), 1, "only the ack stores unsigned");
    assert_eq!(
        fact_kind(&unsigned[0].1),
        TaskAuthorityFactKind::Acked.as_byte(),
        "the twin that dropped was the ack's"
    );
    assert!(
        rows.iter()
            .any(|(_, body)| !is_acked(body) && is_signed(body)),
        "the signed Owner fact stands beside the ack"
    );
    let here = copy
        .task_authority_state(task)
        .expect("the task reads on the copy")
        .expect("the Owner fact still proves an owner on the copy");
    assert!(
        here.acked,
        "the carried mark still counts the ack after its twin dropped"
    );

    // With the signer loaded on the copy, the next pass twins the ack again, and one
    // more twins nothing. The copy joins as a new machine, so whether it twins the
    // Owner fact too depends on its fold admitting the old machine's carrier; the ack's
    // twin is what this pins.
    copy.install_device_keystore(Arc::clone(&keystore));
    copy.prepare_install_signing()
        .expect("the copy's install signer loads");
    assert!(
        copy.adopt_unsigned_task_facts()
            .expect("the copy's adoption pass")
            >= 1,
        "the ack's twin comes back"
    );
    assert!(
        fact_rows(&copy, task)
            .iter()
            .any(|(_, body)| is_acked(body) && is_signed(body)),
        "a signed twin of the ack stands on the copy"
    );
    assert_eq!(
        copy.adopt_unsigned_task_facts()
            .expect("a second adoption pass on the copy"),
        0,
        "the twin stands, so a second pass twins nothing"
    );
}

#[test]
fn an_adopted_owner_fact_does_not_refuse_a_restore_of_the_checkpoint_before_its_twin() {
    // One keystore held across opens, as above.
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let dir = oneiron::test_support::restore_tempdir();
    let path = dir.path().join("vault");

    // Root the vault with the signer loaded, then drop it so the same path can reopen.
    let owner = {
        let vault = Vault::open_owned(&path, VaultConfig::device()).expect("a new vault");
        vault.install_device_keystore(Arc::clone(&keystore));
        assert_eq!(
            vault
                .profile_local_open(Some(b"task-fact-adoption-keeps-owner"), true)
                .expect("the root door"),
            LocalOpenProfile::RootedAndProfiled,
        );
        vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner")
    };

    // Reopen with no signer loaded: the task door writes the Owner fact unsigned, with its
    // written-here mark.
    let vault = Vault::open(&path, VaultConfig::device()).expect("reopen without a keystore");
    let task = owner_task(&vault, owner, "owned while no signer was loaded");
    let rows = fact_rows(&vault, task);
    assert_eq!(rows.len(), 1, "the task door wrote one Owner fact");
    assert!(
        !is_signed(&rows[0].1),
        "the Owner fact written with no signer loaded stores unsigned"
    );

    // Load the signer, then take the checkpoint before any adoption pass: it holds the
    // unsigned Owner row, not its mark. The adoption pass then twins the Owner fact.
    vault.install_device_keystore(Arc::clone(&keystore));
    vault
        .prepare_install_signing()
        .expect("the install signer loads");
    vault.ensure_vault_key().expect("the vault data key");
    let key = vault.checkpoint_key().expect("the checkpoint key");
    let image = dir.path().join("image");
    vault
        .snapshot_checkpoint(&image, 100)
        .expect("a checkpoint holding the unsigned Owner fact");
    assert_eq!(
        vault
            .adopt_unsigned_task_facts()
            .expect("the adoption pass"),
        1,
        "the unsigned Owner fact gets one twin"
    );
    let rows = fact_rows(&vault, task);
    assert_eq!(rows.len(), 2, "the unsigned row and its signed twin stand");
    assert_eq!(
        rows.iter().filter(|(_, body)| is_signed(body)).count(),
        1,
        "one of the two Owner rows carries this install's signature"
    );

    // The twin states the fact the checkpoint already holds on a row the live fold counts,
    // so the restore moves no task authority: it goes through and drops the twin.
    let restore = |into: &str| {
        Vault::restore_checkpoint_keeping_authority(
            &image,
            &key,
            &dir.path().join(into),
            VaultConfig::device(),
            &vault,
            200,
        )
    };
    let (copy, _) = match restore("restored") {
        Ok(restored) => restored,
        Err(error) => panic!(
            "the adopted twin restates the checkpoint's own Owner fact, so the restore \
             goes ahead; it was refused: {error}"
        ),
    };
    let rows = fact_rows(&copy, task);
    assert_eq!(
        rows.len(),
        1,
        "the twin row is gone; the unsigned Owner fact stands"
    );
    assert!(
        !is_signed(&rows[0].1),
        "the Owner row that stands is the unsigned one the checkpoint held"
    );
    let here = copy
        .task_authority_state(task)
        .expect("the task reads on the copy")
        .expect("the carried mark still counts the unsigned Owner fact on the copy");
    assert_eq!(here.owner_ref, owner);
    drop(copy);

    // A cancel written since the checkpoint is no twin of a fact the checkpoint holds: it
    // still refuses the restore.
    mint_fact(&vault, task, TaskAuthorityFactKind::Cancelled, owner, None)
        .expect("the owner's cancel");
    let Err(error) = restore("restored-after-cancel") else {
        panic!("restoring the checkpoint would bring the cancelled task back open");
    };
    let message = error.to_string();
    assert!(
        message.contains("would roll back") && message.contains("task authority"),
        "{message}"
    );
}
