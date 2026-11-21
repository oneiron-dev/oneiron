//! Row [RESTORED-UNJOINED-ROUND2-TESTS] (parent row RESTORED-UNJOINED-STARTS-NO-WORK): the
//! round-2 timer fix arms no deadline for a ready row the queue holds on an unjoined copy.
//! - An unjoined copy arms no deadline for its held Dreamer micro row. After the join the row
//!   arms its micro deadline at its readiness instant.
//!
//! On the red head (main with the timer skip reverted) the test fails at its none assert: without
//! the skip the ready row offers its micro deadline.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test restored_unjoined_deadlines`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{DreamerConsolidationScope, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_driver::{AttemptQueueDeadlines, DeadlineSource};
use rmpv::Value;

/// The vault's first install: rooted, with its owner bound, its own unanswered serving profile,
/// the vault's root held as its owner key, and the sending agent. It never restored, so it is
/// joined.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    vault_id: [u8; 32],
}

fn sender() -> EntityId {
    EntityId::from_bytes([0x61; 16]).expect("FIXTURE: the sender's id")
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
    vault
        .put_entity(
            &sender(),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"restored send sender",
        )
        .expect("FIXTURE: the sending agent");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        vault_id,
    }
}

/// A copy restored beside a host from its checkpoint image, with its own keystore and owner
/// proof: born of a restore, and no machine of the vault yet.
struct Copy {
    vault: Vault,
    proof: AuthenticatedOwner,
}

/// The copy of `host` restored from an image taken now into an empty place under `backups`.
fn restored_copy(host: &Host, backups: &Path) -> Copy {
    let image = backups.join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("FIXTURE: the beside restore source");
    let (vault, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &backups.join("copy"),
        VaultConfig::device(),
        &origin,
        200,
    )
    .expect("FIXTURE: a copy of the image");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: an owner proof on the copy");
    let encryption = vault
        .machine_encryption_key(host.vault_id)
        .expect("FIXTURE: the copy's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, encryption)
        .expect("FIXTURE: the copy's enrolment request");
    assert!(
        vault
            .authority_fold()
            .expect("FIXTURE: the copy's fold")
            .machine(request.machine)
            .is_none(),
        "FIXTURE: the copy is no machine of the vault yet"
    );
    Copy { vault, proof }
}

/// The owner's word that no other machine is left joins `copy` (`Vault::join_restored_install`),
/// with the vault's root held on it as the owner's key.
fn owner_joins(host: &Host, copy: &Copy) {
    copy.vault
        .hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
    copy.vault
        .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered)
        .expect("the owner's word joins the copy");
}

/// One ready Dreamer micro consolidation row on `vault`, and its row id.
fn enqueue_micro(vault: &Vault) -> AttemptId {
    let outcome = DreamerRunnerStore::new(vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: Value::from(format!(
                "input:{}",
                DreamerConsolidationScope::Micro.as_str()
            )),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: vault.now_recorded_at(),
        })
        .expect("FIXTURE: the micro row enqueues");
    match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        _ => panic!("FIXTURE: the micro row enqueues"),
    }
}

/// The Dreamer deadline read arms no held row: an unjoined copy arms no deadline for its ready
/// micro row, which the round-2 timer skip proves.
#[test]
fn an_unjoined_copy_arms_no_timer_deadline_until_its_join() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let id = enqueue_micro(&copy.vault);
    let created = AttemptQueue::new(&copy.vault)
        .get(id)
        .expect("the row reads")
        .expect("the row is kept")
        .created_at;
    let mut source = AttemptQueueDeadlines::new(&copy.vault, 77);
    assert_eq!(
        source.next_deadline().expect("deadline reads"),
        None,
        "an unjoined copy arms no deadline for its held micro row"
    );

    owner_joins(&host, &copy);
    let deadline = AttemptQueueDeadlines::new(&copy.vault, 77)
        .next_deadline()
        .expect("deadline reads")
        .expect("the joined copy arms its row");
    assert_eq!(
        deadline.scope,
        DreamerConsolidationScope::Micro,
        "after the join the row arms its micro deadline"
    );
    assert_eq!(
        deadline.due_at_ms,
        created.saturating_mul(1_000),
        "the deadline is the row's readiness instant"
    );
}
