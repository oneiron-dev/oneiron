//! Row RESTORED-UNJOINED-STARTS-NO-WORK (Setting DESIGN pass 15e "Joined", RULING
//! SETTING-UNTANGLE = A; RULING RESTORED-UNJOINED-OWNER-DIRECT-WORK = A): a copy restored into
//! an empty place on a vault a root roots, which has not joined, starts no work of its own.
//! - Queued work waits: no claim leases a row of a held kind (an agent turn, a send, any kind
//!   but the local and inbound work the queue keeps), and the row stays ready as it was. A kept
//!   kind (an ICS feed poll) is claimed as before. The owner's join wakes the queue's observers,
//!   and the next claim takes the held row, with no restart.
//! - No send leaves it: every send meets the refusal of the outbound chokepoint
//!   (`outbound_chokepoint::execute_outbound_effect`) before its writer, with the machine doors'
//!   words for such a copy, and no transport is called. Once the owner's word joins the copy,
//!   the same send goes through as on the vault's first install.
//! - A vault no restore made claims and sends as before.
//!
//! On the base (main 54f7ce11c55b) the unjoined copy claims its queued work and sends as the
//! source does: the claim tests fail at their "nothing claimed" asserts, the first two send
//! tests at their refusal asserts.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_unjoined_work`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, EnqueueAttempt, EnqueueOutcome,
};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::calendar::ICS_POLL_ATTEMPT_KIND;
use oneiron::consent::AuthenticatedOwner;
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

/// The refusal's words that name the copy's state (`machine_answers::RESTORED_NOT_JOINED`).
const NOT_JOINED: &str = "has not joined the vault";
/// The counterparty every send addresses.
const COUNTERPARTY: &str = "owen@example.com";
const EMAIL: &str = "email";
/// The sending agent, written on the host before the image is taken.
const SENDER_SEED: u8 = 0x61;

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
    EntityId::from_bytes([SENDER_SEED; 16]).expect("FIXTURE: the sender's id")
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
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
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
        .hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    copy.vault
        .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered)
        .expect("the owner's word joins the copy");
}

/// A transport that counts the sends that reach it.
#[derive(Default)]
struct CountingSink {
    calls: usize,
}

impl OutboundExecutionSink for CountingSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        OutboundExecutionOutcome::delivered_to_channel("provider:message:one")
    }
}

/// What one direct-pipeline send by the agent answered: `Err` with the dispatch error's words,
/// or `Ok` with its gate outcome; and how many sends reached the transport.
fn send(vault: &Vault, intent_ref: &str) -> (Result<String, String>, usize) {
    let mut sink = CountingSink::default();
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(sender().to_hex(), "send", EMAIL, COUNTERPARTY)
            .content_ref("content:restored"),
        OutboundIntentTrigger::agent_immediate("session:restored"),
    );
    let request = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(sender()),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(COUNTERPARTY);
    let answer = vault
        .dispatch_outbound_intent(request, &mut sink)
        .map(|result| format!("{:?}", result.gate_reason_codes))
        .map_err(|error| error.to_string());
    (answer, sink.calls)
}

fn refused_not_joined(answer: &Result<String, String>) -> bool {
    answer
        .as_ref()
        .err()
        .is_some_and(|words| words.contains(NOT_JOINED))
}

#[test]
fn an_unjoined_copy_refuses_a_send_before_any_transport() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());

    let (answer, calls) = send(&copy.vault, "unjoined-1");
    assert!(
        refused_not_joined(&answer),
        "the unjoined copy's send refuses naming its state, got {answer:?}"
    );
    assert_eq!(calls, 0, "no send reaches the transport");
    let (again, calls) = send(&copy.vault, "unjoined-1");
    assert!(
        refused_not_joined(&again),
        "a retry of the same send refuses the same way, got {again:?}"
    );
    assert_eq!(calls, 0, "the retry reaches no transport either");
}

#[test]
fn the_owners_join_lets_the_copys_sends_through_with_no_restart() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let (before, calls) = send(&copy.vault, "before-join");
    assert!(
        refused_not_joined(&before),
        "before its join the copy refuses, got {before:?}"
    );
    assert_eq!(calls, 0);

    owner_joins(&host, &copy);
    let (after, copy_calls) = send(&copy.vault, "after-join");
    assert!(
        !refused_not_joined(&after),
        "the joined copy's send is no longer refused, got {after:?}"
    );
    let (on_host, host_calls) = send(&host.vault, "after-join");
    assert_eq!(
        after.is_ok(),
        on_host.is_ok(),
        "the joined copy answers as the first install does: {after:?} vs {on_host:?}"
    );
    assert_eq!(
        copy_calls, host_calls,
        "the joined copy reaches the transport as the first install does"
    );
}

#[test]
fn a_vault_no_restore_made_sends_as_before() {
    let host = rooted_host();
    let (answer, _) = send(&host.vault, "never-restored");
    assert!(
        !refused_not_joined(&answer),
        "a vault no restore made is never refused as a restored copy, got {answer:?}"
    );
}

/// A kind the queue holds on a copy that has not joined: any kind but the kept local and inbound
/// work, as an agent turn's or a send's.
const HELD_KIND: &str = "restored_unjoined.agent_turn";
const WORKER: &str = "restored-unjoined-worker";

/// A fresh ready row of `kind` on `vault`.
fn enqueue(vault: &Vault, kind: &str) -> AttemptId {
    let EnqueueOutcome::Enqueued(queued) = AttemptQueue::new(vault)
        .enqueue(EnqueueAttempt {
            kind: kind.to_owned(),
            payload: b"queued work".to_vec(),
            dedupe_key: None,
            run_id: None,
            now: vault.now_recorded_at(),
        })
        .expect("FIXTURE: enqueue")
    else {
        panic!("FIXTURE: a fresh row is enqueued");
    };
    queued.id
}

fn claim(vault: &Vault, kind: Option<&str>) -> ClaimOutcome {
    let queue = AttemptQueue::new(vault);
    let input = ClaimAttempt {
        lease_owner: WORKER.to_owned(),
        now: vault.now_recorded_at(),
    };
    match kind {
        Some(kind) => queue.claim_kind(kind, input),
        None => queue.claim(input),
    }
    .expect("the claim answers")
}

fn claimed_id(outcome: &ClaimOutcome) -> Option<AttemptId> {
    match outcome {
        ClaimOutcome::Claimed(record) => Some(record.id),
        ClaimOutcome::Empty => None,
        other => panic!("an unknown claim outcome: {other:?}"),
    }
}

fn row(vault: &Vault, id: AttemptId) -> String {
    let record = AttemptQueue::new(vault)
        .get(id)
        .expect("the row reads")
        .expect("the row is kept");
    format!("{record:?}")
}

#[test]
fn an_unjoined_copy_leaves_its_queued_work_queued() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let held = enqueue(&copy.vault, HELD_KIND);
    let before = row(&copy.vault, held);

    let by_kind = claim(&copy.vault, Some(HELD_KIND));
    assert_eq!(
        claimed_id(&by_kind),
        None,
        "a claim of the held kind takes nothing on the unjoined copy"
    );
    let any = claim(&copy.vault, None);
    assert_eq!(
        claimed_id(&any),
        None,
        "a claim of any kind passes the held row over"
    );
    assert_eq!(
        row(&copy.vault, held),
        before,
        "the held row stays ready as it was: no lease, no pause"
    );

    let kept = enqueue(&copy.vault, ICS_POLL_ATTEMPT_KIND);
    assert_eq!(
        claimed_id(&claim(&copy.vault, None)),
        Some(kept),
        "an inbound feed poll is kept: the unjoined copy still claims it"
    );
}

#[test]
fn the_owners_join_starts_the_held_work_with_no_restart() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let held = enqueue(&copy.vault, HELD_KIND);
    assert_eq!(
        claimed_id(&claim(&copy.vault, Some(HELD_KIND))),
        None,
        "before its join the copy holds the row"
    );

    let mut woken = AttemptQueue::new(&copy.vault).subscribe();
    owner_joins(&host, &copy);
    assert!(
        woken.try_recv().is_ok(),
        "the join wakes the queue's observers"
    );
    assert_eq!(
        claimed_id(&claim(&copy.vault, Some(HELD_KIND))),
        Some(held),
        "the joined copy's next claim takes the held row"
    );
}

#[test]
fn a_vault_no_restore_made_claims_as_before() {
    let host = rooted_host();
    let queued = enqueue(&host.vault, HELD_KIND);
    assert_eq!(
        claimed_id(&claim(&host.vault, Some(HELD_KIND))),
        Some(queued),
        "a vault no restore made claims its queued work"
    );
}
