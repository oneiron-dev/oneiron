//! The delete answer lists what remains, and the owner learns "restricted"
//! (FIX HARD-DELETE-ANSWER-SILENT-ON-OWED-SWEEP and
//! FIX HARD-DELETE-RESTRICTED-ANSWERS-NOT-FOUND, Engine ruling 27 Nov).
//!
//! - `owner_hard_delete_answer_lists_the_history_sweep`: the owner's hard
//!   delete applies and its receipt lists `history_sweep` and
//!   `backups_before_delete`, in the ruling's words.
//! - `soft_delete_answer_lists_nothing_remaining`: a soft delete's receipt
//!   lists nothing, and its JSON carries no `remaining` key.
//! - `owner_delete_of_a_restricted_record_answers_restricted`: the owner
//!   deletes a record they chose to restrict and learns `restricted`, in
//!   the ruling's words; the record is still there.
//! - `agent_delete_of_a_restricted_record_still_answers_not_found`: the
//!   same restricted record deleted through the role arm (a Member's own
//!   NOTE, the same `safe_delete_by_role` funnel agents use) still answers
//!   not-found, unchanged.
//! - `owner_erase_of_a_restricted_record_answers_restricted`: the owner's
//!   erase of a restricted record answers `restricted`.
//! - `owner_erase_receipt_lists_the_history_sweep`: an owner erase that
//!   applies at once lists `history_sweep` on the first receipt and before
//!   the erase-level entries on the outcome.
//!
//! Public doors beside the `oneiron::test_doors` cooperative restriction;
//! neutral fixtures; vaults in tempdirs.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test delete_answer_lists_what_remains`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, MachineRole, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{
    BlobArtifactInput, DeleteReceipt, DeleteRequestState, MEMORY_CODE_NOT_FOUND, Memory,
    MemoryResult, SafeDeleteReason,
};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::campaign_member_index::restrict_record;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::verbs::{
    OwnerConfirmPreviewRequest, RecordEraseConfirmRequest, RecordEraseOutcome,
    confirm_record_erase, preview_owner_confirm,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

const SHARED: u64 = 43;
const ERASE: &str = "vault.records.erase_confirm";

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A rooted vault as a host starts one: the owner bound, the root signed,
/// this install profiled to carry the owner's Grant acts. Its owner, the
/// owner's proof and the host issuer.
fn rooted(
    dir: &tempfile::TempDir,
) -> (
    Vault,
    EntityId,
    AuthenticatedOwner,
    oneiron::authority::HostSlipIssuer,
) {
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let owner_proof = proof(&vault, owner);
    (vault, owner, owner_proof, issuer)
}

/// An artifact the owner `memory` writes: the record the erase cases erase.
fn artifact(memory: &Memory<'_>) -> EntityId {
    let put = memory
        .put_blob_artifact(&BlobArtifactInput {
            id: None,
            name: "erase fixture".to_owned(),
            media_type: "text/plain".to_owned(),
            occurred_at: 1,
            learned_at: None,
        })
        .expect("the owner writes an artifact");
    EntityId::from_hex(&put.id_hex).expect("an artifact id")
}

/// The owner previews the erase of `record` through the shared preview
/// (L8-49), then confirms it on `owner_proof` with that preview's confirm.
fn erase(
    memory: &Memory<'_>,
    owner_proof: &AuthenticatedOwner,
    record: EntityId,
) -> RecordEraseOutcome {
    try_erase(memory, owner_proof, record).expect("the owner confirms the erase")
}

/// As [`erase`]: the confirm's answer.
fn try_erase(
    memory: &Memory<'_>,
    owner_proof: &AuthenticatedOwner,
    record: EntityId,
) -> MemoryResult<RecordEraseOutcome> {
    let input = RecordEraseConfirmRequest {
        record,
        confirm: None,
        also_same_bytes: false,
        check_in_ref: None,
    };
    let preview = preview_owner_confirm(
        memory,
        owner_proof,
        OwnerConfirmPreviewRequest {
            verb: ERASE.to_owned(),
            input: serde_json::to_value(&input).expect("the erase input encodes"),
        },
    )
    .expect("the owner previews the erase");
    confirm_record_erase(
        memory,
        owner_proof,
        RecordEraseConfirmRequest {
            confirm: Some(preview.confirm),
            ..input
        },
    )
}

/// `member` accepts its founding invitation to the shared vault at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A rooted shared vault: its owner, a Member who accepted, and a subject
/// PERSON the NOTEs are about.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    member: EntityId,
    subject: EntityId,
}

impl Org {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        // A delete signs its receipt with this install's key.
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [member, subject] = std::array::from_fn(|_| EntityId::now());
        for id in [member, subject] {
            person(&vault, id);
        }
        let founding = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[founding(owner, Role::Owner), founding(member, Role::Member)],
                1,
            )
            .expect("a shared vault with a Member");
        accept(&vault, member, Role::Member);
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            member,
            subject,
        }
    }

    /// A NOTE the Member writes about the subject, by its full hex ref.
    fn member_note(&self) -> String {
        bind_host_actor(&self.vault, &self.issuer, self.member, "human")
            .expect("the host key bound to the Member for its write");
        let note = self
            .vault
            .memory(self.member, EdgeActorClass::Human)
            .author_take(
                TakeTarget::Subject(self.subject),
                "a take about the subject",
            )
            .expect("the Member writes a NOTE")
            .id_hex;
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        note
    }

    /// The live `human` credential this host mints `person`, verified as a
    /// transport verifies the slip a request presents.
    fn credential(&self, person: EntityId) -> VerifiedSlip {
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip");
        let issued_at = self.vault.capability_slip_now().expect("slip clock");
        let mut claims = root.claims;
        claims.slip_id = next_slip_id();
        claims.holder_ref = person.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + 3_600;
        claims.ttl_secs = 3_600;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the person's credential");
        let challenge = b"delete-answer-lists-what-remains";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        self.vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("a verified credential")
    }

    /// The Member's `vault.delete` of its own NOTE, over its own
    /// credential: through the role arm, as an agent's delete goes.
    fn delete_as_member(
        &self,
        note: &str,
        reason: SafeDeleteReason,
    ) -> MemoryResult<DeleteReceipt> {
        let credential = self.credential(self.member);
        self.vault
            .memory(self.member, EdgeActorClass::Human)
            .with_transport_invocation()
            .with_read_proof(&credential)
            .safe_delete_with_check_in(note, reason, None)
    }
}

#[test]
fn owner_hard_delete_answer_lists_the_history_sweep() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, _owner_proof, _issuer) = rooted(&dir);
    let record = EntityId::now();
    person(&vault, record);
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .safe_delete_with_check_in(&record.to_hex(), SafeDeleteReason::UserHardDelete, None)
        .expect("the owner's hard delete applies");
    assert!(receipt.existed, "{receipt:?}");
    assert_eq!(receipt.state, DeleteRequestState::Applied, "{receipt:?}");
    assert_eq!(receipt.remaining.len(), 2, "{receipt:?}");
    assert_eq!(receipt.remaining[0].code, "history_sweep", "{receipt:?}");
    assert_eq!(
        receipt.remaining[0].text,
        "Removed now. Older copies in this vault's sync history are cleared by a background sweep, and the receipt shows when that is done.",
        "{receipt:?}"
    );
    assert_eq!(
        receipt.remaining[1].code, "backups_before_delete",
        "{receipt:?}"
    );
    assert_eq!(
        receipt.remaining[1].text,
        "Backups made before this delete still hold it, and restoring one brings it back.",
        "{receipt:?}"
    );
}

#[test]
fn soft_delete_answer_lists_nothing_remaining() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, _owner_proof, _issuer) = rooted(&dir);
    let record = EntityId::now();
    person(&vault, record);
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .safe_delete_with_check_in(&record.to_hex(), SafeDeleteReason::UserDelete, None)
        .expect("the owner's soft delete applies");
    assert!(receipt.remaining.is_empty(), "{receipt:?}");
    let json = serde_json::to_value(&receipt).expect("the receipt encodes");
    assert!(
        json.get("remaining").is_none(),
        "no remaining key on a soft delete: {json}"
    );
}

#[test]
fn owner_delete_of_a_restricted_record_answers_restricted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, _owner_proof, _issuer) = rooted(&dir);
    let record = EntityId::now();
    person(&vault, record);
    restrict_record(&vault, record).expect("FIXTURE: restrict the record");
    let error = vault
        .memory(owner, EdgeActorClass::Human)
        .safe_delete_with_check_in(&record.to_hex(), SafeDeleteReason::UserHardDelete, None)
        .expect_err("the owner's delete of a restricted record is refused");
    assert_eq!(error.code, "restricted", "{error:?}");
    assert_eq!(
        error.message,
        "This record is restricted: you chose to keep it stored and unused in answer to a deletion request. Lift the restriction to delete it.",
        "{error:?}"
    );
    assert!(
        vault.get(&record).expect("read the record").is_some(),
        "the restricted record is still there"
    );
}

#[test]
fn agent_delete_of_a_restricted_record_still_answers_not_found() {
    let org = Org::new();
    let note = org.member_note();
    restrict_record(&org.vault, EntityId::from_hex(&note).expect("note id"))
        .expect("FIXTURE: restrict the note");
    let error = org
        .delete_as_member(&note, SafeDeleteReason::UserDelete)
        .expect_err("a restricted record keeps its absence on the role path");
    assert_eq!(error.code, MEMORY_CODE_NOT_FOUND, "{error:?}");
    assert!(
        !error.message.contains("restricted"),
        "no restricted words on the role path: {error:?}"
    );
}

#[test]
fn owner_erase_of_a_restricted_record_answers_restricted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, owner_proof, _issuer) = rooted(&dir);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    restrict_record(&vault, record).expect("FIXTURE: restrict the record");
    let error = try_erase(&memory, &owner_proof, record)
        .expect_err("the owner's erase of a restricted record is refused");
    assert_eq!(error.code, "restricted", "{error:?}");
    assert_eq!(
        error.message,
        "This record is restricted: you chose to keep it stored and unused in answer to a deletion request. Lift the restriction to delete it.",
        "{error:?}"
    );
}

#[test]
fn owner_erase_receipt_lists_the_history_sweep() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, owner_proof, _issuer) = rooted(&dir);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let outcome = erase(&memory, &owner_proof, record);
    assert_eq!(
        outcome.first.state,
        DeleteRequestState::Applied,
        "{outcome:?}"
    );
    assert_eq!(outcome.first.remaining.len(), 1, "{outcome:?}");
    for (which, remaining) in [
        ("outcome", &outcome.remaining),
        ("first", &outcome.first.remaining),
    ] {
        assert_eq!(remaining[0].code, "history_sweep", "{which}: {outcome:?}");
        assert_eq!(
            remaining[0].text,
            "Removed now. Older copies in this vault's sync history are cleared by a background sweep, and the receipt shows when that is done.",
            "{which}: {outcome:?}"
        );
    }
    let erase_entries: Vec<_> = outcome.remaining[1..]
        .iter()
        .map(|entry| (entry.code.as_str(), entry.text.as_str()))
        .collect();
    assert_eq!(
        erase_entries,
        [
            (
                "backups_before_erase",
                "Backups made before this erase may still hold parts of it, and restoring one can bring those parts back.",
            ),
            (
                "disk_not_overwritten",
                "The disk space and files it used are freed, not overwritten. Someone who copies this vault's files before that space is reused could still read it.",
            ),
            (
                "exports_before_erase",
                "Exports made before this erase still hold it. This erase does not reach them.",
            ),
            (
                "model_providers",
                "Anything already sent to an AI model provider stays with that provider under its own retention. Oneiron cannot call it back.",
            ),
        ],
        "{outcome:?}"
    );
}

const T0: u64 = 1_800_000_000;

/// A rooted vault on a manual clock with two live Owners who accepted, so
/// an owner erase waits on its veto window: the tempdir, the vault, the
/// clock, the embedded owner and their proof.
fn two_owners() -> (
    tempfile::TempDir,
    Vault,
    Arc<ManualClock>,
    EntityId,
    AuthenticatedOwner,
) {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let owner_proof = proof(&vault, owner);
    let second = EntityId::now();
    person(&vault, second);
    let member = |member_ref| InitialSharedMember {
        member_ref,
        role: Some(Role::Owner),
    };
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[member(owner), member(second)],
            1,
        )
        .expect("a shared vault with two Owners");
    accept(&vault, second, Role::Owner);
    (dir, vault, clock, owner, owner_proof)
}

#[test]
fn a_foreign_proof_delete_of_a_restricted_record_answers_not_found() {
    let dir_a = tempfile::tempdir().expect("tempdir");
    let (vault_a, _owner_a, _proof_a, _issuer_a) = rooted(&dir_a);
    let dir_b = tempfile::tempdir().expect("tempdir");
    let (_vault_b, _owner_b, proof_b, _issuer_b) = rooted(&dir_b);
    let record = EntityId::now();
    person(&vault_a, record);
    restrict_record(&vault_a, record).expect("FIXTURE: restrict the record");
    let error = vault_a
        .delete_entity_with_reason_as_owner(
            &proof_b,
            &record,
            oneiron::deletion::DeleteReason::UserHardDelete,
        )
        .expect_err("a foreign proof's delete of a restricted record is refused");
    assert!(
        matches!(error, oneiron::Error::EntityNotFound),
        "a foreign proof keeps absence, not restricted: {error:?}"
    );
}

#[test]
fn a_held_erase_of_a_record_restricted_in_its_window_answers_restricted() {
    let (_dir, vault, clock, owner, owner_proof) = two_owners();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let outcome = erase(&memory, &owner_proof, record);
    let act_id = outcome
        .first_act
        .clone()
        .unwrap_or_else(|| panic!("two Owners: the erase waits on its act: {outcome:?}"));
    restrict_record(&vault, record).expect("FIXTURE: restrict the record in its window");
    let act = vault
        .pending_authority_act(&act_id)
        .expect("read the act")
        .expect("the act is stored");
    clock.set(act.deadline + 1);
    let error = memory
        .execute_completed_entity_erase(&owner_proof, &act_id)
        .expect_err("a held erase of a restricted record is refused");
    assert_eq!(error.code, "restricted", "{error:?}");
}

#[test]
fn a_served_held_erase_lists_the_history_sweep() {
    let (_dir, vault, clock, owner, owner_proof) = two_owners();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let outcome = erase(&memory, &owner_proof, record);
    let act_id = outcome
        .first_act
        .clone()
        .unwrap_or_else(|| panic!("two Owners: the erase waits on its act: {outcome:?}"));
    let act = vault
        .pending_authority_act(&act_id)
        .expect("read the act")
        .expect("the act is stored");
    clock.set(act.deadline + 1);
    let executed = oneiron::verbs::execute_shared_act(
        &vault,
        &owner_proof,
        None,
        oneiron::verbs::SharedActExecuteRequest {
            act_id,
            owner_key_revokes: Vec::new(),
        },
    )
    .expect("the served held erase runs");
    let sweep = executed
        .remaining
        .iter()
        .find(|entry| entry.code == "history_sweep")
        .unwrap_or_else(|| panic!("the served erase lists the history sweep: {executed:?}"));
    assert_eq!(
        sweep.text,
        "Removed now. Older copies in this vault's sync history are cleared by a background sweep, and the receipt shows when that is done.",
        "{executed:?}"
    );
}
