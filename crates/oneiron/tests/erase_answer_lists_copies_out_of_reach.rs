//! What a delete and an erase cannot reach, told in the answer (H5): T1 the
//! hard delete lists old backups; T2 policy lists them, GDPR and soft do not;
//! T3 a plain erase lists its copies in order; T4 a sealed erase says the free
//! space stays encrypted; T5 a shared record lists devices and peers; T6
//! on-device-only settings leave providers out; T7 a held record lists the
//! hold copy; T8 every bare restore carries the erasure note; T13 an erase that
//! waits on its veto window leaves the disk note out of R, and an applied one
//! keeps it. Entry asserts compare code AND full text against the ruled
//! literals. Fixtures copy H4's `rooted`/`artifact`/`two_owners`,
//! `deletion_setting_keys.rs` shares, `legal_hold_*` holds and `kit_restore_*`
//! restores.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test erase_answer_lists_copies_out_of_reach`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::access_grant::AccessGrantStatus;
use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::llm::ModelLocality;
use oneiron::memory::{BlobArtifactInput, DeleteRequestState, Memory, SafeDeleteReason};
use oneiron::note::TakeTarget;
use oneiron::recovery::checkpoint::RestoreReason;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::share::Share;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::data_key_sealed_vault::create_sealed_owner_vault;
use oneiron::verbs::{
    OwnerConfirmPreviewRequest, RecordEraseConfirmRequest, RecordEraseOutcome,
    confirm_record_erase, preview_owner_confirm,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const ERASE: &str = "vault.records.erase_confirm";
const T0: u64 = 1_800_000_000;

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

/// The owner previews the erase of `record` through the shared preview,
/// then confirms it: the preview's shown JSON (P) and the confirm's answer
/// (R).
fn preview_and_erase(
    memory: &Memory<'_>,
    owner_proof: &AuthenticatedOwner,
    record: EntityId,
) -> (Value, RecordEraseOutcome) {
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
    let takes = preview
        .takes
        .expect("a record erase preview shows what the erase takes");
    let outcome = confirm_record_erase(
        memory,
        owner_proof,
        RecordEraseConfirmRequest {
            confirm: Some(preview.confirm),
            ..input
        },
    )
    .expect("the owner confirms the erase");
    (takes, outcome)
}

/// The `remaining` array of a shown JSON as (code, text) pairs, in order.
fn remaining_of(shown: &Value) -> Vec<(String, String)> {
    shown
        .get("remaining")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            (
                entry
                    .get("code")
                    .and_then(|code| code.as_str())
                    .expect("a remaining entry's code")
                    .to_owned(),
                entry
                    .get("text")
                    .and_then(|text| text.as_str())
                    .expect("a remaining entry's text")
                    .to_owned(),
            )
        })
        .collect()
}

/// One rooted, owner-bound vault on a manual recording clock, as
/// `deletion_setting_keys.rs` opens one. The vault drops first.
struct ShareFixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    owner: EntityId,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ShareFixture {
    fn open(seed: u8) -> Self {
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES])
            .expect("independent host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            owner,
            proof,
            _dir: dir,
        }
    }
}

/// Keep the shipped policy (including credential lifetimes), adding only the owner's explicit
/// permission to create a brief share on this channel.
fn permit_brief_share(fixture: &ShareFixture) {
    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default manifest id");
    let bytes = fixture
        .vault
        .get(&id)
        .expect("read default manifest")
        .expect("the shipped manifest is stored");
    let mut manifest: Value = rmp_serde::from_slice(&bytes).expect("decode shipped manifest");
    manifest["scoped_grants"]
        .as_array_mut()
        .expect("the shipped scoped-grant table")
        .push(json!({
            "actor_ref": fixture.owner.to_hex(),
            "effector": "external:share_brief",
            "scope": oneiron::test_support::effect_preset(),
            "selectors": { "channel": "shared_brief" },
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        &fixture.vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("encode share permission"),
    )
    .expect("store the share permission beside the shipped policy");
}

/// The owner's NOTE brief about a live PERSON, shared with that person: the brief's id (hex)
/// and the share's id.
fn shared_brief(fixture: &ShareFixture) -> (String, EntityId) {
    let recipient = EntityId::now();
    fixture
        .vault
        .put_entity(
            &recipient,
            ENTITY_TYPE_PERSON,
            TimeRange { start: T0, end: T0 },
            T0,
            b"brief recipient",
        )
        .expect("live recipient PERSON");
    let brief = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .author_take(TakeTarget::Subject(recipient), "A brief for the recipient")
        .expect("stored NOTE brief")
        .id_hex;
    permit_brief_share(fixture);
    let share_id = EntityId::now();
    let share = Share {
        recipient_ref: recipient,
        brief_ref: brief.clone(),
        world_refs: BTreeSet::new(),
        facet_refs: BTreeSet::new(),
        include_unscoped: true,
        status: AccessGrantStatus::Active,
        created_at: T0,
        revoked_at: None,
        expires_at: None,
        mention: None,
    };
    fixture
        .vault
        .create_share(
            &share_id,
            &WriteActor::new(fixture.owner, EdgeActorClass::Human),
            &share,
        )
        .expect("admitted brief share");
    (brief, share_id)
}

/// A device keystore with install signing on `vault`, and its embedded
/// owner's proof.
fn hold_owner_on(vault: &Vault) -> (EntityId, AuthenticatedOwner) {
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (actor, owner)
}

/// An owned vault whose hold store lies outside its directory, with the
/// embedded owner's proof.
struct HoldFixture {
    _vault_dir: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn hold_fixture() -> HoldFixture {
    let vault_dir = tempfile::tempdir().expect("vault dir");
    let store_dir = tempfile::tempdir().expect("hold store dir");
    let config = VaultConfig::device().with_legal_hold_store(store_dir.path().to_path_buf());
    let vault = Vault::open_owned(vault_dir.path(), config).expect("open owned");
    let (actor, owner) = hold_owner_on(&vault);
    HoldFixture {
        _vault_dir: vault_dir,
        _store_dir: store_dir,
        vault,
        actor,
        owner,
    }
}

/// A PERSON row named `name` at a fresh id.
fn hold_named_row(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name })).expect("encode row");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .expect("put a fixture row");
    id
}

#[test]
fn user_hard_delete_answer_lists_old_backups() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, _owner_proof, _issuer) = rooted(&dir);
    let record = EntityId::now();
    person(&vault, record);
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .safe_delete_with_check_in(&record.to_hex(), SafeDeleteReason::UserHardDelete, None)
        .expect("the owner's hard delete applies");
    assert_eq!(receipt.state, DeleteRequestState::Applied, "{receipt:?}");
    let codes: Vec<&str> = receipt
        .remaining
        .iter()
        .map(|notice| notice.code.as_str())
        .collect();
    assert_eq!(
        codes,
        ["history_sweep", "backups_before_delete"],
        "{receipt:?}"
    );
    assert_eq!(
        receipt.remaining[0].text,
        "Removed now. Older copies in this vault's sync history are cleared by a background sweep, and the receipt shows when that is done.",
        "{receipt:?}"
    );
    assert_eq!(
        receipt.remaining[1].text,
        "Backups made before this delete still hold it, and restoring one brings it back.",
        "{receipt:?}"
    );
}

#[test]
fn policy_delete_lists_old_backups_and_gdpr_delete_does_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, _owner_proof, _issuer) = rooted(&dir);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let policy = EntityId::now();
    person(&vault, policy);
    let receipt = memory
        .safe_delete_with_check_in(&policy.to_hex(), SafeDeleteReason::PolicyDelete, None)
        .expect("the policy delete applies");
    assert_eq!(receipt.state, DeleteRequestState::Applied, "{receipt:?}");
    let policy_entry = receipt
        .remaining
        .iter()
        .find(|notice| notice.code == "backups_before_delete")
        .expect("a policy delete lists the old backups");
    assert_eq!(
        policy_entry.text,
        "Backups made before this delete still hold it, and restoring one brings it back.",
        "{receipt:?}"
    );
    let gdpr = EntityId::now();
    person(&vault, gdpr);
    let receipt = memory
        .safe_delete_with_check_in(&gdpr.to_hex(), SafeDeleteReason::GdprDelete, None)
        .expect("the GDPR delete applies");
    assert!(
        !receipt
            .remaining
            .iter()
            .any(|notice| notice.code == "backups_before_delete"),
        "a GDPR delete lists no old backups: {receipt:?}"
    );
    let soft = EntityId::now();
    person(&vault, soft);
    let receipt = memory
        .safe_delete_with_check_in(&soft.to_hex(), SafeDeleteReason::UserDelete, None)
        .expect("the soft delete applies");
    assert!(receipt.remaining.is_empty(), "{receipt:?}");
    let json = serde_json::to_value(&receipt).expect("the receipt encodes");
    assert!(
        json.get("remaining").is_none(),
        "no remaining key on a soft delete: {json}"
    );
}

#[test]
fn plain_vault_erase_lists_what_it_cannot_reach() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, owner_proof, _issuer) = rooted(&dir);
    assert!(
        !vault.vault_pages_sealed(),
        "the rooted vault is a plain vault"
    );
    let machines = vault.machine_list(&owner_proof).expect("machine list");
    assert_eq!(
        machines.len(),
        1,
        "the rooted vault names only this install, so no devices entry: {machines:?}"
    );
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let (takes, outcome) = preview_and_erase(&memory, &owner_proof, record);
    assert_eq!(
        outcome.first.state,
        DeleteRequestState::Applied,
        "{outcome:?}"
    );
    let shared_with = takes
        .get("shared_with")
        .and_then(|value| value.as_array())
        .expect("the preview names its shares");
    assert!(shared_with.is_empty(), "the record is unshared: {takes}");
    let preview = remaining_of(&takes);
    let codes: Vec<&str> = preview.iter().map(|(code, _)| code.as_str()).collect();
    assert_eq!(
        codes,
        [
            "backups_before_erase",
            "disk_not_overwritten",
            "exports_before_erase",
            "model_providers",
        ],
        "P lists the erase-level copies in order: {takes}"
    );
    assert_eq!(
        preview[0].1,
        "Backups made before this erase may still hold parts of it, and restoring one can bring those parts back.",
        "{takes}"
    );
    assert_eq!(
        preview[1].1,
        "The disk space and files it used are freed, not overwritten. Someone who copies this vault's files before that space is reused could still read it.",
        "{takes}"
    );
    assert_eq!(
        preview[2].1,
        "Exports made before this erase still hold it. This erase does not reach them.",
        "{takes}"
    );
    assert_eq!(
        preview[3].1,
        "Anything already sent to an AI model provider stays with that provider under its own retention. Oneiron cannot call it back.",
        "{takes}"
    );
    assert!(
        takes.get("legal_copies_kept").is_none(),
        "no hold count without a hold: {takes}"
    );
    let first_codes: Vec<&str> = outcome
        .first
        .remaining
        .iter()
        .map(|notice| notice.code.as_str())
        .collect();
    assert_eq!(first_codes, ["history_sweep"], "{outcome:?}");
    assert_eq!(
        outcome.first.remaining[0].text,
        "Removed now. Older copies in this vault's sync history are cleared by a background sweep, and the receipt shows when that is done.",
        "{outcome:?}"
    );
    let codes: Vec<&str> = outcome
        .remaining
        .iter()
        .map(|notice| notice.code.as_str())
        .collect();
    assert_eq!(
        codes,
        [
            "history_sweep",
            "backups_before_erase",
            "disk_not_overwritten",
            "exports_before_erase",
            "model_providers",
        ],
        "R is the receipt's sweep first, then what P showed: {outcome:?}"
    );
    assert_eq!(
        outcome.remaining[0], outcome.first.remaining[0],
        "{outcome:?}"
    );
    assert_eq!(
        outcome.remaining[1].text,
        "Backups made before this erase may still hold parts of it, and restoring one can bring those parts back.",
        "{outcome:?}"
    );
    assert_eq!(
        outcome.remaining[2].text,
        "The disk space and files it used are freed, not overwritten. Someone who copies this vault's files before that space is reused could still read it.",
        "{outcome:?}"
    );
    assert_eq!(
        outcome.remaining[3].text,
        "Exports made before this erase still hold it. This erase does not reach them.",
        "{outcome:?}"
    );
    assert_eq!(
        outcome.remaining[4].text,
        "Anything already sent to an AI model provider stays with that provider under its own retention. Oneiron cannot call it back.",
        "{outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).expect("the outcome encodes");
    assert!(
        receipt.get("legal_copies_kept").is_none(),
        "no hold count without a hold: {receipt}"
    );
}

#[test]
fn sealed_vault_erase_says_the_free_space_stays_encrypted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = Arc::new(MemoryKeystore::default());
    let vault = create_sealed_owner_vault(&dir.path().join("vault"), Arc::clone(&keystore))
        .expect("a sealed owner vault");
    assert!(vault.vault_pages_sealed(), "the fixture vault is sealed");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = proof(&vault, owner);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let (takes, outcome) = preview_and_erase(&memory, &owner_proof, record);
    let preview = remaining_of(&takes);
    let entry = preview
        .iter()
        .find(|(code, _)| code == "disk_not_overwritten")
        .expect("P lists the freed space");
    assert_eq!(
        entry.1,
        "The disk space it used is freed, not overwritten, and stays encrypted with this vault's key until it is reused.",
        "{takes}"
    );
    let entry = outcome
        .remaining
        .iter()
        .find(|notice| notice.code == "disk_not_overwritten")
        .expect("R lists the freed space");
    assert_eq!(
        entry.text,
        "The disk space it used is freed, not overwritten, and stays encrypted with this vault's key until it is reused.",
        "{outcome:?}"
    );
}

#[test]
fn shared_record_erase_lists_devices_and_peers() {
    let fixture = ShareFixture::open(0x33);
    let (brief, _share_id) = shared_brief(&fixture);
    let record = EntityId::from_hex(&brief).expect("brief id");
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.proof, record);
    let shared_with = takes
        .get("shared_with")
        .and_then(|value| value.as_array())
        .expect("the preview names its shares");
    assert!(
        !shared_with.is_empty(),
        "the erased record is under a live share: {takes}"
    );
    let preview = remaining_of(&takes);
    let entry = preview
        .iter()
        .find(|(code, _)| code == "devices_and_peers")
        .expect("P lists devices and peers");
    assert_eq!(
        entry.1,
        "Your other devices remove it when they next sync. A device that stays offline keeps it until then. People it was shared with are asked to delete their copy, and may not.",
        "{takes}"
    );
    let entry = outcome
        .remaining
        .iter()
        .find(|notice| notice.code == "devices_and_peers")
        .expect("R lists devices and peers");
    assert_eq!(
        entry.text,
        "Your other devices remove it when they next sync. A device that stays offline keeps it until then. People it was shared with are asked to delete their copy, and may not.",
        "{outcome:?}"
    );
}

#[test]
fn on_device_only_settings_leave_out_model_providers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, owner_proof, _issuer) = rooted(&dir);
    let mut table = vault.purpose_default_table().expect("effective table");
    for row in table.purposes.values_mut() {
        row.locality = ModelLocality::OnDevice;
    }
    for row in table.voice.values_mut() {
        row.locality = ModelLocality::OnDevice;
    }
    table.extraction_max_locality = ModelLocality::OnDevice;
    table.self_compaction.locality = ModelLocality::OnDevice;
    vault
        .set_purpose_default_table(&table)
        .expect("the on-device-only table validates");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let (takes, outcome) = preview_and_erase(&memory, &owner_proof, record);
    assert!(
        !remaining_of(&takes)
            .iter()
            .any(|(code, _)| code == "model_providers"),
        "on-device-only settings list no provider copy in P: {takes}"
    );
    assert!(
        !outcome
            .remaining
            .iter()
            .any(|notice| notice.code == "model_providers"),
        "on-device-only settings list no provider copy in R: {outcome:?}"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner, owner_proof, _issuer) = rooted(&dir);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let (takes, outcome) = preview_and_erase(&memory, &owner_proof, record);
    let preview = remaining_of(&takes);
    let entry = preview
        .iter()
        .find(|(code, _)| code == "model_providers")
        .expect("shipped defaults list the provider copy in P");
    assert_eq!(
        entry.1,
        "Anything already sent to an AI model provider stays with that provider under its own retention. Oneiron cannot call it back.",
        "{takes}"
    );
    let entry = outcome
        .remaining
        .iter()
        .find(|notice| notice.code == "model_providers")
        .expect("shipped defaults list the provider copy in R");
    assert_eq!(
        entry.text,
        "Anything already sent to an AI model provider stays with that provider under its own retention. Oneiron cannot call it back.",
        "{outcome:?}"
    );
}

#[test]
fn held_record_erase_lists_the_hold_copy() {
    let fixture = hold_fixture();
    let id = hold_named_row(&fixture.vault, "held record");
    fixture
        .vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(id)],
            None,
            None,
        )
        .expect("the owner's legal hold");
    let memory = fixture.vault.memory(fixture.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, id);
    let preview = remaining_of(&takes);
    let entry = preview
        .iter()
        .find(|(code, _)| code == "legal_hold_copy")
        .expect("P lists the hold copy");
    assert_eq!(
        entry.1,
        "A legal hold keeps a sealed copy of this record outside your vault until the hold is lifted. This erase does not remove that copy.",
        "{takes}"
    );
    assert_eq!(
        takes.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "P counts the one hold: {takes}"
    );
    let entry = outcome
        .remaining
        .iter()
        .find(|notice| notice.code == "legal_hold_copy")
        .expect("R lists the hold copy");
    assert_eq!(
        entry.text,
        "A legal hold keeps a sealed copy of this record outside your vault until the hold is lifted. This erase does not remove that copy.",
        "{outcome:?}"
    );
    assert!(
        !outcome
            .first
            .remaining
            .iter()
            .any(|notice| notice.code == "legal_hold_copy"),
        "the hold copy is erase-level, not the receipt's: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).expect("the outcome encodes");
    assert_eq!(
        receipt.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "R counts the one hold: {receipt}"
    );
    let fixture = hold_fixture();
    let other = hold_named_row(&fixture.vault, "other held");
    let target = hold_named_row(&fixture.vault, "target");
    fixture
        .vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(other)],
            None,
            None,
        )
        .expect("a hold on another record");
    let memory = fixture.vault.memory(fixture.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, target);
    assert!(
        !remaining_of(&takes)
            .iter()
            .any(|(code, _)| code == "legal_hold_copy"),
        "a hold elsewhere lists no hold copy in P: {takes}"
    );
    assert!(
        takes.get("legal_copies_kept").is_none(),
        "a hold elsewhere counts nothing in P: {takes}"
    );
    assert!(
        !outcome
            .remaining
            .iter()
            .any(|notice| notice.code == "legal_hold_copy"),
        "a hold elsewhere lists no hold copy in R: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).expect("the outcome encodes");
    assert!(
        receipt.get("legal_copies_kept").is_none(),
        "a hold elsewhere counts nothing in R: {receipt}"
    );
}

#[test]
fn every_bare_restore_carries_the_erasure_note() {
    let dir = oneiron::test_support::restore_tempdir();
    let vault =
        Vault::open(dir.path().join("source"), VaultConfig::device()).expect("the source vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    vault.ensure_vault_key().expect("the vault's data key");
    let record = EntityId::now();
    person(&vault, record);
    let key = vault.checkpoint_key().expect("the checkpoint key");
    let image = dir.path().join("snapshot.image");
    vault
        .snapshot_checkpoint(&image, 100)
        .expect("the checkpoint");
    let (restored, report) = Vault::restore_checkpoint(
        &image,
        &key,
        &dir.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        200,
    )
    .expect("the bare copy of the vault");
    assert!(
        restored
            .get(&record)
            .expect("read the restored record")
            .is_some(),
        "the payload opened: the restored vault reads the snapshotted record"
    );
    assert_eq!(
        report.erasure_note.as_deref(),
        Some(
            "Records erased after this backup was taken may be back. This restore had no live vault to check them against."
        ),
        "every bare restore carries the erasure note"
    );
}

const SHARED: u64 = 43;

/// A rooted vault on a manual clock with two live Owners who accepted, so an
/// owner erase waits on its veto window (H4's `two_owners`): the tempdir, the
/// vault, the clock, the embedded owner and their proof.
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
    let second_proof = proof(&vault, second);
    let invitation = vault
        .shared_invitations(&second_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&second_proof, SHARED, &invitation.id)
        .expect("the second Owner accepts");
    (dir, vault, clock, owner, owner_proof)
}

/// The (code, text) pairs of an answer's `remaining` list, in order.
fn notices_of(outcome: &RecordEraseOutcome) -> Vec<(String, String)> {
    outcome
        .remaining
        .iter()
        .map(|notice| (notice.code.clone(), notice.text.clone()))
        .collect()
}

#[test]
fn a_pending_erase_answer_leaves_out_the_freed_disk() {
    let (_dir, vault, _clock, owner, owner_proof) = two_owners();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let record = artifact(&memory);
    let (takes, outcome) = preview_and_erase(&memory, &owner_proof, record);
    assert!(
        outcome.first_act.is_some() && outcome.first.state != DeleteRequestState::Applied,
        "two Owners: the erase waits on its veto window: {outcome:?}"
    );
    let preview = remaining_of(&takes);
    assert!(
        preview
            .iter()
            .any(|(code, _)| code == "disk_not_overwritten"),
        "P says what the erase will do, the freed disk included: {takes}"
    );
    let receipt_list: Vec<(String, String)> = outcome
        .first
        .remaining
        .iter()
        .map(|notice| (notice.code.clone(), notice.text.clone()))
        .collect();
    let expected: Vec<(String, String)> = receipt_list
        .into_iter()
        .chain(
            preview
                .iter()
                .filter(|(code, _)| code != "disk_not_overwritten")
                .cloned(),
        )
        .collect();
    assert_eq!(
        notices_of(&outcome),
        expected,
        "a pending R is the receipt's list, then P's entries without the disk note: {outcome:?}"
    );

    // The applied twin: a one-owner vault's erase applies at once, and its R
    // keeps the disk note.
    let applied_dir = tempfile::tempdir().expect("tempdir");
    let (applied_vault, applied_owner, applied_proof, _issuer) = rooted(&applied_dir);
    let applied_memory = applied_vault.memory(applied_owner, EdgeActorClass::Human);
    let applied_record = artifact(&applied_memory);
    let (_takes, applied) = preview_and_erase(&applied_memory, &applied_proof, applied_record);
    assert_eq!(
        applied.first.state,
        DeleteRequestState::Applied,
        "{applied:?}"
    );
    assert!(
        notices_of(&applied).contains(&(
            "disk_not_overwritten".to_owned(),
            "The disk space and files it used are freed, not overwritten. Someone who copies this vault's files before that space is reused could still read it.".to_owned(),
        )),
        "an applied R keeps the disk note: {applied:?}"
    );
}
