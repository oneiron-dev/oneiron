//! The erase answer counts sealed prospective and inquiry copies: a future message in a
//! flushed capture, one waiting in the outbox, a missed seal, an inquiry-only hold's copy CLAIM,
//! a widening that adds an inquiry, a lifted hold, and a capture whose hold key is gone. Each
//! test reads P through the preview and R through the confirm.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test erase_answer_counts_sealed_members`.
#![cfg(all(oneiron_test_support, unix))]

use std::sync::Arc;

use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{LegalHoldFutureMessages, LegalHoldTarget, MessageSelector};
use oneiron::federation::FederationGrantRole;
use oneiron::inquiry::{
    Inquiry, InquiryAnswer, InquiryEdge, InquiryEdgeRequest, InquiryKeep, InquiryOutcome,
    InquiryRouteRequest, InquirySendRequest, InquirySent, InquiryStatement, InquiryTransport,
    InquiryTransportError, StatementSource,
};
use oneiron::memory::Memory;
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::legal_hold::{hold_dir, sealed_record_rows, spoil_prospective_recipient};
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::verbs::{
    OwnerConfirmPreviewRequest, RecordEraseConfirmRequest, RecordEraseOutcome,
    confirm_record_erase, preview_owner_confirm,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_store::witness_message_body::WitnessMessageEnvelope;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A device keystore with install signing on `vault`, and its embedded
/// owner's proof.
fn owner_on(vault: &Vault) -> TestResult<(EntityId, AuthenticatedOwner)> {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .map_err(at("install signing"))?;
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(at("owner proof"))?;
    Ok((actor, owner))
}

/// The fixture clock's start, in recorded seconds.
const T0: u64 = 1_000_000;

/// An owned vault on a manual clock whose hold store lies outside its
/// directory, with the embedded owner's proof.
struct Fixture {
    _vault_dir: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _clock: Arc<ManualClock>,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn fixture() -> TestResult<Fixture> {
    let vault_dir = tempfile::tempdir()?;
    let store_dir = tempfile::tempdir()?;
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device().with_legal_hold_store(store_dir.path().to_path_buf());
    config.store_clock = clock.bundle();
    let vault = Vault::open_owned(vault_dir.path(), config).map_err(at("open owned"))?;
    let (actor, owner) = owner_on(&vault)?;
    Ok(Fixture {
        _vault_dir: vault_dir,
        _store_dir: store_dir,
        _clock: clock,
        vault,
        actor,
        owner,
    })
}

/// A PERSON row named `name` at a fresh id.
fn named_row(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name }))?;
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, &body)
        .map_err(at("put a fixture row"))?;
    Ok(id)
}

/// A base MESSAGE row with `content` at a fresh id.
fn message_row(vault: &Vault, content: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = WitnessMessageEnvelope {
        author: "user",
        message_type: "text",
        content,
        parts: None,
        metadata: None,
        is_visible: true,
        order: 0,
    }
    .encode_body()
    .map_err(at("a fixture message"))?;
    vault
        .put_entity(&id, ENTITY_TYPE_MESSAGE, range(1), 1, &body)
        .map_err(at("put a fixture message"))?;
    Ok(id)
}

const ERASE: &str = "vault.records.erase_confirm";

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
    assert_eq!(
        outcome.first.state,
        oneiron::memory::DeleteRequestState::Applied,
        "the erase applies: {outcome:?}"
    );
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

const SHARED: u64 = 42;
const ASKER_BYTES: [u8; 16] = [0xE1; 16];
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";
const MEMBER_HOST: &str = "https://member.example";
const QUESTION: &str = "Is owen in the office on Thursday?";
const OUT_THURSDAY: &str = "Out Thursday. Back Friday.";
const BUSY_THURSDAY: &str = "Busy Thursday.";
const STATEMENT_PREDICATE: &str = "profile.statement";

struct Side {
    vault: Vault,
    /// The owner actor `proof` authenticates.
    actor: EntityId,
    proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    vault_id: AuthorityVaultId,
    _dir: tempfile::TempDir,
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    (dir, vault)
}

fn open_company_vault() -> (tempfile::TempDir, tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault directory");
    let store = tempfile::tempdir().expect("hold store directory");
    let config = VaultConfig::device().with_legal_hold_store(store.path().to_path_buf());
    let vault = Vault::open_owned(dir.path(), config).expect("fresh company vault");
    (dir, store, vault)
}

fn root(dir: tempfile::TempDir, vault: Vault, seed: u8) -> Side {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES]).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let vault_id = vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("a rooted vault has an id");
    Side {
        vault,
        actor: owner,
        proof,
        issuer,
        vault_id,
        _dir: dir,
    }
}

fn person(vault: &Vault, id: EntityId) -> EntityId {
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person of the company",
        )
        .expect("person");
    id
}

fn open_task(vault: &Vault, actor: EntityId, title: &str) -> EntityId {
    vault
        .memory(actor, EdgeActorClass::Agent)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from(title),
            None,
            None,
            Some(3_600),
        ))
        .expect("the agent creates its TASK")
        .task_ref
        .expect("the TASK is minted")
}

#[allow(dead_code)]
struct Asking {
    member: Side,
    company: Side,
    asker: EntityId,
    task: EntityId,
    seat: EntityId,
    edge: InquiryEdge,
    slip: CapabilitySlip,
    _store_dir: tempfile::TempDir,
}

fn asking() -> Asking {
    let (member_dir, member_vault) = open_vault();
    let member = root(member_dir, member_vault, 0x11);
    let (dir, store_dir, vault) = open_company_vault();
    let asker = person(&vault, EntityId::from_bytes(ASKER_BYTES).expect("asker id"));
    let task = open_task(&vault, asker, "plan the Thursday visit");
    let company = root(dir, vault, 0x22);
    company
        .vault
        .initialize_shared_vault(
            &company.proof,
            SHARED,
            None,
            &[],
            company.vault.now_recorded_at(),
        )
        .expect("the company's shared vault");
    let seat = seat(&company);
    let edge = activate_edge(&member, &company, MEMBER);
    let slip = mint_slip(&member, &edge, company.issuer.binding_key());
    let fixture = Asking {
        member,
        company,
        asker,
        task,
        seat,
        edge,
        slip,
        _store_dir: store_dir,
    };
    fixture
        .company
        .vault
        .open_inquiry_route(
            &fixture.company.proof,
            &fixture.company.issuer,
            &fixture.route_request(fixture.seat, fixture.slip.clone()),
        )
        .expect("the company Owner opens the route");
    fixture
}

fn seat(company: &Side) -> EntityId {
    let seat = person(&company.vault, EntityId::now());
    stand_member_grant(&company.vault, seat, SHARED, FederationGrantRole::Member)
        .expect("the member's seat");
    seat
}

fn activate_edge(member: &Side, company: &Side, name: &str) -> InquiryEdge {
    let edge = member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(company.vault_id, COMPANY),
        )
        .expect("the member mints the inquiry edge");
    let reciprocal = company
        .vault
        .mint_inquiry_edge_reciprocal_grant(&company.proof, member.vault_id, name)
        .expect("the company Owner mints the reciprocal grant");
    let offer = member
        .vault
        .propose_connect_as(
            &member.proof,
            &member.issuer,
            edge.grant,
            company.vault_id,
            edge.pact_direction().expect("the edge's direction"),
            reciprocal
                .pact_direction()
                .expect("the reciprocal grant's direction"),
        )
        .expect("the member offers the Connect");
    let (_, counter) = company
        .vault
        .accept_connect_as(&company.proof, &company.issuer, reciprocal.grant, &offer)
        .expect("the company Owner accepts");
    member
        .vault
        .accept_connect_as(&member.proof, &member.issuer, edge.grant, &counter)
        .expect("the member accepts the company's half");
    edge
}

fn mint_slip(member: &Side, edge: &InquiryEdge, holder_key: [u8; 32]) -> CapabilitySlip {
    member
        .vault
        .mint_guest_slip(
            &member.proof,
            &member.issuer,
            edge.grant,
            Some(holder_key),
            member.vault.now_recorded_at() + 3_600,
            None,
        )
        .expect("the member's vault mints the company host's slip")
}

impl Asking {
    fn route_request(&self, seat: EntityId, slip: CapabilitySlip) -> InquiryRouteRequest {
        InquiryRouteRequest {
            shared_vault_id: SHARED,
            member: seat,
            member_vault_id: self.member.vault_id,
            member_host: MEMBER_HOST.to_owned(),
            slip,
        }
    }

    fn request(&self, task: EntityId, inquiry_id: Option<EntityId>) -> InquirySendRequest {
        InquirySendRequest {
            shared_vault_id: SHARED,
            member: self.seat,
            asker: self.asker,
            asker_role: "scheduling agent".to_owned(),
            task,
            purpose: "plan the Thursday visit".to_owned(),
            question: QUESTION.to_owned(),
            expires_at: self.company.vault.now_recorded_at() + 600,
            inquiry_id,
        }
    }

    fn send(&self, host: &MemberHost, task: EntityId) -> InquirySent {
        self.company
            .vault
            .send_inquiry(&self.request(task, None), host)
            .expect("the send")
    }

    fn install_keep(&self, keep: &str) {
        let policy = serde_json::json!({
            "schema_version": "1.2",
            "pack_id": "inquiry-asking-side",
            "pack_version": "1.0.0",
            "min_engine_version": "0.0.0",
            "defaults": {},
            "rules": [],
            "actor_ceilings": [],
            "inquiry": { "version": 1, "keep": keep },
        });
        self.company
            .vault
            .install_owner_policy_manifest(
                &self.company.proof,
                EntityId::now(),
                rmp_serde::to_vec_named(&policy).expect("encode"),
                self.company.vault.now_recorded_at(),
            )
            .expect("the company Owner installs the inquiry row");
    }

    fn copies(&self) -> Vec<(EntityId, oneiron::claim::ClaimBody)> {
        let mut copies: Vec<_> = self
            .company
            .vault
            .claims_for_subject(&self.seat)
            .expect("claims about the member")
            .into_iter()
            .filter_map(|id| {
                let body = self.company.vault.get_claim(&id).expect("claim read")?;
                (body.predicate == STATEMENT_PREDICATE).then_some((id, body))
            })
            .collect();
        copies.sort_by_key(|(id, _)| *id);
        copies
    }
}

struct MemberHost {
    valid_until: u64,
}

impl MemberHost {
    fn answering(company: &Side) -> Self {
        Self {
            valid_until: company.vault.now_recorded_at() + 3_600,
        }
    }
}

impl InquiryTransport for MemberHost {
    fn exchange(
        &self,
        _member_host: &str,
        _member_vault_id: &AuthorityVaultId,
        _slip_token: &str,
        inquiry: &[u8],
    ) -> Result<Vec<u8>, InquiryTransportError> {
        let inquiry = Inquiry::decode_wire(inquiry).expect("the inquiry crosses in its wire shape");
        let answer = InquiryAnswer::answered(
            &inquiry,
            vec![
                InquiryStatement::new(OUT_THURSDAY, StatementSource::MemberWord)
                    .expect("statement"),
                InquiryStatement::new(BUSY_THURSDAY, StatementSource::CompanionOfMember)
                    .expect("statement"),
            ],
            self.valid_until,
        )
        .expect("answer");
        Ok(answer.encode_wire().expect("encode"))
    }
}

/// A future message in a flushed capture counts its copy: the preview lists `legal_hold_copy`,
/// the answer keeps one, and the hold names both sealed records.
#[test]
fn a_future_message_in_a_flushed_capture_counts_its_copy() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let now = vault.now_recorded_at();
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            Some(LegalHoldFutureMessages {
                selector: MessageSelector::Vault,
                until: now + 3600,
            }),
        )
        .map_err(at("place with future messages"))?;
    let message = message_row(vault, "a future message")?;
    let memory = vault.memory(fixture.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, message);
    let preview = remaining_of(&takes);
    let entries: Vec<_> = preview
        .iter()
        .filter(|(code, _)| code == "legal_hold_copy")
        .collect();
    assert_eq!(entries.len(), 1, "P lists the sealed copy once: {takes}");
    assert_eq!(
        takes.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "P counts the one sealed copy: {takes}"
    );
    let entries: Vec<_> = outcome
        .remaining
        .iter()
        .filter(|notice| notice.code == "legal_hold_copy")
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "R lists the sealed copy once: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).map_err(at("the outcome encodes"))?;
    assert_eq!(
        receipt.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "R counts the one sealed copy: {receipt}"
    );
    assert_eq!(
        sealed_record_rows(vault, hold.hold_id).map_err(at("the sealed rows"))?,
        2,
        "the hold names the record and the message"
    );
    Ok(())
}

/// A future message waiting in the outbox counts its copy: with the hold dir replaced by a
/// plain file the flush fails and the sealed entry stays, but the answer still keeps one.
#[test]
fn a_future_message_waiting_in_the_outbox_counts_its_copy() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let now = vault.now_recorded_at();
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            Some(LegalHoldFutureMessages {
                selector: MessageSelector::Vault,
                until: now + 3600,
            }),
        )
        .map_err(at("place with future messages"))?;
    let dir = hold_dir(vault, hold.hold_id).map_err(at("the hold's directory"))?;
    std::fs::remove_dir_all(&dir).map_err(at("remove the hold dir"))?;
    std::fs::write(&dir, b"not a directory").map_err(at("a file at the hold dir"))?;
    let message = message_row(vault, "a future message")?;
    let memory = vault.memory(fixture.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, message);
    let preview = remaining_of(&takes);
    assert!(
        preview.iter().any(|(code, _)| code == "legal_hold_copy"),
        "P lists the outbox copy: {takes}"
    );
    assert_eq!(
        takes.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "P counts the outbox copy: {takes}"
    );
    assert!(
        outcome
            .remaining
            .iter()
            .any(|notice| notice.code == "legal_hold_copy"),
        "R lists the outbox copy: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).map_err(at("the outcome encodes"))?;
    assert_eq!(
        receipt.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "R counts the outbox copy: {receipt}"
    );
    Ok(())
}

/// A missed seal counts no copy: with the standing recipient spoiled the seal fails, the answer
/// keeps nothing, and the hold names only its placed record.
#[test]
fn a_missed_seal_counts_no_copy() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let now = vault.now_recorded_at();
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            Some(LegalHoldFutureMessages {
                selector: MessageSelector::Vault,
                until: now + 3600,
            }),
        )
        .map_err(at("place with future messages"))?;
    spoil_prospective_recipient(vault, hold.hold_id).map_err(at("spoil the recipient"))?;
    let message = message_row(vault, "a missed message")?;
    let memory = vault.memory(fixture.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, message);
    assert!(
        !remaining_of(&takes)
            .iter()
            .any(|(code, _)| code == "legal_hold_copy"),
        "P lists no hold copy for a missed seal: {takes}"
    );
    assert!(
        takes.get("legal_copies_kept").is_none(),
        "P counts nothing for a missed seal: {takes}"
    );
    assert!(
        !outcome
            .remaining
            .iter()
            .any(|notice| notice.code == "legal_hold_copy"),
        "R lists no hold copy for a missed seal: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).map_err(at("the outcome encodes"))?;
    assert!(
        receipt.get("legal_copies_kept").is_none(),
        "R counts nothing for a missed seal: {receipt}"
    );
    assert_eq!(
        sealed_record_rows(vault, hold.hold_id).map_err(at("the sealed rows"))?,
        1,
        "the hold names only its placed record"
    );
    Ok(())
}

/// An inquiry-only hold counts its sealed copy CLAIM: erasing the kept copy keeps one.
#[test]
fn an_inquiry_only_hold_counts_its_sealed_copy_claim() -> TestResult {
    let fixture = asking();
    fixture.install_keep("copy");
    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(
        sent.outcome,
        InquiryOutcome::Answered,
        "the copy send is answered"
    );
    assert_eq!(
        sent.inquiry.keep,
        InquiryKeep::Copy,
        "the inquiry keeps a copy"
    );
    let copies = fixture.copies();
    assert_eq!(copies.len(), 2, "the two statements land as two CLAIMs");
    let vault = &fixture.company.vault;
    vault
        .place_legal_hold(
            &fixture.company.proof,
            vec![LegalHoldTarget::Inquiry(sent.inquiry.id)],
            None,
            None,
        )
        .map_err(at("place the inquiry hold"))?;
    let memory = vault.memory(fixture.company.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.company.proof, copies[0].0);
    let preview = remaining_of(&takes);
    let entries: Vec<_> = preview
        .iter()
        .filter(|(code, _)| code == "legal_hold_copy")
        .collect();
    assert_eq!(entries.len(), 1, "P lists the sealed copy once: {takes}");
    assert_eq!(
        takes.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "P counts the one sealed copy: {takes}"
    );
    let entries: Vec<_> = outcome
        .remaining
        .iter()
        .filter(|notice| notice.code == "legal_hold_copy")
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "R lists the sealed copy once: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).map_err(at("the outcome encodes"))?;
    assert_eq!(
        receipt.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "R counts the one sealed copy: {receipt}"
    );
    Ok(())
}

/// A widening that adds an inquiry counts its copy CLAIM: erasing the kept copy keeps one.
#[test]
fn a_widening_that_adds_an_inquiry_counts_its_copy_claim() -> TestResult {
    let fixture = asking();
    fixture.install_keep("copy");
    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(
        sent.outcome,
        InquiryOutcome::Answered,
        "the copy send is answered"
    );
    assert_eq!(
        sent.inquiry.keep,
        InquiryKeep::Copy,
        "the inquiry keeps a copy"
    );
    let copies = fixture.copies();
    assert_eq!(copies.len(), 2, "the two statements land as two CLAIMs");
    let vault = &fixture.company.vault;
    let unrelated = person(vault, EntityId::now());
    let hold = vault
        .place_legal_hold(
            &fixture.company.proof,
            vec![LegalHoldTarget::Record(unrelated)],
            None,
            None,
        )
        .map_err(at("place the hold"))?;
    vault
        .widen_legal_hold(
            &fixture.company.proof,
            hold.hold_id,
            vec![LegalHoldTarget::Inquiry(sent.inquiry.id)],
        )
        .map_err(at("widen with the inquiry"))?;
    let memory = vault.memory(fixture.company.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.company.proof, copies[0].0);
    let preview = remaining_of(&takes);
    let entries: Vec<_> = preview
        .iter()
        .filter(|(code, _)| code == "legal_hold_copy")
        .collect();
    assert_eq!(entries.len(), 1, "P lists the sealed copy once: {takes}");
    assert_eq!(
        takes.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "P counts the one sealed copy: {takes}"
    );
    let entries: Vec<_> = outcome
        .remaining
        .iter()
        .filter(|notice| notice.code == "legal_hold_copy")
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "R lists the sealed copy once: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).map_err(at("the outcome encodes"))?;
    assert_eq!(
        receipt.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "R counts the one sealed copy: {receipt}"
    );
    Ok(())
}

/// A lifted hold drops its sealed records: erasing its message keeps nothing, and a record
/// outside every hold keeps nothing too.
#[test]
fn a_lifted_hold_drops_its_sealed_records() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let now = vault.now_recorded_at();
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            Some(LegalHoldFutureMessages {
                selector: MessageSelector::Vault,
                until: now + 3600,
            }),
        )
        .map_err(at("place with future messages"))?;
    let message = message_row(vault, "a future message")?;
    vault
        .lift_legal_hold(&fixture.owner, hold.hold_id)
        .map_err(at("lift the hold"))?;
    let memory = vault.memory(fixture.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, message);
    assert!(
        !remaining_of(&takes)
            .iter()
            .any(|(code, _)| code == "legal_hold_copy"),
        "P lists no hold copy after the lift: {takes}"
    );
    assert!(
        takes.get("legal_copies_kept").is_none(),
        "P counts nothing after the lift: {takes}"
    );
    assert!(
        !outcome
            .remaining
            .iter()
            .any(|notice| notice.code == "legal_hold_copy"),
        "R lists no hold copy after the lift: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).map_err(at("the outcome encodes"))?;
    assert!(
        receipt.get("legal_copies_kept").is_none(),
        "R counts nothing after the lift: {receipt}"
    );
    assert_eq!(
        sealed_record_rows(vault, hold.hold_id).map_err(at("the sealed rows"))?,
        0,
        "the lift drops the hold's sealed records"
    );
    let outside = named_row(vault, "outside every hold")?;
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, outside);
    assert!(
        !remaining_of(&takes)
            .iter()
            .any(|(code, _)| code == "legal_hold_copy"),
        "P lists no hold copy outside every hold: {takes}"
    );
    assert!(
        takes.get("legal_copies_kept").is_none(),
        "P counts nothing outside every hold: {takes}"
    );
    assert!(
        !outcome
            .remaining
            .iter()
            .any(|notice| notice.code == "legal_hold_copy"),
        "R lists no hold copy outside every hold: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).map_err(at("the outcome encodes"))?;
    assert!(
        receipt.get("legal_copies_kept").is_none(),
        "R counts nothing outside every hold: {receipt}"
    );
    Ok(())
}

/// A capture whose hold key is gone counts no copy: the flushed capture's file stays, but
/// without the hold's `hold.key` nothing opens it (a lift cut short after its key went), so
/// neither the future message nor the explicit target counts.
#[test]
fn a_capture_whose_hold_key_is_gone_counts_no_copy() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let now = vault.now_recorded_at();
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            Some(LegalHoldFutureMessages {
                selector: MessageSelector::Vault,
                until: now + 3600,
            }),
        )
        .map_err(at("place with future messages"))?;
    let message = message_row(vault, "a future message")?;
    assert_eq!(
        sealed_record_rows(vault, hold.hold_id).map_err(at("the sealed rows"))?,
        2,
        "the hold names the record and the flushed message"
    );
    let dir = hold_dir(vault, hold.hold_id).map_err(at("the hold's directory"))?;
    std::fs::remove_file(dir.join("hold.key")).map_err(at("remove the hold key"))?;
    let memory = vault.memory(fixture.actor, EdgeActorClass::Human);
    for (record, what) in [
        (message, "the flushed message"),
        (held, "the explicit target"),
    ] {
        let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, record);
        assert!(
            !remaining_of(&takes)
                .iter()
                .any(|(code, _)| code == "legal_hold_copy"),
            "P lists no copy of {what}: {takes}"
        );
        assert!(
            takes.get("legal_copies_kept").is_none(),
            "P counts no copy of {what}: {takes}"
        );
        let receipt = serde_json::to_value(&outcome).map_err(at("the outcome encodes"))?;
        assert!(
            receipt.get("legal_copies_kept").is_none(),
            "R counts no copy of {what}: {receipt}"
        );
    }
    Ok(())
}
