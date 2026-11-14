//! Engine ruling INQUIRE-RESEND = A (FIX INQUIRY-RESEND-MEMBER-BINDING,
//! INQUIRY-RESEND-CHANGED-FIELDS-UNAVAILABLE and INQUIRY-WIRE-SIZE-BOUNDS
//! part 2): a re-send of an inquiry id is bound to the inquiry's first send
//! from the company vault, as its first `inquiry` receipt records it.
//! - an id the vault never sent is refused;
//! - another member, asker or task is refused, and the refusal names the
//!   field; the first member's held answer stays;
//! - another question or purpose is refused, and the refusal names the
//!   field; the same send goes out as the stored inquiry, with the first
//!   send's expiry and keep, whatever the request's expiry and the vault's
//!   `inquiry_keep` say now;
//! - once the first send's expiry has come, a re-send is refused; and the
//!   byte caps refuse an oversized role, purpose or question, while the
//!   largest valid inquiry still fits the member route's body limit.
//!
//! Every refusal sends nothing and writes no receipt. The member host is a
//! double in this process, as in `tests/inquiry_asking_side.rs`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_resend`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::FederationGrantRole;
use oneiron::inquiry::{
    Inquiry, InquiryAnswer, InquiryAsker, InquiryEdge, InquiryEdgeRequest, InquiryKeep,
    InquiryKeepSource, InquiryOutcome, InquiryRouteRequest, InquirySendRequest, InquirySent,
    InquiryStatement, InquiryTask, InquiryTransport, InquiryTransportError,
    MAX_INQUIRY_PURPOSE_BYTES, MAX_INQUIRY_QUESTION_BYTES, MAX_INQUIRY_ROLE_BYTES,
    MAX_INQUIRY_WIRE_BYTES, StatementSource,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

/// The company's shared vault the member holds a seat in.
const SHARED: u64 = 42;
/// The first-party actor the default policy manifest grants an Auto
/// ceiling, so its TASK create takes direct effect: the asking agent.
const ASKER_BYTES: [u8; 16] = [0xE1; 16];
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";
const MEMBER_HOST: &str = "https://member.example";
const QUESTION: &str = "Is owen in the office on Thursday?";
const PURPOSE: &str = "plan the Thursday visit";
/// The member's word.
const OUT_THURSDAY: &str = "Out Thursday. Back Friday.";

/// One rooted vault with its owner bound to its own host.
struct Side {
    vault: Vault,
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

/// Roots `vault` under a host of its own (`seed`), its engine machines and
/// install profile provisioned and its owner bound, as a host does.
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
        proof,
        issuer,
        vault_id,
        _dir: dir,
    }
}

fn side(seed: u8) -> Side {
    let (dir, vault) = open_vault();
    root(dir, vault, seed)
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

/// An open TASK `actor` creates for itself.
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

/// A member's seat in the shared vault.
fn seat(company: &Side) -> EntityId {
    let seat = person(&company.vault, EntityId::now());
    stand_member_grant(&company.vault, seat, SHARED, FederationGrantRole::Member)
        .expect("the member's seat");
    seat
}

/// The member's inquiry edge to the company and the company's reciprocal
/// grant, bound by the existing Connect offer and accept.
fn activate_edge(member: &Side, company: &Side) -> InquiryEdge {
    let edge = member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(company.vault_id, COMPANY),
        )
        .expect("the member mints the inquiry edge");
    let reciprocal = company
        .vault
        .mint_inquiry_edge_reciprocal_grant(&company.proof, member.vault_id, MEMBER)
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

/// The member vault's guest slip on its edge, bound to `holder_key`.
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

/// The member's vault and the company's, the member's seat in the shared
/// vault, the member's inquiry edge Active over the Connect pact, and the
/// route the company Owner opened with the member's slip.
struct Asking {
    _member: Side,
    company: Side,
    asker: EntityId,
    task: EntityId,
    other_task: EntityId,
    seat: EntityId,
}

fn asking() -> Asking {
    let member = side(0x11);
    let (dir, vault) = open_vault();
    let asker = person(&vault, EntityId::from_bytes(ASKER_BYTES).expect("asker id"));
    let task = open_task(&vault, asker, "plan the Thursday visit");
    let other_task = open_task(&vault, asker, "plan the Friday review");
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
    let edge = activate_edge(&member, &company);
    let slip = mint_slip(&member, &edge, company.issuer.binding_key());
    company
        .vault
        .open_inquiry_route(
            &company.proof,
            &company.issuer,
            &InquiryRouteRequest {
                shared_vault_id: SHARED,
                member: seat,
                member_vault_id: member.vault_id,
                member_host: MEMBER_HOST.to_owned(),
                slip,
            },
        )
        .expect("the company Owner opens the route");
    Asking {
        _member: member,
        company,
        asker,
        task,
        other_task,
        seat,
    }
}

impl Asking {
    /// The asking agent's send for `task`, re-sending `inquiry_id` when
    /// given, with an expiry computed for this call.
    fn request(&self, task: EntityId, inquiry_id: Option<EntityId>) -> InquirySendRequest {
        InquirySendRequest {
            shared_vault_id: SHARED,
            member: self.seat,
            asker: self.asker,
            asker_role: "scheduling agent".to_owned(),
            task,
            purpose: PURPOSE.to_owned(),
            question: QUESTION.to_owned(),
            expires_at: self.company.vault.now_recorded_at() + 600,
            inquiry_id,
        }
    }

    fn send(
        &self,
        request: &InquirySendRequest,
        host: &MemberHost,
    ) -> oneiron::Result<InquirySent> {
        self.company.vault.send_inquiry(request, host)
    }

    /// Every `inquiry` receipt of inquiry `id`, in the order they were
    /// written.
    fn receipts(&self, id: EntityId) -> Vec<ReceiptRecord> {
        let mut query = ReceiptQuery::new(100);
        query.kinds = [ReceiptKind::Inquiry].into();
        query.job_ref = Some(id.to_hex());
        let mut receipts = self.company.vault.receipts(query).expect("receipts");
        receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
        receipts
    }

    /// Installs the company's `inquiry` policy row with `keep`.
    fn install_keep(&self, keep: &str) {
        let policy = serde_json::json!({
            "schema_version": "1.2",
            "pack_id": "inquiry-resend",
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
}

/// What the member host double answers.
#[derive(Clone, Copy)]
enum Reply {
    Answered { valid_until: u64 },
    Pending,
}

/// The member host, in this process: it records each inquiry it takes.
struct MemberHost {
    reply: Mutex<Reply>,
    taken: Mutex<Vec<Inquiry>>,
}

impl MemberHost {
    fn new(reply: Reply) -> Self {
        Self {
            reply: Mutex::new(reply),
            taken: Mutex::new(Vec::new()),
        }
    }

    fn answering(company: &Side) -> Self {
        Self::new(answered(company))
    }

    fn set(&self, reply: Reply) {
        *self.reply.lock().expect("reply") = reply;
    }

    fn taken(&self) -> Vec<Inquiry> {
        self.taken.lock().expect("taken").clone()
    }
}

fn answered(company: &Side) -> Reply {
    Reply::Answered {
        valid_until: company.vault.now_recorded_at() + 3_600,
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
        let answer = match *self.reply.lock().expect("reply") {
            Reply::Pending => InquiryAnswer::pending(&inquiry),
            Reply::Answered { valid_until } => InquiryAnswer::answered(
                &inquiry,
                vec![
                    InquiryStatement::new(OUT_THURSDAY, StatementSource::MemberWord)
                        .expect("statement"),
                ],
                valid_until,
            )
            .expect("answer"),
        };
        self.taken.lock().expect("taken").push(inquiry);
        Ok(answer.encode_wire().expect("encode"))
    }
}

/// `sent` is a refusal whose words hold `words`.
fn assert_refused(sent: oneiron::Result<InquirySent>, words: &str) {
    let refused = sent.expect_err(words);
    assert!(
        format!("{refused:?}").contains(words),
        "{words}: {refused:?}"
    );
}

fn differs_in(field: &str) -> String {
    format!("differs from its first send in its {field};")
}

#[test]
fn a_re_send_of_an_id_this_vault_never_sent_is_refused() {
    let fixture = asking();
    let host = MemberHost::new(Reply::Pending);
    let unsent = EntityId::now();
    assert_refused(
        fixture.send(&fixture.request(fixture.task, Some(unsent)), &host),
        "names no inquiry this vault sent",
    );
    assert!(host.taken().is_empty(), "nothing goes out");
    assert!(
        fixture.receipts(unsent).is_empty(),
        "a refused re-send writes no receipt"
    );
}

#[test]
fn a_re_send_naming_another_member_asker_or_task_is_refused_naming_the_field() {
    let fixture = asking();
    let host = MemberHost::answering(&fixture.company);
    let first = fixture
        .send(&fixture.request(fixture.task, None), &host)
        .expect("the first send");
    assert!(first.held, "the member's answer is held with the task");
    let id = Some(first.inquiry.id);

    let mut other_member = fixture.request(fixture.task, id);
    other_member.member = seat(&fixture.company);
    let mut other_asker = fixture.request(fixture.task, id);
    other_asker.asker = person(&fixture.company.vault, EntityId::now());
    let other_task = fixture.request(fixture.other_task, id);
    for (request, field) in [
        (other_member, "member"),
        (other_asker, "asker"),
        (other_task, "task"),
    ] {
        assert_refused(fixture.send(&request, &host), &differs_in(field));
    }

    assert_eq!(host.taken().len(), 1, "only the first send went out");
    assert_eq!(
        fixture.receipts(first.inquiry.id).len(),
        1,
        "a refused re-send writes no receipt"
    );
    let held = fixture
        .company
        .vault
        .held_inquiry_answer(fixture.asker, fixture.task, first.inquiry.id)
        .expect("the held answer")
        .expect("still held");
    let texts: Vec<&str> = held.iter().map(InquiryStatement::text).collect();
    assert_eq!(texts, [OUT_THURSDAY], "the first member's answer stays");
}

#[test]
fn a_re_send_goes_out_as_the_stored_inquiry_and_refuses_a_changed_question_or_purpose() {
    let fixture = asking();
    let host = MemberHost::new(Reply::Pending);
    let first = fixture
        .send(&fixture.request(fixture.task, None), &host)
        .expect("the first send");
    assert_eq!(first.outcome, InquiryOutcome::Pending);
    assert_eq!(
        first.inquiry.keep,
        InquiryKeep::Task,
        "no inquiry row: task"
    );
    let id = Some(first.inquiry.id);

    let mut question = fixture.request(fixture.task, id);
    question.question = "Is owen in the office on Friday?".to_owned();
    let mut purpose = fixture.request(fixture.task, id);
    purpose.purpose = "plan the Friday review".to_owned();
    for (request, field) in [(question, "question"), (purpose, "purpose")] {
        assert_refused(fixture.send(&request, &host), &differs_in(field));
    }
    assert_eq!(host.taken().len(), 1, "a refused re-send sends nothing");
    assert_eq!(
        fixture.receipts(first.inquiry.id).len(),
        1,
        "and writes no receipt"
    );

    // The agent computes a later expiry for each call, and the company
    // Owner has set `inquiry_keep = copy` since the first send.
    fixture.install_keep("copy");
    let setting = fixture.company.vault.inquiry_keep().expect("the setting");
    assert_eq!(
        (setting.keep, setting.source),
        (InquiryKeep::Copy, InquiryKeepSource::Row)
    );
    host.set(answered(&fixture.company));
    let mut same = fixture.request(fixture.task, id);
    same.expires_at = first.inquiry.expires_at + 3_600;
    let again = fixture.send(&same, &host).expect("the re-send");
    assert_eq!(
        again.inquiry, first.inquiry,
        "the re-send is the stored inquiry"
    );
    assert_eq!(again.outcome, InquiryOutcome::Answered);
    assert!(again.held, "held with the task, the first send's keep");

    let taken = host.taken();
    assert_eq!(taken.len(), 2);
    assert_eq!(
        taken[1].expires_at, first.inquiry.expires_at,
        "the member gets the first send's expiry"
    );
    assert_eq!(
        taken[1].keep,
        InquiryKeep::Task,
        "the member gets the first send's keep"
    );
    let receipts = fixture.receipts(first.inquiry.id);
    assert_eq!(receipts.len(), 2);
    let expiry = first.inquiry.expires_at.to_string();
    assert_eq!(receipts[1].fields.get("expires_at"), Some(&expiry));
    assert_eq!(
        receipts[1].fields.get("keep").map(String::as_str),
        Some("task")
    );
}

#[test]
fn an_expired_re_send_or_an_oversized_inquiry_is_refused_before_any_send() {
    let fixture = asking();
    let host = MemberHost::new(Reply::Pending);
    let mut request = fixture.request(fixture.task, None);
    request.expires_at = fixture.company.vault.now_recorded_at() + 1;
    let first = fixture.send(&request, &host).expect("the first send");
    let deadline = Instant::now() + Duration::from_secs(10);
    while fixture.company.vault.now_recorded_at() < first.inquiry.expires_at {
        assert!(
            Instant::now() < deadline,
            "the vault clock reaches the expiry"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_refused(
        fixture.send(
            &fixture.request(fixture.task, Some(first.inquiry.id)),
            &host,
        ),
        "expired at",
    );
    assert_eq!(host.taken().len(), 1, "an expired re-send sends nothing");
    assert_eq!(
        fixture.receipts(first.inquiry.id).len(),
        1,
        "and writes no receipt"
    );

    let mut role = fixture.request(fixture.task, None);
    role.asker_role = "r".repeat(MAX_INQUIRY_ROLE_BYTES + 1);
    let mut purpose = fixture.request(fixture.task, None);
    purpose.purpose = "p".repeat(MAX_INQUIRY_PURPOSE_BYTES + 1);
    let mut question = fixture.request(fixture.task, None);
    question.question = "q".repeat(MAX_INQUIRY_QUESTION_BYTES + 1);
    for (request, words) in [
        (role, "role is over"),
        (purpose, "purpose is over"),
        (question, "question is over"),
    ] {
        assert_refused(fixture.send(&request, &host), words);
    }
    assert_eq!(host.taken().len(), 1, "an oversized inquiry sends nothing");

    // The largest valid inquiry, each capped field all control bytes that
    // JSON writes as six bytes each, still fits the member route's limit.
    let largest = Inquiry {
        id: EntityId::now(),
        from: InquiryAsker {
            vault: "f".repeat(64),
            actor: fixture.asker,
            role: "\u{1}".repeat(MAX_INQUIRY_ROLE_BYTES),
        },
        task: InquiryTask {
            id: fixture.task,
            purpose: "\u{1}".repeat(MAX_INQUIRY_PURPOSE_BYTES),
        },
        question: "\u{1}".repeat(MAX_INQUIRY_QUESTION_BYTES),
        keep: InquiryKeep::Copy,
        expires_at: u64::MAX,
    };
    let wire = largest
        .encode_wire()
        .expect("the largest valid inquiry encodes");
    assert!(
        wire.len() <= MAX_INQUIRY_WIRE_BYTES,
        "{} bytes over the route's {MAX_INQUIRY_WIRE_BYTES}",
        wire.len()
    );
    assert_eq!(
        Inquiry::decode_wire(&wire).expect("the member decodes it"),
        largest
    );
}
