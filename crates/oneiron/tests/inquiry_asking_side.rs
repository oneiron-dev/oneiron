//! INQUIRE-1 PR 4 (federation.md #inquiry, #inquiry-keep; Engine ruling
//! INQUIRE-SHAPE Q2, Q3, Q6 = A): the asking side, on the company vault.
//! - the company Owner opens the route to a member's vault, bound to the
//!   member's seat, once the Connect pact over the member's inquiry edge is
//!   Active; it refuses a slip another vault issued or bound to another
//!   host, a person with no seat, and a proof that is not the Owner's;
//! - a send carries the inquiry and the member's slip to the member host,
//!   writes an `inquiry` receipt with no answer text, and holds the answer
//!   for the asking actor's task;
//! - the held answer is gone once its task ends, and an answer past its
//!   `valid_until` is not held;
//! - a housekeeping pass drops an ended task's answer when nothing reads it
//!   (Engine ruling INQUIRE-HOLDER-EVICT);
//! - a stopped member vault, no route, and the member's leave each give
//!   `unavailable`;
//! - a re-send with the same id writes the next receipt of that inquiry.
//!
//! INQUIRE-1 PR 6 (federation.md #inquiry-copy; Engine ruling INQUIRE-SHAPE
//! Q9 = A): the copy landing.
//! - with `inquiry_keep = copy`, each answered statement lands as one CLAIM
//!   about the member's PERSON, in the foreign WORLD derived from the
//!   member's vault and the world the member opened, with its text and
//!   source and no member record id; it is attributed by a delivery record
//!   (pact, epoch, member vault, the member's edge grant) and not held with
//!   the task; its world is not registered to the pact, so the copy does not
//!   read stale when the member leaves; a re-send lands on the same CLAIMs;
//! - a caller re-using one inquiry id for a second member lands that
//!   member's copy on CLAIMs of its own: the first member's copies keep
//!   their subject, world, text and attribution;
//! - a `task` answer and an unanswered `copy` inquiry land nothing;
//! - once the member ends the pact and asks for the copies' deletion, a
//!   retain-under-basis answer keeps them out of shared reads, as it does a
//!   courtesy copy in a world the pact registered (BIZ-LEGAL-0004 B2); a
//!   second member's copy, under another pact, stays readable.
//!
//! The member host is a double in this process; the member-side admit and
//! the member host's route are later PRs.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_asking_side`.

use std::sync::{Arc, Mutex};

use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{
    CooperativeDeletionAnswer, CooperativeDeletionDispositionKind, CooperativeDeletionIngress,
    CooperativeDeletionRetention, encode_signed_cooperative_deletion_request,
};
use oneiron::federation::FederationGrantRole;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::inquiry::{
    Inquiry, InquiryAnswer, InquiryEdge, InquiryEdgeRequest, InquiryKeep, InquiryOutcome,
    InquiryRouteRequest, InquirySendRequest, InquirySent, InquiryStatement, InquiryTransport,
    InquiryTransportError, StatementSource,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::inquiry as door;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

/// The company's shared vault the member holds a seat in.
const SHARED: u64 = 42;
/// The first-party actor the default policy manifest grants an Auto
/// ceiling, so its TASK create takes direct effect: the asking agent.
const ASKER_BYTES: [u8; 16] = [0xE1; 16];
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";
/// The second member, for the copy tests that ask two members.
const OTHER_MEMBER: &str = "yuki";
const MEMBER_HOST: &str = "https://member.example";
const QUESTION: &str = "Is owen in the office on Thursday?";
/// The member's word.
const OUT_THURSDAY: &str = "Out Thursday. Back Friday.";
/// The member's companion's answer: provisional.
const BUSY_THURSDAY: &str = "Busy Thursday.";
/// The predicate an inquiry statement is a CLAIM of.
const STATEMENT_PREDICATE: &str = "profile.statement";
/// A peer vault no fixture opens.
const UNOPENED_PEER: AuthorityVaultId = [0xbd; 32];

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

/// The member's vault and the company's, the member's seat in the shared
/// vault, the member's inquiry edge Active over the Connect pact, and the
/// route the company Owner opened with the member's slip.
struct Asking {
    member: Side,
    company: Side,
    asker: EntityId,
    task: EntityId,
    other_task: EntityId,
    seat: EntityId,
    edge: InquiryEdge,
    slip: CapabilitySlip,
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
    let edge = activate_edge(&member, &company, MEMBER);
    let slip = mint_slip(&member, &edge, company.issuer.binding_key());
    let fixture = Asking {
        member,
        company,
        asker,
        task,
        other_task,
        seat,
        edge,
        slip,
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

fn side(seed: u8) -> Side {
    let (dir, vault) = open_vault();
    root(dir, vault, seed)
}

/// A member's seat in the shared vault.
fn seat(company: &Side) -> EntityId {
    let seat = person(&company.vault, EntityId::now());
    stand_member_grant(&company.vault, seat, SHARED, FederationGrantRole::Member)
        .expect("the member's seat");
    seat
}

/// The member's inquiry edge to the company and the company's reciprocal
/// grant for the member `name`, bound by the existing Connect offer and
/// accept.
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

    /// A second member `name` of the company: its own vault (`seed`), seat,
    /// inquiry edge, Connect pact and route. Returns its side and its seat.
    fn open_other_member(&self, seed: u8, name: &str) -> (Side, EntityId) {
        let other = side(seed);
        let other_seat = seat(&self.company);
        let other_edge = activate_edge(&other, &self.company, name);
        let other_slip = mint_slip(&other, &other_edge, self.company.issuer.binding_key());
        self.company
            .vault
            .open_inquiry_route(
                &self.company.proof,
                &self.company.issuer,
                &InquiryRouteRequest {
                    member_vault_id: other.vault_id,
                    ..self.route_request(other_seat, other_slip)
                },
            )
            .expect("the company Owner opens the second member's route");
        (other, other_seat)
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

    fn held(&self, task: EntityId, sent: &InquirySent) -> Option<Vec<InquiryStatement>> {
        self.company
            .vault
            .held_inquiry_answer(self.asker, task, sent.inquiry.id)
            .expect("the held answer")
    }

    /// Every `inquiry` receipt of `inquiry`, in the order they were written.
    /// Installs the company's `inquiry` policy row with `keep`.
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

    /// Every inquiry-statement CLAIM about the member in the company vault.
    fn copies(&self) -> Vec<(EntityId, oneiron::claim::ClaimBody)> {
        self.copies_about(self.seat)
    }

    /// Every inquiry-statement CLAIM about the PERSON `seat` in the company
    /// vault.
    fn copies_about(&self, seat: EntityId) -> Vec<(EntityId, oneiron::claim::ClaimBody)> {
        let mut copies: Vec<_> = self
            .company
            .vault
            .claims_for_subject(&seat)
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

    /// The foreign WORLD the member's copies land in: derived from the
    /// company's pact with the member's vault and the world the member
    /// opened.
    fn copy_world(&self) -> EntityId {
        let (pact, _) = self.company_pact();
        oneiron::federation::pact_foreign_world(
            &self.company.vault.authority_fold().expect("fold"),
            &pact,
            self.edge.terms.opened_world,
        )
        .expect("derive")
        .expect("the pact")
        .entity_id()
    }

    /// The company's Active Connect pact with the member's vault, and its
    /// consent epoch.
    fn company_pact(&self) -> ([u8; 32], u64) {
        let fold = self.company.vault.authority_fold().expect("authority fold");
        let mut live = fold.federation_pacts.iter().filter(|(_, state)| {
            state.peer_vault_id == self.member.vault_id
                && state.status == oneiron::authority::FederationPactStatus::Active
        });
        let (Some((pact, state)), None) = (live.next(), live.next()) else {
            panic!("one Active pact with the member's vault");
        };
        (*pact, state.pact_epoch)
    }

    fn receipts(&self, inquiry: &Inquiry) -> Vec<ReceiptRecord> {
        let mut query = ReceiptQuery::new(100);
        query.kinds = [ReceiptKind::Inquiry].into();
        query.job_ref = Some(inquiry.id.to_hex());
        let mut receipts = self.company.vault.receipts(query).expect("receipts");
        receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
        receipts
    }
}

/// What the member host double answers.
#[derive(Clone, Copy)]
enum Reply {
    Answered {
        valid_until: u64,
    },
    /// The member's word and the companion's answer.
    AnsweredWithCompanion {
        valid_until: u64,
    },
    Pending,
    Stopped,
}

/// One call the double took.
struct Call {
    member_host: String,
    member_vault_id: AuthorityVaultId,
    slip_token: String,
    inquiry: Inquiry,
}

/// The member host, in this process.
struct MemberHost {
    reply: Mutex<Reply>,
    calls: Mutex<Vec<Call>>,
}

impl MemberHost {
    fn new(reply: Reply) -> Self {
        Self {
            reply: Mutex::new(reply),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn answering(company: &Side) -> Self {
        Self::new(Reply::Answered {
            valid_until: company.vault.now_recorded_at() + 3_600,
        })
    }

    fn set(&self, reply: Reply) {
        *self.reply.lock().expect("reply") = reply;
    }

    fn call_count(&self) -> usize {
        self.calls.lock().expect("calls").len()
    }
}

impl InquiryTransport for MemberHost {
    fn exchange(
        &self,
        member_host: &str,
        member_vault_id: &AuthorityVaultId,
        slip_token: &str,
        inquiry: &[u8],
    ) -> Result<Vec<u8>, InquiryTransportError> {
        let inquiry = Inquiry::decode_wire(inquiry).expect("the inquiry crosses in its wire shape");
        let reply = *self.reply.lock().expect("reply");
        let answer = match reply {
            Reply::Stopped => None,
            Reply::Pending => Some(InquiryAnswer::pending(&inquiry)),
            Reply::Answered { valid_until } => Some(
                InquiryAnswer::answered(
                    &inquiry,
                    vec![
                        InquiryStatement::new(OUT_THURSDAY, StatementSource::MemberWord)
                            .expect("statement"),
                    ],
                    valid_until,
                )
                .expect("answer"),
            ),
            Reply::AnsweredWithCompanion { valid_until } => Some(
                InquiryAnswer::answered(
                    &inquiry,
                    vec![
                        InquiryStatement::new(OUT_THURSDAY, StatementSource::MemberWord)
                            .expect("statement"),
                        InquiryStatement::new(BUSY_THURSDAY, StatementSource::CompanionOfMember)
                            .expect("statement"),
                    ],
                    valid_until,
                )
                .expect("answer"),
            ),
        };
        self.calls.lock().expect("calls").push(Call {
            member_host: member_host.to_owned(),
            member_vault_id: *member_vault_id,
            slip_token: slip_token.to_owned(),
            inquiry,
        });
        let Some(answer) = answer else {
            return Err(InquiryTransportError::Unreachable(
                "the member's vault is stopped".to_owned(),
            ));
        };
        Ok(answer.encode_wire().expect("encode"))
    }
}

fn texts(statements: &[InquiryStatement]) -> Vec<&str> {
    statements.iter().map(InquiryStatement::text).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn an_answer_is_held_for_the_task_and_its_receipt_has_no_text() {
    let fixture = asking();
    let route = fixture
        .company
        .vault
        .inquiry_route(SHARED, fixture.seat)
        .expect("route read")
        .expect("the route is open");
    assert_eq!(route.member_vault_id, fixture.member.vault_id);
    assert_eq!(route.member_host, MEMBER_HOST);
    assert_eq!(route.edge_grant, fixture.edge.grant.to_hex());

    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(sent.outcome, InquiryOutcome::Answered);
    assert_eq!(texts(&sent.statements), [OUT_THURSDAY]);
    assert!(sent.held, "the answer is held with the task");

    {
        let calls = host.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.member_host, MEMBER_HOST);
        assert_eq!(call.member_vault_id, fixture.member.vault_id);
        assert_eq!(
            call.slip_token,
            fixture.slip.to_token().expect("token"),
            "the send carries the member's slip"
        );
        assert_eq!(call.inquiry, sent.inquiry);
        assert_eq!(call.inquiry.question, QUESTION);
        assert_eq!(call.inquiry.task.id, fixture.task);
        assert_eq!(call.inquiry.from.actor, fixture.asker);
        assert_eq!(call.inquiry.from.vault, hex(&fixture.company.vault_id));
        assert_eq!(call.inquiry.keep, InquiryKeep::Task, "no inquiry row: task");
    }

    let held = fixture
        .held(fixture.task, &sent)
        .expect("held while the task is open");
    assert_eq!(texts(&held), [OUT_THURSDAY]);
    assert_eq!(
        fixture
            .company
            .vault
            .held_inquiry_answer(EntityId::now(), fixture.task, sent.inquiry.id)
            .expect("read"),
        None,
        "the held answer is bound to the asking actor"
    );

    let receipts = fixture.receipts(&sent.inquiry);
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.receipt_id, sent.receipt_id);
    assert_eq!(receipt.outcome, "answered");
    assert_eq!(
        receipt.fields.get("member"),
        Some(&fixture.seat.to_hex()),
        "the receipt names the member asked about"
    );
    let written = format!("{receipt:?}");
    assert!(
        !written.contains("Out Thursday") && !written.contains("Back Friday"),
        "the receipt holds no answer text: {written}"
    );
}

#[test]
fn the_held_answer_is_gone_once_its_task_ends() {
    let fixture = asking();
    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    let other = fixture.send(&host, fixture.other_task);
    assert!(fixture.held(fixture.task, &sent).is_some());

    door::cancel_task(&fixture.company.vault, fixture.task, fixture.asker).expect("the task ends");
    assert_eq!(
        fixture.held(fixture.task, &sent),
        None,
        "the answer goes with its task"
    );
    assert_eq!(
        fixture
            .held(fixture.other_task, &other)
            .map(|held| texts(&held).len()),
        Some(1),
        "another task's answer stays while that task is open"
    );
    let refused = fixture
        .company
        .vault
        .send_inquiry(&fixture.request(fixture.task, None), &host)
        .expect_err("an ended task sends no inquiry");
    assert!(
        format!("{refused:?}").contains("not an open TASK"),
        "{refused:?}"
    );
}

#[test]
fn a_housekeeping_pass_drops_an_ended_tasks_answer_with_no_read() {
    let fixture = asking();
    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    let other = fixture.send(&host, fixture.other_task);
    let vault = &fixture.company.vault;
    assert_eq!(door::held_inquiry_answer_count(vault), 2);

    door::cancel_task(vault, fixture.task, fixture.asker).expect("the task ends");
    assert_eq!(
        door::held_inquiry_answer_count(vault),
        2,
        "ending the task alone drops no held answer"
    );
    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("the pass runs");
    assert_eq!(
        door::held_inquiry_answer_count(vault),
        1,
        "the pass drops the ended task's answer and keeps the open task's"
    );
    assert_eq!(fixture.held(fixture.task, &sent), None);
    assert!(fixture.held(fixture.other_task, &other).is_some());
}

#[test]
fn an_unanswered_or_refused_send_drops_an_ended_tasks_answer() {
    let fixture = asking();
    let host = MemberHost::answering(&fixture.company);
    assert!(fixture.send(&host, fixture.task).held);
    assert!(fixture.send(&host, fixture.other_task).held);
    let vault = &fixture.company.vault;

    door::cancel_task(vault, fixture.task, fixture.asker).expect("the task ends");
    assert_eq!(door::held_inquiry_answer_count(vault), 2);
    let stopped = MemberHost::new(Reply::Stopped);
    let unavailable = fixture.send(&stopped, fixture.other_task);
    assert_eq!(unavailable.outcome, InquiryOutcome::Unavailable);
    assert_eq!(
        door::held_inquiry_answer_count(vault),
        1,
        "an unavailable send drops the ended task's answer and keeps the open task's"
    );

    door::cancel_task(vault, fixture.other_task, fixture.asker).expect("the other task ends");
    vault
        .send_inquiry(&fixture.request(fixture.other_task, None), &host)
        .expect_err("an ended task sends no inquiry");
    assert_eq!(
        door::held_inquiry_answer_count(vault),
        0,
        "a refused send drops the ended task's answer too"
    );
}

#[test]
fn an_answer_past_its_valid_until_is_not_held() {
    let fixture = asking();
    let host = MemberHost::new(Reply::Answered {
        valid_until: fixture.company.vault.now_recorded_at(),
    });
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(sent.outcome, InquiryOutcome::Answered);
    assert!(
        !sent.held,
        "an answer whose valid_until has come is not held"
    );
    assert_eq!(fixture.held(fixture.task, &sent), None);
}

#[test]
fn a_stopped_member_vault_gives_unavailable() {
    let fixture = asking();
    let host = MemberHost::new(Reply::Stopped);
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(host.call_count(), 1, "the send went out");
    assert_eq!(sent.outcome, InquiryOutcome::Unavailable);
    assert!(sent.statements.is_empty() && !sent.held);
    let receipts = fixture.receipts(&sent.inquiry);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "unavailable");
}

#[test]
fn after_the_member_leaves_the_route_is_gone_and_a_send_is_unavailable() {
    let fixture = asking();
    let seat_proof = fixture
        .company
        .vault
        .authenticate_owner(
            fixture.seat,
            &fixture.seat.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the member's proof");
    fixture
        .company
        .vault
        .leave_shared_vault(&seat_proof, SHARED, Some(&fixture.company.issuer))
        .expect("the member leaves");
    assert!(
        fixture
            .company
            .vault
            .inquiry_route(SHARED, fixture.seat)
            .expect("route read")
            .is_none(),
        "the leave ends the route"
    );
    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(sent.outcome, InquiryOutcome::Unavailable);
    assert_eq!(host.call_count(), 0, "nothing goes out without a route");
    assert_eq!(fixture.receipts(&sent.inquiry)[0].outcome, "unavailable");
}

#[test]
fn a_seat_with_no_route_gives_unavailable_without_a_send() {
    let fixture = asking();
    let host = MemberHost::answering(&fixture.company);
    let mut request = fixture.request(fixture.task, None);
    request.member = seat(&fixture.company);
    let sent = fixture
        .company
        .vault
        .send_inquiry(&request, &host)
        .expect("the send");
    assert_eq!(sent.outcome, InquiryOutcome::Unavailable);
    assert_eq!(host.call_count(), 0);
}

#[test]
fn a_re_send_with_the_same_id_writes_the_next_receipt() {
    let fixture = asking();
    let host = MemberHost::new(Reply::Pending);
    let first = fixture.send(&host, fixture.task);
    assert_eq!(first.outcome, InquiryOutcome::Pending);
    assert!(!first.held);

    host.set(Reply::Answered {
        valid_until: fixture.company.vault.now_recorded_at() + 3_600,
    });
    let again = fixture
        .company
        .vault
        .send_inquiry(
            &fixture.request(fixture.task, Some(first.inquiry.id)),
            &host,
        )
        .expect("the re-send");
    assert_eq!(again.inquiry.id, first.inquiry.id, "the same inquiry");
    assert_eq!(again.outcome, InquiryOutcome::Answered);
    assert!(again.held);

    let receipts = fixture.receipts(&first.inquiry);
    let ids: Vec<&str> = receipts
        .iter()
        .map(|receipt| receipt.receipt_id.as_str())
        .collect();
    let base = format!("inquiry:{}", first.inquiry.id.to_hex());
    assert_eq!(ids, [format!("{base}:000000"), format!("{base}:000001")]);
    let outcomes: Vec<&str> = receipts
        .iter()
        .map(|receipt| receipt.outcome.as_str())
        .collect();
    assert_eq!(outcomes, ["pending", "answered"]);
}

#[test]
fn opening_a_route_refuses_another_vaults_slip_another_host_no_seat_and_no_owner() {
    let fixture = asking();
    let company = &fixture.company;
    let open = |request: &InquiryRouteRequest, proof: &AuthenticatedOwner| {
        company
            .vault
            .open_inquiry_route(proof, &company.issuer, request)
            .expect_err("the open refuses")
    };

    let mut request = fixture.route_request(fixture.seat, fixture.slip.clone());
    request.member_vault_id = UNOPENED_PEER;
    let refused = open(&request, &company.proof);
    assert!(
        format!("{refused:?}").contains("not issued by the member's vault"),
        "{refused:?}"
    );

    let other_host = HostSlipIssuer::from_seed(&[0x33; HOST_ISSUER_SEED_BYTES]).expect("host");
    let elsewhere = mint_slip(&fixture.member, &fixture.edge, other_host.binding_key());
    let refused = open(
        &fixture.route_request(fixture.seat, elsewhere),
        &company.proof,
    );
    assert!(
        format!("{refused:?}").contains("bound to this host's key"),
        "{refused:?}"
    );

    let stranger = person(&company.vault, EntityId::now());
    let refused = open(
        &fixture.route_request(stranger, fixture.slip.clone()),
        &company.proof,
    );
    assert!(format!("{refused:?}").contains("no seat"), "{refused:?}");

    let seat_proof = company
        .vault
        .authenticate_owner(
            fixture.seat,
            &fixture.seat.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the member's proof");
    let refused = open(
        &fixture.route_request(fixture.seat, fixture.slip.clone()),
        &seat_proof,
    );
    assert!(format!("{refused:?}").contains("owner"), "{refused:?}");
}

#[test]
fn a_copy_answer_lands_foreign_attributed_and_is_not_held() {
    let fixture = asking();
    fixture.install_keep("copy");
    let host = MemberHost::new(Reply::AnsweredWithCompanion {
        valid_until: fixture.company.vault.now_recorded_at() + 3_600,
    });
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(sent.outcome, InquiryOutcome::Answered);
    assert_eq!(
        host.calls.lock().expect("calls")[0].inquiry.keep,
        InquiryKeep::Copy,
        "the inquiry tells the member the company keeps a copy"
    );
    assert!(!sent.held, "a copied answer is not held with the task");
    assert_eq!(fixture.held(fixture.task, &sent), None);

    let (pact, epoch) = fixture.company_pact();
    let world = fixture.copy_world();
    let copies = fixture.copies();
    assert_eq!(copies.len(), 2, "one CLAIM per statement: {copies:?}");
    let mut landed = Vec::new();
    for (_, body) in &copies {
        assert_eq!(
            body.world,
            Some(world),
            "the copy sits in the foreign world"
        );
        assert_eq!(body.source, Some(oneiron::claim::ClaimSource::Imported));
        assert_eq!(body.lifecycle, oneiron::claim::ClaimLifecycleStatus::Active);
        let text = body
            .value
            .as_str()
            .expect("the statement's text")
            .to_owned();
        let evidence = body
            .evidence
            .as_ref()
            .expect("evidence")
            .as_map()
            .expect("a map");
        let field = |name: &str| {
            evidence
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .and_then(|(_, value)| value.as_str())
                .map(str::to_owned)
        };
        assert_eq!(field("inquiry"), Some(sent.inquiry.id.to_hex()));
        landed.push((text, field("statement_source").expect("its source")));
        let written = format!("{body:?}");
        assert!(
            !written.contains(&fixture.edge.terms.opened_world.to_hex()),
            "no id of the member's vault lands: {written}"
        );
    }
    landed.sort();
    assert_eq!(
        landed,
        [
            (BUSY_THURSDAY.to_owned(), "companion_of_member".to_owned()),
            (OUT_THURSDAY.to_owned(), "member_word".to_owned()),
        ]
    );

    let ids: Vec<EntityId> = copies.iter().map(|(id, _)| *id).collect();
    let history = fixture
        .company
        .vault
        .federation_delivery_history(&ids)
        .expect("delivery history");
    assert_eq!(
        history.len(),
        2,
        "one delivery record per copy: {history:?}"
    );
    for record in &history {
        assert!(ids.contains(&record.source_ref));
        assert_eq!(record.delivering_pact, pact);
        assert_eq!(record.consent_epoch, epoch);
        assert_eq!(record.source_vault, fixture.member.vault_id);
        assert_eq!(
            record.grant_ref, fixture.edge.grant,
            "the member's edge grant"
        );
        assert_eq!(record.world, Some(world));
    }
    assert!(
        oneiron::federation::registered_foreign_worlds_for_pact(&fixture.company.vault, &pact)
            .expect("registered worlds")
            .is_empty(),
        "the copy's world is not registered to the pact: it stays when the member leaves"
    );

    let again = fixture
        .company
        .vault
        .send_inquiry(&fixture.request(fixture.task, Some(sent.inquiry.id)), &host)
        .expect("the re-send");
    assert_eq!(again.outcome, InquiryOutcome::Answered);
    let again: Vec<EntityId> = fixture.copies().iter().map(|(id, _)| *id).collect();
    assert_eq!(again, ids, "a re-send lands on the same CLAIMs");
    assert_eq!(fixture.receipts(&sent.inquiry).len(), 2);
}

#[test]
fn a_re_used_id_for_another_member_lands_on_that_members_own_claims() {
    let fixture = asking();
    fixture.install_keep("copy");
    let valid_until = fixture.company.vault.now_recorded_at() + 3_600;
    let host = MemberHost::new(Reply::AnsweredWithCompanion { valid_until });
    let first = fixture.send(&host, fixture.task);
    assert_eq!(first.outcome, InquiryOutcome::Answered);
    let first_ids: Vec<EntityId> = fixture.copies().iter().map(|(id, _)| *id).collect();
    assert_eq!(first_ids.len(), 2, "the first member's two statements land");

    // A second member: its own vault, seat, inquiry edge, Connect pact and
    // route.
    let (_other, other_seat) = fixture.open_other_member(0x44, OTHER_MEMBER);

    host.set(Reply::Answered { valid_until });
    let mut request = fixture.request(fixture.task, Some(first.inquiry.id));
    request.member = other_seat;
    let second = fixture
        .company
        .vault
        .send_inquiry(&request, &host)
        .expect("the send to the second member");
    assert_eq!(second.outcome, InquiryOutcome::Answered);
    assert_eq!(
        second.inquiry.id, first.inquiry.id,
        "the caller re-used the first inquiry's id"
    );

    let world = fixture.copy_world();
    let first_copies = fixture.copies();
    let ids: Vec<EntityId> = first_copies.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, first_ids, "the first member's copies stand");
    let mut texts_landed = Vec::new();
    for (_, body) in &first_copies {
        let about_first = matches!(
            body.subject,
            oneiron::ClaimSubject::Entity(subject) if subject == fixture.seat
        );
        assert!(
            about_first,
            "a first member's copy stays about the first member"
        );
        assert_eq!(body.world, Some(world), "and in the first member's world");
        texts_landed.push(body.value.as_str().expect("text").to_owned());
    }
    texts_landed.sort();
    assert_eq!(texts_landed, [BUSY_THURSDAY, OUT_THURSDAY]);

    let second_copies = fixture.copies_about(other_seat);
    assert_eq!(
        second_copies.len(),
        1,
        "the second member's statement lands once: {second_copies:?}"
    );
    let (second_id, second_body) = &second_copies[0];
    assert!(
        !first_ids.contains(second_id),
        "the second member's copy lands on a CLAIM of its own"
    );
    assert!(
        second_body.world.is_some() && second_body.world != Some(world),
        "the second member's copy sits in its own foreign world"
    );

    let history = fixture
        .company
        .vault
        .federation_delivery_history(&first_ids)
        .expect("delivery history");
    assert_eq!(history.len(), 2, "one delivery per first copy: {history:?}");
    for record in &history {
        assert_eq!(
            record.source_vault, fixture.member.vault_id,
            "each first copy is attributed to the first member's vault"
        );
    }
}

#[test]
fn a_task_answer_and_an_unanswered_copy_land_nothing() {
    let fixture = asking();
    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(sent.outcome, InquiryOutcome::Answered);
    assert!(sent.held);
    assert!(fixture.copies().is_empty(), "a task answer lands nothing");

    fixture.install_keep("copy");
    host.set(Reply::Pending);
    let pending = fixture.send(&host, fixture.other_task);
    assert_eq!(pending.outcome, InquiryOutcome::Pending);
    host.set(Reply::Stopped);
    let stopped = fixture.send(&host, fixture.other_task);
    assert_eq!(stopped.outcome, InquiryOutcome::Unavailable);
    assert!(
        fixture.copies().is_empty(),
        "a pending or unavailable copy inquiry lands nothing"
    );
}

#[test]
fn a_retained_courtesy_ask_keeps_the_copied_answers_out_of_shared_reads() {
    let fixture = asking();
    fixture.install_keep("copy");
    let valid_until = fixture.company.vault.now_recorded_at() + 3_600;
    let host = MemberHost::new(Reply::AnsweredWithCompanion { valid_until });
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(sent.outcome, InquiryOutcome::Answered);
    let ids: Vec<EntityId> = fixture.copies().iter().map(|(id, _)| *id).collect();
    assert_eq!(ids.len(), 2, "the member's two statements land");

    // A second member's copy, under a pact of its own that the ask is not
    // about.
    let (_other, other_seat) = fixture.open_other_member(0x44, OTHER_MEMBER);
    host.set(Reply::Answered { valid_until });
    let mut request = fixture.request(fixture.other_task, None);
    request.member = other_seat;
    let other_sent = fixture
        .company
        .vault
        .send_inquiry(&request, &host)
        .expect("the send to the second member");
    assert_eq!(other_sent.outcome, InquiryOutcome::Answered);
    let other_ids: Vec<EntityId> = fixture
        .copies_about(other_seat)
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(other_ids.len(), 1, "the second member's statement lands");

    let admits = |id: EntityId| {
        door::retained_copy_admits(&fixture.company.vault, id).expect("the retained-copy check")
    };
    for id in ids.iter().chain(&other_ids) {
        assert!(
            admits(*id),
            "with no ask filed, a shared read admits each copy"
        );
    }

    // The member ends the pact and asks, about every world, for what the
    // pact delivered up to its end; the company Owner keeps the copies
    // under a basis.
    let (pact, epoch) = fixture.company_pact();
    let ended = fixture
        .member
        .vault
        .disconnect_connect_as(&fixture.member.proof, &fixture.member.issuer, pact)
        .expect("the member ends the pact");
    let cutoff = ended.terminal_epoch.unwrap_or(ended.pact_epoch);
    assert!(
        epoch <= cutoff,
        "the ask's cutoff {cutoff} covers the copies' delivery epoch {epoch}"
    );
    let nonce = [0x5a; 16];
    let pages = fixture
        .member
        .issuer
        .sign_cooperative_deletion_request(&fixture.member.vault, &pact, Vec::new(), cutoff, nonce)
        .expect("the member signs the ask");
    assert_eq!(pages.len(), 1, "an ask about every world is one page");
    let now = fixture.company.vault.now_recorded_at();
    let bytes = encode_signed_cooperative_deletion_request(&pages[0]).expect("encode the ask");
    assert_eq!(
        fixture
            .company
            .vault
            .receive_cooperative_deletion_request(&bytes, now)
            .expect("the company receives the ask"),
        CooperativeDeletionIngress::Filed
    );
    fixture
        .company
        .vault
        .answer_cooperative_deletion_as(
            &fixture.company.proof,
            &pact,
            &nonce,
            &CooperativeDeletionAnswer {
                kind: CooperativeDeletionDispositionKind::RetainUnderBasis,
                reason_code: Some("business_record".to_owned()),
                review_at: Some(now + 86_400),
                delete: Vec::new(),
                hold: Vec::new(),
                retention: Some(CooperativeDeletionRetention {
                    records: ids.clone(),
                    basis_code: "legitimate_interest".to_owned(),
                    retention_class: "business_record".to_owned(),
                }),
                restrict: Vec::new(),
                restriction_notice_given: Vec::new(),
                redact: Vec::new(),
            },
            now,
        )
        .expect("the company Owner keeps the copies under a basis");

    for id in &ids {
        assert!(
            !admits(*id),
            "a retained ask keeps the member's copied answer out of shared reads"
        );
    }
    assert!(
        admits(other_ids[0]),
        "the second member's copy, under another pact, stays readable"
    );
}
