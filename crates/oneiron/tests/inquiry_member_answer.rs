//! INQUIRE-1 PR 3 (federation.md #inquiry, #inquiry-checkin; ARCH-0082
//! #inquiry; Engine ruling INQUIRE-SHAPE Q4, Q5 = A): the member's vault
//! answers an inquiry. Two rooted vaults on one clock the test moves: the
//! member's, with its inquiry edge to the company Active on both sides, and
//! the company's, whose host holds its own credential on that edge.
//! - an opened statement answers through the companion, as the companion's
//!   statement, and the member is not asked;
//! - the companion is shown the opened scope alone, at the unstamped tier:
//!   neither the member's other claims nor a stamped statement in the
//!   opened WORLD;
//! - an unsure companion takes the inquiry to the member as a pending
//!   check-in (verb `vault.inquiry.answer`, act `outbound_send`, the
//!   company's guest actor asking, until the inquiry expires); the member's
//!   words answer as the member's word and are filed in the opened scope;
//! - a decline and an inquiry ignored until it expires both answer
//!   `no_answer`, in one shape;
//! - a repeat returns the current answer and opens no second check-in; a
//!   repeat that carries another inquiry under the same id refuses;
//! - on a never-ask edge the vault answers from the scope without asking,
//!   "nothing there" is `no_answer` at once, and a copy inquiry on an edge
//!   that allows only `task` still goes to the member;
//! - an inquiry from another vault, a new inquiry already expired, and one
//!   after the member revoked the edge are refused, and none is logged.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_member_answer`.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
    VerifiedSlip,
};
use oneiron::check_in::{ActClass, CheckInMode, HolderAnswer, PendingState, WaitReason};
use oneiron::consent::AuthenticatedOwner;
use oneiron::inquiry::{
    INQUIRY_ANSWER_VERB, INQUIRY_STATEMENT_PREDICATE, Inquiry, InquiryAnswer, InquiryAsker,
    InquiryCheckInMode, InquiryDecider, InquiryEdge, InquiryEdgeRequest, InquiryJudgment,
    InquiryJudgmentOutcome, InquiryKeep, InquiryLogEntry, InquiryMemberAnswer, InquiryOutcome,
    InquiryTask, StatementSource, UnsureInquiryJudgment,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value;

/// The second the shared clock starts at.
const T0: u64 = 1_790_000_000;
const DAY: u64 = 24 * 60 * 60;
/// How long after it is sent an inquiry expires.
const INQUIRY_SECS: u64 = 600;
/// The company's name, as the opened scope's title reads it.
const COMPANY: &str = "Acme";
/// The member's name, as the company's reciprocal WORLD reads it.
const MEMBER: &str = "owen";
/// The member's word the company may ask about.
const OUT_THURSDAY: &str = "Out Thursday. Back Friday.";
/// The member's own claim, which no inquiry reaches.
const CHEMO: &str = "Chemo on Thursday.";
const QUESTION: &str = "Is owen in the office on Thursday?";
/// The challenge the company host signs with its connection key.
const CHALLENGE: &[u8] = b"inquiry-member-answer-test";
/// The keys of every wire answer.
const ANSWER_KEYS: [&str; 5] = ["inquiry_id", "keep", "outcome", "statements", "valid_until"];

/// One rooted vault with its owner bound to its own host.
struct Side {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    vault_id: AuthorityVaultId,
    _dir: tempfile::TempDir,
}

/// A vault on `clock`, rooted under a host of its own (`seed`), its engine
/// machines and install profile provisioned and its owner bound.
fn side(seed: u8, clock: &Arc<ManualClock>) -> Side {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("fresh vault");
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
        owner,
        proof,
        issuer,
        vault_id,
        _dir: dir,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A companion that is sure of `sure` (unsure when it is empty) and keeps
/// every question and admitted scope it was shown.
struct ScriptedCompanion {
    sure: Vec<String>,
    shown: Mutex<Vec<(String, Vec<String>)>>,
}

impl ScriptedCompanion {
    fn sure_of(statements: &[&str]) -> Self {
        Self {
            sure: statements.iter().map(|text| (*text).to_owned()).collect(),
            shown: Mutex::new(Vec::new()),
        }
    }

    fn unsure() -> Self {
        Self::sure_of(&[])
    }

    fn shown(&self) -> Vec<(String, Vec<String>)> {
        self.shown.lock().expect("companion log").clone()
    }
}

impl InquiryJudgment for ScriptedCompanion {
    fn judge(
        &self,
        question: &str,
        admitted: &[String],
    ) -> oneiron::Result<InquiryJudgmentOutcome> {
        self.shown
            .lock()
            .expect("companion log")
            .push((question.to_owned(), admitted.to_vec()));
        Ok(if self.sure.is_empty() {
            InquiryJudgmentOutcome::Unsure
        } else {
            InquiryJudgmentOutcome::Sure(self.sure.clone())
        })
    }
}

/// The member's vault, the company's, the member's inquiry edge Active on
/// both, and the company host's connection key with its slip on the edge.
struct Thursday {
    clock: Arc<ManualClock>,
    member: Side,
    company: Side,
    edge: InquiryEdge,
    host_key: SigningKey,
    slip: CapabilitySlip,
}

impl Thursday {
    /// The edge on the member defaults, but in `mode`.
    fn open(mode: InquiryCheckInMode) -> Self {
        let clock = ManualClock::new(T0);
        let member = side(0x11, &clock);
        let company = side(0x22, &clock);
        let edge = member
            .vault
            .mint_inquiry_edge(
                &member.proof,
                &InquiryEdgeRequest {
                    check_in_mode: mode,
                    ..InquiryEdgeRequest::member_defaults(company.vault_id, COMPANY)
                },
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
        let host_key = SigningKey::from_bytes(&[0x5a; 32]);
        let slip = member
            .vault
            .mint_guest_slip(
                &member.proof,
                &member.issuer,
                edge.grant,
                Some(host_key.verifying_key().to_bytes()),
                T0 + DAY,
                None,
            )
            .expect("the member's vault mints the company host's slip");
        Self {
            clock,
            member,
            company,
            edge,
            host_key,
            slip,
        }
    }

    fn at(&self, now: u64) {
        self.clock.set(now);
    }

    /// The company host's credential on the edge, as the member's host
    /// verifies it.
    fn credential(&self) -> VerifiedSlip {
        let transcript = self
            .slip
            .binding_transcript(CHALLENGE)
            .expect("binding transcript");
        let signature = self.host_key.sign(&transcript).to_bytes();
        self.member
            .vault
            .verify_capability_slip(
                &self.member.issuer.public_key(),
                &self.slip,
                CHALLENGE,
                &signature,
            )
            .expect("the company host's credential verifies")
    }

    /// A new inquiry from the company's scheduling agent, expiring
    /// `INQUIRY_SECS` after `sent_at`.
    fn inquiry(&self, question: &str, keep: InquiryKeep, sent_at: u64) -> Inquiry {
        Inquiry {
            id: EntityId::now(),
            from: InquiryAsker {
                vault: hex(&self.company.vault_id),
                actor: EntityId::now(),
                role: "scheduling agent".to_owned(),
            },
            task: InquiryTask {
                id: EntityId::now(),
                purpose: "find a time for the review".to_owned(),
            },
            question: question.to_owned(),
            keep,
            expires_at: sent_at + INQUIRY_SECS,
        }
    }

    fn admit(
        &self,
        inquiry: &Inquiry,
        judgment: &dyn InquiryJudgment,
    ) -> oneiron::Result<InquiryAnswer> {
        self.member
            .vault
            .admit_inquiry(self.edge.grant, &self.credential(), inquiry, judgment)
    }

    /// The member opens `text` to the company.
    fn open_statement(&self, text: &str) {
        self.member
            .vault
            .open_inquiry_scope_item(&self.member.proof, self.edge.grant, text, None)
            .expect("the member opens a statement");
    }

    /// A claim of the member's in the opened WORLD that carries a
    /// sensitivity stamp.
    fn put_stamped_statement(&self, text: &str) {
        let mut body = ClaimBody::new(
            INQUIRY_STATEMENT_PREDICATE,
            ClaimSubject::Entity(self.member.owner),
            Value::from(text),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        body.world = Some(self.edge.terms.opened_world);
        body.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("sensitive"),
        )]));
        self.member
            .vault
            .put_claim(
                &EntityId::now(),
                &body,
                TimeRange { start: T0, end: T0 },
                T0,
            )
            .expect("a stamped claim in the opened WORLD");
    }

    /// A claim of the member's outside any opened scope.
    fn put_own_claim(&self, text: &str) {
        let body = ClaimBody::new(
            "profile.appointment",
            ClaimSubject::Entity(self.member.owner),
            Value::from(text),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        self.member
            .vault
            .put_claim(
                &EntityId::now(),
                &body,
                TimeRange { start: T0, end: T0 },
                T0,
            )
            .expect("the member's own claim");
    }

    fn answer(
        &self,
        inquiry: &Inquiry,
        answer: &InquiryMemberAnswer,
    ) -> oneiron::Result<InquiryAnswer> {
        self.member
            .vault
            .answer_inquiry(&self.member.proof, self.edge.grant, inquiry.id, answer)
    }

    fn logged(&self, inquiry: &Inquiry) -> InquiryLogEntry {
        self.member
            .vault
            .inquiry_log_entry(&self.edge.grant, &inquiry.id)
            .expect("log read")
            .expect("the inquiry is logged")
    }

    fn pending(&self, inquiry: &Inquiry) -> Option<oneiron::check_in::PendingCheckIn> {
        self.member
            .vault
            .inquiry_pending_check_in(&self.edge.grant, &inquiry.id)
            .expect("pending check-in read")
    }

    fn opened(&self) -> Vec<String> {
        self.member
            .vault
            .inquiry_scope_items(&self.member.proof, self.edge.grant)
            .expect("the opened scope")
            .into_iter()
            .map(|item| item.statement)
            .collect()
    }
}

/// `answer` is `no_answer` to `inquiry`, in the one shape: no statements,
/// no `valid_until`, the inquiry's id and keep, and the wire keys of every
/// answer.
fn assert_no_answer(answer: &InquiryAnswer, inquiry: &Inquiry) -> serde_json::Value {
    assert_eq!(answer.outcome(), InquiryOutcome::NoAnswer);
    assert!(answer.statements().is_empty());
    assert_eq!(answer.valid_until(), None);
    assert_eq!(answer.inquiry_id(), inquiry.id);
    assert_eq!(answer.keep(), inquiry.keep);
    let mut json: serde_json::Value =
        serde_json::from_slice(&answer.encode_wire().expect("wire")).expect("wire JSON");
    let keys: BTreeSet<&str> = json
        .as_object()
        .expect("an answer is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, BTreeSet::from(ANSWER_KEYS));
    json.as_object_mut()
        .expect("an answer is an object")
        .remove("inquiry_id");
    json
}

#[test]
fn an_opened_statement_answers_through_the_companion_and_the_member_is_not_asked() {
    let thursday = Thursday::open(InquiryCheckInMode::AskWhenUnsure);
    thursday.open_statement(OUT_THURSDAY);
    let inquiry = thursday.inquiry(QUESTION, InquiryKeep::Task, T0);
    let companion = ScriptedCompanion::sure_of(&[OUT_THURSDAY]);

    let answer = thursday
        .admit(&inquiry, &companion)
        .expect("the member's vault admits the inquiry");
    assert_eq!(answer.outcome(), InquiryOutcome::Answered);
    assert_eq!(answer.statements().len(), 1);
    assert_eq!(answer.statements()[0].text(), OUT_THURSDAY);
    assert_eq!(
        answer.statements()[0].source(),
        StatementSource::CompanionOfMember,
        "the companion's answer is never the member's word",
    );
    assert_eq!(answer.valid_until(), Some(inquiry.expires_at));
    assert!(answer.answers(&inquiry));

    assert!(
        thursday.pending(&inquiry).is_none(),
        "the member is not asked"
    );
    let logged = thursday.logged(&inquiry);
    assert_eq!(
        logged.inquiry, inquiry,
        "\"Asked about you\" keeps the inquiry"
    );
    assert_eq!(logged.answer, answer);
    assert_eq!(logged.decided_by, Some(InquiryDecider::Companion));
    assert!(logged.decided_at.is_some());
}

#[test]
fn the_companion_is_shown_the_opened_scope_alone_at_the_unstamped_tier() {
    let thursday = Thursday::open(InquiryCheckInMode::AskWhenUnsure);
    thursday.put_own_claim(CHEMO);
    thursday.put_stamped_statement("Treatment on Thursday.");
    thursday.open_statement(OUT_THURSDAY);
    let inquiry = thursday.inquiry(QUESTION, InquiryKeep::Task, T0);
    let companion = ScriptedCompanion::unsure();

    thursday
        .admit(&inquiry, &companion)
        .expect("the member's vault admits the inquiry");
    assert_eq!(
        companion.shown(),
        vec![(QUESTION.to_owned(), vec![OUT_THURSDAY.to_owned()])],
        "neither the member's own claim nor a stamped statement reaches the companion",
    );
}

#[test]
fn an_unsure_companion_takes_the_inquiry_to_the_member_and_the_members_words_answer_it() {
    let thursday = Thursday::open(InquiryCheckInMode::AskWhenUnsure);
    let inquiry = thursday.inquiry(QUESTION, InquiryKeep::Task, T0);

    let answer = thursday
        .admit(&inquiry, &UnsureInquiryJudgment)
        .expect("the member's vault admits the inquiry");
    assert_eq!(answer.outcome(), InquiryOutcome::Pending);
    assert_eq!(thursday.logged(&inquiry).answer, answer);
    let pending = thursday
        .pending(&inquiry)
        .expect("the ladder took the inquiry to the member");
    assert_eq!(pending.asker, thursday.edge.guest_actor);
    assert_eq!(pending.grant_ref, thursday.edge.grant.to_hex());
    assert_eq!(pending.verb, INQUIRY_ANSWER_VERB);
    assert_eq!(pending.act, ActClass::OutboundSend);
    assert_eq!(pending.mode, CheckInMode::AskWhenUnsure);
    assert_eq!(pending.reason, WaitReason::Unsure);
    assert_eq!(pending.until, Some(inquiry.expires_at));
    assert_eq!(pending.state, PendingState::Open);

    let answer = thursday
        .answer(
            &inquiry,
            &InquiryMemberAnswer::Words(format!("  {OUT_THURSDAY} ")),
        )
        .expect("the member answers");
    assert_eq!(answer.outcome(), InquiryOutcome::Answered);
    assert_eq!(answer.statements().len(), 1);
    assert_eq!(answer.statements()[0].text(), OUT_THURSDAY);
    assert_eq!(answer.statements()[0].source(), StatementSource::MemberWord);
    assert_eq!(answer.valid_until(), Some(inquiry.expires_at));
    let pending = thursday.pending(&inquiry).expect("the check-in stays");
    assert!(
        matches!(
            pending.state,
            PendingState::Answered {
                answer: HolderAnswer::Approve,
                ..
            }
        ),
        "the member's words approve the check-in: {:?}",
        pending.state,
    );
    let logged = thursday.logged(&inquiry);
    assert_eq!(logged.answer, answer);
    assert!(
        matches!(
            logged.decided_by,
            Some(InquiryDecider::Member { principal: Some(_) })
        ),
        "the member decided: {:?}",
        logged.decided_by,
    );
    assert_eq!(
        thursday.opened(),
        vec![OUT_THURSDAY.to_owned()],
        "the answer is filed in the opened scope for next time",
    );
    assert!(
        thursday
            .answer(&inquiry, &InquiryMemberAnswer::Decline)
            .is_err(),
        "a settled inquiry takes no second answer",
    );
}

#[test]
fn a_decline_and_an_inquiry_ignored_until_it_expires_both_answer_no_answer_in_one_shape() {
    let thursday = Thursday::open(InquiryCheckInMode::AskWhenUnsure);
    let declined = thursday.inquiry("Why is owen out?", InquiryKeep::Task, T0);
    let ignored = thursday.inquiry("Why is owen out on Thursday?", InquiryKeep::Task, T0);
    for inquiry in [&declined, &ignored] {
        let answer = thursday
            .admit(inquiry, &UnsureInquiryJudgment)
            .expect("the member's vault admits the inquiry");
        assert_eq!(answer.outcome(), InquiryOutcome::Pending);
    }

    let declined_answer = thursday
        .answer(&declined, &InquiryMemberAnswer::Decline)
        .expect("the member declines");
    let declined_shape = assert_no_answer(&declined_answer, &declined);
    assert!(matches!(
        thursday.pending(&declined).expect("check-in").state,
        PendingState::Answered {
            answer: HolderAnswer::Deny,
            ..
        }
    ));

    thursday.at(ignored.expires_at);
    let ignored_answer = thursday
        .admit(&ignored, &UnsureInquiryJudgment)
        .expect("the company sends the inquiry again");
    let ignored_shape = assert_no_answer(&ignored_answer, &ignored);
    assert!(matches!(
        thursday.pending(&ignored).expect("check-in").state,
        PendingState::LetGo { .. }
    ));
    assert_eq!(
        thursday.logged(&ignored).decided_by,
        Some(InquiryDecider::LetGo)
    );

    assert_eq!(
        declined_shape, ignored_shape,
        "the member said no and no reply in time read the same"
    );
    assert!(
        thursday.opened().is_empty(),
        "nothing is filed without words"
    );
}

#[test]
fn a_repeat_returns_the_current_answer_and_opens_no_second_check_in() {
    let thursday = Thursday::open(InquiryCheckInMode::AskWhenUnsure);
    let inquiry = thursday.inquiry(QUESTION, InquiryKeep::Task, T0);
    let companion = ScriptedCompanion::unsure();
    let first = thursday
        .admit(&inquiry, &companion)
        .expect("the member's vault admits the inquiry");
    let check_in = thursday.pending(&inquiry).expect("check-in").id;

    thursday.at(T0 + 60);
    let repeat = thursday
        .admit(&inquiry, &companion)
        .expect("the company sends the inquiry again");
    assert_eq!(repeat, first, "still pending");
    assert_eq!(
        thursday.pending(&inquiry).expect("check-in").id,
        check_in,
        "the repeat waits on the same check-in",
    );
    assert_eq!(
        companion.shown().len(),
        1,
        "the companion checks an inquiry once"
    );
    assert_eq!(thursday.member.vault.inquiry_log().expect("log").len(), 1);

    let mut changed = inquiry.clone();
    changed.question = "Where is owen on Thursday?".to_owned();
    assert!(
        thursday.admit(&changed, &companion).is_err(),
        "another inquiry under the same id refuses",
    );

    let answered = thursday
        .answer(
            &inquiry,
            &InquiryMemberAnswer::Words(OUT_THURSDAY.to_owned()),
        )
        .expect("the member answers");
    let repeat = thursday
        .admit(&inquiry, &companion)
        .expect("the company sends the inquiry again");
    assert_eq!(repeat, answered, "a repeat returns the settled answer");
}

#[test]
fn a_never_ask_edge_answers_from_the_scope_and_a_copy_inquiry_still_goes_to_the_member() {
    let thursday = Thursday::open(InquiryCheckInMode::NeverAsk);
    thursday.open_statement(OUT_THURSDAY);

    let asked = thursday.inquiry(QUESTION, InquiryKeep::Task, T0);
    let answer = thursday
        .admit(&asked, &ScriptedCompanion::sure_of(&[OUT_THURSDAY]))
        .expect("the member's vault admits the inquiry");
    assert_eq!(answer.outcome(), InquiryOutcome::Answered);
    assert!(thursday.pending(&asked).is_none());

    let nothing_there = thursday.inquiry("What is owen's salary?", InquiryKeep::Task, T0);
    let answer = thursday
        .admit(&nothing_there, &ScriptedCompanion::unsure())
        .expect("the member's vault admits the inquiry");
    assert_no_answer(&answer, &nothing_there);
    assert!(
        thursday.pending(&nothing_there).is_none(),
        "the member said not to be asked"
    );
    assert_eq!(
        thursday.logged(&nothing_there).decided_by,
        Some(InquiryDecider::Companion)
    );

    let copy = thursday.inquiry(QUESTION, InquiryKeep::Copy, T0);
    let answer = thursday
        .admit(&copy, &ScriptedCompanion::sure_of(&[OUT_THURSDAY]))
        .expect("the member's vault admits the inquiry");
    assert_eq!(
        answer.outcome(),
        InquiryOutcome::Pending,
        "the edge allows keep task only: a copy inquiry goes to the member",
    );
    assert_eq!(answer.keep(), InquiryKeep::Copy);
    let pending = thursday.pending(&copy).expect("check-in");
    assert_eq!(pending.mode, CheckInMode::AlwaysAsk);
    assert_eq!(pending.reason, WaitReason::AlwaysAsk);
}

#[test]
fn an_inquiry_from_another_vault_already_expired_or_after_the_edge_is_revoked_is_refused() {
    let thursday = Thursday::open(InquiryCheckInMode::AskWhenUnsure);
    thursday.open_statement(OUT_THURSDAY);
    let companion = ScriptedCompanion::sure_of(&[OUT_THURSDAY]);

    let mut foreign = thursday.inquiry(QUESTION, InquiryKeep::Task, T0);
    foreign.from.vault = hex(&[0xbd; 32]);
    assert!(
        thursday.admit(&foreign, &companion).is_err(),
        "another vault than the edge's company",
    );

    let expired = thursday.inquiry(QUESTION, InquiryKeep::Task, T0 - INQUIRY_SECS);
    assert!(
        thursday.admit(&expired, &companion).is_err(),
        "a new inquiry already expired",
    );

    let credential = thursday.credential();
    thursday
        .member
        .vault
        .revoke_inquiry_edge(
            &thursday.member.proof,
            &thursday.member.issuer,
            thursday.edge.grant,
        )
        .expect("the member revokes the edge");
    let after = thursday.inquiry(QUESTION, InquiryKeep::Task, T0);
    assert!(
        thursday
            .member
            .vault
            .admit_inquiry(thursday.edge.grant, &credential, &after, &companion)
            .is_err(),
        "a revoked edge admits nothing",
    );

    assert!(
        thursday.member.vault.inquiry_log().expect("log").is_empty(),
        "a refused inquiry is not logged",
    );
    assert!(companion.shown().is_empty(), "nor shown to the companion");
}
