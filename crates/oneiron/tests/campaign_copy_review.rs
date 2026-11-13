// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "test-support")]
//! Campaign copy review (ARCH-0059 #copy-review, Top-15 item 13).
//!
//! A campaign that names a voice guide (a NOTE) or pins human review has its
//! copy reviewed before it sends. The host asks a judge model once per body
//! version and stores the verdict; the Gate holds the campaign leg whose copy
//! failed, or has no passing verdict, with `gate.pending.campaign_copy_review`.
//!
//! Every test drives one real campaign leg through the public door
//! (`Vault::drive_enrollment_outbound_leg`) on an unseeded vault with no
//! policy manifest. There the Gate already holds every send for external-effect
//! authority, so the leg answers `AwaitingApproval` in every case; what each
//! test reads is WHY it holds: the reason codes and receipt reasons the held
//! send's owner ask states.
//!
//! The campaign is created through the JSON door (`self.campaign.create`),
//! so the tests outside `mod judged` build on a main that has no copy review:
//! there the door ignores the new keys and the send holds for authority only.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::{AttemptRecord, ClaimOutcome, EnqueueOutcome};
use oneiron::campaign::enrollment::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, CampaignEnrollmentAttemptPayload, CampaignEnrollmentClaim,
    CampaignEnrollmentRunner, CampaignHomeNodeCandidate, CampaignProgramDraft,
    CampaignProgramOutbound, CampaignProgramStepDraft, DetectEnrollment, EnrollmentDetection,
    EnrollmentLegDrive, create_campaign_program, detect_enrollment,
    elect_campaign_home_node_designation,
};
use oneiron::campaign::register_crm_pack;
use oneiron::campaign::surface::{SurfaceCall, invoke_campaign_surface, launch_campaign};
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::outbound_consent::{OutboundResultSender, OutboundTransportResult};
use oneiron::outbound_intent_ledger::FrozenOutboundCall;
use oneiron::saved_query::{
    ClaimComparison, CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatcherSpec,
    QueryScope, SAVED_QUERY_SCHEMA_VERSION, SavedQueryEvaluator, create_saved_query,
    sweep_owner_read,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};

mod common;

const SENIORITY: &str = "profile.seniority";
const CHANNEL: &str = "email";
const MEMBER_ADDRESS: &str = "yuki@example.com";
const SENDER_ADDRESS: &str = "owen@example.com";
const HOME_NODE: u64 = 11;
const CALL_SEQ: u64 = 7;
const BODY: &[u8] = b"Hi Yuki, our new plan cuts your costs in half. Reply to book a call.";
const VOICE_GUIDE: &str = "Write plainly and warmly. Never promise numbers we cannot show.";
const PENDING_COPY_REVIEW: &str = "gate.pending.campaign_copy_review";
const COPY_REVIEW_MISSING: &str = "copy_review_missing";

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Minimal executor: detection is async and the crate is runtime-agnostic.
fn block_on<F: Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl std::task::Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// An unseeded vault with a device keystore and the CRM pack, as the
/// enrollment oracle opens it, and its owner.
fn open_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    register_crm_pack(
        &vault,
        107,
        108,
        oneiron::registry::TypeByteFamily::Productivity,
    )
    .unwrap();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    (dir, vault, owner)
}

/// The owner's voice guide NOTE.
fn voice_guide(vault: &Vault, owner: EntityId) -> EntityId {
    vault
        .create_note(
            "research",
            VOICE_GUIDE,
            WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the voice guide NOTE")
}

/// `self.campaign.create` through the JSON door, as the owner, with `extra`
/// keys merged into the body.
fn create_campaign_json(
    vault: &Vault,
    owner: EntityId,
    extra: Value,
) -> oneiron::memory::MemoryResult<Value> {
    let mut body = json!({ "name": "copy review campaign" });
    if let (Some(body), Value::Object(extra)) = (body.as_object_mut(), extra) {
        body.extend(extra);
    }
    let memory = vault.memory(owner, EdgeActorClass::Human);
    invoke_campaign_surface(
        &memory,
        SurfaceCall {
            verb: "self.campaign.create".to_owned(),
            body,
        },
    )
    .map(|reply| reply.body)
}

/// One claimed enrollment attempt on a launched campaign whose one email step
/// has a filed body, a live sender and an active contact for the member.
struct Leg {
    _dir: tempfile::TempDir,
    vault: Vault,
    campaign: EntityId,
    program: EntityId,
    step: EntityId,
    attempt: AttemptRecord,
    /// The drive's wall instant, milliseconds, after every fixture write.
    drive_at_ms: u64,
}

/// Builds the leg. `review` gives the campaign's copy-review keys, from the
/// vault and its owner (a test names a voice guide NOTE through it).
fn leg(review: impl FnOnce(&Vault, EntityId) -> Value) -> Leg {
    let (dir, vault, owner) = open_vault();
    let member = oneiron::comm::resolve_or_create_comm_party(&vault, MEMBER_ADDRESS)
        .expect("the member PERSON");
    put_claim(&vault, member, SENIORITY, "vp");
    let sender = EntityId::now();
    let identity = common::self_held_identity_in_state(
        CHANNEL,
        SENDER_ADDRESS,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::actor(owner),
        ChannelIdentityState::Active,
        1,
    );
    vault.create_channel_identity(&sender, &identity).unwrap();
    vault
        .create_counterparty_contact(
            &EntityId::now(),
            &CounterpartyContactRecord::user_introduction(sender, MEMBER_ADDRESS, 1).unwrap(),
        )
        .unwrap();
    let query = create_saved_query(
        &vault,
        owner,
        EdgeActorClass::Human,
        &CreateSavedQueryRequest {
            schema_version: SAVED_QUERY_SCHEMA_VERSION,
            scope: QueryScope::default(),
            filter: seniority_is("vp"),
            matcher: MatcherSpec::Hard {
                expression: seniority_is("vp"),
            },
            eval: EvalPolicy {
                mode: EvalMode::Manual,
                max_entities_per_wake: 8,
                max_judges_per_wake: 4,
            },
        },
        1,
    )
    .unwrap();
    let keys = review(&vault, owner);
    let created = create_campaign_json(&vault, owner, keys).expect("the campaign");
    let campaign = EntityId::from_hex(created["campaign_ref"].as_str().unwrap()).unwrap();
    let version = created["definition"]["definition_version"]
        .as_u64()
        .unwrap();
    // The JSON door stamps the campaign with the vault's clock (Unix
    // seconds); every later write is dated at or after it, or the launch
    // refuses an `updated_at` before `created_at`.
    let now = vault.now_recorded_at();
    let step = EntityId::now();
    let program = create_campaign_program(
        &vault,
        owner,
        campaign,
        CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        &CampaignProgramDraft {
            name: "copy review program".to_owned(),
            steps: vec![CampaignProgramStepDraft {
                step_ref: step,
                channel: CHANNEL.to_owned(),
                sender_ref: sender,
                basis_evidence: EntityId::now(),
                outbound: Some(CampaignProgramOutbound {
                    call_seq: CALL_SEQ,
                    verb: "send".to_owned(),
                    payload: BODY.to_vec(),
                    idempotency_supported: true,
                    subject: Some("A plan for you".to_owned()),
                }),
            }],
            audience: None,
        },
        now,
    )
    .unwrap()
    .program
    .program_ref;
    // The free door files no body; the leg sends only a body filed for the
    // step that matches the program row byte for byte.
    vault
        .save_campaign_step_body(
            program,
            step,
            CALL_SEQ,
            BODY,
            WriteActor::new(owner, EdgeActorClass::Human),
            now,
        )
        .unwrap();
    launch_campaign(&vault, owner, EdgeActorClass::Human, campaign, version, now).unwrap();
    elect_campaign_home_node_designation(
        &vault,
        &[CampaignHomeNodeCandidate::always_on_local(HOME_NODE)],
        now,
    )
    .unwrap();
    let read = sweep_owner_read(&vault, owner, EdgeActorClass::Human)
        .unwrap()
        .expect("the owner has a usable read");
    let grants = QueryScope::default();
    let evaluator = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        owner_read: &read,
        judge: None,
    };
    let event = match block_on(detect_enrollment(
        &evaluator,
        owner,
        &DetectEnrollment {
            query_ref: query.query_ref,
            campaign_ref: campaign,
            entity_ref: member,
            now: now + 1,
        },
    ))
    .unwrap()
    {
        EnrollmentDetection::Recorded(event) => *event,
        EnrollmentDetection::NoTransition => panic!("expected a recorded transition"),
    };
    let runner = CampaignEnrollmentRunner::new(&vault);
    match runner
        .enqueue(
            &CampaignEnrollmentAttemptPayload {
                membership_event_ref: event.event_ref,
                campaign_program_ref: program,
                program_step_ref: step,
            },
            None,
            now + 2,
        )
        .unwrap()
    {
        EnqueueOutcome::Enqueued(_) | EnqueueOutcome::Existing(_) => {}
        other => panic!("unexpected enqueue outcome: {other:?}"),
    }
    let attempt = match runner
        .claim_if_home(HOME_NODE, format!("worker:{HOME_NODE}"), now + 3)
        .unwrap()
    {
        CampaignEnrollmentClaim::Queue(ClaimOutcome::Claimed(record)) => record,
        other => panic!("expected a claim, got {other:?}"),
    };
    Leg {
        _dir: dir,
        vault,
        campaign,
        program,
        step,
        attempt,
        drive_at_ms: (now + 4) * 1000,
    }
}

fn seniority_is(value: &str) -> FilterAst {
    FilterAst::Claim {
        predicate: SENIORITY.to_owned(),
        cmp: ClaimComparison::Eq,
        value: json!(value),
    }
}

fn put_claim(vault: &Vault, subject: EntityId, predicate: &str, value: &str) {
    vault
        .put_claim(
            &EntityId::now(),
            &ClaimBody::new(
                predicate,
                ClaimSubject::Entity(subject),
                rmpv::Value::from(value),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )
            .expect("fixture"),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();
}

/// The transport behind the leg. Every case here holds at the Gate, so a
/// send is a failure.
struct NoSend;

impl OutboundResultSender for NoSend {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        panic!("the copy-review fixture holds every send before transport")
    }
}

/// Drives the leg; it must be held for the owner's press.
fn drive_held(leg: &Leg) {
    let drive = leg
        .vault
        .drive_enrollment_outbound_leg(HOME_NODE, &leg.attempt, &mut NoSend, leg.drive_at_ms)
        .unwrap();
    assert!(
        matches!(drive, EnrollmentLegDrive::AwaitingApproval { .. }),
        "the leg reaches the Gate and is held for the owner's press: {drive:?}"
    );
}

/// The state of the held send's owner ask: its reason codes, receipt reasons
/// and copy-review facts.
fn held_ask_state(vault: &Vault) -> Value {
    vault
        .decision_asks(None, 100, true)
        .unwrap()
        .into_iter()
        .filter_map(|ask| ask.pack_state)
        .find(|state| state.get("gate_reason_codes").is_some())
        .expect("the held campaign send's owner ask")
}

fn strings(state: &Value, key: &str) -> Vec<String> {
    state[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is a list: {state}"))
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// The Gate's copy-review stage
// ---------------------------------------------------------------------------

/// A campaign that names a voice guide holds a send no review covers yet,
/// and says so. On main the guide is dropped and the send holds only for
/// external-effect authority.
#[test]
fn a_voice_guided_send_with_no_review_is_held_for_copy_review() {
    let leg = leg(|vault, owner| json!({ "voice_guide_ref": voice_guide(vault, owner).to_hex() }));
    drive_held(&leg);
    let state = held_ask_state(&leg.vault);
    assert!(
        strings(&state, "gate_reason_codes").contains(&PENDING_COPY_REVIEW.to_owned()),
        "the send is held for copy review: {state}"
    );
    assert!(
        strings(&state, "gate_receipt_reasons").contains(&COPY_REVIEW_MISSING.to_owned()),
        "the receipt says no review covers the copy: {state}"
    );
}

/// A campaign pinned to human review holds every send for the owner's press.
#[test]
fn a_human_review_campaign_holds_its_send_for_the_owner() {
    let leg = leg(|_, _| json!({ "copy_review": "human" }));
    drive_held(&leg);
    let state = held_ask_state(&leg.vault);
    assert!(
        strings(&state, "gate_reason_codes").contains(&PENDING_COPY_REVIEW.to_owned()),
        "a human-review campaign's send is held for copy review: {state}"
    );
    assert_eq!(
        state["copy_review"]["mode"], "human",
        "the owner ask names the pinned human review: {state}"
    );
}

/// A campaign with no voice guide and no human pin is not governed: its send
/// holds only for what held it before copy review existed.
#[test]
fn a_campaign_without_a_voice_guide_is_not_held_for_copy_review() {
    let leg = leg(|_, _| json!({}));
    drive_held(&leg);
    let state = held_ask_state(&leg.vault);
    assert!(
        !strings(&state, "gate_reason_codes").contains(&PENDING_COPY_REVIEW.to_owned()),
        "an ungoverned campaign is not held for copy review: {state}"
    );
}

/// A voice guide must be a NOTE: the review reads its text.
#[test]
fn a_voice_guide_that_is_not_a_note_is_refused() {
    let (_dir, vault, owner) = open_vault();
    let person =
        oneiron::comm::resolve_or_create_comm_party(&vault, MEMBER_ADDRESS).expect("a PERSON");
    let refused =
        create_campaign_json(&vault, owner, json!({ "voice_guide_ref": person.to_hex() }));
    assert!(
        refused.is_err(),
        "a PERSON is not a voice guide: {refused:?}"
    );
}

// ---------------------------------------------------------------------------
// The judge (new API)
// ---------------------------------------------------------------------------

mod judged {
    use super::*;
    use oneiron::campaign::enrollment::{
        CAMPAIGN_COPY_REVIEW_DIAL, CampaignCopyReviewDecisions, CampaignCopyReviewWording,
        CopyReviewOutcome, campaign_program_step,
    };
    use oneiron::llm::decision::{
        AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder,
        DecisionProvider, DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision,
        ProviderPin,
    };
    use oneiron::note::{NoteProgramEdit, NoteProgramEditOutcome, NoteReadRequest};
    use oneiron::registry::ENTITY_TYPE_PERSON;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The judge's one model rung: whether the copy follows the guide, and
    /// the reason class it answers with.
    struct CopyJudge {
        follows: bool,
        reason: &'static str,
    }

    impl DecisionProvider for CopyJudge {
        fn pin(&self) -> ProviderPin {
            ProviderPin {
                rung: DecisionRung::Local,
                model: "copy-review-fixture".into(),
                version: "1".into(),
            }
        }

        fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
            let (answer, probability) = match call.question.contract {
                AnswerContract::Choice { .. } => {
                    (DecisionAnswer::Choice(self.reason.to_owned()), 0.9)
                }
                _ => (
                    DecisionAnswer::Noul(self.follows),
                    if self.follows { 0.9 } else { 0.1 },
                ),
            };
            Ok(ProviderDecision {
                answer,
                probability: Some(probability),
                paired: None,
                person: None,
                served: None,
                cost_per_thousand: None,
            })
        }
    }

    struct NoPerson;

    impl HumanDecisionQueue for NoPerson {
        fn queue(&self, _: HumanDecisionRequest) -> oneiron::Result<()> {
            Err(oneiron::Error::InvalidConfig(
                "a copy review queues no person ask".into(),
            ))
        }
    }

    /// The copy review's decision path with `judge` as its only model rung.
    /// The default bands are unlearned, so the first rung's answer stands.
    fn decisions(judge: &dyn DecisionProvider) -> CampaignCopyReviewDecisions<'_> {
        CampaignCopyReviewDecisions {
            ladder: DecisionLadder {
                rule: None,
                local: Some(judge),
                system_one: None,
                escalation: None,
                big: None,
                human: &NoPerson,
                human_pin: ProviderPin {
                    rung: DecisionRung::Human,
                    model: "test-queue".into(),
                    version: "1".into(),
                },
                ask_to: None,
                paired: None,
                person: None,
                presence: None,
                correlation: None,
            },
            dial: CAMPAIGN_COPY_REVIEW_DIAL,
            bands: DecisionBandPolicy::default(),
            wording: CampaignCopyReviewWording {
                follows_voice: "Does this message follow the voice guide?".to_owned(),
                reason: "What most decides whether it keeps to the guide?".to_owned(),
            },
            budget: std::time::Duration::from_secs(3600),
        }
    }

    fn voice_guided_leg() -> Leg {
        leg(|vault, owner| json!({ "voice_guide_ref": voice_guide(vault, owner).to_hex() }))
    }

    /// The census case: an off-voice draft is held, with its reason, and
    /// nothing is sent.
    #[test]
    fn an_off_voice_draft_is_held_with_its_reason() {
        let leg = voice_guided_leg();
        let judge = CopyJudge {
            follows: false,
            reason: "claims",
        };
        let outcome = leg
            .vault
            .review_enrollment_copy(&leg.attempt, &decisions(&judge))
            .unwrap();
        let CopyReviewOutcome::Reviewed(verdict) = outcome else {
            panic!("the judge reviews the new body: {outcome:?}");
        };
        assert!(!verdict.passed, "the judge failed the copy: {verdict:?}");
        assert_eq!(verdict.reason, "claims");
        let step = campaign_program_step(&leg.vault, leg.program, leg.step)
            .unwrap()
            .expect("the step");
        assert_eq!(
            leg.vault
                .campaign_copy_review_verdict(leg.campaign, &step)
                .unwrap()
                .map(|stored| stored.reason),
            Some("claims".to_owned()),
            "the verdict is stored with its reason"
        );
        drive_held(&leg);
        let state = held_ask_state(&leg.vault);
        assert!(
            strings(&state, "gate_reason_codes").contains(&PENDING_COPY_REVIEW.to_owned()),
            "the off-voice send is held for copy review: {state}"
        );
        assert!(
            strings(&state, "gate_receipt_reasons").contains(&"copy_review_failed".to_owned()),
            "the receipt says the copy failed its review: {state}"
        );
        assert_eq!(state["copy_review"]["passed"], false, "{state}");
        assert_eq!(
            state["copy_review"]["reason"], "claims",
            "the owner ask states the judge's reason: {state}"
        );
        // The verdict is cached: the same body is not judged twice.
        let again = leg
            .vault
            .review_enrollment_copy(&leg.attempt, &decisions(&judge))
            .unwrap();
        assert!(
            matches!(again, CopyReviewOutcome::Cached(_)),
            "a stored verdict covers the same body: {again:?}"
        );
    }

    /// Copy the judge passes is not held by copy review.
    #[test]
    fn a_passing_draft_is_not_held_by_copy_review() {
        let leg = voice_guided_leg();
        let judge = CopyJudge {
            follows: true,
            reason: "on_voice",
        };
        let outcome = leg
            .vault
            .review_enrollment_copy(&leg.attempt, &decisions(&judge))
            .unwrap();
        assert!(
            matches!(&outcome, CopyReviewOutcome::Reviewed(verdict) if verdict.passed),
            "the judge passes the copy: {outcome:?}"
        );
        drive_held(&leg);
        let state = held_ask_state(&leg.vault);
        assert!(
            !strings(&state, "gate_reason_codes").contains(&PENDING_COPY_REVIEW.to_owned()),
            "passing copy is not held for copy review: {state}"
        );
    }

    /// A judge that passes every body and counts how often it is asked.
    struct CountingJudge {
        inner: CopyJudge,
        calls: AtomicUsize,
    }

    impl CountingJudge {
        fn passing() -> Self {
            Self {
                inner: CopyJudge {
                    follows: true,
                    reason: "on_voice",
                },
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl DecisionProvider for CountingJudge {
        fn pin(&self) -> ProviderPin {
            self.inner.pin()
        }

        fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.decide(call)
        }
    }

    /// A voice-guided leg whose guide is the NOTE `guide` makes on the leg's
    /// vault, and that NOTE.
    fn leg_with_guide(guide: impl FnOnce(&Vault, EntityId) -> EntityId) -> (Leg, EntityId) {
        let made = Cell::new(None);
        let leg = leg(|vault, owner| {
            let note = guide(vault, owner);
            made.set(Some(note));
            json!({ "voice_guide_ref": note.to_hex() })
        });
        let note = made.take().expect("the leg names its voice guide");
        (leg, note)
    }

    /// An edit that appends `words` to the NOTE's text.
    fn append(vault: &Vault, note: EntityId, words: &str) -> NoteProgramEdit {
        let doc = vault
            .note_program_document(note)
            .expect("read the NOTE document")
            .expect("the NOTE document");
        NoteProgramEdit::InsertAfter {
            anchor: doc.anchor(doc.text().chars().count()).expect("end anchor"),
            text: words.to_owned(),
        }
    }

    /// A passing verdict covers its body only at the guide version it was
    /// judged at. The owner edits the guide after the review passed, and no
    /// review runs again (the judge abstains or is unavailable): the send is
    /// held for copy review, not sent under the old guide's verdict.
    #[test]
    fn a_voice_guide_edited_after_a_passing_review_holds_the_send() {
        let (leg, guide) = leg_with_guide(voice_guide);
        let judge = CountingJudge::passing();
        let outcome = leg
            .vault
            .review_enrollment_copy(&leg.attempt, &decisions(&judge))
            .unwrap();
        assert!(
            matches!(&outcome, CopyReviewOutcome::Reviewed(verdict) if verdict.passed),
            "the judge passes the copy under the first guide: {outcome:?}"
        );
        let first_review = judge.calls();
        let owner = leg.vault.ensure_embedded_owner_actor().unwrap();
        let edited = leg
            .vault
            .edit_note(
                guide,
                &append(&leg.vault, guide, " Never name a price."),
                WriteActor::new(owner, EdgeActorClass::Human),
            )
            .expect("the owner edits the voice guide");
        assert!(
            matches!(edited, NoteProgramEditOutcome::Edited { .. }),
            "the owner's edit of the guide lands: {edited:?}"
        );
        drive_held(&leg);
        let state = held_ask_state(&leg.vault);
        assert!(
            strings(&state, "gate_reason_codes").contains(&PENDING_COPY_REVIEW.to_owned()),
            "a review of the old guide does not cover the send: {state}"
        );
        assert!(
            strings(&state, "gate_receipt_reasons").contains(&COPY_REVIEW_MISSING.to_owned()),
            "the receipt says no review covers the copy: {state}"
        );
        // Reviewed again, the copy is judged against the edited guide.
        let again = leg
            .vault
            .review_enrollment_copy(&leg.attempt, &decisions(&judge))
            .unwrap();
        assert!(
            matches!(again, CopyReviewOutcome::Reviewed(_)),
            "the edited guide asks the judge again: {again:?}"
        );
        assert!(
            judge.calls() > first_review,
            "the judge is asked again for the edited guide"
        );
    }

    const DIARY_ENTRY: &str = "A private diary entry of an agent, shared with no one.";

    /// The judge reads the voice guide only as the campaign's owner reads
    /// it. A campaign names an agent's diary entry, which no Grant opens to
    /// the owner, as its guide: no judge is asked (a provider never sees the
    /// entry), and the send is held for copy review.
    #[test]
    fn a_voice_guide_its_owner_cannot_read_asks_no_judge() {
        let (leg, guide) = leg_with_guide(|vault, _owner| {
            let agent = EntityId::now();
            vault
                .put_entity(
                    &agent,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"agent",
                )
                .expect("the agent PERSON");
            vault
                .create_note(
                    "diary",
                    DIARY_ENTRY,
                    WriteActor::new(agent, EdgeActorClass::Agent),
                )
                .expect("the agent's diary entry")
        });
        let owner = leg.vault.ensure_embedded_owner_actor().unwrap();
        // The fixture's premise, on main as well: the entry's text is stored,
        // and the owner's scoped NOTE read does not admit it.
        assert_eq!(
            leg.vault.note_text(guide).expect("the entry's stored text"),
            DIARY_ENTRY
        );
        let read = leg
            .vault
            .memory(owner, EdgeActorClass::Human)
            .read_note(&NoteReadRequest {
                note_ref: guide.to_hex(),
                reason: Some("copy review fixture".to_owned()),
                version: None,
                spans: Vec::new(),
            });
        let admitted = matches!(&read, Ok(result) if result.value.is_some());
        assert!(
            !admitted,
            "the owner's scoped read does not admit the agent's diary entry"
        );
        let judge = CountingJudge::passing();
        let outcome = leg
            .vault
            .review_enrollment_copy(&leg.attempt, &decisions(&judge))
            .unwrap();
        assert_eq!(
            judge.calls(),
            0,
            "no judge is asked about a guide the owner cannot read: {outcome:?}"
        );
        assert!(
            !matches!(
                outcome,
                CopyReviewOutcome::Reviewed(_) | CopyReviewOutcome::Cached(_)
            ),
            "no verdict covers the copy: {outcome:?}"
        );
        drive_held(&leg);
        let state = held_ask_state(&leg.vault);
        assert!(
            strings(&state, "gate_reason_codes").contains(&PENDING_COPY_REVIEW.to_owned()),
            "the send is held for copy review: {state}"
        );
        assert!(
            strings(&state, "gate_receipt_reasons").contains(&COPY_REVIEW_MISSING.to_owned()),
            "the receipt says no review covers the copy: {state}"
        );
    }
}
