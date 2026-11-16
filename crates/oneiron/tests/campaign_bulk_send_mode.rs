// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "test-support")]
//! Campaign send mode (ARCH-0059 #opt-out; FIX [CAMPAIGN-BULK-SEND-MODE],
//! Engine ruling L3-02-SEND-MODE-SCOPE = A).
//!
//! A campaign's mail goes out one_to_one (a genuine 1:1 mail: the plain
//! opt-out line, no bulk header) or bulk (List-Unsubscribe, or it blocks).
//! The mode rides the campaign create and update surface beside
//! `copy_review`, and a campaign that names none sends one_to_one, as every
//! campaign did before.
//!
//! Every campaign here is written and read through the JSON door
//! (`self.campaign.create` / `.read` / `.update`), so the tests build on a
//! main that has no send mode: there the door ignores the key.

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

/// An unseeded vault with a device keystore and the CRM pack, and its owner.
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

/// One campaign surface call through the JSON door, as the owner.
fn surface(
    vault: &Vault,
    owner: EntityId,
    verb: &str,
    body: Value,
) -> oneiron::memory::MemoryResult<Value> {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    invoke_campaign_surface(
        &memory,
        SurfaceCall {
            verb: verb.to_owned(),
            body,
        },
    )
    .map(|reply| reply.body)
}

/// `self.campaign.create` with `extra` keys merged into the body.
fn create(vault: &Vault, owner: EntityId, extra: Value) -> oneiron::memory::MemoryResult<Value> {
    let mut body = json!({ "name": "send mode campaign" });
    if let (Some(body), Value::Object(extra)) = (body.as_object_mut(), extra) {
        body.extend(extra);
    }
    surface(vault, owner, "self.campaign.create", body)
}

fn read(vault: &Vault, owner: EntityId, campaign_ref: &str) -> Value {
    surface(
        vault,
        owner,
        "self.campaign.read",
        json!({ "campaign_ref": campaign_ref }),
    )
    .expect("the owner reads its campaign")
}

fn campaign_ref(record: &Value) -> String {
    record["campaign_ref"]
        .as_str()
        .expect("a campaign_ref")
        .to_owned()
}

fn send_mode(record: &Value) -> &Value {
    &record["definition"]["send_mode"]
}

// ---------------------------------------------------------------------------
// The field
// ---------------------------------------------------------------------------

/// A bulk campaign reads back bulk; a campaign that names no mode reads back
/// one_to_one; an update moves the mode, and an update that names none keeps
/// it; an unknown mode is refused.
#[test]
fn bulk_campaign_create_read_round_trips_send_mode() {
    let (_dir, vault, owner) = open_vault();

    let bulk = create(&vault, owner, json!({ "send_mode": "bulk" })).expect("a bulk campaign");
    assert_eq!(send_mode(&bulk), "bulk", "create answers the mode: {bulk}");
    let bulk_ref = campaign_ref(&bulk);
    let stored = read(&vault, owner, &bulk_ref);
    assert_eq!(
        send_mode(&stored),
        "bulk",
        "the stored mode reads back: {stored}"
    );

    let plain = create(&vault, owner, json!({})).expect("a campaign with no mode");
    assert_eq!(
        send_mode(&read(&vault, owner, &campaign_ref(&plain))),
        "one_to_one",
        "a campaign that names no mode sends one_to_one: {plain}"
    );

    let version = stored["definition"]["definition_version"].as_u64().unwrap();
    let moved = surface(
        &vault,
        owner,
        "self.campaign.update",
        json!({
            "campaign_ref": bulk_ref,
            "expected_definition_version": version,
            "name": "send mode campaign",
            "send_mode": "one_to_one",
        }),
    )
    .expect("the owner moves the mode");
    assert_eq!(
        send_mode(&moved),
        "one_to_one",
        "update moves the mode: {moved}"
    );

    let version = moved["definition"]["definition_version"].as_u64().unwrap();
    let kept = surface(
        &vault,
        owner,
        "self.campaign.update",
        json!({
            "campaign_ref": bulk_ref,
            "expected_definition_version": version,
            "name": "renamed send mode campaign",
        }),
    )
    .expect("an update that names no mode");
    assert_eq!(
        send_mode(&read(&vault, owner, &bulk_ref)),
        "one_to_one",
        "an update that names no mode keeps the stored one: {kept}"
    );

    let refused = create(&vault, owner, json!({ "send_mode": "mass" }));
    assert!(
        refused
            .as_ref()
            .is_err_and(|err| format!("{err:?}").contains("send_mode")),
        "an unknown send mode is refused by name: {refused:?}"
    );
}

// ---------------------------------------------------------------------------
// The leg (ARCH-0059:256, "A bulk send without List-Unsubscribe blocks.")
// ---------------------------------------------------------------------------

/// The vault, its owner, the step's sender identity and the saved query its
/// members match.
struct Base {
    dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    sender: EntityId,
    query: EntityId,
}

fn base() -> Base {
    let (dir, vault, owner) = open_vault();
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
    .unwrap()
    .query_ref;
    Base {
        dir,
        vault,
        owner,
        sender,
        query,
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

/// A member the query matches: a comm PERSON at `address`, with an active
/// contact from the sender.
fn add_member(base: &Base, address: &str) -> EntityId {
    let member = oneiron::comm::resolve_or_create_comm_party(&base.vault, address)
        .expect("the member PERSON");
    put_claim(&base.vault, member, SENIORITY, "vp");
    base.vault
        .create_counterparty_contact(
            &EntityId::now(),
            &CounterpartyContactRecord::user_introduction(base.sender, address, 1).unwrap(),
        )
        .unwrap();
    member
}

/// A launched campaign, created through the JSON door with `keys`, with one
/// program of one email step from the sender, its body filed, and this node
/// its home node.
fn launched_campaign(base: &Base, keys: Value, step: EntityId) -> (EntityId, EntityId) {
    let (vault, owner) = (&base.vault, base.owner);
    let created = create(vault, owner, keys).expect("the campaign");
    let campaign = EntityId::from_hex(created["campaign_ref"].as_str().unwrap()).unwrap();
    let version = created["definition"]["definition_version"]
        .as_u64()
        .unwrap();
    // The JSON door stamps the campaign with the vault's clock; every later
    // write is dated at or after it.
    let now = vault.now_recorded_at();
    let draft = CampaignProgramStepDraft {
        step_ref: step,
        channel: CHANNEL.to_owned(),
        sender_ref: base.sender,
        basis_evidence: EntityId::now(),
        outbound: Some(CampaignProgramOutbound {
            call_seq: CALL_SEQ,
            verb: "send".to_owned(),
            payload: BODY.to_vec(),
            idempotency_supported: true,
            subject: Some("A plan for you".to_owned()),
        }),
        arm: None,
    };
    let program = create_campaign_program(
        vault,
        owner,
        campaign,
        CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        &CampaignProgramDraft {
            name: "send mode program".to_owned(),
            steps: vec![draft],
            audience: None,
        },
        now,
    )
    .unwrap()
    .program
    .program_ref;
    // The leg sends only a body filed for the step, matching the program row.
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
    launch_campaign(vault, owner, EdgeActorClass::Human, campaign, version, now).unwrap();
    elect_campaign_home_node_designation(
        vault,
        &[CampaignHomeNodeCandidate::always_on_local(HOME_NODE)],
        now,
    )
    .unwrap();
    (campaign, program)
}

/// `member`'s enrollment at `step`, detected, enqueued and claimed by this
/// node.
fn claimed_attempt(
    base: &Base,
    campaign: EntityId,
    program: EntityId,
    step: EntityId,
    member: EntityId,
) -> AttemptRecord {
    let vault = &base.vault;
    let now = vault.now_recorded_at();
    let read = sweep_owner_read(vault, base.owner, EdgeActorClass::Human)
        .unwrap()
        .expect("the owner has a usable read");
    let grants = QueryScope::default();
    let evaluator = SavedQueryEvaluator {
        vault,
        owner_grants: &grants,
        owner_read: &read,
        judge: None,
    };
    let event = match block_on(detect_enrollment(
        &evaluator,
        base.owner,
        &DetectEnrollment {
            query_ref: base.query,
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
    let runner = CampaignEnrollmentRunner::new(vault);
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
    match runner
        .claim_if_home(HOME_NODE, format!("worker:{HOME_NODE}"), now + 3)
        .unwrap()
    {
        CampaignEnrollmentClaim::Queue(ClaimOutcome::Claimed(record)) => record,
        other => panic!("expected a claim, got {other:?}"),
    }
}

/// The transport behind the leg. Nothing here may reach it: a bulk send
/// blocks before the chokepoint, and the Gate holds a 1:1 send on this
/// unseeded vault for the owner's press.
struct NoSend;

impl OutboundResultSender for NoSend {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        panic!("no campaign send reaches transport in this fixture")
    }
}

/// Drives one claimed email leg of a campaign created with `keys`.
fn drive_leg(
    keys: Value,
) -> (
    Base,
    Result<EnrollmentLegDrive, oneiron::outbound_intent_ledger::IntentLedgerError>,
) {
    let base = base();
    let member = add_member(&base, MEMBER_ADDRESS);
    let step = EntityId::now();
    let (campaign, program) = launched_campaign(&base, keys, step);
    let attempt = claimed_attempt(&base, campaign, program, step, member);
    let at_ms = (base.vault.now_recorded_at() + 4) * 1000;
    let drive = base
        .vault
        .drive_enrollment_outbound_leg(HOME_NODE, &attempt, &mut NoSend, at_ms);
    (base, drive)
}

/// Whether the vault holds a Gate-held send's owner ask.
fn holds_a_send(vault: &Vault) -> bool {
    vault
        .decision_asks(None, 100, true)
        .unwrap()
        .into_iter()
        .filter_map(|ask| ask.pack_state)
        .any(|state| state.get("gate_reason_codes").is_some())
}

/// A bulk campaign's email send that carries no List-Unsubscribe blocks: the
/// leg refuses it by that rule before the chokepoint, so nothing is frozen,
/// held or sent. The same leg of a 1:1 campaign reaches the Gate, which
/// holds it for the owner's press on this unseeded vault.
#[test]
fn bulk_send_without_list_unsubscribe_is_refused() {
    let (bulk, drive) = drive_leg(json!({ "send_mode": "bulk" }));
    let refusal = drive.as_ref().err().map(|err| err.to_string());
    assert!(
        refusal
            .as_deref()
            .is_some_and(|reason| reason.contains("List-Unsubscribe")),
        "a bulk email send without List-Unsubscribe is refused by that rule: {drive:?}"
    );
    assert!(
        !holds_a_send(&bulk.vault),
        "a blocked bulk send holds no owner ask: nothing reached the Gate"
    );

    let (plain, drive) = drive_leg(json!({}));
    assert!(
        matches!(drive, Ok(EnrollmentLegDrive::AwaitingApproval { .. })),
        "a 1:1 campaign's send reaches the Gate and is held: {drive:?}"
    );
    assert!(holds_a_send(&plain.vault), "the 1:1 send's owner ask");
}
