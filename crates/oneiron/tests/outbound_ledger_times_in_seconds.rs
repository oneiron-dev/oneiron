// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "test-support")]
//! Outbound ledger times in seconds (FIX [OUTBOUND-LEDGER-MS-FIELDS-HOLD-DISPATCH-SECONDS]).
//!
//! The intent ledger's `created_ms` / `updated_ms` / `accounted_at_ms` hold Unix seconds on
//! every path, though the names still say `_ms`. Before the fix the campaign enrollment leg
//! and its derived request stamped wall milliseconds, so an admitted send's row read as if
//! written in the far future to every reader (admission ceilings, the booking mid-call wait),
//! which already reads seconds.
//!
//! Each test drives one writer through a public door with a real millisecond clock and reads
//! the touched row back through the public `intent_ledger_records`, asserting every time is
//! below the seconds ceiling. A pre-fix millisecond stamp is far above it, so each test fails
//! on main and passes on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test outbound_ledger_times_in_seconds`.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::{AttemptRecord, ClaimOutcome, EnqueueOutcome};
use oneiron::campaign::enrollment::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, CampaignEnrollmentAttemptPayload, CampaignEnrollmentClaim,
    CampaignEnrollmentEvent, CampaignEnrollmentRunner, CampaignHomeNodeCandidate,
    CampaignProgramDraft, CampaignProgramOutbound, CampaignProgramStepDraft, DetectEnrollment,
    EnrollmentDetection, EnrollmentLegDrive, create_campaign_program,
    derive_enrollment_outbound_request, detect_enrollment, elect_campaign_home_node_designation,
};
use oneiron::campaign::register_crm_pack;
use oneiron::campaign::surface::{SurfaceCall, invoke_campaign_surface, launch_campaign};
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::consent::AuthenticatedOwner;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::outbound_consent::{OutboundResultSender, OutboundTransportResult, RawOutboundResult};
use oneiron::outbound_intent_ledger::{
    FrozenOutboundCall, OutboundSendOutcome, intent_ledger_records,
};
use oneiron::saved_query::{
    ClaimComparison, CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatcherSpec,
    QueryScope, SAVED_QUERY_SCHEMA_VERSION, SavedQueryEvaluator, create_saved_query,
    sweep_owner_read,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};

mod common;

/// Year 2286 in seconds; any millisecond time after April 1970 is above it.
const SECONDS_CEILING: u64 = 10_000_000_000;

const SENIORITY: &str = "profile.seniority";
const CHANNEL: &str = "email";
const MEMBER_ADDRESS: &str = "yuki@example.com";
const SENDER_ADDRESS: &str = "owen@example.com";
const HOME_NODE: u64 = 11;
const CALL_SEQ: u64 = 7;
const BODY: &[u8] = b"Hi Yuki, our new plan cuts your costs in half. Reply to book a call.";

// ---------------------------------------------------------------------------
// Fixture (copied from `campaign_bulk_send_mode.rs`)
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
    let mut body = json!({ "name": "ledger seconds campaign" });
    if let (Some(body), Value::Object(extra)) = (body.as_object_mut(), extra) {
        body.extend(extra);
    }
    surface(vault, owner, "self.campaign.create", body)
}

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
    // The gate governs a campaign send under the step's sender, this
    // channel identity: a stored non-agent entity, so the send policy's
    // Auto ceiling for it applies unclamped. No PERSON row is seeded here:
    // the identity door refuses an id that already has an entity row.
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
            name: "ledger seconds program".to_owned(),
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
    claimed_enrollment(base, campaign, program, step, member).0
}

/// As [`claimed_attempt`], with the detected event and the payload the
/// attempt carries.
fn claimed_enrollment(
    base: &Base,
    campaign: EntityId,
    program: EntityId,
    step: EntityId,
    member: EntityId,
) -> (
    AttemptRecord,
    CampaignEnrollmentEvent,
    CampaignEnrollmentAttemptPayload,
) {
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
    let payload = CampaignEnrollmentAttemptPayload {
        membership_event_ref: event.event_ref,
        campaign_program_ref: program,
        program_step_ref: step,
    };
    match runner.enqueue(&payload, None, now + 2).unwrap() {
        EnqueueOutcome::Enqueued(_) | EnqueueOutcome::Existing(_) => {}
        other => panic!("unexpected enqueue outcome: {other:?}"),
    }
    match runner
        .claim_if_home(HOME_NODE, format!("worker:{HOME_NODE}"), now + 3)
        .unwrap()
    {
        CampaignEnrollmentClaim::Queue(ClaimOutcome::Claimed(record)) => (record, event, payload),
        other => panic!("expected a claim, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Admission (a Gate-held send leaves no ledger row, so the leg test admits)
// ---------------------------------------------------------------------------

/// The transport behind the admitted leg: the Gate admits the send, so the
/// frozen bytes reach the provider, which acknowledges them at once.
struct AckSend;

impl OutboundResultSender for AckSend {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        OutboundTransportResult {
            outcome: OutboundSendOutcome::Acked,
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

fn owner_proof(base: &Base) -> AuthenticatedOwner {
    base.vault
        .authenticate_owner(
            base.owner,
            &base.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the owner's proof")
}

/// The owner's standing grant for the sender's sends.
fn permit_send(base: &Base) {
    base.vault
        .mint_standing_outbound_grant(
            &owner_proof(base),
            EntityId::now(),
            &GrantMintIntent {
                principal_ref: base.sender.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "create".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: "send".to_owned(),
                },
            },
        )
        .expect("the owner grants the sender's sends");
}

/// The explicit policy the admitted leg runs under (copied from the
/// send-hygiene oracle's sending vault): an Auto ceiling and an
/// `external:send` grant on the channel for the sender, the way the in-crate
/// enrollment tests reach the ledger.
fn send_grant_manifest(actor: EntityId, channel: &str, verb: &str) -> Vec<u8> {
    let actor_ref = actor.to_hex();
    let manifest = serde_json::json!({
        "schema_version": "1.2",
        "pack_id": "ledger-seconds-send",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [
            {"actor_class": "agent", "actor_ref": actor_ref, "ceiling": "auto"}
        ],
        "scoped_grants": [{
            "actor_ref": actor_ref,
            "effector": format!("external:{verb}"),
            "scope": oneiron::test_support::effect_preset(),
            "selectors": {"channel": channel},
        }],
    });
    rmp_serde::to_vec_named(&manifest).unwrap()
}

/// Admits the sender's campaign send: the policy first, so the standing
/// grant binds to the frontier the Gate reads at the drive.
fn admit_sender(base: &Base) {
    let manifest = send_grant_manifest(base.sender, CHANNEL, "send");
    oneiron::test_support::put_policy_manifest_bytes(&base.vault, EntityId::now(), &manifest)
        .expect("install the send policy");
    permit_send(base);
}

// ---------------------------------------------------------------------------
// The times
// ---------------------------------------------------------------------------

/// An admitted campaign enrollment leg freezes its ledger row in Unix seconds: the
/// dispatch path hands the chokepoint `now_ms / 1_000`, and the row's creation,
/// update and budget-accounting clocks all read below the seconds ceiling. Before
/// the fix the leg handed wall milliseconds, so every one of the three times read
/// far above it.
#[test]
fn campaign_enrollment_leg_admitted_send_stamps_seconds() {
    let base = base();
    let member = add_member(&base, MEMBER_ADDRESS);
    let step = EntityId::now();
    let (campaign, program) = launched_campaign(&base, json!({}), step);
    let attempt = claimed_attempt(&base, campaign, program, step, member);
    admit_sender(&base);
    let at_ms = (base.vault.now_recorded_at() + 4) * 1000;
    assert!(
        at_ms > SECONDS_CEILING,
        "the drive's wall clock is milliseconds far above the seconds ceiling: {at_ms}"
    );
    let drive = base
        .vault
        .drive_enrollment_outbound_leg(HOME_NODE, &attempt, &mut AckSend, at_ms)
        .expect("the admitted leg drives");
    assert!(
        matches!(drive, EnrollmentLegDrive::Dispatched),
        "the admitted send dispatches instead of holding: {drive:?}"
    );
    let ledger = intent_ledger_records(&base.vault).expect("read the ledger");
    assert_eq!(ledger.len(), 1, "one admitted send freezes one row");
    let record = &ledger[0];
    assert!(
        record.created_ms < SECONDS_CEILING
            && record.updated_ms < SECONDS_CEILING
            && record.budget_accounting.accounted_at_ms < SECONDS_CEILING,
        "the admitted row's times are seconds: created {} updated {} accounted {}",
        record.created_ms,
        record.updated_ms,
        record.budget_accounting.accounted_at_ms,
    );
}

/// The derived enrollment request carries Unix seconds: `derive_enrollment_outbound_request`
/// hands `OutboundCallRequest::new` `now_ms / 1_000` for a wall-millisecond `now_ms`, so the
/// request's clock reads below the seconds ceiling. Before the fix it handed the milliseconds
/// through, so the request read far above it.
#[test]
fn derived_enrollment_request_stamps_seconds() {
    let base = base();
    let member = add_member(&base, MEMBER_ADDRESS);
    let step = EntityId::now();
    let (campaign, program) = launched_campaign(&base, json!({}), step);
    let (_attempt, event, payload) = claimed_enrollment(&base, campaign, program, step, member);
    let at_ms = (base.vault.now_recorded_at() + 4) * 1000;
    assert!(
        at_ms > SECONDS_CEILING,
        "the derive call's wall clock is milliseconds far above the seconds ceiling: {at_ms}"
    );
    let request = derive_enrollment_outbound_request(&base.vault, &payload, &event, at_ms)
        .expect("derive the member's outward call")
        .expect("the member's outward call");
    assert!(
        request.now_ms < SECONDS_CEILING,
        "the derived request's clock is seconds: {}",
        request.now_ms,
    );
}
