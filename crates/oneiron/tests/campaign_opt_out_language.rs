// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "test-support")]
// The sealing is crate-private; `oneiron::test_doors` reaches it, and only
// the test command's `--cfg oneiron_test_support` compiles that door.
#![cfg(oneiron_test_support)]
//! The 1:1 campaign email's opt-out line is in the member's language (FIX
//! [CAMPAIGN-OPT-OUT-LINE-LOCALE], filed under Engine ruling
//! L3-02-SEND-MODE-SCOPE; canon ARCH-0059 #opt-out: "A genuine 1:1 mail
//! carries a plain opt-out line in its body").
//!
//! Detection reads the member's recorded `comm.jurisdiction`, as the
//! dispatch gate reads it, and keeps the language on the enrollment event:
//! JP is Japanese, EU/DE German, EU/FR French, anything else English. The
//! outbound leg freezes it in the 1:1 email envelope, and the sender seals
//! the line in it. A language never moves after detection: the envelope
//! bytes hash into the intent id, so a moved language would mint a second
//! send on a redrive.
//!
//! Before this, every campaign email ended with the English line, whatever
//! the member's jurisdiction.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::campaign::enrollment::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, CampaignEnrollmentAttemptPayload, CampaignEnrollmentEvent,
    CampaignHomeNodeCandidate, CampaignProgramDraft, CampaignProgramOutbound,
    CampaignProgramStepDraft, DetectEnrollment, EnrollmentDetection, create_campaign_program,
    derive_enrollment_outbound_request, detect_enrollment, elect_campaign_home_node_designation,
};
use oneiron::campaign::register_crm_pack;
use oneiron::campaign::surface::{SurfaceCall, invoke_campaign_surface, launch_campaign};
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::saved_query::{
    ClaimComparison, CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatcherSpec,
    QueryScope, SAVED_QUERY_SCHEMA_VERSION, SavedQueryEvaluator, create_saved_query,
    sweep_owner_read,
};
use oneiron::surface_event::is_stop_reply;
use oneiron::test_doors::campaign_opt_out_line::seal_native_mail_from_envelope;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};

mod common;

const SENIORITY: &str = "profile.seniority";
const JURISDICTION: &str = "comm.jurisdiction";
const CHANNEL: &str = "email";
const MEMBER_ADDRESS: &str = "yuki@example.com";
const SENDER_ADDRESS: &str = "owen@example.com";
const SUBJECT: &str = "A plan for you";
const HOME_NODE: u64 = 11;
const CALL_SEQ: u64 = 7;
const BODY: &str = "Hi Yuki, our new plan cuts your costs in half. Reply to book a call.";
const ORIGIN: &str = "https://oneiron.test";

/// The English line, as before this row.
const LINE_EN: &str = "If you would rather not hear from me again, reply STOP to owen@example.com and I will not write to you again.";
/// The Japanese line: an opt-out address with a statement beside it (the
/// pack's JP opt-out row), asking for a reply the STOP path reads.
const LINE_JA: &str = "今後のご連絡が不要な場合は、owen@example.com 宛に「配信停止」とご返信ください。以後ご連絡いたしません。";
/// The German line.
const LINE_DE: &str = "Wenn Sie keine weiteren Nachrichten von mir erhalten möchten, antworten Sie mit STOP an owen@example.com, dann schreibe ich Ihnen nicht mehr.";
/// The French line.
const LINE_FR: &str = "Si vous ne souhaitez plus recevoir de messages de ma part, répondez STOP à owen@example.com et je ne vous écrirai plus.";

// ---------------------------------------------------------------------------
// Fixture (as tests/campaign_bulk_send_mode.rs)
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

/// The vault, its owner, the step's sender identity and the saved query its
/// members match.
struct Base {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    sender: EntityId,
    query: EntityId,
}

/// An unseeded vault with a device keystore, the CRM pack, the sender's
/// email identity and a saved query matching every `vp`.
fn base() -> Base {
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
    let vp = FilterAst::Claim {
        predicate: SENIORITY.to_owned(),
        cmp: ClaimComparison::Eq,
        value: json!("vp"),
    };
    let query = create_saved_query(
        &vault,
        owner,
        EdgeActorClass::Human,
        &CreateSavedQueryRequest {
            schema_version: SAVED_QUERY_SCHEMA_VERSION,
            scope: QueryScope::default(),
            filter: vp.clone(),
            matcher: MatcherSpec::Hard { expression: vp },
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
        _dir: dir,
        vault,
        owner,
        sender,
        query,
    }
}

fn put_claim(vault: &Vault, body: &ClaimBody) {
    vault
        .put_claim(&EntityId::now(), body, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
}

/// Records `member`'s jurisdiction as the compliance oracle does: an ACTIVE,
/// approved `comm.jurisdiction` observation with an owner attestation,
/// observed at `observed_at`.
fn record_jurisdiction(vault: &Vault, member: EntityId, jurisdiction: &str, observed_at: u64) {
    let mut body = ClaimBody::new(
        JURISDICTION,
        ClaimSubject::Entity(member),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("jurisdiction"),
                rmpv::Value::from(jurisdiction),
            ),
            (
                rmpv::Value::from("observed_at"),
                rmpv::Value::from(observed_at),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("fixture");
    body.evidence = Some(rmpv::Value::from("owner attestation"));
    put_claim(vault, &body);
}

/// A member the query matches: a comm PERSON at `MEMBER_ADDRESS`, with an
/// active contact from the sender and, when given, a recorded jurisdiction.
fn add_member(base: &Base, jurisdiction: Option<&str>) -> EntityId {
    let member = oneiron::comm::resolve_or_create_comm_party(&base.vault, MEMBER_ADDRESS)
        .expect("the member PERSON");
    put_claim(
        &base.vault,
        &ClaimBody::new(
            SENIORITY,
            ClaimSubject::Entity(member),
            rmpv::Value::from("vp"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("fixture"),
    );
    if let Some(jurisdiction) = jurisdiction {
        record_jurisdiction(&base.vault, member, jurisdiction, 10);
    }
    base.vault
        .create_counterparty_contact(
            &EntityId::now(),
            &CounterpartyContactRecord::user_introduction(base.sender, MEMBER_ADDRESS, 1).unwrap(),
        )
        .unwrap();
    member
}

/// A launched campaign, created through the JSON door with `keys`, with one
/// program of one email step from the sender, its body filed, and this node
/// its home node; with the program.
fn launched_campaign(base: &Base, keys: Value, step: EntityId) -> (EntityId, EntityId) {
    let (vault, owner) = (&base.vault, base.owner);
    let mut body = json!({ "name": "opt-out language campaign" });
    if let (Some(body), Value::Object(keys)) = (body.as_object_mut(), keys) {
        body.extend(keys);
    }
    let created = invoke_campaign_surface(
        &vault.memory(owner, EdgeActorClass::Human),
        SurfaceCall {
            verb: "self.campaign.create".to_owned(),
            body,
        },
    )
    .expect("the campaign")
    .body;
    let campaign = EntityId::from_hex(created["campaign_ref"].as_str().unwrap()).unwrap();
    let version = created["definition"]["definition_version"]
        .as_u64()
        .unwrap();
    let now = vault.now_recorded_at();
    let program = create_campaign_program(
        vault,
        owner,
        campaign,
        CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        &CampaignProgramDraft {
            name: "opt-out language program".to_owned(),
            steps: vec![CampaignProgramStepDraft {
                step_ref: step,
                channel: CHANNEL.to_owned(),
                sender_ref: base.sender,
                basis_evidence: EntityId::now(),
                outbound: Some(CampaignProgramOutbound {
                    call_seq: CALL_SEQ,
                    verb: "send".to_owned(),
                    payload: BODY.as_bytes().to_vec(),
                    idempotency_supported: true,
                    subject: Some(SUBJECT.to_owned()),
                }),
                arm: None,
            }],
            audience: None,
        },
        now,
    )
    .unwrap()
    .program
    .program_ref;
    vault
        .save_campaign_step_body(
            program,
            step,
            CALL_SEQ,
            BODY.as_bytes(),
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

/// `member`'s enrollment in `campaign`, detected and persisted now, and the
/// attempt payload naming it at `step`.
fn detected_enrollment(
    base: &Base,
    campaign: EntityId,
    program: EntityId,
    step: EntityId,
    member: EntityId,
) -> (CampaignEnrollmentEvent, CampaignEnrollmentAttemptPayload) {
    let vault = &base.vault;
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
            now: vault.now_recorded_at() + 1,
        },
    ))
    .unwrap()
    {
        EnrollmentDetection::Recorded(event) => *event,
        EnrollmentDetection::NoTransition => panic!("expected a recorded transition"),
    };
    let payload = CampaignEnrollmentAttemptPayload {
        membership_event_ref: event.event_ref,
        campaign_program_ref: program,
        program_step_ref: step,
    };
    (event, payload)
}

/// The envelope bytes the leg freezes for this event now.
fn frozen_envelope_bytes(
    base: &Base,
    event: &CampaignEnrollmentEvent,
    payload: &CampaignEnrollmentAttemptPayload,
) -> Vec<u8> {
    let at_ms = (base.vault.now_recorded_at() + 4) * 1000;
    derive_enrollment_outbound_request(&base.vault, payload, event, at_ms)
        .unwrap()
        .expect("the member's outward call")
        .payload
}

/// One member, recorded in `jurisdiction`, detected into a campaign created
/// with `keys`: the base, the member, the event and its payload.
fn enrolled(
    jurisdiction: Option<&str>,
    keys: Value,
) -> (
    Base,
    EntityId,
    CampaignEnrollmentEvent,
    CampaignEnrollmentAttemptPayload,
) {
    let base = base();
    base.vault
        .install_one_click_unsubscribe_origin(ORIGIN)
        .expect("the host's public origin");
    let member = add_member(&base, jurisdiction);
    let step = EntityId::now();
    let (campaign, program) = launched_campaign(&base, keys, step);
    let (event, payload) = detected_enrollment(&base, campaign, program, step, member);
    (base, member, event, payload)
}

/// The body the sender seals from `envelope`; `None` when it refuses the
/// envelope's opt-out keys.
fn sealed_body(envelope: &[u8]) -> Option<String> {
    seal_native_mail_from_envelope(envelope, MEMBER_ADDRESS, SUBJECT, BODY, SENDER_ADDRESS)
        .expect("the message seals")
        .map(|sealed| sealed.body_text)
}

fn json_of(envelope: &[u8]) -> Value {
    serde_json::from_slice(envelope).expect("a JSON envelope")
}

// ---------------------------------------------------------------------------
// The line
// ---------------------------------------------------------------------------

/// A JP member's 1:1 mail ends with the Japanese line, an EU/DE member's
/// with the German one and an EU/FR member's with the French one; each
/// envelope names the language the leg froze, and the line follows the step
/// body after one blank line, as the English one does. The Japanese line's
/// reply, 配信停止, is a STOP reply.
#[test]
fn a_members_one_to_one_mail_ends_with_the_opt_out_line_in_the_members_language() {
    for (jurisdiction, tag, line) in [
        ("JP", "ja", LINE_JA),
        ("EU/DE", "de", LINE_DE),
        ("EU/FR", "fr", LINE_FR),
    ] {
        let (base, _, event, payload) = enrolled(Some(jurisdiction), json!({}));
        let envelope = frozen_envelope_bytes(&base, &event, &payload);
        assert_eq!(
            json_of(&envelope)["opt_out_language"],
            tag,
            "{jurisdiction}: the frozen language"
        );
        assert_eq!(
            sealed_body(&envelope).as_deref(),
            Some(format!("{BODY}\n\n{line}").as_str()),
            "{jurisdiction}: the body ends with the line in its language"
        );
    }
    assert!(
        is_stop_reply("配信停止"),
        "the Japanese line's reply opts out"
    );
}

/// A member with no recorded jurisdiction, or one without its own line
/// (UK), gets the English line byte for byte as before: the envelope names
/// no language, so its bytes are those of a main without this row.
#[test]
fn a_member_without_a_language_of_its_own_keeps_the_english_line_byte_for_byte() {
    for jurisdiction in [None, Some("UK")] {
        let (base, _, event, payload) = enrolled(jurisdiction, json!({}));
        let envelope = frozen_envelope_bytes(&base, &event, &payload);
        assert!(
            json_of(&envelope).get("opt_out_language").is_none(),
            "{jurisdiction:?}: an English envelope names no language"
        );
        assert_eq!(
            sealed_body(&envelope).as_deref(),
            Some(format!("{BODY}\n\n{LINE_EN}").as_str()),
            "{jurisdiction:?}: the English line"
        );
    }
}

/// The language is the event's: a newer jurisdiction recorded after
/// detection leaves the envelope a redrive freezes byte for byte the same,
/// so the intent id it hashes into does not move and no second send is
/// minted.
#[test]
fn a_jurisdiction_recorded_after_detection_leaves_the_frozen_envelope_unchanged() {
    let (base, member, event, payload) = enrolled(Some("JP"), json!({}));
    let before = frozen_envelope_bytes(&base, &event, &payload);
    record_jurisdiction(&base.vault, member, "EU/DE", 20);
    let after = frozen_envelope_bytes(&base, &event, &payload);
    assert_eq!(before, after, "the redrive freezes the same envelope bytes");
    assert_eq!(
        sealed_body(&after).as_deref(),
        Some(format!("{BODY}\n\n{LINE_JA}").as_str()),
        "still the Japanese line"
    );
}

/// A bulk send carries its opt-out in List-Unsubscribe and no body line, so
/// a JP member's bulk envelope names no language. The sender refuses a
/// language beside the bulk keys, an unknown language and English named
/// outright: none is a shape the leg freezes.
#[test]
fn a_bulk_send_names_no_language_and_a_language_the_leg_never_freezes_is_refused() {
    let (base, _, event, payload) = enrolled(Some("JP"), json!({ "send_mode": "bulk" }));
    let envelope = json_of(&frozen_envelope_bytes(&base, &event, &payload));
    assert_eq!(envelope["send_mode"], "bulk", "a bulk envelope: {envelope}");
    assert!(
        envelope.get("opt_out_language").is_none(),
        "a bulk envelope names no language: {envelope}"
    );
    assert_eq!(
        sealed_body(&serde_json::to_vec(&envelope).unwrap()).as_deref(),
        Some(BODY),
        "a bulk send has no body line"
    );

    let mut with_language = envelope.clone();
    with_language["opt_out_language"] = json!("ja");
    let mut one_to_one = envelope;
    if let Some(keys) = one_to_one.as_object_mut() {
        keys.remove("send_mode");
        keys.remove("list_unsubscribe");
    }
    for (refused, why) in [
        (with_language, "a language beside the bulk keys"),
        (
            json_with(&one_to_one, "opt_out_language", "xx"),
            "an unknown language",
        ),
        (
            json_with(&one_to_one, "opt_out_language", "en"),
            "English named outright",
        ),
    ] {
        assert_eq!(
            sealed_body(&serde_json::to_vec(&refused).unwrap()),
            None,
            "{why} is refused: {refused}"
        );
    }
    assert_eq!(
        sealed_body(
            &serde_json::to_vec(&json_with(&one_to_one, "opt_out_language", "fr")).unwrap()
        )
        .as_deref(),
        Some(format!("{BODY}\n\n{LINE_FR}").as_str()),
        "a 1:1 envelope naming a language it knows seals"
    );
}

/// `envelope` with `key` set to `value`.
fn json_with(envelope: &Value, key: &str, value: &str) -> Value {
    let mut envelope = envelope.clone();
    envelope[key] = json!(value);
    envelope
}
