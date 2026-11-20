//! K-proof (oracle) for PLAN-UC-04 stage 4.1: the request digests a replay or a retention
//! compares with a stored value keep their bytes.
//!
//! A task post's request (`purposes::task::POST_REQUEST`), a report's request
//! (`purposes::feedback::REPORT_REQUEST`), an eval measurement's request and re-measure keys
//! (`purposes::skill_optimize::{EVAL_MEASUREMENT_REQUEST, EVAL_MEASUREMENT_REMEASURE}`), a
//! campaign's retained request (`purposes::task::CAMPAIGN_RETAINED_REQUEST`), the Linear
//! mirror's three event keys and its edit request (`purposes::connector::LINEAR_MIRROR_*`), a
//! phone line arrival's input (`purposes::phone_line::ARRIVAL_INPUT`) and a queued note
//! request's input (`purposes::note::PENDING_REQUEST_INPUT`) now start their BLAKE3 through
//! the fingerprint crate's K door. Each is stored, and a replay or a later ask compares a
//! fresh one with it: a match replays, a mismatch refuses. So each must give main's bytes
//! for every value. The `base_*` modules hold main's lines at d9371998846e, copied by range (each
//! range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation. The few lines around the copies give them main's names: stand-in error
//! helpers (an encoding failure is an `Err`), the campaign leg's facts, and wrappers and
//! aliases that carry main's private fns and tags to the tests.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_request_digests`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::feedback::ReportRequest;
use oneiron::memory::campaign_records::program_definition::{
    CampaignProgramOutbound, CampaignProgramStep,
};
use oneiron::note::{NoteChange, NoteOperation};
use oneiron::phone_line::PhoneLineArrival;
use oneiron::skill_optimize::{
    EvalArmPin, EvalAxisPin, EvalMeasurement, EvalMeasurementRequest, EvalSeat, FloorSlicePolicy,
    MeasurementMethodPin, MeasurementState, ScoreDirection,
};
use oneiron::task_verb::TaskPost;
use oneiron::test_doors::fingerprint_keep_request_digests::{self as door, CampaignLeg};
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use rmpv::Value;
use serde_json::json;

/// Main's `super::invalid` in the report module, as a stand-in: an encoding failure is an
/// `Err`.
fn invalid(_: &str) {}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_task {
    use oneiron::EntityId;
    use oneiron::task_verb::{TaskPost, brief_digest};

    /// Main's error names, as stand-ins: an encoding failure is an `Err`.
    pub(crate) type MemoryResult<T> = Result<T, ()>;
    #[allow(dead_code)]
    pub(crate) struct MemoryError;

    impl MemoryError {
        pub(crate) fn bad_request(_: &str) {}
    }

    /// Main's tag, which is private there.
    // main d9371998846e: crates/oneiron/src/task_verb/highway_post.rs:76-76
    const POST_REQUEST_DOMAIN: &[u8] = b"oneiron.tasks.post.request.v1";

    // main d9371998846e: crates/oneiron/src/task_verb/highway_post.rs:220-248
    /// The digest one post's request binds: the actor, the key, the brief,
    /// every routed field and `parent_ref`, the parent it files under
    /// (DOOR-113), its due time (FIX 4749) and whether it is a watch (FIX
    /// 22121). A replay under the same key with any other request is refused,
    /// as an ask's is.
    fn request_digest(
        actor: EntityId,
        key: &str,
        post: &TaskPost,
        parent_ref: Option<EntityId>,
    ) -> MemoryResult<[u8; 32]> {
        let bytes = rmp_serde::to_vec_named(&(
            actor,
            key,
            brief_digest(&post.brief).to_vec(),
            post.assignee,
            &post.spec,
            post.ttl,
            &post.label,
            parent_ref,
            post.due_at,
            post.watch,
        ))
        .map_err(|_| MemoryError::bad_request("task post does not encode"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(POST_REQUEST_DOMAIN);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Main's post request digest, which is private there.
    pub(crate) fn main_post_request_digest(actor: EntityId, key: &str, post: &TaskPost, parent_ref: Option<EntityId>) -> Option<[u8; 32]> {
        request_digest(actor, key, post, parent_ref).ok()
    }

    /// The tag's bytes, for the tag test outside this module.
    pub(crate) const MAIN_POST_REQUEST_DOMAIN: &[u8] = POST_REQUEST_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_report {
    use oneiron::feedback::ReportRequest;

    /// Main's result, as a stand-in: an encoding failure is an `Err`.
    type Result<T> = core::result::Result<T, ()>;

    /// Main's tag, which is private there.
    // main d9371998846e: crates/oneiron/src/feedback/report/disclosure.rs:36-36
    const REQUEST_DIGEST_DOMAIN: &[u8] = b"oneiron.report.request_digest.v1\0";

    // main d9371998846e: crates/oneiron/src/feedback/report/disclosure.rs:75-83
    /// The digest of a report's exact request, in its canonical encoding.
    fn request_digest(request: &ReportRequest) -> Result<[u8; 32]> {
        let bytes =
            rmp_serde::to_vec_named(request).map_err(|_| super::invalid("report request encoding"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(REQUEST_DIGEST_DOMAIN);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Main's report request digest, which is private there.
    pub(crate) fn main_report_request_digest(request: &ReportRequest) -> Option<[u8; 32]> {
        request_digest(request).ok()
    }

    /// The tag's bytes, for the tag test outside this module.
    pub(crate) const MAIN_REQUEST_DIGEST_DOMAIN: &[u8] = REQUEST_DIGEST_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_eval {
    use oneiron::skill_optimize::{EvalMeasurement, EvalMeasurementRequest};

    /// Main's result and error helper, as stand-ins: an encoding failure is an `Err`.
    type Result<T> = core::result::Result<T, ()>;
    fn invalid(_: &str) {}

    /// Main's tags, which are private there.
    // main d9371998846e: crates/oneiron/src/skill_optimize/eval_set/measurement/doors.rs:22-22
    const DIGEST_DOMAIN: &[u8] = b"skill_optimize:eval_measurement:v1\0";

    // main d9371998846e: crates/oneiron/src/skill_optimize/eval_set/measurement/doors.rs:436-436
    const REMEASURE_DOMAIN: &[u8] = b"skill_optimize:eval_measurement:remeasure:v1\0";

    // main d9371998846e: crates/oneiron/src/skill_optimize/eval_set/measurement/doors.rs:65-73
    /// The digest that keys a request's row: its domain and its named encoding.
    pub(super) fn request_digest(request: &EvalMeasurementRequest) -> Result<[u8; 32]> {
        let bytes = rmp_serde::to_vec_named(request)
            .map_err(|_| invalid("an eval measurement request does not encode"))?;
        let mut hash = blake3::Hasher::new();
        hash.update(DIGEST_DOMAIN);
        hash.update(&bytes);
        Ok(*hash.finalize().as_bytes())
    }

    // main d9371998846e: crates/oneiron/src/skill_optimize/eval_set/measurement/doors.rs:438-448
    /// Where the request `digest` keys is measured again while its Partial
    /// `row` stands: one digest per Partial row, so each settled row opens a
    /// new one.
    fn remeasure_digest(digest: &[u8; 32], row: &EvalMeasurement) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(REMEASURE_DOMAIN);
        hash.update(digest);
        hash.update(&row.requested_at.to_be_bytes());
        hash.update(&row.settled_at.unwrap_or_default().to_be_bytes());
        *hash.finalize().as_bytes()
    }

    /// Main's request digest, which is visible only to its parent there.
    pub(crate) fn main_request_digest(request: &EvalMeasurementRequest) -> Option<[u8; 32]> {
        request_digest(request).ok()
    }

    /// Main's re-measure digest, which is private there.
    pub(crate) fn main_remeasure_digest(digest: &[u8; 32], row: &EvalMeasurement) -> [u8; 32] {
        remeasure_digest(digest, row)
    }

    /// The tags' bytes, for the tag test outside this module.
    pub(crate) const MAIN_DIGEST_DOMAIN: &[u8] = DIGEST_DOMAIN;
    pub(crate) const MAIN_REMEASURE_DOMAIN: &[u8] = REMEASURE_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_campaign {
    use oneiron::EntityId;
    use oneiron::memory::campaign_records::program_definition::{
        CampaignProgramOutbound, CampaignProgramStep,
    };

    /// A campaign leg's facts, by main's names: the fields main's lines read.
    pub(crate) struct CampaignLegFacts {
        pub(crate) query_ref: EntityId,
        pub(crate) campaign_ref: EntityId,
        pub(crate) entity_ref: EntityId,
        pub(crate) epoch: u64,
        pub(crate) program_ref: EntityId,
        pub(crate) step_ref: EntityId,
        pub(crate) consequence_id: [u8; 16],
        pub(crate) call_seq: u64,
        pub(crate) payload_digest: [u8; 32],
    }

    /// Main's tag, which is private there.
    // main d9371998846e: crates/oneiron/src/campaign/enrollment/approval.rs:39-39
    const REQUEST_DOMAIN: &[u8] = b"oneiron.campaign.enrollment.retained_request.v1";

    // main d9371998846e: crates/oneiron/src/campaign/enrollment/approval.rs:125-154
    /// One prepared request's identity: its target, its sender, its channel,
    /// verb and idempotency.
    fn request_digest(
        facts: &CampaignLegFacts,
        step: &CampaignProgramStep,
        outbound: &CampaignProgramOutbound,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(REQUEST_DOMAIN);
        for id in [
            facts.query_ref,
            facts.campaign_ref,
            facts.entity_ref,
            facts.program_ref,
            facts.step_ref,
            step.sender_ref,
        ] {
            hasher.update(id.as_bytes());
        }
        hasher.update(&facts.epoch.to_be_bytes());
        hasher.update(&facts.consequence_id);
        hasher.update(&facts.call_seq.to_be_bytes());
        hasher.update(&facts.payload_digest);
        for text in [step.channel.as_str(), outbound.verb.as_str()] {
            hasher.update(&(text.len() as u64).to_be_bytes());
            hasher.update(text.as_bytes());
        }
        hasher.update(&[u8::from(outbound.idempotency_supported)]);
        *hasher.finalize().as_bytes()
    }

    /// Main's retained request digest, which is private there.
    pub(crate) fn main_retained_request_digest(facts: &CampaignLegFacts, step: &CampaignProgramStep, outbound: &CampaignProgramOutbound) -> [u8; 32] {
        request_digest(facts, step, outbound)
    }

    /// The tag's bytes, for the tag test outside this module.
    pub(crate) const MAIN_REQUEST_DOMAIN: &[u8] = REQUEST_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_linear {
    use oneiron::EntityId;
    use oneiron_contracts::entity_id::bytes_to_hex_lower;
    use oneiron_verb_wire::linear_sync::mirror_event::EventDirection;

    // main d9371998846e: crates/oneiron/src/linear_sync/mirror_event.rs:33-39
    /// A direction byte and a 32-byte digest.
    pub(crate) type EventKey = [u8; 33];

    const DELIVERY_DOMAIN: &[u8] = b"oneiron:linear-mirror-delivery:v1";
    const MAPPING_DOMAIN: &[u8] = b"oneiron:linear-mirror-mapping:v1";
    const TASK_EDIT_DOMAIN: &[u8] = b"oneiron:linear-mirror-task-edit:v1";
    const BODY_DOMAIN: &[u8] = b"oneiron:linear-mirror-body:v1";

    // main d9371998846e: crates/oneiron/src/linear_sync/mirror_event.rs:84-108
    fn keyed(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }

    /// The key of one row: its direction byte, then its digest.
    pub(crate) fn event_key(direction: EventDirection, digest: &[u8; 32]) -> EventKey {
        let mut key = [0; 33];
        key[0] = direction as u8;
        key[1..].copy_from_slice(digest);
        key
    }

    /// The key of one webhook delivery.
    pub(crate) fn delivery_key(delivery_id: &str) -> EventKey {
        event_key(
            EventDirection::IssueToTask,
            &keyed(DELIVERY_DOMAIN, &[delivery_id.as_bytes()]),
        )
    }

    // main d9371998846e: crates/oneiron/src/linear_sync/mirror_event.rs:153-175
    /// The key of one mapping edit: its TASK and intent key.
    pub(crate) fn mapping_key(task: EntityId, intent_key: &str) -> EventKey {
        event_key(
            EventDirection::MappingEdit,
            &keyed(MAPPING_DOMAIN, &[task.as_bytes(), intent_key.as_bytes()]),
        )
    }

    /// The key of one title edit: its TASK, actor and qualified report key.
    pub(crate) fn task_edit_key(task: EntityId, actor: EntityId, report_key: &str) -> EventKey {
        event_key(
            EventDirection::TaskEdit,
            &keyed(
                TASK_EDIT_DOMAIN,
                &[task.as_bytes(), actor.as_bytes(), report_key.as_bytes()],
            ),
        )
    }

    /// The hex digest an edit's request is compared by on a replay.
    pub(crate) fn request_digest(parts: &[&[u8]]) -> String {
        bytes_to_hex_lower(&keyed(BODY_DOMAIN, parts))
    }

    /// The tags' bytes, for the tag test outside this module.
    pub(crate) const MAIN_DOMAINS: [&[u8]; 4] = [DELIVERY_DOMAIN, MAPPING_DOMAIN, TASK_EDIT_DOMAIN, BODY_DOMAIN];
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_phone {
    use oneiron::phone_line::PhoneLineArrival;

    /// Main's result and error helper, as stand-ins: an encoding failure is an `Err`.
    type Result<T> = core::result::Result<T, ()>;
    fn invalid() {}

    // main d9371998846e: crates/oneiron/src/phone_line/mod.rs:230-233
    pub(crate) fn input_digest(arrival: &PhoneLineArrival) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(arrival).map_err(|_| invalid())?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_note {
    use oneiron::Result;
    use oneiron::note::NoteOperation;

    /// A queued note request, by main's name.
    #[allow(dead_code)]
    pub(crate) struct PendingNoteRequest;

    impl PendingNoteRequest {
    // main d9371998846e: crates/oneiron/src/note/pending_request.rs:37-40
        /// The digest a retry of `operation`, as its caller gives it, matches.
        pub(crate) fn input_digest(operation: &NoteOperation) -> Result<[u8; 32]> {
            Ok(*blake3::hash(&operation.encode()?).as_bytes())
        }
    }
}

fn id(byte: u8) -> EntityId {
    let mut bytes = [byte; 16];
    bytes[0] = 0x01;
    EntityId::from_bytes_unchecked(bytes)
}

/// Texts with the edges a length framing or an encoder could miss: empty, one byte,
/// unicode, a NUL, a quote and a backslash, and a long run.
fn texts() -> Vec<String> {
    vec![
        String::new(),
        "a".to_owned(),
        "tide-log/ünïcødé ✓".to_owned(),
        "nul\0inside".to_owned(),
        "quote\" and \\ backslash".to_owned(),
        "x".repeat(300),
    ]
}

fn assert_legacy(purpose: LegacyPurpose, mode: TagMode) {
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), mode);
}

#[test]
fn the_request_purposes_keep_main_s_tags() {
    let hashed_first = [
        (
            purposes::task::POST_REQUEST,
            base_task::MAIN_POST_REQUEST_DOMAIN,
        ),
        (
            purposes::feedback::REPORT_REQUEST,
            base_report::MAIN_REQUEST_DIGEST_DOMAIN,
        ),
        (
            purposes::skill_optimize::EVAL_MEASUREMENT_REQUEST,
            base_eval::MAIN_DIGEST_DOMAIN,
        ),
        (
            purposes::skill_optimize::EVAL_MEASUREMENT_REMEASURE,
            base_eval::MAIN_REMEASURE_DOMAIN,
        ),
        (
            purposes::task::CAMPAIGN_RETAINED_REQUEST,
            base_campaign::MAIN_REQUEST_DOMAIN,
        ),
        (
            purposes::connector::LINEAR_MIRROR_DELIVERY,
            base_linear::MAIN_DOMAINS[0],
        ),
        (
            purposes::connector::LINEAR_MIRROR_MAPPING,
            base_linear::MAIN_DOMAINS[1],
        ),
        (
            purposes::connector::LINEAR_MIRROR_TASK_EDIT,
            base_linear::MAIN_DOMAINS[2],
        ),
    ];
    for (purpose, main) in hashed_first {
        assert_legacy(purpose, TagMode::HashedFirst);
        assert_eq!(purpose.tag().as_bytes(), main);
    }
    // These write no tag: the edit request writes main's body domain itself (the string is
    // also a body occurrence's id context), and the two inputs never had one.
    for purpose in [
        purposes::connector::LINEAR_MIRROR_EDIT_REQUEST,
        purposes::phone_line::ARRIVAL_INPUT,
        purposes::note::PENDING_REQUEST_INPUT,
    ] {
        assert_legacy(purpose, TagMode::NotHashed);
    }
    assert_eq!(
        base_linear::MAIN_DOMAINS[3],
        b"oneiron:linear-mirror-body:v1"
    );
}

/// A task post by the planner fixture's shape, with one routed field set from `routed`.
fn post(objective: &str, routed: serde_json::Value) -> TaskPost {
    let mut value = json!({
        "intent_key": "fingerprint/post",
        "assignee": {"agent_def": {"agent_def_ref": id(0x21).to_hex()}},
        "brief": {
            "schema": 1,
            "type_ref": {"node_id": id(0x22).to_hex(), "tree_version": 1},
            "objective": objective,
            "intent": {"need": objective, "care": "light"},
            "context": {"read_first": []},
            "success": {
                "question": "Is it done?",
                "criteria": {"yes_if_all": [{"text": "It is done."}]},
            },
            "settled": [],
            "escalation": {
                "to": {"people": [id(0x23).to_hex()]},
                "triggers": [],
                "default": "proceed",
                "reversibility": "reversible_read",
            },
        },
    });
    for (field, field_value) in routed.as_object().expect("routed fields").iter() {
        value[field] = field_value.clone();
    }
    serde_json::from_value(value).expect("a task post")
}

fn specs() -> Vec<Option<Value>> {
    let map = |pairs: Vec<(&str, Value)>| {
        Value::Map(
            pairs
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        )
    };
    vec![
        None,
        Some(Value::Nil),
        Some(map(vec![])),
        Some(map(vec![("a", Value::from(1)), ("b", Value::from("two"))])),
        Some(map(vec![("b", Value::from("two")), ("a", Value::from(1))])),
        Some(Value::F64(f64::NAN)),
        Some(Value::F64(-0.0)),
        Some(Value::F32(1.5)),
        Some(Value::from(u64::MAX)),
        Some(Value::Array(vec![
            Value::from(true),
            Value::Binary(vec![0, 255]),
            Value::Nil,
        ])),
    ]
}

#[test]
fn the_post_request_digest_keeps_its_bytes() {
    let mut posts = Vec::new();
    for objective in ["Tidy the tide log", "ünïcødé ✓"] {
        posts.push(post(objective, json!({})));
    }
    posts.push(post(
        "routed",
        json!({"assignee": "dreamer", "label": "", "due_at": 0, "watch": true}),
    ));
    posts.push(post(
        "routed",
        json!({"ttl": {"deadline_at": u64::MAX}, "label": "x".repeat(300), "due_at": u64::MAX}),
    ));
    for spec in specs() {
        let mut with_spec = post("spec", json!({}));
        with_spec.spec = spec;
        posts.push(with_spec);
    }
    let mut cases = 0;
    for post in &posts {
        for actor in [id(0x31), id(0x32)] {
            for key in texts() {
                for parent_ref in [None, Some(id(0x33))] {
                    let head = door::post_request_digest(actor, &key, post, parent_ref);
                    let main = base_task::main_post_request_digest(actor, &key, post, parent_ref);
                    assert!(main.is_some());
                    assert_eq!(
                        head, main,
                        "post {post:?} actor {actor:?} key {key:?} parent {parent_ref:?}"
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, posts.len() * 2 * 6 * 2);
}

#[test]
fn the_report_request_digest_keeps_its_bytes() {
    let mut cases = 0;
    for category in [
        "skill_defect",
        "execution_lapse",
        "discovery",
        "environment",
        "preference_shift",
        "unclear",
    ] {
        for text in texts() {
            for (kind, proposal) in [
                ("problem", serde_json::Value::Null),
                ("proposal", json!({"problem": text, "fix": "the fix"})),
            ] {
                let note = if text.is_empty() {
                    serde_json::Value::Null
                } else {
                    json!(text)
                };
                let request: ReportRequest = serde_json::from_value(json!({
                    "subject_ref": text,
                    "category": category,
                    "kind": kind,
                    "note": note,
                    "evidence_refs": [text, "claim:1", ""],
                    "why": text,
                    "proposal": proposal,
                }))
                .expect("a report request");
                let head = door::report_request_digest(&request);
                let main = base_report::main_report_request_digest(&request);
                assert!(main.is_some());
                assert_eq!(head, main, "request {request:?}");
                cases += 1;
            }
        }
    }
    let bare: ReportRequest =
        serde_json::from_value(json!({"subject_ref": "", "category": "unclear"}))
            .expect("a bare request");
    assert_eq!(
        door::report_request_digest(&bare),
        base_report::main_report_request_digest(&bare)
    );
    assert_eq!(cases, 6 * 6 * 2);
}

fn eval_requests() -> Vec<EvalMeasurementRequest> {
    let arm = |model: &str, skill_digest: Option<&str>| EvalArmPin {
        model: model.to_owned(),
        revision: "r1".to_owned(),
        skill_digest: skill_digest.map(str::to_owned),
    };
    let request = |seat: EvalSeat, text: &str, method: MeasurementMethodPin, retry: u32| {
        EvalMeasurementRequest {
            decision: text.to_owned(),
            seat,
            incumbent: arm("model-a", None),
            candidate: arm(text, Some("ab".repeat(32).as_str())),
            requested_offers: None,
            cohort: id(0x41),
            membership_digest: "cd".repeat(32),
            rubric_revision: text.to_owned(),
            scorer: "judge".to_owned(),
            axis: EvalAxisPin {
                axis: "score".to_owned(),
                direction: ScoreDirection::LowerIsBetter,
                units: text.to_owned(),
            },
            floor_slices: FloorSlicePolicy::default(),
            canary: (!text.is_empty()).then(|| text.to_owned()),
            method,
            retry,
        }
    };
    let mut requests = Vec::new();
    for text in texts() {
        requests.push(request(
            EvalSeat::Companion,
            &text,
            MeasurementMethodPin::current(),
            0,
        ));
        requests.push(request(
            EvalSeat::Named(text.clone()),
            &text,
            MeasurementMethodPin::current(),
            u32::MAX,
        ));
    }
    for ci_level in [f64::NAN, f64::INFINITY, -0.0, 0.95] {
        let method = MeasurementMethodPin {
            ci_level,
            detectable_z_alpha: -ci_level,
            ..MeasurementMethodPin::current()
        };
        requests.push(request(EvalSeat::Router, "method", method, 1));
    }
    requests
}

fn eval_row(
    request: &EvalMeasurementRequest,
    requested_at: u64,
    settled_at: Option<u64>,
) -> EvalMeasurement {
    EvalMeasurement {
        digest: String::new(),
        request: request.clone(),
        state: MeasurementState::Pending,
        requested_at,
        claimed_at: None,
        settled_at,
        members: Vec::new(),
        exposures: Vec::new(),
        cases: Vec::new(),
        families: Vec::new(),
        mean_delta: None,
        gap: None,
        card: None,
    }
}

#[test]
fn the_eval_measurement_digests_keep_their_bytes() {
    let requests = eval_requests();
    let mut remeasures = 0;
    for request in &requests {
        let head = door::eval_measurement_request_digest(request);
        let main = base_eval::main_request_digest(request);
        assert!(main.is_some());
        assert_eq!(head, main, "request {request:?}");
        let digest = main.expect("a digest");
        for (requested_at, settled_at) in [
            (0, None),
            (0, Some(0)),
            (1, Some(u64::MAX)),
            (u64::MAX, None),
        ] {
            let row = eval_row(request, requested_at, settled_at);
            assert_eq!(
                door::eval_measurement_remeasure_digest(&digest, &row),
                base_eval::main_remeasure_digest(&digest, &row),
                "request {request:?} at {requested_at} settled {settled_at:?}"
            );
            remeasures += 1;
        }
    }
    assert_eq!(requests.len(), 6 * 2 + 4);
    assert_eq!(remeasures, requests.len() * 4);
}

#[test]
fn the_campaign_retained_request_digest_keeps_its_bytes() {
    let leg = |seed: u8, epoch: u64, call_seq: u64| CampaignLeg {
        query_ref: id(seed),
        campaign_ref: id(seed + 1),
        entity_ref: id(seed + 2),
        epoch,
        program_ref: id(seed + 3),
        step_ref: id(seed + 4),
        consequence_id: [seed; 16],
        call_seq,
        payload_digest: [seed.wrapping_mul(7); 32],
    };
    let mut cases = 0;
    for (seed, epoch, call_seq) in [(0x51, 0, 0), (0x61, u64::MAX, 1), (0x71, 7, u64::MAX)] {
        let head_leg = leg(seed, epoch, call_seq);
        let main_leg = base_campaign::CampaignLegFacts {
            query_ref: head_leg.query_ref,
            campaign_ref: head_leg.campaign_ref,
            entity_ref: head_leg.entity_ref,
            epoch: head_leg.epoch,
            program_ref: head_leg.program_ref,
            step_ref: head_leg.step_ref,
            consequence_id: head_leg.consequence_id,
            call_seq: head_leg.call_seq,
            payload_digest: head_leg.payload_digest,
        };
        for channel in texts() {
            for verb in texts() {
                for idempotency_supported in [false, true] {
                    let outbound = CampaignProgramOutbound {
                        call_seq,
                        verb: verb.clone(),
                        payload: verb.clone().into_bytes(),
                        idempotency_supported,
                        subject: None,
                    };
                    let step = CampaignProgramStep {
                        schema_version: 1,
                        program_ref: head_leg.program_ref,
                        step_ref: head_leg.step_ref,
                        channel: channel.clone(),
                        sender_ref: id(seed + 5),
                        basis_evidence: id(seed + 6),
                        outbound: Some(outbound.clone()),
                        arm: None,
                    };
                    assert_eq!(
                        door::campaign_retained_request_digest(&head_leg, &step, &outbound),
                        base_campaign::main_retained_request_digest(&main_leg, &step, &outbound),
                        "leg {head_leg:?} channel {channel:?} verb {verb:?} idempotent {idempotency_supported}"
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 3 * 6 * 6 * 2);
}

#[test]
fn the_linear_mirror_digests_keep_their_bytes() {
    let mut cases = 0;
    for text in texts() {
        assert_eq!(
            door::linear_delivery_key(&text),
            base_linear::delivery_key(&text)
        );
        for task in [id(0x81), id(0x82)] {
            assert_eq!(
                door::linear_mapping_key(task, &text),
                base_linear::mapping_key(task, &text)
            );
            assert_eq!(
                door::linear_task_edit_key(task, id(0x83), &text),
                base_linear::task_edit_key(task, id(0x83), &text)
            );
            let op = serde_json::to_vec(
                &json!({"kind": "link", "issue_id": text, "identifier": "ENG-1"}),
            )
            .expect("an op");
            let revision = u64::MAX.to_be_bytes();
            let part_sets: [&[&[u8]]; 4] = [
                &[task.as_bytes(), &op],
                &[task.as_bytes(), &revision, text.as_bytes()],
                &[text.as_bytes()],
                &[text.as_bytes(), b"", text.as_bytes()],
            ];
            for parts in part_sets {
                assert_eq!(
                    door::linear_edit_request_digest(parts),
                    base_linear::request_digest(parts)
                );
                cases += 1;
            }
        }
    }
    assert_eq!(
        door::linear_edit_request_digest(&[]),
        base_linear::request_digest(&[])
    );
    assert_eq!(cases, 6 * 2 * 4);
}

#[test]
fn the_arrival_and_note_inputs_keep_their_bytes() {
    let mut cases = 0;
    for call_id in texts() {
        for caller in [
            None,
            Some(String::new()),
            Some("+15550100".to_owned()),
            Some(call_id.clone()),
        ] {
            let arrival = PhoneLineArrival {
                call_id: call_id.clone(),
                caller,
            };
            let main = base_phone::input_digest(&arrival).ok();
            assert!(main.is_some());
            assert_eq!(
                door::phone_line_input_digest(&arrival),
                main,
                "arrival {arrival:?}"
            );
            cases += 1;
        }
    }
    for title in texts() {
        for change in [
            NoteChange::SetTitle {
                title: title.clone(),
            },
            NoteChange::Edit {
                base: title.clone().into_bytes(),
                edits: Vec::new(),
            },
        ] {
            let operation = NoteOperation {
                request_id: id(0x91),
                change,
            };
            let main = base_note::PendingNoteRequest::input_digest(&operation).ok();
            assert!(main.is_some());
            assert_eq!(
                door::note_request_input_digest(&operation),
                main,
                "operation {operation:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 6 * 4 + 6 * 2);
}
