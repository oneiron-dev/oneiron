//! K-proof (oracle) for PLAN-UC-04 stage 6.4d: nine sorted-JSON digests of the oneiron crate
//! keep their bytes.
//!
//! A durable model step's params identity, a public model step's call hash, a durable media
//! step's step hash, a model trial's measurements hash, a model call's messages, system and
//! tools digests and a native read's request hash (two sites) now start through the
//! fingerprint crate's K door (`purposes::llm`, `purposes::code_run`). A terminal step claim
//! stores the params identity, an invocation claim holds the call hash, a budget trap
//! persists the step hash, a trial's quality refuses an assessment naming other measurements,
//! and a model call's evidence record (`ModelCallRecord`) stores the model-call digests. So
//! each must give main's bytes for every value.
//!
//! `base_step_claim`, `base_llm`, `base_media_step`, `base_evidence` and `base_model_call`
//! hold main's lines at 0b0f7603ddc9, copied by range (each range is named above its copy; the
//! generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing
//! from them only in indentation. The few lines around the copies are the imports main's
//! lines name, the `crate::` and `super::super::` paths they call (the engine's own
//! `canonical_json_bytes`), and stand-ins for the values main's lines read (a trial's set pin
//! and cases; a vault whose invocation claim holds the hash it is given).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test fingerprint_keep_oneiron_json_digests`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::code_run::model_call::{
    model_call_digests, native_read_digests, native_seat_read_digests,
};
use oneiron::llm::model_step::{ModelStepRetryPolicy, ModelStepSubmit};
use oneiron::llm::model_trials::{
    FrozenTrialCase, HeldOutSelection, TrialMeasurement, TrialSetPin,
};
use oneiron::test_doors::fingerprint_keep_oneiron_json_digests as door;
use oneiron::{EntityId, LlmMessageRole, LlmRequest};
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use oneiron_model::llm::image::ImageBytes;
use oneiron_model::llm::media::{AiOperation, MediaPart, MediaRequest};
use oneiron_model::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, LabelReadout,
    LabelSet, LlmMessage, LlmToolSpec, ModelId, ModelLocality, ModelTierRef, ReasoningPartKind,
    ResponseFormat, Scope, TierPrecedence,
};
use serde_json::{Value as JsonValue, json};

/// The paths main's lines name (`crate::llm::...`).
mod llm {
    pub(crate) use oneiron::llm::canonical_json_bytes;
    pub(crate) use oneiron_model::llm::{LabelReadout, LabelSet};
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_step_claim {
    use oneiron::LlmRequest;
    use oneiron::llm::canonical_json_bytes;
    use oneiron_contracts::entity_id::bytes_to_hex_lower;

    /// Main's step result, as far as these lines use it.
    pub(crate) type DurableStepResult<T> = Result<T, serde_json::Error>;

    // main 0b0f7603ddc9: crates/oneiron/src/llm/step/step_claim.rs:348-352
    pub(super) fn request_params_hash(request: &LlmRequest) -> DurableStepResult<String> {
        Ok(bytes_to_hex_lower(
            blake3::hash(&canonical_json_bytes(&request.params)?).as_bytes(),
        ))
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_llm {
    // The path main's submit names (`super::super::canonical_json_bytes`).
    pub(crate) use oneiron::llm::canonical_json_bytes;

    pub(crate) mod step {
        pub(crate) mod public {
            use oneiron::MemoryError;
            use oneiron::llm::model_step::ModelStepSubmit;

            /// Main's claim outcome, as far as these lines use it.
            pub(crate) enum InvocationEntry {
                Claimed([u8; 32]),
            }

            /// A vault whose invocation claim holds the hash it is given.
            pub(crate) struct Vault;

            impl Vault {
                pub(crate) fn claim_invocation(&self, _invocation: (), body: [u8; 32]) -> InvocationEntry {
                    InvocationEntry::Claimed(body)
                }
            }

            /// Main's submit, from its call's encoding to the hash its claim holds.
            pub(crate) fn main_submit_call_hash(input: ModelStepSubmit) -> Result<[u8; 32], MemoryError> {
                let (vault, invocation) = (Vault, ());
                // main 0b0f7603ddc9: crates/oneiron/src/llm/step/public.rs:348-351
                    let call = super::super::canonical_json_bytes(&input)
                        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
                    let _claim = match vault.claim_invocation(invocation, *blake3::hash(&call).as_bytes()) {
                        InvocationEntry::Claimed(claim) => claim,
                };
                Ok(_claim)
            }
        }
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_media_step {
    use oneiron::llm::canonical_json_bytes;
    use oneiron_model::llm::media::MediaRequest;

    /// Main's media step hash of `request`.
    pub(crate) fn main_step_hash(request: MediaRequest) -> Result<[u8; 32], serde_json::Error> {
        // main 0b0f7603ddc9: crates/oneiron/src/llm/step/media_step.rs:67-67
            let step_hash = *blake3::hash(&canonical_json_bytes(&request)?).as_bytes();
        Ok(step_hash)
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_evidence {
    use oneiron::llm::model_trials::{FrozenTrialCase, TrialMeasurement, TrialSetPin};
    use oneiron_verb_wire::llm::registry::invalid;

    /// The trial request's set pin, which main's lines read.
    pub(crate) struct Request {
        pub(crate) set: TrialSetPin,
    }

    /// The trial's request and frozen cases, which main's lines read.
    pub(crate) struct Trial {
        pub(crate) request: Request,
        pub(crate) cases: Vec<FrozenTrialCase>,
    }

    /// The evidence field main's line fills.
    struct Evidence {
        measurements_hash: [u8; 32],
    }

    /// Main's measurements hash of `trial` and `measurements`.
    pub(crate) fn main_measurements_hash(trial: &Trial, measurements: Vec<TrialMeasurement>) -> oneiron::Result<[u8; 32]> {
        // main 0b0f7603ddc9: crates/oneiron/src/llm/model_trials/evidence.rs:241-243
            let encoded =
                crate::llm::canonical_json_bytes(&(&trial.request.set, &trial.cases, &measurements))
                    .map_err(|error| invalid(error.to_string()))?;
        let evidence = Evidence {
            // main 0b0f7603ddc9: crates/oneiron/src/llm/model_trials/evidence.rs:246-246
                    measurements_hash: *blake3::hash(&encoded).as_bytes(),
        };
        Ok(evidence.measurements_hash)
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_model_call {
    use oneiron::{Error, Result};
    use oneiron_records::code_run::model_call::{ModelCallDigests, NativeReadDigests, invalid};
    use serde::Serialize;

    // main 0b0f7603ddc9: crates/oneiron/src/code_run/model_call.rs:199-272
    /// Canonical request and prefix fingerprints used by replay admission.
    pub fn model_call_digests(request: &crate::LlmRequest) -> Result<ModelCallDigests> {
        let invalid = || Error::InvalidConfig("model call request did not canonicalize".to_owned());
        let request_hash = request.canonical_hash().map_err(|_| invalid())?;
        let messages_digest =
            *blake3::hash(&crate::llm::canonical_json_bytes(&request.messages).map_err(|_| invalid())?)
                .as_bytes();
        let system = request
            .messages
            .iter()
            .filter(|message| message.role == crate::LlmMessageRole::System)
            .collect::<Vec<_>>();
        let system_digest =
            *blake3::hash(&crate::llm::canonical_json_bytes(&system).map_err(|_| invalid())?)
                .as_bytes();
        let tools_digest =
            *blake3::hash(&crate::llm::canonical_json_bytes(&request.tools).map_err(|_| invalid())?)
                .as_bytes();
        Ok(ModelCallDigests {
            request_hash,
            messages_digest,
            system_digest,
            tools_digest,
        })
    }

    #[derive(Serialize)]
    enum NativeLabels {
        Noul,
        Choice(Vec<String>),
    }

    #[derive(Serialize)]
    struct NativeReadCanonical<'a> {
        state: &'a serde_json::Value,
        questions: Vec<(String, NativeLabels, Option<String>)>,
    }

    /// Canonical fingerprint of the actual reader-bound label-read pack.
    pub fn native_read_digests(
        state: &serde_json::Value,
        questions: &[crate::llm::LabelReadout<'_>],
    ) -> Result<NativeReadDigests> {
        let invalid = || Error::InvalidConfig("native read request did not canonicalize".to_owned());
        let questions = questions
            .iter()
            .map(|question| {
                let labels = match question.labels {
                    crate::llm::LabelSet::Noul => NativeLabels::Noul,
                    crate::llm::LabelSet::Choice(options) => NativeLabels::Choice(options.to_vec()),
                };
                (
                    question.text.to_owned(),
                    labels,
                    question.paired.map(|paired| paired.to_owned()),
                )
            })
            .collect::<Vec<_>>();
        let canonical = NativeReadCanonical { state, questions };
        let request_hash =
            *blake3::hash(&crate::llm::canonical_json_bytes(&canonical).map_err(|_| invalid())?)
                .as_bytes();
        Ok(NativeReadDigests { request_hash })
    }

    /// Canonical JSON-tree fingerprint of the actual built native-seat body.
    /// This is not a hash of wire bytes, headers or credentials.
    pub fn native_seat_read_digests(body: &serde_json::Value) -> Result<NativeReadDigests> {
        let canonical = crate::llm::canonical_json_bytes(body)
            .map_err(|_| invalid("native seat request did not canonicalize"))?;
        Ok(NativeReadDigests {
            request_hash: *blake3::hash(&canonical).as_bytes(),
        })
    }
}

fn id(n: u8) -> EntityId {
    let mut bytes = [0x5a_u8; 16];
    bytes[0] = n;
    EntityId::from_bytes(bytes).expect("an unreserved id")
}

fn envelope(
    purpose: CallPurpose,
    class: CallClass,
    response_format: ResponseFormat,
    locality: ModelLocality,
) -> CallEnvelope {
    CallEnvelope {
        seat_effort: None,
        scope: Scope::default(),
        tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("a".into())),
        purpose,
        class,
        response_format,
        locality,
        host_keyless: false,
        host_paid: false,
    }
}

fn plain_envelope() -> CallEnvelope {
    envelope(
        CallPurpose::AnswerGen,
        CallClass::BestEffort,
        ResponseFormat::Text,
        ModelLocality::ThirdParty,
    )
}

fn text(role: LlmMessageRole, text: &str) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text {
            text: text.into(),
            signature: None,
        }],
    }
}

fn tool_turn() -> LlmMessage {
    LlmMessage {
        role: LlmMessageRole::Assistant,
        content: vec![
            ContentPart::Reasoning {
                text: "look it up".into(),
                signature: Some("sig-1".into()),
                reasoning_kind: ReasoningPartKind::default(),
                data: None,
            },
            ContentPart::ToolCall {
                call_id: "call-1".into(),
                name: "lookup".into(),
                input: json!({ "z": 1, "a": [1.5, null, "x"], "m": { "k2": true, "k1": -0.0 } }),
                signature: None,
            },
        ],
    }
}

fn tool_result() -> LlmMessage {
    LlmMessage {
        role: LlmMessageRole::Tool,
        content: vec![ContentPart::ToolResult {
            call_id: "call-1".into(),
            output: json!({ "rows": [{ "b": 2, "a": 1 }], "more": false }),
            is_error: true,
        }],
    }
}

fn request(messages: Vec<LlmMessage>) -> LlmRequest {
    LlmRequest {
        model: ModelId::new("fake/small@v1").expect("model id"),
        envelope: plain_envelope(),
        messages,
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

fn object(pairs: &[(&str, JsonValue)]) -> BTreeMap<String, JsonValue> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

/// Nine requests that differ in each part their JSON holds: messages of every role, with
/// text, reasoning, tool-call and tool-result parts (no image or audio part); tools, params,
/// provider options and the model; and the envelope's purpose, class, response format and
/// locality. Among them are 5 message lists, 2 system lists, 2 tool lists and 2 params maps.
fn requests() -> Vec<(&'static str, LlmRequest)> {
    let mut cases = vec![
        ("empty", request(Vec::new())),
        (
            "system and user",
            request(vec![
                text(LlmMessageRole::System, "be brief"),
                text(LlmMessageRole::User, "hi"),
            ]),
        ),
        (
            "tool turn",
            request(vec![
                text(LlmMessageRole::User, "find it"),
                tool_turn(),
                tool_result(),
            ]),
        ),
    ];
    let mut tools = request(vec![text(LlmMessageRole::User, "find it")]);
    tools.tools.push(LlmToolSpec {
        name: "lookup".into(),
        description: "Looks a row up.".into(),
        input_schema: json!({ "type": "object", "properties": { "b": {}, "a": {} } }),
    });
    cases.push(("tools", tools));
    let mut params = request(vec![text(LlmMessageRole::User, "hi")]);
    params.params = object(&[
        ("temperature", json!(0.2)),
        ("max_tokens", json!(512)),
        ("stop", json!(["\n\n"])),
    ]);
    cases.push(("params", params));
    let mut options = request(vec![text(LlmMessageRole::User, "hi")]);
    options.provider_options = object(&[("openai", json!({ "reasoning": { "effort": "low" } }))]);
    cases.push(("provider options", options));
    let mut model = request(vec![text(LlmMessageRole::User, "hi")]);
    model.model = ModelId::new("fake/large@v2").expect("model id");
    cases.push(("model", model));
    let mut durable = request(vec![text(LlmMessageRole::User, "hi")]);
    durable.envelope = envelope(
        CallPurpose::Extraction,
        CallClass::Durable {
            fallback: DeterministicFallback {
                name: "fixed".into(),
                config: Some(json!({ "b": 2, "a": 1 })),
            },
        },
        ResponseFormat::Json {
            schema: json!({ "type": "object", "required": ["b", "a"] }),
        },
        ModelLocality::OnDevice,
    );
    cases.push(("durable json on device", durable));
    let mut own = request(vec![text(LlmMessageRole::User, "hi")]);
    own.envelope = envelope(
        CallPurpose::Consolidation,
        CallClass::BestEffort,
        ResponseFormat::Text,
        ModelLocality::OwnServer,
    );
    cases.push(("own server", own));
    cases
}

/// Twelve JSON values: scalars at their edges, escapes and a NUL, empty and unsorted
/// containers, and a seat body.
fn json_values() -> Vec<JsonValue> {
    vec![
        json!(null),
        json!(true),
        json!(0),
        json!(-0.5),
        json!(u64::MAX),
        json!(""),
        json!("\u{e9}\u{0}\""),
        json!([]),
        json!({}),
        json!([3, 1, 2]),
        json!({ "b": 1, "a": { "d": [], "c": null } }),
        json!({
            "model": "fake/small@v1",
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": 16
        }),
    ]
}

fn media(operation: AiOperation, parts: Vec<MediaPart>) -> MediaRequest {
    MediaRequest {
        model: ModelId::new("fake/media@v1").expect("model id"),
        envelope: plain_envelope(),
        operation,
        parts,
        references: Vec::new(),
        mask: None,
        params: BTreeMap::new(),
        voice: None,
    }
}

fn prompt(text: &str) -> MediaPart {
    MediaPart::Text { text: text.into() }
}

/// Media calls of every operation and part, with references, a mask and params.
fn media_requests() -> Vec<(&'static str, MediaRequest)> {
    let mut edit = media(AiOperation::Image, vec![prompt("make it blue")]);
    edit.references.push(MediaPart::Image {
        media_type: "image/png".into(),
        bytes: vec![1, 2, 3],
    });
    edit.mask = Some(ImageBytes {
        bytes: vec![9, 9],
        media_type: "image/png".into(),
    });
    let mut speech = media(AiOperation::Speech, vec![prompt("hello there")]);
    speech.params = object(&[("speed", json!(1.25)), ("format", json!("wav"))]);
    vec![
        ("text", media(AiOperation::Text, vec![prompt("draw a cat")])),
        (
            "image",
            media(AiOperation::Image, vec![prompt("draw a cat")]),
        ),
        ("image edit", edit),
        (
            "video",
            media(
                AiOperation::Video,
                vec![
                    prompt("pan left"),
                    MediaPart::Video {
                        media_type: "video/mp4".into(),
                        bytes: Vec::new(),
                        uri: Some("https://example.com/v.mp4".into()),
                    },
                ],
            ),
        ),
        ("speech", speech),
        (
            "transcribe",
            media(
                AiOperation::Transcribe,
                vec![MediaPart::Audio {
                    media_type: "audio/wav".into(),
                    bytes: vec![0, 255, 128],
                }],
            ),
        ),
        (
            "embed",
            media(
                AiOperation::Embed,
                vec![MediaPart::Embedding {
                    vector: vec![0.25, -1.5, f32::MIN_POSITIVE, 3.0e38],
                }],
            ),
        ),
    ]
}

/// A label-read question: its text, its closed options (`None` for yes/no) and its paired
/// question.
type Question = (&'static str, Option<Vec<String>>, Option<&'static str>);

fn options(items: &[&str]) -> Option<Vec<String>> {
    Some(items.iter().map(|item| (*item).to_owned()).collect())
}

fn readouts(questions: &[Question]) -> Vec<LabelReadout<'_>> {
    questions
        .iter()
        .map(|(text, options, paired)| LabelReadout {
            text: *text,
            labels: options.as_deref().map_or(LabelSet::Noul, LabelSet::Choice),
            paired: *paired,
        })
        .collect()
}

/// Six label-read packs: no question, a yes/no question, a choice, a paired choice, a choice
/// with no options, and two questions over a nested state.
fn read_packs() -> Vec<(&'static str, JsonValue, Vec<Question>)> {
    let state = json!({ "b": 1, "a": [1, 2] });
    vec![
        ("empty", json!({}), Vec::new()),
        (
            "yes or no",
            state.clone(),
            vec![("is it late?", None, None)],
        ),
        (
            "choice",
            state.clone(),
            vec![("which colour?", options(&["red", "blue"]), None)],
        ),
        (
            "paired choice",
            state,
            vec![(
                "which colour?",
                options(&["red", "blue"]),
                Some("is it late?"),
            )],
        ),
        (
            "no options",
            json!(null),
            vec![("which colour?", options(&[]), None)],
        ),
        (
            "two questions",
            json!({ "z": { "y": true, "x": -0.5 } }),
            vec![
                ("is it late?", None, Some("is it dark?")),
                ("which colour?", options(&["blue", "red"]), None),
            ],
        ),
    ]
}

fn trial_sets() -> Vec<TrialSetPin> {
    vec![
        TrialSetPin {
            id: "set-a".into(),
            version: 1,
            rubric_version: "r1".into(),
        },
        TrialSetPin {
            id: "set-b".into(),
            version: u32::MAX,
            rubric_version: String::new(),
        },
    ]
}

fn frozen(n: u8, label: bool, noise_weight: f64) -> FrozenTrialCase {
    FrozenTrialCase {
        selection: HeldOutSelection {
            answer: id(n),
            fact: id(n + 100),
            source_family: format!("family-{n}"),
        },
        unit: id(n + 50),
        source_frontier: [n; 32],
        fact_value_hash: [n ^ 0xff; 32],
        label,
        noise_weight,
        derived_from: (0..n).map(id).collect(),
    }
}

fn measured(n: u8) -> TrialMeasurement {
    TrialMeasurement {
        answer: id(n),
        incumbent: None,
        candidate: None,
        incumbent_cost: None,
        candidate_cost: None,
    }
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    // Each of main's nine starts is plain BLAKE3 of the sorted JSON: no purpose writes a tag.
    let recipes: [(LegacyPurpose, &[u8]); 8] = [
        (purposes::llm::STEP_PARAMS, b"oneiron.llm.step.params.v1"),
        (purposes::llm::STEP_SUBMIT, b"oneiron.llm.step.submit.v1"),
        (
            purposes::llm::MEDIA_REQUEST,
            b"oneiron.llm.media_request.v1",
        ),
        (
            purposes::llm::TRIAL_MEASUREMENTS,
            b"oneiron.llm.model_trials.measurements.v1",
        ),
        (
            purposes::code_run::MODEL_CALL_MESSAGES,
            b"oneiron.code_run.model_call.messages.v1",
        ),
        (
            purposes::code_run::MODEL_CALL_SYSTEM,
            b"oneiron.code_run.model_call.system.v1",
        ),
        (
            purposes::code_run::MODEL_CALL_TOOLS,
            b"oneiron.code_run.model_call.tools.v1",
        ),
        (
            purposes::code_run::NATIVE_READ_REQUEST,
            b"oneiron.code_run.native_read.request.v1",
        ),
    ];
    for (purpose, tag) in recipes {
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::NotHashed);
        assert_eq!(purpose.tag().as_bytes(), tag);
    }
}

#[test]
fn the_model_call_digests_keep_their_bytes() {
    let mut messages = BTreeSet::new();
    let mut system = BTreeSet::new();
    let mut tools = BTreeSet::new();
    for (name, request) in &requests() {
        let head = model_call_digests(request).expect("head digests");
        assert_eq!(
            head,
            base_model_call::model_call_digests(request).expect("main digests"),
            "{name}"
        );
        messages.insert(head.messages_digest);
        system.insert(head.system_digest);
        tools.insert(head.tools_digest);
    }
    assert_eq!((messages.len(), system.len(), tools.len()), (5, 2, 2));
}

#[test]
fn the_native_read_digest_keeps_its_bytes() {
    let packs = read_packs();
    let mut hashes = BTreeSet::new();
    for (name, state, questions) in &packs {
        let questions = readouts(questions);
        let head = native_read_digests(state, &questions).expect("head digest");
        assert_eq!(
            head,
            base_model_call::native_read_digests(state, &questions).expect("main digest"),
            "{name}"
        );
        hashes.insert(head.request_hash);
    }
    assert_eq!(hashes.len(), packs.len(), "each pack is its own read");
}

#[test]
fn the_native_seat_read_digest_keeps_its_bytes() {
    let values = json_values();
    let mut hashes = BTreeSet::new();
    for body in &values {
        let head = native_seat_read_digests(body).expect("head digest");
        assert_eq!(
            head,
            base_model_call::native_seat_read_digests(body).expect("main digest"),
            "{body}"
        );
        hashes.insert(head.request_hash);
    }
    assert_eq!(hashes.len(), values.len(), "each body is its own read");
}

#[test]
fn the_step_params_hash_keeps_its_bytes() {
    let mut cases = requests();
    for (name, params) in [
        ("one param", object(&[("temperature", json!(0.2))])),
        (
            "nested unsorted",
            object(&[
                ("b", json!({ "z": 1, "a": [null, -0.0] })),
                ("a", json!("")),
            ]),
        ),
        ("null param", object(&[("x", json!(null))])),
    ] {
        let mut request = request(vec![text(LlmMessageRole::User, "hi")]);
        request.params = params;
        cases.push((name, request));
    }
    let mut hashes = BTreeSet::new();
    for (name, request) in &cases {
        let head = door::request_params_hash(request).expect("head hash");
        assert_eq!(
            head,
            base_step_claim::request_params_hash(request).expect("main hash"),
            "{name}"
        );
        assert_eq!(head.len(), 64, "{name}");
        hashes.insert(head);
    }
    assert_eq!(hashes.len(), 5, "five distinct params maps");
}

#[test]
fn the_step_call_hash_keeps_its_bytes() {
    let mut submits = requests()
        .into_iter()
        .map(|(name, request)| {
            let submit = ModelStepSubmit {
                step_key: "step-1".into(),
                request,
                retry: ModelStepRetryPolicy { max_attempts: 1 },
            };
            (name.to_owned(), submit)
        })
        .collect::<Vec<_>>();
    for (key, max_attempts) in [("", 0), ("step-2", 1), ("step-\u{fc}\u{0}", u8::MAX)] {
        let submit = ModelStepSubmit {
            step_key: key.into(),
            request: request(vec![text(LlmMessageRole::User, "hi")]),
            retry: ModelStepRetryPolicy { max_attempts },
        };
        submits.push((format!("key {key:?}, {max_attempts} attempts"), submit));
    }
    let mut hashes = BTreeSet::new();
    for (name, submit) in &submits {
        let head = door::submit_call_hash(submit).expect("head hash");
        assert_eq!(
            head,
            base_llm::step::public::main_submit_call_hash(submit.clone()).expect("main hash"),
            "{name}"
        );
        hashes.insert(head);
    }
    assert_eq!(hashes.len(), submits.len(), "each submit is its own call");
}

#[test]
fn the_media_step_hash_keeps_its_bytes() {
    let cases = media_requests();
    let mut hashes = BTreeSet::new();
    for (name, request) in &cases {
        let head = request.canonical_hash().expect("head hash");
        assert_eq!(
            head,
            base_media_step::main_step_hash(request.clone()).expect("main hash"),
            "{name}"
        );
        // One digest: the step hash is the request hash its receipt names.
        assert_eq!(
            bytes_to_hex_lower(&head),
            request.canonical_hash_hex().expect("head hex"),
            "{name}"
        );
        hashes.insert(head);
    }
    assert_eq!(hashes.len(), cases.len(), "each case is its own request");
}

#[test]
fn the_trial_measurements_hash_keeps_its_bytes() {
    let case_lists = [
        Vec::new(),
        vec![frozen(1, true, 1.0)],
        vec![frozen(1, true, 1.0), frozen(2, false, 0.25)],
    ];
    let measurement_lists = [
        Vec::new(),
        vec![measured(1)],
        vec![measured(1), measured(2)],
    ];
    let mut hashes = BTreeSet::new();
    let mut count = 0;
    for set in trial_sets() {
        for cases in &case_lists {
            for measurements in &measurement_lists {
                let head =
                    door::trial_measurements_hash(&set, cases, measurements).expect("head hash");
                let trial = base_evidence::Trial {
                    request: base_evidence::Request { set: set.clone() },
                    cases: cases.clone(),
                };
                assert_eq!(
                    head,
                    base_evidence::main_measurements_hash(&trial, measurements.clone())
                        .expect("main hash"),
                    "{set:?} {} cases {} measurements",
                    cases.len(),
                    measurements.len()
                );
                hashes.insert(head);
                count += 1;
            }
        }
    }
    assert_eq!((hashes.len(), count), (18, 18), "each trial is its own");
}
