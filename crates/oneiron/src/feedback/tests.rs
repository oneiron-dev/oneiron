use super::*;

use rmpv::Value;

use crate::Vault;
use crate::board_verb::BOARD_VERBS;
use crate::genui::{ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface};
use crate::outbound::OutboundDispatchOutcome;
use crate::receipt::{ReceiptKind, ReceiptRecord};
use crate::task_verb::TASKS_VERBS;
use crate::test_util::{entity, open_test_vault_with, put_policy_manifest_bytes};

/// The feedback module source, read at compile time so the network-freedom and
/// secret-hygiene guards are structural rather than aspirational.
const FEEDBACK_SOURCE: &str = include_str!("../feedback.rs");

/// Text that must never leave the vault: it stands in for a configuration
/// value the whitelist projection deliberately does not carry.
const OMITTED_CANARY: &str = "canary-omitted-configuration-value";

/// Text that must never survive redaction.
const PII_CANARY: &str = "canary-person@example.invalid";

const REDACTED_MARKER: &str = "[redacted]";

/// Presentation copy a caller owns. The engine carries it through untouched
/// and never substitutes wording of its own.
const CALLER_PROMPT: &str = "Share this feedback bundle with the engine team?";

const MSGPACK_NIL: u8 = 0xc0;

// ---------------------------------------------------------------- fixtures

fn fixed_platform() -> FeedbackPlatform {
    FeedbackPlatform {
        os: "testos".to_owned(),
        arch: "testarch".to_owned(),
        family: "testfamily".to_owned(),
    }
}

fn minimal_bundle() -> FeedbackBundle {
    FeedbackBundle::new(FeedbackCategory::Bug, "0.0.0-test", fixed_platform())
}

fn canary_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 16 * 1024 * 1024;
    config.max_readers = 16;
    // A value the projection must never copy, seeded so its absence is proven
    // rather than assumed.
    config.dict_search_paths = vec![std::path::PathBuf::from(format!("/tmp/{OMITTED_CANARY}"))];
    config
}

fn healer_diagnosis() -> FeedbackHealerDiagnosis {
    let mut diagnosis = FeedbackHealerDiagnosis::new("healer:diagnosis:1");
    diagnosis.subject_refs.insert("memory:alpha".to_owned());
    diagnosis.subject_refs.insert("memory:beta".to_owned());
    diagnosis.dag = vec![
        FeedbackDagHop::new("memory:alpha", "supersedes", "memory:beta"),
        FeedbackDagHop::new("memory:beta", "contradicts", "claim:gamma"),
    ];
    diagnosis.mechanism = Some("the later write shadowed the earlier one".to_owned());
    diagnosis
}

fn full_bundle() -> FeedbackBundle {
    minimal_bundle()
        .with_config(
            FeedbackConfigSnapshot::from_config(&canary_config()).expect("config snapshot"),
        )
        .with_healer_diagnosis(healer_diagnosis())
        .with_user_note("search felt slow after the import")
}

fn preview_of(bundle: FeedbackBundle) -> FeedbackPreview {
    prepare_feedback_preview(bundle, &PassThroughFeedbackRedactor).expect("prepare preview")
}

fn send_route() -> FeedbackSendRoute {
    FeedbackSendRoute::new("email", "send", "feedback@example.com")
}

fn send_scope() -> FeedbackApprovalScope {
    FeedbackApprovalScope::Send(send_route())
}

fn dispatch_actor(seed: u8) -> OutboundDispatchActor {
    OutboundDispatchActor::agent(entity(seed))
}

fn send_context(route: FeedbackSendRoute, actor: OutboundDispatchActor) -> FeedbackSendContext {
    FeedbackSendContext::new(
        route,
        actor,
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .on_behalf_of("owner")
}

/// Builds a host-supplied consent evaluation by hand.
///
/// This mirrors what a host hands back after it evaluated a consent action.
/// Building it directly is the point: the evaluation is trusted field input,
/// so the tests exercise exactly the bytes a host controls.
fn evaluation_with(
    decision: ConsentActionDecision,
    component_kind: &str,
    component_id: &str,
    action_id: &str,
    receipt_id: &str,
) -> ConsentActionEvaluation {
    let mut fields = BTreeMap::new();
    fields.insert("component_kind".to_owned(), component_kind.to_owned());
    fields.insert("component_id".to_owned(), component_id.to_owned());
    fields.insert("action_id".to_owned(), action_id.to_owned());
    ConsentActionEvaluation {
        decision,
        receipt: ReceiptRecord {
            receipt_id: receipt_id.to_owned(),
            receipt_kind: ReceiptKind::Gate,
            occurred_at: 900,
            actor: Some("owner".to_owned()),
            on_behalf_of: Some("owner".to_owned()),
            outcome: decision.outcome().to_owned(),
            job_ref: None,
            trigger_ref: None,
            policy_trace: Vec::new(),
            fields,
        },
        grant_mint_intent: None,
    }
}

fn approved_for(
    preview: &FeedbackPreview,
    scope: &FeedbackApprovalScope,
) -> ConsentActionEvaluation {
    evaluation_with(
        ConsentActionDecision::ApprovedOnce,
        "consent_ask",
        &preview.approval_component_id(scope),
        FEEDBACK_APPROVE_ONCE_ACTION,
        "consent:feedback:approval:1",
    )
}

/// Records every transport call so "the sink saw exactly these bytes, exactly
/// this many times" is a direct assertion rather than an inference.
#[derive(Default)]
struct RecordingTransport {
    payloads: Vec<Vec<u8>>,
    digests: Vec<String>,
    approval_refs: Vec<String>,
    intent_refs: Vec<String>,
    outcome: Option<OutboundExecutionOutcome>,
}

impl FeedbackTransport for RecordingTransport {
    fn send_feedback_bundle(
        &mut self,
        request: &FeedbackTransportRequest<'_>,
    ) -> OutboundExecutionOutcome {
        self.payloads.push(request.bundle_bytes.to_vec());
        self.digests.push(request.bundle_digest.to_owned());
        self.approval_refs
            .push(request.approval_receipt_ref.to_owned());
        self.intent_refs
            .push(request.execution.intent_ref.to_owned());
        self.outcome.clone().unwrap_or_else(|| {
            OutboundExecutionOutcome::delivered_to_channel("provider:feedback:1")
        })
    }
}

/// A writer that always fails, so the export error path is real.
struct FailingWriter;

impl std::io::Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("export writer refused"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ------------------------------------------------- independent msgpack oracle

fn push_fixstr(out: &mut Vec<u8>, text: &str) {
    let len = u8::try_from(text.len()).expect("fixture string length fits a byte");
    assert!(len < 32, "the fixture oracle only emits fixstr");
    out.push(0xa0 | len);
    out.extend_from_slice(text.as_bytes());
}

fn push_fixmap(out: &mut Vec<u8>, entries: usize) {
    let len = u8::try_from(entries).expect("fixture map length fits a byte");
    assert!(len < 16, "the fixture oracle only emits fixmap");
    out.push(0x80 | len);
}

/// Hand-built named-MessagePack encoding of [`minimal_bundle`], written
/// against the MessagePack spec rather than produced by the encoder under
/// test. If the key set, the key order, the category token, or the nil
/// treatment of absent optionals drifts, this fixture stops matching.
fn golden_minimal_bundle_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    push_fixmap(&mut out, 6);
    push_fixstr(&mut out, "category");
    push_fixstr(&mut out, "bug");
    push_fixstr(&mut out, "engine_version");
    push_fixstr(&mut out, "0.0.0-test");
    push_fixstr(&mut out, "platform");
    push_fixmap(&mut out, 3);
    push_fixstr(&mut out, "os");
    push_fixstr(&mut out, "testos");
    push_fixstr(&mut out, "arch");
    push_fixstr(&mut out, "testarch");
    push_fixstr(&mut out, "family");
    push_fixstr(&mut out, "testfamily");
    push_fixstr(&mut out, "config");
    out.push(MSGPACK_NIL);
    push_fixstr(&mut out, "healer_diagnosis");
    out.push(MSGPACK_NIL);
    push_fixstr(&mut out, "user_note");
    out.push(MSGPACK_NIL);
    out
}

fn generic_minimal_entries() -> Vec<(Value, Value)> {
    vec![
        (Value::from("category"), Value::from("bug")),
        (Value::from("engine_version"), Value::from("0.0.0-test")),
        (
            Value::from("platform"),
            Value::Map(vec![
                (Value::from("os"), Value::from("testos")),
                (Value::from("arch"), Value::from("testarch")),
                (Value::from("family"), Value::from("testfamily")),
            ]),
        ),
        (Value::from("config"), Value::Nil),
        (Value::from("healer_diagnosis"), Value::Nil),
        (Value::from("user_note"), Value::Nil),
    ]
}

fn encode_generic(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode fixture map");
    out
}

fn top_level_keys(bytes: &[u8]) -> Vec<String> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .expect("bundle bytes decode as generic MessagePack");
    match value {
        Value::Map(entries) => entries
            .iter()
            .map(|(key, _)| {
                key.as_str()
                    .expect("every top-level bundle key is a string")
                    .to_owned()
            })
            .collect(),
        other => panic!("a bundle must encode as a map, got {other:?}"),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_source_free_of(tokens: &[&str]) {
    for token in tokens {
        assert!(
            !FEEDBACK_SOURCE.contains(token),
            "the feedback module must not mention {token}"
        );
    }
}

/// Tokens whose absence proves the module cannot reach the environment, the
/// filesystem, a socket, a subprocess, or a credential store.
fn ambient_acquisition_tokens() -> Vec<&'static str> {
    vec![
        "crate::connector_key",
        "secret_manifest",
        "dict_search_paths",
        "std::env::var",
        "std::fs",
        "std::net",
        "std::process",
        "reqwest",
        "ureq",
    ]
}

// -------------------------------------------------------------- vault fixtures

fn temp_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::default())
}

fn policy_manifest(actor_ref: &str, channel: &str, verbs: &[&str]) -> Vec<u8> {
    let scoped_grants = verbs
        .iter()
        .map(|verb| {
            Value::Map(vec![
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (
                    Value::from("effector"),
                    Value::from(format!("external:{verb}")),
                ),
                (
                    Value::from("scope"),
                    Value::Map(vec![(Value::from("channel"), Value::from(channel))]),
                ),
            ])
        })
        .collect::<Vec<_>>();
    encode_generic(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("feedback-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("agent")),
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (Value::from("scoped_grants"), Value::Array(scoped_grants)),
    ])
}

/// Seeds an agent that may send on `email`, the shape every landed outbound
/// dispatch fixture uses.
fn seeded_send_vault(
    actor_seed: u8,
    manifest_seed: u8,
) -> (tempfile::TempDir, Vault, OutboundDispatchActor) {
    let (dir, vault) = temp_vault();
    let agent = entity(actor_seed);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"feedback dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(manifest_seed),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )
    .expect("seed policy manifest");
    (dir, vault, actor)
}

// ------------------------------------------------------------------ 1. wire

#[test]
fn feedback_bundle_wire_contract_is_stable() {
    let bundle = minimal_bundle();
    let bytes = encode_feedback_bundle(&bundle).expect("encode minimal bundle");

    assert_eq!(
        bytes,
        golden_minimal_bundle_bytes(),
        "the minimal bundle encoding is frozen against a hand-built oracle"
    );
    assert_eq!(
        bytes,
        encode_generic(generic_minimal_entries()),
        "the oracle agrees with an independent generic encoder"
    );
    assert_eq!(
        bytes,
        encode_feedback_bundle(&bundle).expect("re-encode minimal bundle"),
        "repeated encodes are byte-identical"
    );
    assert_eq!(
        decode_feedback_bundle(&bytes).expect("decode minimal bundle"),
        bundle
    );

    assert_eq!(top_level_keys(&bytes), FEEDBACK_BUNDLE_KEYS.to_vec());
    let full = encode_feedback_bundle(&full_bundle()).expect("encode full bundle");
    assert_eq!(
        top_level_keys(&full),
        FEEDBACK_BUNDLE_KEYS.to_vec(),
        "a fully populated bundle carries the same six keys in the same order"
    );

    let tokens = FeedbackCategory::ALL
        .into_iter()
        .map(FeedbackCategory::as_str)
        .collect::<Vec<_>>();
    assert_eq!(tokens, vec!["bug", "papercut", "confusion", "feature-wish"]);
    for category in FeedbackCategory::ALL {
        let mut candidate = minimal_bundle();
        candidate.category = category;
        let encoded = encode_feedback_bundle(&candidate).expect("encode category");
        let decoded = decode_feedback_bundle(&encoded).expect("decode category");
        assert_eq!(decoded.category, category);
        assert!(contains_bytes(&encoded, category.as_str().as_bytes()));
    }
}

#[test]
fn feedback_bundle_wire_contract_rejects_malformed_bytes() {
    let mut unknown = generic_minimal_entries();
    unknown.push((
        Value::from("collector_endpoint"),
        Value::from("https://example.invalid"),
    ));
    assert!(
        matches!(
            decode_feedback_bundle(&encode_generic(unknown)),
            Err(FeedbackError::Decode(_))
        ),
        "an unknown top-level field is a typed decode failure"
    );

    let mut duplicate = generic_minimal_entries();
    duplicate.push((Value::from("category"), Value::from("papercut")));
    assert!(
        matches!(
            decode_feedback_bundle(&encode_generic(duplicate)),
            Err(FeedbackError::Decode(_))
        ),
        "a duplicate field is a typed decode failure"
    );

    let mut trailing = golden_minimal_bundle_bytes();
    let clean_len = trailing.len() as u64;
    trailing.push(MSGPACK_NIL);
    match decode_feedback_bundle(&trailing) {
        Err(FeedbackError::TrailingBytes { consumed, total }) => {
            assert_eq!(consumed, clean_len);
            assert_eq!(total, clean_len + 1);
        }
        other => panic!("trailing bytes must be rejected by position check, got {other:?}"),
    }
}

// ---------------------------------------------------------------- 2. digest

fn independent_digest(bytes: &[u8]) -> String {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"oneiron.feedback.bundle.v1\0");
    preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    preimage.extend_from_slice(bytes);
    blake3::hash(&preimage).to_hex().to_string()
}

#[test]
fn feedback_digest_binds_exact_post_redaction_bytes() {
    let bundle = full_bundle();
    let bytes = encode_feedback_bundle(&bundle).expect("encode bundle");
    let digest = feedback_bundle_digest(&bytes);

    assert_eq!(digest, independent_digest(&bytes));
    assert_eq!(digest.len(), 64);
    assert_eq!(digest, digest.to_lowercase());
    assert_eq!(
        digest,
        feedback_bundle_digest(&encode_feedback_bundle(&bundle).expect("re-encode")),
        "repeated encodes digest identically"
    );

    let scope = send_scope();
    let component = feedback_approval_component_id(&digest, &scope);
    let export_component = feedback_approval_component_id(&digest, &FeedbackApprovalScope::Export);
    assert!(component.starts_with(FEEDBACK_APPROVAL_COMPONENT_PREFIX));
    assert_ne!(component, export_component);

    let changed = bundle.with_user_note("a different note entirely");
    let changed_bytes = encode_feedback_bundle(&changed).expect("encode changed bundle");
    let changed_digest = feedback_bundle_digest(&changed_bytes);
    assert_ne!(
        digest, changed_digest,
        "any field change changes the digest"
    );
    assert_ne!(
        component,
        feedback_approval_component_id(&changed_digest, &scope),
        "a changed digest changes the send component id"
    );
    assert_ne!(
        export_component,
        feedback_approval_component_id(&changed_digest, &FeedbackApprovalScope::Export),
        "a changed digest changes the export component id"
    );
}

// ---------------------------------------------------------------- 3. config

#[test]
fn feedback_config_snapshot_is_constrained_and_whitelisted() {
    let snapshot = FeedbackConfigSnapshot::from_config(&canary_config()).expect("snapshot");
    let rendered = serde_json::to_value(&snapshot).expect("render snapshot");
    let keys = rendered
        .as_object()
        .expect("the snapshot renders as an object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "dimensions",
        "fast_dims",
        "embedding_model",
        "map_size_bytes",
        "max_readers",
        "hnsw",
        "skip_text_index_manifest_check",
        "off_record_enabled",
        "off_record_overlay_budget_bytes",
    ]);
    assert_eq!(keys, expected, "the snapshot carries exactly the whitelist");
    assert_eq!(snapshot.map_size_bytes, 16 * 1024 * 1024);

    assert_source_free_of(&ambient_acquisition_tokens());

    let bundle = minimal_bundle().with_config(snapshot);
    let bytes = encode_feedback_bundle(&bundle).expect("encode snapshot bundle");
    assert!(
        !contains_bytes(&bytes, OMITTED_CANARY.as_bytes()),
        "omitted configuration data never reaches the wire"
    );
    let preview = preview_of(bundle);
    assert!(
        !preview
            .display_json()
            .expect("render preview")
            .contains(OMITTED_CANARY),
        "omitted configuration data never reaches the human preview"
    );
}

#[test]
fn feedback_config_snapshot_rejects_unsafe_embedding_model() {
    let long_model = "m".repeat(FEEDBACK_EMBEDDING_MODEL_MAX_BYTES + 1);
    let rejected = [
        "",
        "  test/model@v1  ",
        "test model@v1",
        "https://models.example.invalid/model",
        long_model.as_str(),
    ];
    for candidate in rejected {
        let mut config = canary_config();
        config.embedding_model = Some(candidate.to_owned());
        assert!(
            matches!(
                FeedbackConfigSnapshot::from_config(&config),
                Err(FeedbackError::InvalidBundle(_))
            ),
            "embedding_model {candidate:?} must be rejected"
        );
    }

    let mut absent = canary_config();
    absent.embedding_model = None;
    let snapshot = FeedbackConfigSnapshot::from_config(&absent).expect("absent model is fine");
    assert!(snapshot.embedding_model.is_none());
}

// ---------------------------------------------------------------- 4. healer

#[test]
fn healer_diagnosis_carries_refs_dag_and_mechanism() {
    let bundle = minimal_bundle().with_healer_diagnosis(healer_diagnosis());
    let bytes = encode_feedback_bundle(&bundle).expect("encode diagnosis bundle");
    let decoded = decode_feedback_bundle(&bytes).expect("decode diagnosis bundle");
    let diagnosis = decoded
        .healer_diagnosis
        .as_ref()
        .expect("diagnosis round-trips");

    assert_eq!(diagnosis.diagnosis_ref, "healer:diagnosis:1");
    assert_eq!(
        diagnosis.subject_refs.iter().collect::<Vec<_>>(),
        vec!["memory:alpha", "memory:beta"]
    );
    assert_eq!(
        diagnosis.dag,
        vec![
            FeedbackDagHop::new("memory:alpha", "supersedes", "memory:beta"),
            FeedbackDagHop::new("memory:beta", "contradicts", "claim:gamma"),
        ],
        "DAG hop order survives the wire"
    );

    let blank_ref = {
        let mut broken = healer_diagnosis();
        broken.subject_refs.insert("   ".to_owned());
        broken
    };
    let blank_relation = {
        let mut broken = healer_diagnosis();
        broken.dag = vec![FeedbackDagHop::new("memory:alpha", "", "memory:beta")];
        broken
    };
    let blank_mechanism = {
        let mut broken = healer_diagnosis();
        broken.mechanism = Some("   ".to_owned());
        broken
    };
    let dumped_trace = {
        let mut broken = healer_diagnosis();
        broken.mechanism =
            Some("panic at line 1\n  stack frame two\n  stack frame three".to_owned());
        broken
    };
    let blank_diagnosis_ref = {
        let mut broken = healer_diagnosis();
        broken.diagnosis_ref = String::new();
        broken
    };

    for broken in [
        blank_ref,
        blank_relation,
        blank_mechanism,
        dumped_trace,
        blank_diagnosis_ref,
    ] {
        let candidate = minimal_bundle().with_healer_diagnosis(broken);
        assert!(
            matches!(
                encode_feedback_bundle(&candidate),
                Err(FeedbackError::InvalidBundle(_))
            ),
            "a malformed diagnosis is a typed rejection, not a silent encode"
        );
    }
}

// ------------------------------------------------------------- 5. no dispatch

#[test]
fn prepare_and_redact_never_dispatch() {
    // Preview, card, and disclosure take no transport and no vault: there is
    // no parameter through which they could reach one.
    let preview = preview_of(full_bundle());
    let scope = send_scope();
    let card =
        feedback_approval_card(&preview, "owner", CALLER_PROMPT, &scope).expect("approval card");
    assert!(!card.preview.is_empty());
    assert!(!preview.display_json().expect("render preview").is_empty());

    // Export takes a writer the caller owns, and nothing else.
    let mut sink = Vec::new();
    let approval = approved_for(&preview, &FeedbackApprovalScope::Export);
    export_feedback_bundle(&preview, &approval, &mut sink).expect("export");
    assert_eq!(sink, preview.bytes());

    // A transport exists in this test and is handed to nothing, so it stays at
    // zero calls across the whole preview/consent/export path.
    let transport = RecordingTransport::default();
    assert!(transport.payloads.is_empty());

    assert_source_free_of(&ambient_acquisition_tokens());
}

// ------------------------------------------------------------- 6. redaction

struct CanaryRedactor;

impl FeedbackRedactor for CanaryRedactor {
    fn redact(&self, mut bundle: FeedbackBundle) -> Result<FeedbackBundle, FeedbackRedactionError> {
        if let Some(note) = bundle.user_note.take() {
            bundle.user_note = Some(note.replace(PII_CANARY, REDACTED_MARKER));
        }
        Ok(bundle)
    }
}

#[test]
fn redactor_output_is_the_only_preview_and_send_payload() {
    let raw = minimal_bundle().with_user_note(format!("reach me at {PII_CANARY} please"));
    let preview = prepare_feedback_preview(raw, &CanaryRedactor).expect("prepare redacted preview");

    let rendered = preview.display_json().expect("render preview");
    assert!(rendered.contains(REDACTED_MARKER));
    assert!(
        !rendered.contains(PII_CANARY),
        "the pre-redaction value never reaches the human preview"
    );
    assert!(
        !contains_bytes(preview.bytes(), PII_CANARY.as_bytes()),
        "the pre-redaction value never reaches the wire"
    );
    assert!(
        !rendered.contains(preview.digest()),
        "the digest is a consent fact, not payload content"
    );

    let scope = send_scope();
    let card =
        feedback_approval_card(&preview, "owner", CALLER_PROMPT, &scope).expect("approval card");
    assert!(card.preview.contains(preview.digest()));
    assert!(card.preview.contains("feedback@example.com"));
    assert!(card.preview.contains(FEEDBACK_BUNDLE_ENCODING));

    // The person approves what they can see: the card carries the redacted
    // content view itself, not just consent facts about it.
    assert!(
        card.preview.contains(&rendered),
        "the redacted content render reaches the approval card"
    );
    assert!(
        card.preview.contains(REDACTED_MARKER),
        "the redacted note is visible on the card"
    );
    assert!(
        !card.preview.contains(PII_CANARY),
        "the pre-redaction value never reaches the card"
    );

    let (_dir, vault, actor) = seeded_send_vault(0x61, 0x62);
    let mut transport = RecordingTransport::default();
    let context = send_context(send_route(), actor);
    let outcome = send_feedback(
        &vault,
        &preview,
        &context,
        &approved_for(&preview, &scope),
        &mut transport,
    )
    .expect("send redacted bundle");
    assert_eq!(outcome.transport_calls, 1);
    assert_eq!(transport.payloads, vec![preview.bytes().to_vec()]);
    assert!(!contains_bytes(
        &transport.payloads[0],
        PII_CANARY.as_bytes()
    ));

    let mut exported = Vec::new();
    export_feedback_bundle(
        &preview,
        &approved_for(&preview, &FeedbackApprovalScope::Export),
        &mut exported,
    )
    .expect("export redacted bundle");
    assert!(!contains_bytes(&exported, PII_CANARY.as_bytes()));

    // A pass-through redactor changes nothing about the consent requirement.
    let plain = preview_of(minimal_bundle());
    let mut refused = Vec::new();
    assert!(
        export_feedback_bundle(
            &plain,
            &evaluation_with(
                ConsentActionDecision::Declined,
                "consent_ask",
                &plain.approval_component_id(&FeedbackApprovalScope::Export),
                FEEDBACK_APPROVE_ONCE_ACTION,
                "consent:declined:1",
            ),
            &mut refused,
        )
        .is_err(),
        "pass-through output still needs approval"
    );
    assert!(refused.is_empty());
}

// -------------------------------------------------------------- 7. approval

#[test]
fn feedback_approval_is_exact_and_once_only() {
    let preview = preview_of(full_bundle());
    let scope = send_scope();
    let card =
        feedback_approval_card(&preview, "owner", CALLER_PROMPT, &scope).expect("approval card");

    assert_eq!(
        card.card_id,
        feedback_approval_component_id(preview.digest(), &scope),
        "the card id is the scoped component-id formula"
    );
    assert_eq!(card.verb_class, FEEDBACK_SEND_VERB);
    assert_eq!(card.verb_class, "feedback.send");
    assert_eq!(
        card.prompt, CALLER_PROMPT,
        "the caller's prompt reaches the card verbatim"
    );
    for blank in ["", "   ", "\n"] {
        assert!(
            matches!(
                feedback_approval_card(&preview, "owner", blank, &scope),
                Err(FeedbackError::InvalidBundle(_))
            ),
            "a blank prompt {blank:?} is refused, not replaced with engine copy"
        );
    }
    assert_eq!(
        card.origin_receipt_ref.as_deref(),
        Some(preview.content_ref().as_str())
    );
    assert!(card.scope_escalators.is_empty());

    let action_ids = card
        .actions()
        .into_iter()
        .map(|action| action.action_id)
        .collect::<Vec<_>>();
    assert_eq!(action_ids, vec!["approve_once", "decline"]);

    // The card constructor substitutes the full standing/widening set for an
    // empty escalator list; feedback builds the struct directly to avoid
    // minting an "always allow feedback" grant.
    let via_ctor = ConsentAskCard::new(
        "ask:feedback",
        "owner",
        "prompt",
        "preview",
        FEEDBACK_SEND_VERB,
        Vec::new(),
    )
    .expect("constructor card");
    assert!(!via_ctor.scope_escalators.is_empty());

    for line in [
        "bundle_digest: ",
        "bundle_encoding: ",
        "destination: ",
        "scope: ",
    ] {
        assert!(
            card.preview.contains(line),
            "disclosure line {line} is present"
        );
    }

    let approval = validate_feedback_approval(&preview, &scope, &approved_for(&preview, &scope))
        .expect("approve once validates");
    assert_eq!(approval.component_id(), card.card_id);
    assert_eq!(
        approval.approval_receipt_ref(),
        "consent:feedback:approval:1"
    );

    // The evaluation is host-trusted field input, not authentication: the
    // binding checks the scoped component id, and does not re-derive identity
    // from the receipt actor.
    let mut foreign_actor = approved_for(&preview, &scope);
    foreign_actor.receipt.actor = Some("someone-else".to_owned());
    assert!(validate_feedback_approval(&preview, &scope, &foreign_actor).is_ok());
}

#[test]
fn feedback_approval_rejects_every_non_approval() {
    let preview = preview_of(full_bundle());
    let scope = send_scope();
    let component = preview.approval_component_id(&scope);

    let declined = evaluation_with(
        ConsentActionDecision::Declined,
        "consent_ask",
        &component,
        FEEDBACK_APPROVE_ONCE_ACTION,
        "consent:declined:1",
    );
    assert!(matches!(
        validate_feedback_approval(&preview, &scope, &declined),
        Err(FeedbackError::ApprovalNotGranted { .. })
    ));

    let noop = evaluation_with(
        ConsentActionDecision::NoopNonPrincipal,
        "consent_ask",
        &component,
        FEEDBACK_APPROVE_ONCE_ACTION,
        "consent:noop:1",
    );
    assert!(matches!(
        validate_feedback_approval(&preview, &scope, &noop),
        Err(FeedbackError::ApprovalNotGranted { .. })
    ));

    let mut widening = approved_for(&preview, &scope);
    widening.grant_mint_intent = Some(crate::genui::GrantMintIntent {
        principal_ref: "owner".to_owned(),
        origin_component_id: component.clone(),
        origin_action_id: FEEDBACK_APPROVE_ONCE_ACTION.to_owned(),
        origin_receipt_ref: None,
        scope: crate::genui::GrantMintIntentScope::VerbClass {
            verb_class: FEEDBACK_SEND_VERB.to_owned(),
        },
    });
    assert!(matches!(
        validate_feedback_approval(&preview, &scope, &widening),
        Err(FeedbackError::WideningNotPermitted)
    ));

    let mut missing = approved_for(&preview, &scope);
    missing.receipt.fields.remove("component_id");
    assert!(matches!(
        validate_feedback_approval(&preview, &scope, &missing),
        Err(FeedbackError::ApprovalFieldMissing {
            field: "component_id"
        })
    ));

    let forged = evaluation_with(
        ConsentActionDecision::ApprovedOnce,
        "consent_ask",
        "feedback-preview:0000",
        FEEDBACK_APPROVE_ONCE_ACTION,
        "consent:forged:1",
    );
    assert!(matches!(
        validate_feedback_approval(&preview, &scope, &forged),
        Err(FeedbackError::StalePreviewDigest { .. })
    ));

    let wrong_kind = evaluation_with(
        ConsentActionDecision::ApprovedOnce,
        "bundle_approve",
        &component,
        FEEDBACK_APPROVE_ONCE_ACTION,
        "consent:wrong-kind:1",
    );
    assert!(matches!(
        validate_feedback_approval(&preview, &scope, &wrong_kind),
        Err(FeedbackError::ApprovalFieldMismatch {
            field: "component_kind",
            ..
        })
    ));

    let wrong_action = evaluation_with(
        ConsentActionDecision::ApprovedOnce,
        "consent_ask",
        &component,
        "escalate_always_this_verb_class",
        "consent:wrong-action:1",
    );
    assert!(matches!(
        validate_feedback_approval(&preview, &scope, &wrong_action),
        Err(FeedbackError::ApprovalFieldMismatch {
            field: "action_id",
            ..
        })
    ));
}

#[test]
fn feedback_approval_rides_the_landed_consent_surface() {
    let (_dir, vault) = temp_vault();
    let owner_actor = entity(0x71);
    vault
        .put_entity(
            &owner_actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("seed owner");
    let owner = vault
        .authenticate_owner(
            owner_actor,
            "owner",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("authenticate owner");

    let preview = preview_of(full_bundle());
    let scope = send_scope();
    let card =
        feedback_approval_card(&preview, "owner", CALLER_PROMPT, &scope).expect("approval card");
    let request = ConsentActionRequest::new(
        card.card_id.clone(),
        FEEDBACK_APPROVE_ONCE_ACTION,
        ConsentActionKind::Approve,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::EiriConversation,
        1_200,
    )
    .expect("consent action request");

    let evaluation = card
        .evaluate_action(&request, &owner)
        .expect("evaluate approve-once");
    assert_eq!(evaluation.decision, ConsentActionDecision::ApprovedOnce);
    assert!(evaluation.grant_mint_intent.is_none());

    let approval = validate_feedback_approval(&preview, &scope, &evaluation)
        .expect("the landed consent surface produces a valid feedback approval");
    assert_eq!(approval.component_id(), card.card_id);
    assert_eq!(
        approval.approval_receipt_ref(),
        evaluation.receipt.receipt_id
    );
}

// ----------------------------------------------------------------- 8. scope

#[test]
fn approval_scope_binds_destination() {
    let preview = preview_of(full_bundle());
    let route_a = send_route();
    let route_b = FeedbackSendRoute::new("email", "send", "other@example.com");
    let scope_a = FeedbackApprovalScope::Send(route_a.clone());
    let scope_b = FeedbackApprovalScope::Send(route_b);

    let id_a = preview.approval_component_id(&scope_a);
    assert_ne!(id_a, preview.approval_component_id(&scope_b));
    assert_eq!(
        id_a,
        preview.approval_component_id(&FeedbackApprovalScope::Send(send_route())),
        "the same route yields the same component id every time"
    );

    let with_counterparty = FeedbackApprovalScope::Send(send_route().with_counterparty_ref("cp"));
    let with_identity =
        FeedbackApprovalScope::Send(send_route().with_channel_identity_ref(entity(0x63)));
    assert_ne!(id_a, preview.approval_component_id(&with_counterparty));
    assert_ne!(id_a, preview.approval_component_id(&with_identity));
    assert_ne!(
        preview.approval_component_id(&with_counterparty),
        preview.approval_component_id(&with_identity)
    );

    // Length prefixing and tag framing keep routes distinct that a naive
    // NUL-joined preimage would collide.
    let crafted_left = FeedbackApprovalScope::Send(
        FeedbackSendRoute::new("x", "y", "z").with_counterparty_ref("p"),
    );
    let crafted_right = FeedbackApprovalScope::Send(FeedbackSendRoute::new("x", "y", "z\u{0}p"));
    assert_ne!(
        preview.approval_component_id(&crafted_left),
        preview.approval_component_id(&crafted_right)
    );
    let split_left = FeedbackApprovalScope::Send(FeedbackSendRoute::new("em", "ail", "t"));
    let split_right = FeedbackApprovalScope::Send(FeedbackSendRoute::new("e", "mail", "t"));
    assert_ne!(
        preview.approval_component_id(&split_left),
        preview.approval_component_id(&split_right)
    );

    // An approval for route B cannot authorize route A, and it fails before an
    // outbound contract is resolved, before the gate, and before a transport.
    let context = send_context(route_a, dispatch_actor(0x64));
    let approved_elsewhere = approved_for(&preview, &scope_b);
    assert!(matches!(
        feedback_dispatch_request(&preview, &context, &approved_elsewhere),
        Err(FeedbackError::StalePreviewDigest { .. })
    ));

    // An export approval never authorizes a send.
    let export_approval = approved_for(&preview, &FeedbackApprovalScope::Export);
    assert!(matches!(
        feedback_dispatch_request(&preview, &context, &export_approval),
        Err(FeedbackError::StalePreviewDigest { .. })
    ));

    let (_dir, vault, actor) = seeded_send_vault(0x65, 0x66);
    let mut transport = RecordingTransport::default();
    let vault_context = send_context(send_route(), actor);
    assert!(
        send_feedback(
            &vault,
            &preview,
            &vault_context,
            &approved_elsewhere,
            &mut transport
        )
        .is_err()
    );
    assert!(
        transport.payloads.is_empty(),
        "the transport is never reached"
    );
}

// ----------------------------------------------------------------- 9. stale

#[test]
fn stale_preview_digest_never_sends() {
    let preview_a = preview_of(minimal_bundle().with_user_note("first report"));
    let preview_b = preview_of(minimal_bundle().with_user_note("second report"));
    assert_ne!(preview_a.digest(), preview_b.digest());

    let scope = send_scope();
    let approved_a = approved_for(&preview_a, &scope);

    let (_dir, vault, actor) = seeded_send_vault(0x67, 0x68);
    let mut transport = RecordingTransport::default();
    let context = send_context(send_route(), actor);
    match send_feedback(&vault, &preview_b, &context, &approved_a, &mut transport) {
        Err(FeedbackError::StalePreviewDigest { expected, found }) => {
            assert_eq!(expected, preview_b.approval_component_id(&scope));
            assert_eq!(found, preview_a.approval_component_id(&scope));
        }
        other => panic!("a stale approval must fail typed, got {other:?}"),
    }
    assert!(transport.payloads.is_empty());

    let export_a = approved_for(&preview_a, &FeedbackApprovalScope::Export);
    let mut sink = Vec::new();
    assert!(matches!(
        export_feedback_bundle(&preview_b, &export_a, &mut sink),
        Err(FeedbackError::StalePreviewDigest { .. })
    ));
    assert!(
        sink.is_empty(),
        "nothing is written before the binding check"
    );
}

// ------------------------------------------------------------------ 10. send

#[test]
fn send_is_an_ordinary_outbound_effect() {
    let preview = preview_of(full_bundle());
    let scope = send_scope();
    let approval = approved_for(&preview, &scope);
    let (_dir, vault, actor) = seeded_send_vault(0x69, 0x6a);
    let actor_ref = actor.actor_ref.clone().expect("actor ref");
    let context = send_context(send_route(), actor);

    let mut transport = RecordingTransport::default();
    let outcome = send_feedback(&vault, &preview, &context, &approval, &mut transport)
        .expect("approved feedback send");

    assert_eq!(
        outcome.dispatch.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(outcome.transport_calls, 1);
    assert_eq!(transport.payloads, vec![preview.bytes().to_vec()]);
    assert_eq!(transport.digests, vec![preview.digest().to_owned()]);
    assert_eq!(
        transport.approval_refs,
        vec!["consent:feedback:approval:1".to_owned()]
    );

    assert_eq!(
        transport.intent_refs,
        vec![feedback_logical_send_ref(
            preview.digest(),
            "consent:feedback:approval:1"
        )]
    );

    let receipt = &outcome.dispatch.receipt;
    assert_eq!(receipt.receipt_kind, ReceiptKind::Outbound);
    assert_eq!(outcome.dispatch.gate_outcome, "allow");
    assert_eq!(
        receipt.fields.get("gate_decision_ref").map(String::as_str),
        outcome.dispatch.gate_decision_id.as_deref(),
        "the ordinary gate lineage rides the feedback receipt"
    );
    assert!(outcome.dispatch.gate_decision_id.is_some());
    assert_eq!(
        receipt.fields.get("content_ref").map(String::as_str),
        Some(preview.content_ref().as_str())
    );
    assert_eq!(
        receipt
            .fields
            .get(FEEDBACK_RECEIPT_FIELD_VERB)
            .map(String::as_str),
        Some(FEEDBACK_SEND_VERB)
    );
    assert_eq!(
        receipt
            .fields
            .get(FEEDBACK_RECEIPT_FIELD_BUNDLE_ENCODING)
            .map(String::as_str),
        Some(FEEDBACK_BUNDLE_ENCODING)
    );
    assert_eq!(
        receipt
            .fields
            .get(FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST)
            .map(String::as_str),
        Some(preview.digest())
    );
    assert_eq!(
        receipt
            .fields
            .get(FEEDBACK_RECEIPT_FIELD_APPROVAL_RECEIPT_REF)
            .map(String::as_str),
        Some("consent:feedback:approval:1")
    );

    let request = feedback_dispatch_request(&preview, &context, &approval).expect("request");
    assert_eq!(request.intent.actor, actor_ref);
    assert_eq!(request.intent.trigger_ref, "consent:feedback:approval:1");
    assert_eq!(
        request.intent.content_ref.as_deref(),
        Some(preview.content_ref().as_str())
    );
    assert_eq!(request.intent.verb, "send");
    assert_eq!(request.intent.channel, "email");
    assert_eq!(request.intent.target, "feedback@example.com");
}

#[test]
fn send_without_an_actor_ref_fails_before_the_gate() {
    let preview = preview_of(full_bundle());
    let scope = send_scope();
    let approval = approved_for(&preview, &scope);
    let actor = OutboundDispatchActor {
        actor_class: "agent".to_owned(),
        actor_ref: None,
        actor_entity_ref: None,
    };
    let context = send_context(send_route(), actor);
    assert!(matches!(
        feedback_dispatch_request(&preview, &context, &approval),
        Err(FeedbackError::InvalidBundle(_))
    ));

    let (_dir, vault, _seeded) = seeded_send_vault(0x6b, 0x6c);
    let mut transport = RecordingTransport::default();
    assert!(send_feedback(&vault, &preview, &context, &approval, &mut transport).is_err());
    assert!(transport.payloads.is_empty());
}

#[test]
fn unsupported_carrier_route_fails_before_the_gate() {
    let preview = preview_of(full_bundle());
    // `email` is a registered connector, but it carries no `edit` verb: the
    // route names a carrier pair this deployment cannot dispatch through.
    let route = FeedbackSendRoute::new("email", "edit", "feedback@example.com");
    let scope = FeedbackApprovalScope::Send(route.clone());
    let approval = approved_for(&preview, &scope);
    let context = send_context(route, dispatch_actor(0x76));

    // The approval is exact for this route, so what fails is the carrier
    // contract and not the binding — the contract is resolved after the
    // approval check and before anything can dispatch.
    match feedback_dispatch_request(&preview, &context, &approval) {
        Err(FeedbackError::UnsupportedRoute(detail)) => {
            assert!(
                detail.contains("edit") && detail.contains("email"),
                "the typed error names the carrier pair, got {detail:?}"
            );
        }
        other => panic!("an unregistered carrier pair must fail typed, got {other:?}"),
    }

    let (_dir, vault, actor) = seeded_send_vault(0x77, 0x78);
    let vault_context = send_context(
        FeedbackSendRoute::new("email", "edit", "feedback@example.com"),
        actor,
    );
    let mut transport = RecordingTransport::default();
    assert!(matches!(
        send_feedback(&vault, &preview, &vault_context, &approval, &mut transport),
        Err(FeedbackError::UnsupportedRoute(_))
    ));
    assert!(
        transport.payloads.is_empty(),
        "an unsupported route never reaches the transport"
    );

    // A registered carrier pair still resolves, so the check discriminates.
    let supported = send_context(send_route(), dispatch_actor(0x79));
    assert!(
        feedback_dispatch_request(&preview, &supported, &approved_for(&preview, &send_scope()))
            .is_ok()
    );
}

// ------------------------------------------------------------------ 11. gate

#[test]
fn gate_outcomes_remain_authoritative() {
    let preview = preview_of(full_bundle());
    let (_dir, vault, actor) = seeded_send_vault(0x6d, 0x6e);

    let identity_ref = entity(0x6f);
    let contact_id = entity(0x70);
    let contact = crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
        identity_ref,
        "feedback@example.com",
        10,
    )
    .expect("build contact");
    vault
        .create_counterparty_contact(&contact_id, &contact)
        .expect("store contact");
    vault
        .opt_out_counterparty_contact(
            &contact_id,
            crate::counterparty_contact::CounterpartyOptOutReason::Unsubscribe,
            20,
        )
        .expect("opt the contact out");

    let route = send_route()
        .with_channel_identity_ref(identity_ref)
        .with_counterparty_ref("feedback@example.com");
    let scope = FeedbackApprovalScope::Send(route.clone());
    let approval = approved_for(&preview, &scope);
    let context = send_context(route, actor);

    let mut transport = RecordingTransport::default();
    let outcome = send_feedback(&vault, &preview, &context, &approval, &mut transport)
        .expect("a denied dispatch is still an ordinary result");

    assert_eq!(
        outcome.dispatch.outcome,
        OutboundDispatchOutcome::Suppressed
    );
    assert_eq!(outcome.dispatch.gate_outcome, "deny");
    assert!(
        outcome
            .dispatch
            .receipt
            .policy_trace
            .contains(&"gate.deny.counterparty_opt_out".to_owned()),
        "the opt-out deny arm fired over a stored contact"
    );
    assert_eq!(outcome.transport_calls, 0);
    assert!(
        transport.payloads.is_empty(),
        "a denied send charges no transport"
    );
    assert!(
        !outcome
            .dispatch
            .receipt
            .fields
            .contains_key(FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST),
        "transport fields only exist when a transport ran"
    );
}

// ---------------------------------------------------------------- 12. replay

#[test]
fn approved_replay_is_idempotent() {
    let preview = preview_of(full_bundle());
    let scope = send_scope();
    let approval = approved_for(&preview, &scope);
    let (_dir, vault, actor) = seeded_send_vault(0x72, 0x73);
    let context = send_context(send_route(), actor);

    let request = feedback_dispatch_request(&preview, &context, &approval).expect("request");
    let expected = feedback_logical_send_ref(preview.digest(), "consent:feedback:approval:1");
    assert_eq!(request.receipt_id, expected);
    assert_eq!(request.intent_ref, expected);
    assert_eq!(
        request.ledger_identity_ref.as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(
        request.intent.idempotency_key.as_deref(),
        Some(expected.as_str())
    );

    let mut transport = RecordingTransport::default();
    let first =
        send_feedback(&vault, &preview, &context, &approval, &mut transport).expect("first send");
    assert_eq!(first.logical_send_ref, expected);
    assert_eq!(first.transport_calls, 1);

    let second = send_feedback(&vault, &preview, &context, &approval, &mut transport)
        .expect("replayed send");
    assert_eq!(second.logical_send_ref, expected);
    assert_eq!(second.transport_calls, 0, "one approval delivers once");
    assert_eq!(transport.payloads.len(), 1);
    assert_eq!(
        second
            .dispatch
            .receipt
            .fields
            .get("content_ref")
            .map(String::as_str),
        Some(preview.content_ref().as_str()),
        "lineage rides content_ref on the replay"
    );
    assert!(
        !second
            .dispatch
            .receipt
            .fields
            .contains_key(FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST),
        "the replay short-circuit does not reinsert transport fields"
    );

    // A different bundle under the same approval receipt is a different
    // logical send.
    let other = preview_of(minimal_bundle().with_user_note("another report"));
    assert_ne!(
        feedback_logical_send_ref(other.digest(), "consent:feedback:approval:1"),
        expected
    );
}

#[test]
fn recorded_definite_non_delivery_permits_an_ordinary_retry() {
    let preview = preview_of(full_bundle());
    let scope = send_scope();
    let approval = approved_for(&preview, &scope);
    let (_dir, vault, actor) = seeded_send_vault(0x74, 0x75);
    let context = send_context(send_route(), actor);

    let mut transport = RecordingTransport {
        outcome: Some(OutboundExecutionOutcome::failed("transport refused")),
        ..RecordingTransport::default()
    };
    let first = send_feedback(&vault, &preview, &context, &approval, &mut transport)
        .expect("first attempt");
    assert_eq!(first.transport_calls, 1);
    assert_ne!(
        first.dispatch.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );

    transport.outcome = Some(OutboundExecutionOutcome::delivered_to_channel(
        "provider:feedback:retry",
    ));
    let retry = send_feedback(&vault, &preview, &context, &approval, &mut transport)
        .expect("ordinary retry");
    assert_eq!(
        retry.transport_calls, 1,
        "a recorded definite non-delivery leaves the ordinary retry available"
    );
    assert_eq!(retry.logical_send_ref, first.logical_send_ref);
}

// ---------------------------------------------------------------- 13. export

#[test]
fn air_gapped_export_is_identical_and_network_free() {
    let preview = preview_of(full_bundle());
    let export_scope = FeedbackApprovalScope::Export;
    let approval = approved_for(&preview, &export_scope);

    let mut sink = Vec::new();
    let outcome = export_feedback_bundle(&preview, &approval, &mut sink).expect("export");
    assert_eq!(sink, preview.bytes());
    assert_eq!(outcome.bytes_written, preview.bytes().len());
    assert_eq!(outcome.bundle_digest, preview.digest());
    assert_eq!(outcome.bundle_encoding, FEEDBACK_BUNDLE_ENCODING);
    assert_eq!(outcome.approval_receipt_ref, "consent:feedback:approval:1");
    assert_eq!(
        feedback_bundle_digest(&sink),
        preview.digest(),
        "the exported bytes digest to the approved digest"
    );

    // A send-scoped approval is not an export approval.
    let send_approval = approved_for(&preview, &send_scope());
    let mut refused = Vec::new();
    assert!(matches!(
        export_feedback_bundle(&preview, &send_approval, &mut refused),
        Err(FeedbackError::StalePreviewDigest { .. })
    ));
    assert!(refused.is_empty());

    // A failing writer is a typed error, never a success.
    let mut failing = FailingWriter;
    assert!(matches!(
        export_feedback_bundle(&preview, &approval, &mut failing),
        Err(FeedbackError::ExportWrite(_))
    ));

    assert_source_free_of(&ambient_acquisition_tokens());
}

// ------------------------------------------------------------------ 14. verb

#[test]
fn feedback_verb_registration_is_local_and_exact() {
    assert_eq!(FEEDBACK_VERBS, ["feedback.send"]);
    assert_eq!(FEEDBACK_SEND_VERB, "feedback.send");
    assert_eq!(FeedbackVerb::ALL.len(), 1);
    assert_eq!(FeedbackVerb::Send.as_str(), FEEDBACK_SEND_VERB);

    assert!(
        !TASKS_VERBS.contains(&FEEDBACK_SEND_VERB),
        "feedback does not join the agent-visible task verb surface"
    );
    assert!(
        !BOARD_VERBS.contains(&FEEDBACK_SEND_VERB),
        "feedback does not join the agent-visible board verb surface"
    );

    // The esign guard looks for the verb token as it would actually appear —
    // a string literal or a module path — so ordinary prose such as "by
    // design" is not mistaken for a reservation.
    assert_source_free_of(&[
        "\"esign.",
        "crate::esign",
        "TASKS_VERBS",
        "BOARD_VERBS",
        "ENTITY_TYPE_",
        "ReceiptKind::",
        "outbound_capability_manifest",
    ]);
}

// ----------------------------------------------------------- module cohesion

#[test]
fn feedback_module_owns_its_own_wire_and_domain_tokens() {
    assert_eq!(FEEDBACK_BUNDLE_ENCODING, "oneiron.feedback.bundle.v1");
    assert_eq!(FEEDBACK_APPROVAL_COMPONENT_PREFIX, "feedback-preview:");
    assert_eq!(FEEDBACK_CONTENT_REF_PREFIX, "feedback:");
    assert_eq!(FEEDBACK_LOGICAL_SEND_PREFIX, "feedback-send:");

    let preview = preview_of(minimal_bundle());
    assert_eq!(
        preview.content_ref(),
        format!("feedback:{}", preview.digest())
    );
    assert_eq!(
        feedback_logical_send_ref(preview.digest(), "consent:x"),
        format!("feedback-send:{}:consent:x", preview.digest())
    );
}
