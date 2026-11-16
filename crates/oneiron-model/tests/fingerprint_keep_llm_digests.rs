//! K-proof (oracle) for PLAN-UC-04 stage 6.4b: the oneiron-model sorted-JSON digests keep
//! their bytes.
//!
//! A model call's request key (`LlmRequest::canonical_hash` and its hex form), a media
//! call's request hash (`MediaRequest::canonical_hash_hex`), a segment manifest's digest and
//! a session's binding now start through the fingerprint crate's K door (`purposes::llm`).
//! Steps memoize on the request key, receipts, replies, decisions and replay keys name the
//! request digests, a model worker refuses an op on a handle bound to another, and two
//! manifests are equal when their digests are. So each must give main's bytes for every
//! value.
//!
//! `base_protocol`, `base_media` and `base_llm` hold main's lines at 41c9d7ffe245, copied by range
//! (each range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation. The few lines around the copies are the imports main's lines name, the
//! `crate::llm` and `super::` paths they call (the engine's own `canonical_json_bytes`), a
//! stand-in for each type whose methods are copied (holding the engine's value, so it
//! encodes as that value), and a wrapper for the private manifest digest.
//!
//! Run: `cargo test --locked -p oneiron-model --all-features --test fingerprint_keep_llm_digests`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron_contracts::EntityId;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use oneiron_model::llm::image::ImageBytes;
use oneiron_model::llm::media::{AiOperation, MediaPart, MediaRequest};
use oneiron_model::llm::{
    ByteSpan, CacheDigest, CacheIdentity, CallClass, CallEnvelope, CallPurpose, ConditioningDigest,
    ContentPart, ConversationAnchor, DeterministicFallback, DisclosureLabel, LlmMessage,
    LlmMessageRole, LlmRequest, LlmToolSpec, ModelId, ModelLocality, ModelTierRef,
    ReasoningPartKind, ResponseFormat, Scope, ScopeDigest, Segment, SegmentClock, SegmentKind,
    SegmentLocator, SegmentManifest, SessionKey, SourceRevision, TierPrecedence, TrustFence,
    VaultRef,
};
use serde_json::{Value as JsonValue, json};

/// The path main's media request hash names (`crate::llm::canonical_json_bytes`).
mod llm {
    pub(crate) use oneiron_model::llm::canonical_json_bytes;
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_protocol {
    use oneiron_contracts::entity_id::bytes_to_hex_lower;
    use oneiron_model::llm::canonical_json_bytes;
    use serde::Serialize;

    /// Main's `LlmRequest` methods, over the engine's request, which it encodes as.
    #[derive(Serialize)]
    #[serde(transparent)]
    pub(crate) struct LlmRequest(pub(crate) oneiron_model::llm::LlmRequest);

    impl LlmRequest {
        // main 41c9d7ffe245: crates/oneiron-model/src/llm/protocol.rs:45-57
            pub fn canonical_bytes(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
                canonical_json_bytes(self)
            }

            pub fn canonical_hash(&self) -> std::result::Result<[u8; 32], serde_json::Error> {
                let bytes = self.canonical_bytes()?;
                Ok(*blake3::hash(&bytes).as_bytes())
            }

            pub fn canonical_hash_hex(&self) -> std::result::Result<String, serde_json::Error> {
                let bytes = self.canonical_hash()?;
                Ok(bytes_to_hex_lower(&bytes))
            }
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_media {
    use serde::Serialize;

    /// Main's `MediaRequest` method, over the engine's request, which it encodes as.
    #[derive(Serialize)]
    #[serde(transparent)]
    pub(crate) struct MediaRequest(pub(crate) oneiron_model::llm::media::MediaRequest);

    impl MediaRequest {
        // main 41c9d7ffe245: crates/oneiron-model/src/llm/media/request.rs:197-204
            /// The digest of the call's canonical bytes: what its dispatch receipt
            /// names.
            pub fn canonical_hash_hex(&self) -> Result<String, serde_json::Error> {
                let bytes = crate::llm::canonical_json_bytes(self)?;
                Ok(oneiron_contracts::entity_id::bytes_to_hex_lower(
                    blake3::hash(&bytes).as_bytes(),
                ))
            }
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_llm {
    // The path main's two digests name (`super::canonical_json_bytes`).
    use oneiron_model::llm::canonical_json_bytes;

    pub(crate) mod segments {
        use oneiron_model::llm::{ConversationAnchor, ManifestDigest, MessageStamp, Segment, SegmentManifest};

        // main 41c9d7ffe245: crates/oneiron-model/src/llm/segments.rs:484-494
        fn manifest_digest(
            segments: &[Segment],
            anchor: Option<&ConversationAnchor>,
            messages: &[MessageStamp],
        ) -> ManifestDigest {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"oneiron.llm.segments.manifest.v1\0");
            let bytes = super::canonical_json_bytes(&(segments, anchor, messages)).unwrap_or_default();
            hasher.update(&bytes);
            ManifestDigest(*hasher.finalize().as_bytes())
        }

        /// Main's manifest digest, which is private there, of a manifest's parts.
        pub(crate) fn main_manifest_digest(manifest: &SegmentManifest) -> ManifestDigest {
            manifest_digest(manifest.segments(), manifest.anchor(), manifest.messages())
        }
    }

    pub(crate) mod session {
        use oneiron_model::llm::{CacheIdentity, ConditioningDigest, ConversationAnchor, SessionBinding};
        use serde::Serialize;

        /// Main's `SessionKey`, field for field.
        pub(crate) struct SessionKey {
            pub(crate) anchor: ConversationAnchor,
            pub(crate) identity: CacheIdentity,
            pub(crate) conditioning: ConditioningDigest,
        }

        impl SessionKey {
            // main 41c9d7ffe245: crates/oneiron-model/src/llm/session.rs:129-149
                /// The key less its HEAD: one session per binding, whose checkpoint
                /// advances with the HEAD.
                #[must_use]
                pub fn binding(&self) -> SessionBinding {
                    let ConversationAnchor {
                        vault,
                        read_scope,
                        conversation,
                        head: _,
                        fold_epoch,
                    } = &self.anchor;
                    let line = (
                        vault,
                        read_scope,
                        conversation,
                        fold_epoch,
                        &self.identity,
                        &self.conditioning,
                    );
                    SessionBinding(digest(b"oneiron.llm.session.binding.v1\0", &line))
                }
        }

        // main 41c9d7ffe245: crates/oneiron-model/src/llm/session.rs:152-157
        fn digest<T: Serialize>(domain: &[u8], value: &T) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(domain);
            hasher.update(&super::canonical_json_bytes(value).unwrap_or_default());
            *hasher.finalize().as_bytes()
        }
    }
}

fn id(n: u8) -> EntityId {
    let mut bytes = [0x5a_u8; 16];
    bytes[0] = n;
    EntityId::from_bytes(bytes).expect("an unreserved id")
}

fn cache_digest(nibble: char) -> CacheDigest {
    CacheDigest::new(nibble.to_string().repeat(64)).expect("64 lowercase hex digits")
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

/// Requests that differ in each part their JSON holds: messages of every role and part,
/// tools, params, provider options, the model and each envelope field serde writes.
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

fn anchor(n: u8, head: Option<EntityId>, fold_epoch: u64) -> ConversationAnchor {
    ConversationAnchor {
        vault: VaultRef([n; 32]),
        read_scope: ScopeDigest([n.wrapping_add(1); 32]),
        conversation: id(n),
        head,
        fold_epoch,
    }
}

/// Segment lists from none to every field set: locators of each kind, a byte span, a
/// source revision, dependencies, a guest fence and a disclosure label.
fn segment_lists() -> Vec<Vec<Segment>> {
    let mut detailed = Segment::whole(SegmentKind::ActivatedMemory, SegmentClock::Log, 1)
        .at(SegmentLocator::Memory {
            id: id(4),
            revision: Some(SourceRevision([7; 16])),
        })
        .within(ByteSpan { start: 0, end: 2 });
    detailed.source_revision = Some(SourceRevision([8; 16]));
    detailed.dependencies = vec![
        SegmentLocator::Skill {
            id: id(5),
            version: Some("1.2".into()),
        },
        SegmentLocator::ToolCall {
            call_id: "call-1".into(),
        },
    ];
    detailed.fence = TrustFence::Guest;
    detailed.disclosure = Some(DisclosureLabel::Private);
    vec![
        Vec::new(),
        vec![Segment::whole(SegmentKind::System, SegmentClock::Epoch, 0)],
        vec![
            Segment::whole(SegmentKind::System, SegmentClock::Epoch, 0),
            Segment::whole(SegmentKind::LogMessage, SegmentClock::Log, 1)
                .at(SegmentLocator::Message { id: id(3) }),
            Segment::whole(SegmentKind::NewestUser, SegmentClock::Live, 2),
        ],
        vec![
            detailed,
            Segment::whole(
                SegmentKind::BoardSection("tasks".into()),
                SegmentClock::Live,
                1,
            )
            .at(SegmentLocator::BoardSection {
                name: "tasks".into(),
            }),
            Segment::whole(SegmentKind::LogSummary, SegmentClock::Log, 0).at(
                SegmentLocator::Summary {
                    id: id(6),
                    epoch: 3,
                },
            ),
        ],
    ]
}

/// Message lists from none to a tool turn (a message that is not plain text).
fn message_lists() -> Vec<Vec<LlmMessage>> {
    vec![
        Vec::new(),
        vec![text(LlmMessageRole::System, "be brief")],
        vec![
            text(LlmMessageRole::System, "be brief"),
            text(LlmMessageRole::User, "hi"),
        ],
        vec![
            text(LlmMessageRole::User, "find it"),
            tool_turn(),
            tool_result(),
        ],
    ]
}

fn identities() -> Vec<CacheIdentity> {
    vec![
        CacheIdentity::default(),
        CacheIdentity {
            model: Some(cache_digest('a')),
            draft_weights_digest: Some("draft-1".into()),
            ..CacheIdentity::default()
        },
        CacheIdentity {
            model: Some(cache_digest('b')),
            tokenizer: Some(cache_digest('c')),
            runtime: Some(cache_digest('d')),
            template: Some(cache_digest('e')),
            execution_mode: Some(cache_digest('f')),
            cache_mode: Some(cache_digest('0')),
            ..CacheIdentity::default()
        },
    ]
}

fn assert_recipe(purpose: LegacyPurpose, tag_mode: TagMode, tag: &[u8]) {
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), tag_mode);
    assert_eq!(purpose.tag().as_bytes(), tag);
}

#[test]
fn the_llm_purposes_keep_main_s_recipes() {
    // Main's two request digests write no tag; its manifest and binding digests write
    // these bytes first, with their NUL.
    assert_recipe(
        purposes::llm::REQUEST,
        TagMode::NotHashed,
        b"oneiron.llm.request.v1",
    );
    assert_recipe(
        purposes::llm::MEDIA_REQUEST,
        TagMode::NotHashed,
        b"oneiron.llm.media_request.v1",
    );
    assert_recipe(
        purposes::llm::SEGMENTS_MANIFEST,
        TagMode::HashedFirst,
        b"oneiron.llm.segments.manifest.v1\0",
    );
    assert_recipe(
        purposes::llm::SESSION_BINDING,
        TagMode::HashedFirst,
        b"oneiron.llm.session.binding.v1\0",
    );
}

#[test]
fn the_request_key_keeps_its_bytes() {
    let cases = requests();
    let mut keys = BTreeSet::new();
    for (name, request) in &cases {
        let main = base_protocol::LlmRequest(request.clone());
        let key = request.canonical_hash().expect("head key");
        assert_eq!(key, main.canonical_hash().expect("main key"), "{name}");
        assert_eq!(
            request.canonical_hash_hex().expect("head hex"),
            main.canonical_hash_hex().expect("main hex"),
            "{name}"
        );
        keys.insert(key);
    }
    assert_eq!(keys.len(), cases.len(), "each case is its own request");

    // What serde skips is not in the key, on main and the head alike.
    let (_, plain) = &cases[1];
    let mut host = plain.clone();
    host.envelope.host_keyless = true;
    host.envelope.host_paid = true;
    host.host_segments = Some(Arc::new(SegmentManifest::new(
        segment_lists().remove(1),
        None,
        &host.messages,
    )));
    let key = host.canonical_hash().expect("head key");
    assert_eq!(
        key,
        base_protocol::LlmRequest(host.clone())
            .canonical_hash()
            .expect("main key")
    );
    assert_eq!(key, plain.canonical_hash().expect("head key"));
}

#[test]
fn the_media_request_hash_keeps_its_bytes() {
    let cases = media_requests();
    let mut hashes = BTreeSet::new();
    for (name, request) in &cases {
        let hash = request.canonical_hash_hex().expect("head hash");
        assert_eq!(
            hash,
            base_media::MediaRequest(request.clone())
                .canonical_hash_hex()
                .expect("main hash"),
            "{name}"
        );
        assert_eq!(hash.len(), 64, "{name}");
        hashes.insert(hash);
    }
    assert_eq!(hashes.len(), cases.len(), "each case is its own request");
}

#[test]
fn the_manifest_digest_keeps_its_bytes() {
    let anchors = [
        None,
        Some(anchor(1, None, 0)),
        Some(anchor(2, Some(id(9)), 7)),
    ];
    let mut digests = BTreeSet::new();
    let mut count = 0;
    for segments in segment_lists() {
        for anchor in &anchors {
            for messages in message_lists() {
                let manifest = SegmentManifest::new(segments.clone(), anchor.clone(), &messages);
                let digest = *manifest.digest();
                assert_eq!(
                    digest,
                    base_llm::segments::main_manifest_digest(&manifest),
                    "{segments:?} {anchor:?} {messages:?}"
                );
                digests.insert(digest);
                count += 1;
            }
        }
    }
    assert_eq!(count, 48);
    assert_eq!(digests.len(), count, "each case is its own manifest");
}

#[test]
fn the_session_binding_keeps_its_bytes() {
    let anchors = [
        anchor(1, None, 0),
        anchor(2, Some(id(9)), 7),
        anchor(3, Some(id(10)), u64::MAX),
    ];
    let conditionings = [ConditioningDigest([0; 32]), ConditioningDigest([0xc3; 32])];
    let mut bindings = BTreeSet::new();
    let mut count = 0;
    for anchor in &anchors {
        for identity in identities() {
            for conditioning in conditionings {
                let head = SessionKey {
                    anchor: anchor.clone(),
                    identity: identity.clone(),
                    conditioning,
                };
                let main = base_llm::session::SessionKey {
                    anchor: anchor.clone(),
                    identity: identity.clone(),
                    conditioning,
                };
                let binding = head.binding();
                assert_eq!(binding, main.binding(), "{anchor:?} {conditioning:?}");
                bindings.insert(binding);
                count += 1;
            }
        }
    }
    assert_eq!(count, 18);
    assert_eq!(bindings.len(), count, "each case is its own binding");

    // The HEAD is not in the binding, on main and the head alike.
    let moved = SessionKey {
        anchor: anchor(2, Some(id(11)), 7),
        identity: CacheIdentity::default(),
        conditioning: conditionings[0],
    };
    let main = base_llm::session::SessionKey {
        anchor: anchor(2, None, 7),
        identity: CacheIdentity::default(),
        conditioning: conditionings[0],
    };
    assert_eq!(moved.binding(), main.binding());
}
