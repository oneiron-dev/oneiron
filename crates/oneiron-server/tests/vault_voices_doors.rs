//! Public-door promise tests for the `vault.voices` family (ruling L4-23 =
//! A: each test proves a promise at the door; DOOR-FAMILIES Part 2, row 12).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.voices.packs.put`,
//! `.render_consent`, `.targets.provision`, `.targets.evict`, `.inspect`,
//! `.lineage`, `.recognition.withdraw` and `.recognition.consent`, and the
//! owner's voice-bank routes under `/v1/ai/voices`.
//! Callers: the owner on the host root credential, whose live PERSON is the
//! subject of the owner's own voice; a second live person on their own
//! paired human credential; and an agent on its own paired credential, the
//! creator of the designed voice it banks. Each case owns its vault. The
//! server's AI host is the inert one, so no target clones a voice and no
//! vendor is called. No sleeps, no models.
//!
//! The promises, with their canon lines (oneiron-docs `generated/`):
//! - voice identity lives in the owner's ref bank and vendors are render
//!   targets only (`oneiron/planning/provider-adapter-architecture-v1.md:385`):
//!   a captured pack banks only under its subject's own current render
//!   grant, reads back as metadata with no audio, and a target clones only
//!   when it is configured;
//! - design and cloning have their own consent and lifecycle
//!   (`provider-adapter-architecture-v1.md:533`): an agent banks the voice
//!   it designed, never a real person's, and a banked pack never changes;
//! - a person's voice is reached only on that person's own proof, so nobody
//!   enrolls another's (`oneiron/agents/oneiron-arch-0061-voice-loop-v1.md:8`
//!   "counterparties only on logged consent"; no door enrolls a counterparty);
//! - a render withdrawal ends the grant and keeps the consent record
//!   (`oneiron-arch-0061-voice-loop-v1.md:124` keeps the record);
//! - withdrawing voice-recognition consent deletes the voiceprint and its
//!   samples, and keeps the consent record (`oneiron-arch-0061-voice-loop-v1.md:124`,
//!   promise-dura-13; VOICE-RECOGNITION-CONSENT-NO-DOOR): a person withdraws
//!   their own voice, the owner any subject's, and nobody else another's.
//!   No door enrolls a print, so these cases enroll on the served vault
//!   through the engine's public calls;
//! - the way out is never harder than the way in (VOICE-WITHDRAW-AGENT = C,
//!   VOICE-WITHDRAW-AGENT-GRANT = A): an agent whose own Grant names the
//!   consent-log verb `vault.voices.recognition.consent` logs a
//!   counterparty's spoken withdrawal on a call, the owner is told which
//!   consent was withdrawn, and the withdrawal only narrows;
//! - logging voice-recognition consent enrols nothing (VOICE-CONSENT-LOG-WHO = A;
//!   oneiron-arch-0061 "the agent logs who/when/what"): a person logs their own
//!   voice, the owner any subject's, and an agent with the consent-log Grant a
//!   counterparty's spoken yes on a call, telling each live owner who agreed, for
//!   which purposes, and under which Grant; enrolment reads the door's consent;
//! - the `/v1/ai/voices` routes are the owner's alone
//!   (`crates/oneiron-server/src/api/ai/voices.rs` `owner_only`).
//!
//! These promises hold on main, but for the recognition withdrawal and consent,
//! whose doors main does not have: their cases are red on main, the two consent
//! cases because main's server knows no such route (run against main's code
//! they fail at the first consent call), and the withdrawal agent's case
//! is also red on the door's first PR (#8973), which refuses every agent.
//! The others' red proof is a seeded fault (Test rules v2, rule 5), named in the PR.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_voices_doors`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::voice_identity::{
    VoiceConsentBasis, VoiceConsentEventV1, VoiceConsentState, VoiceEmbeddingFamily,
    VoiceEmbeddingSpaceV1, VoiceEnrollmentLegalContext, VoiceEnrollmentOrigin,
    VoiceEnrollmentRequest, VoiceEnrollmentSampleV1, VoiceMatchPolicy, VoiceMatchRequest,
    VoicePrintPurpose, VoiceRunCoverage, VoiceSegmentEmbeddingInput,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const PACKS_PUT: &str = "vault.voices.packs.put";
const RENDER_CONSENT: &str = "vault.voices.render_consent";
const PROVISION: &str = "vault.voices.targets.provision";
const EVICT: &str = "vault.voices.targets.evict";
const INSPECT: &str = "vault.voices.inspect";
const LINEAGE: &str = "vault.voices.lineage";
const RECOGNITION_WITHDRAW: &str = "vault.voices.recognition.withdraw";
const GRANT_MINT: &str = "vault.agents.grants.mint";
/// The verb an agent's Grant names to log recognition consent, and with it
/// a spoken withdrawal: the engine's `VOICE_RECOGNITION_CONSENT_VERB`,
/// spelled out so a change of that name turns this file red.
const RECOGNITION_CONSENT: &str = "vault.voices.recognition.consent";

/// The owner's own voice, a real person's.
const OWNER_VOICE: &str = "doors-custody-owner-voice";
/// The render grant the owner records on their own voice.
const OWNER_GRANT: &str = "doors-custody-owner-grant";
/// The pack the owner banks under that grant.
const OWNER_PACK: &str = "doors-custody-owner-pack";
/// A target name no provider of this host has.
const NO_TARGET: &str = "doors-custody-no-such-target";
/// One clip's audio, as the wire carries it (standard base64 of 3 bytes).
const AUDIO: &str = "AQID";
/// One clip's transcript.
const TRANSCRIPT: &str = "the doors custody reference line";

/// One credential a test holds: its actor, its slip, its holder key and its
/// token.
struct Holder {
    actor: EntityId,
    key: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// A served vault with its owner's host root credential, the owner's own
/// PERSON, a second live person and an agent, each on its own paired
/// credential.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner_person: EntityId,
    person: Holder,
    agent: Holder,
}

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The owner on the host root credential.
    Owner,
    /// A second live person on their own paired human credential.
    Person,
    /// The paired agent.
    Agent,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// A self-hosted served vault on the wall clock.
async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-voices-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    let owner_person = vault
        .ensure_embedded_owner_actor()
        .expect("the owner's PERSON");
    let second_person = EntityId::now();
    vault
        .put_entity(
            &second_person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a second person",
        )
        .expect("a live second PERSON");
    let app = build_app(server);
    let person = pair(&vault, &app, &issuer, second_person, "human", [0x51; 32]).await;
    let agent_principal = vault
        .ensure_agent_principal("voices-doors-agent")
        .expect("agent principal");
    let agent = pair(&vault, &app, &issuer, agent_principal, "agent", [0x42; 32]).await;
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner_person,
        person,
        agent,
    }
}

/// Pairs `principal` at actor class `class` the way `token agent` does: a
/// principal-bound link narrowed to `core:read` and `core:write`, redeemed
/// over the real pairing route with the holder-signed binding transcript.
async fn pair(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    principal: EntityId,
    class: &str,
    seed: [u8; 32],
) -> Holder {
    let key = SigningKey::from_bytes(&seed);
    let binding_key = key.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let link = vault
        .issue_pairing_link_for_principal(
            issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some(class.to_owned()),
                ..Default::default()
            },
        )
        .expect("pairing link");
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let signature = hex(&key.sign(&transcript).to_bytes());
    let request = Request::post("/v1/core/pairing/redeem")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": link.code,
                "holder_ref": principal.to_hex(),
                "binding_key": hex(&binding_key),
                "signature": signature,
            })
            .to_string(),
        ))
        .expect("pairing redeem request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("pairing redeem response");
    assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("pairing redeem body");
    let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
    let token = body["token"].as_str().expect("paired token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("paired slip");
    assert_eq!(
        slip.claims.actor_class.as_deref(),
        Some(class),
        "the redeemed slip binds its class"
    );
    Holder {
        actor: principal,
        key,
        slip,
        token,
    }
}

/// A captured pack's origin, citing the render grant `event_id`.
fn captured(event_id: &str) -> Value {
    json!({"kind": "captured", "consent_event_ref": event_id})
}

/// A designed pack's origin.
fn designed() -> Value {
    json!({"kind": "designed", "vendor": "doors-custody-design-tool"})
}

/// One clip of `audio` (standard base64).
fn clips(audio: &str) -> Value {
    json!([{
        "register": "neutral",
        "media_type": "audio/wav",
        "audio": audio,
        "transcript": TRANSCRIPT,
    }])
}

/// The `packs.put` input of one pack.
fn pack(voice_id: &str, pack_id: &str, origin: Value, audio: &str) -> Value {
    json!({
        "voice_id": voice_id,
        "pack_id": pack_id,
        "origin": origin,
        "clips": clips(audio),
    })
}

/// The embedding space the recognition cases enroll and match in.
fn voice_space() -> VoiceEmbeddingSpaceV1 {
    VoiceEmbeddingSpaceV1::new(
        VoiceEmbeddingFamily::EcapaTdnn,
        "ecapa/voxceleb",
        "rev-1",
        16_000,
        4,
        "mono/16k/vad-v1",
    )
    .expect("the embedding space")
}

/// A unit vector of the space along `axis`: one per enrolled subject, so a
/// segment at it matches that subject's print alone.
fn axis_vector(axis: usize) -> Vec<f32> {
    let mut vector = vec![0.0; 4];
    vector[axis] = 1.0;
    vector
}

/// The enrollment of `subject`'s print under the logged grant `grant_id`:
/// one solo-session sample at `vector`, requested at `requested_at`.
fn enrollment(
    subject: EntityId,
    grant_id: &str,
    vector: &[f32],
    requested_at: u64,
) -> VoiceEnrollmentRequest {
    VoiceEnrollmentRequest {
        subject_ref: subject,
        contact_ref: None,
        relationship_ref: None,
        consent_event_ref: grant_id.to_owned(),
        purpose: VoicePrintPurpose::MeetingAttribution,
        space: voice_space(),
        samples: vec![VoiceEnrollmentSampleV1 {
            sample_id: "sample-1".to_owned(),
            source_ref: "solo-session-1".to_owned(),
            language: "en".to_owned(),
            origin: VoiceEnrollmentOrigin::AuthenticatedSoloSession {
                session_ref: "solo-session-1".to_owned(),
                speaker_count: 1,
            },
            duration_ms: 4_000,
            source_sha256: "ab".repeat(32),
            vector: vector.to_vec(),
        }],
        requested_at,
        legal: VoiceEnrollmentLegalContext::unresolved(),
    }
}

/// The `recognition.withdraw` input of withdrawal `event_id` at
/// `occurred_at`, of `subject`'s voice when one is named.
fn recognition_withdrawal(event_id: &str, occurred_at: u64, subject: Option<EntityId>) -> Value {
    let mut input = json!({
        "event_id": event_id,
        "occurred_at": occurred_at,
        "basis": {"ConversationalNotice": {"notice": "please stop learning my voice"}},
    });
    if let Some(subject) = subject {
        input["subject"] = json!(subject.to_hex());
    }
    input
}

/// The `recognition.consent` input of consent `event_id` at `occurred_at`,
/// for `purposes`, of `subject`'s voice when one is named.
fn recognition_consent(
    event_id: &str,
    occurred_at: u64,
    subject: Option<EntityId>,
    purposes: &[&str],
) -> Value {
    let mut input = json!({
        "event_id": event_id,
        "occurred_at": occurred_at,
        "purposes": purposes,
        "basis": {"ConversationalNotice": {"notice": "please learn my voice so you know it's me"}},
    });
    if let Some(subject) = subject {
        input["subject"] = json!(subject.to_hex());
    }
    input
}

impl Served {
    fn holder(&self, caller: Caller) -> Option<&Holder> {
        match caller {
            Caller::Owner => None,
            Caller::Person => Some(&self.person),
            Caller::Agent => Some(&self.agent),
        }
    }

    /// The request binding `caller` signs afresh for one request.
    fn binding(&self, caller: Caller) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = match self.holder(caller) {
            None => hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge.as_bytes())
                .expect("owner holder proof")),
            Some(holder) => {
                let transcript = holder
                    .slip
                    .binding_transcript(challenge.as_bytes())
                    .expect("holder binding transcript");
                hex(&holder.key.sign(&transcript).to_bytes())
            }
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn token(&self, caller: Caller) -> &str {
        match self.holder(caller) {
            None => self.owner_token.as_str(),
            Some(holder) => holder.token.as_str(),
        }
    }

    /// `caller` sends `method` to `uri` with an optional JSON `body`: the
    /// status and the body.
    async fn send(
        &self,
        caller: Caller,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller));
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `caller` posts `verb` with `input` to its facade door.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        self.send(
            caller,
            Method::POST,
            &format!("/v1/core/facade/{verb}"),
            Some(input),
        )
        .await
    }

    /// `caller` posts `verb` and expects a 200: the answer.
    async fn ok(&self, caller: Caller, verb: &str, input: Value) -> Value {
        let (status, body) = self.post(caller, verb, input).await;
        assert_eq!(status, StatusCode::OK, "{caller:?} at {verb}: {body}");
        body
    }

    /// The `render_consent` input of a decision by `caller` on `voice_id`:
    /// a person's decision carries how it was captured.
    fn decision(&self, voice_id: &str, event_id: &str, state: &str, kind: &str) -> Value {
        let mut input = json!({
            "voice_id": voice_id,
            "event_id": event_id,
            "occurred_at": self.vault.now_recorded_at(),
            "reach": "third_party",
            "subject_kind": kind,
            "state": state,
        });
        if kind == "person" {
            input["basis"] = json!({
                "ConversationalNotice": {"notice": "this call's voice may render replies"}
            });
        }
        input
    }

    /// The owner grants render consent on their own voice and banks one
    /// captured pack under it.
    async fn bank_owner_voice(&self) {
        let granted = self
            .ok(
                Caller::Owner,
                RENDER_CONSENT,
                self.decision(OWNER_VOICE, OWNER_GRANT, "granted", "person"),
            )
            .await;
        assert_eq!(granted["state"], "granted", "{granted}");
        let receipt = self
            .ok(
                Caller::Owner,
                PACKS_PUT,
                pack(OWNER_VOICE, OWNER_PACK, captured(OWNER_GRANT), AUDIO),
            )
            .await;
        assert_eq!(
            receipt,
            json!({"voice_id": OWNER_VOICE, "pack_id": OWNER_PACK}),
            "the pack receipt"
        );
    }

    /// `caller`'s inspection of `voice_id`.
    async fn inspect(&self, caller: Caller, voice_id: &str) -> Value {
        self.ok(
            caller,
            INSPECT,
            json!({"voice_id": voice_id, "target": NO_TARGET}),
        )
        .await
    }

    /// `caller`'s render lineage of `voice_id`.
    async fn lineage(&self, caller: Caller, voice_id: &str) -> Vec<Value> {
        self.ok(caller, LINEAGE, json!({"voice_id": voice_id}))
            .await
            .as_array()
            .expect("a lineage list")
            .clone()
    }

    /// `subject`'s voiceprint at `vector`, enrolled on the served vault
    /// through the engine's public calls (no door enrolls a print): the owner
    /// logs the grant `grant_id` for both
    /// purposes, then one solo sample enrolls. Both come before `at`, the
    /// grant first.
    fn enroll_print(&self, subject: EntityId, grant_id: &str, vector: &[f32], at: u64) {
        self.vault
            .record_voice_consent(&VoiceConsentEventV1 {
                event_id: grant_id.to_owned(),
                subject_ref: subject,
                recorded_by_ref: self.owner_person,
                occurred_at: at - 20,
                purposes: vec![
                    VoicePrintPurpose::MeetingAttribution,
                    VoicePrintPurpose::LiveInterlocutor,
                ],
                basis: VoiceConsentBasis::ConversationalNotice {
                    notice: "I learn your voice so I know it's you".to_owned(),
                },
                state: VoiceConsentState::Granted,
            })
            .expect("the logged recognition grant");
        self.vault
            .enroll_voice_print(&enrollment(subject, grant_id, vector, at - 10))
            .expect("the enrolled print");
    }

    /// Whom the served vault recognizes in one segment at `vector`, in a
    /// fresh session `session`: `None` when no enrolled print matches it.
    fn recognized(&self, session: &str, vector: &[f32]) -> Option<EntityId> {
        let space = voice_space();
        let roster = self
            .vault
            .resolve_voice_segments(&VoiceMatchRequest {
                voice_session_ref: session.to_owned(),
                recording_id: format!("{session}-recording"),
                space_id: space.space_id.clone(),
                segments: vec![VoiceSegmentEmbeddingInput {
                    segment_id: "segment-1".to_owned(),
                    diarization_label: "cluster-1".to_owned(),
                    speaker_key: "cluster-1".to_owned(),
                    start_ms: 0,
                    end_ms: 1_000,
                    space_id: space.space_id,
                    vector: vector.to_vec(),
                }],
                invite_attendee_refs: Vec::new(),
                policy: VoiceMatchPolicy::with_known_default(0.7),
                created_at: self.vault.now_recorded_at(),
                purpose: VoicePrintPurpose::MeetingAttribution,
                coverage: VoiceRunCoverage::Partial,
            })
            .expect("the match");
        roster.segments[0].subject_ref
    }

    /// The owner mints the agent one Grant naming `read` (so the Grant
    /// confers) and `verbs`, at the Grant mint door: answers its id.
    async fn grant_agent(&self, verbs: &[&str]) -> String {
        let verbs: Vec<&str> = std::iter::once("read")
            .chain(verbs.iter().copied())
            .collect();
        let minted = self
            .ok(
                Caller::Owner,
                GRANT_MINT,
                json!({
                    "agent": self.agent.actor.to_hex(),
                    "authority_scope": {
                        "worlds": {"kind": "all"},
                        "facets": {"kind": "all"},
                        "bands": {"kind": "all"},
                        "audience": {"kind": "all"},
                        "verbs": {"kind": "some", "values": verbs},
                        "sensitivity": {"kind": "at_most", "value": "restricted"},
                    },
                }),
            )
            .await;
        assert_eq!(
            minted["grant"]["confers"], true,
            "the Grant confers: {minted}"
        );
        minted["grant"]["grant_ref"]
            .as_str()
            .expect("the Grant's id")
            .to_owned()
    }

    /// The owner's inbox notices that a person's spoken recognition
    /// withdrawal was logged, as (result, detail).
    fn withdrawal_notices(&self) -> Vec<(Option<String>, Option<String>)> {
        self.vault
            .memory(self.owner_person, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows
            .into_iter()
            .filter(|row| {
                serde_json::to_value(row.kind).ok() == Some(json!("voice_recognition_withdrawn"))
            })
            .map(|row| (row.source.result, row.source.detail))
            .collect()
    }

    /// The owner's inbox notices that a counterparty's spoken recognition
    /// consent was logged, as (result, detail).
    fn consent_notices(&self) -> Vec<(Option<String>, Option<String>)> {
        self.vault
            .memory(self.owner_person, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows
            .into_iter()
            .filter(|row| {
                serde_json::to_value(row.kind).ok() == Some(json!("voice_recognition_consented"))
            })
            .map(|row| (row.source.result, row.source.detail))
            .collect()
    }
}

/// A captured pack banks only under its subject's own current render grant;
/// then the bank holds it as the owner's person voice and answers its
/// metadata, never its audio or transcript. (P1: identity lives in our ref
/// bank.)
#[test]
fn a_captured_pack_needs_its_subjects_own_grant_and_reads_back_as_metadata() {
    run_on_engine_stack("voices-captured-pack", || async {
        let served = served().await;
        let (status, body) = served
            .post(
                Caller::Owner,
                PACKS_PUT,
                pack(OWNER_VOICE, OWNER_PACK, captured(OWNER_GRANT), AUDIO),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "no pack before the grant: {body}"
        );
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");

        served.bank_owner_voice().await;
        let inspection = served.inspect(Caller::Owner, OWNER_VOICE).await;
        let identity = &inspection["identity"];
        assert_eq!(
            identity["owner"],
            served.owner_person.to_hex(),
            "the owner's PERSON is the voice's subject: {inspection}"
        );
        assert_eq!(identity["subject_kind"], "person", "{inspection}");
        assert_eq!(identity["pack_ids"], json!([OWNER_PACK]), "{inspection}");
        assert_eq!(
            inspection["render_consent"]["state"], "granted",
            "{inspection}"
        );
        let clip = &inspection["packs"][0]["clips"][0];
        assert_eq!(clip["register"], "neutral", "{inspection}");
        assert_eq!(clip["audio_bytes"], 3, "{inspection}");
        let text = inspection.to_string();
        assert!(
            !text.contains(AUDIO) && !text.contains(TRANSCRIPT),
            "the inspection answers metadata, never audio or transcripts: {inspection}"
        );
    });
}

/// A second person and an agent are refused at all six doors on the owner's
/// voice, and nothing of it changes. (Door: a person's voice is reached only
/// on that person's own proof.)
#[test]
fn another_person_and_an_agent_never_reach_the_owners_voice() {
    run_on_engine_stack("voices-strangers", || async {
        let served = served().await;
        served.bank_owner_voice().await;
        let inspection = served.inspect(Caller::Owner, OWNER_VOICE).await;
        let lineage = served.lineage(Caller::Owner, OWNER_VOICE).await;
        assert_eq!(lineage.len(), 1, "one decision: {lineage:?}");

        for caller in [Caller::Person, Caller::Agent] {
            let doors = [
                (
                    PACKS_PUT,
                    pack(
                        OWNER_VOICE,
                        "doors-custody-stranger-pack",
                        designed(),
                        AUDIO,
                    ),
                ),
                (
                    RENDER_CONSENT,
                    served.decision(
                        OWNER_VOICE,
                        "doors-custody-stranger-withdrawal",
                        "withdrawn",
                        "person",
                    ),
                ),
                (
                    PROVISION,
                    json!({"voice_id": OWNER_VOICE, "target": NO_TARGET}),
                ),
                (EVICT, json!({"voice_id": OWNER_VOICE, "target": NO_TARGET})),
                (
                    INSPECT,
                    json!({"voice_id": OWNER_VOICE, "target": NO_TARGET}),
                ),
                (LINEAGE, json!({"voice_id": OWNER_VOICE})),
            ];
            for (verb, input) in doors {
                let (status, body) = served.post(caller, verb, input).await;
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "{caller:?} at {verb}: {body}"
                );
                assert_eq!(
                    error_code(&body),
                    Some("BAD_REQUEST"),
                    "{caller:?} at {verb}: {body}"
                );
            }
        }

        assert_eq!(
            served.inspect(Caller::Owner, OWNER_VOICE).await,
            inspection,
            "the owner's voice is unchanged"
        );
        assert_eq!(
            served.lineage(Caller::Owner, OWNER_VOICE).await,
            lineage,
            "no decision was recorded on the owner's voice"
        );
    });
}

/// An agent banks the voice it designed and reads it as its creator, but its
/// credential never records a decision on a real person's voice. (P2:
/// design has its own consent and lifecycle.)
#[test]
fn an_agent_banks_its_own_designed_voice_but_never_consents_for_a_person() {
    run_on_engine_stack("voices-designed", || async {
        let served = served().await;
        let voice = "doors-custody-designed-voice";
        let receipt = served
            .ok(
                Caller::Agent,
                PACKS_PUT,
                pack(voice, "doors-custody-designed-pack", designed(), AUDIO),
            )
            .await;
        assert_eq!(receipt["voice_id"], voice, "{receipt}");
        let inspection = served.inspect(Caller::Agent, voice).await;
        assert_eq!(
            inspection["identity"]["owner"],
            served.agent.actor.to_hex(),
            "the agent is the designed voice's creator: {inspection}"
        );
        assert_eq!(
            inspection["identity"]["subject_kind"], "designed",
            "{inspection}"
        );

        let person_voice = "doors-custody-agent-person-voice";
        let (status, body) = served
            .post(
                Caller::Agent,
                RENDER_CONSENT,
                served.decision(
                    person_voice,
                    "doors-custody-agent-grant",
                    "granted",
                    "person",
                ),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a creator's credential never consents for a person: {body}"
        );
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");
        let (status, body) = served
            .post(
                Caller::Owner,
                INSPECT,
                json!({"voice_id": person_voice, "target": NO_TARGET}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "the bank holds nothing of that voice: {body}"
        );
    });
}

/// A render withdrawal becomes the voice's current decision: the grant no
/// longer admits a captured pack, while the banked packs, the grant and the
/// withdrawal stay on record, and replaying the withdrawal changes nothing.
/// (Arch-0061 :124: withdrawal keeps the consent record.)
#[test]
fn a_render_withdrawal_ends_the_grant_and_keeps_the_record() {
    run_on_engine_stack("voices-withdrawal", || async {
        let served = served().await;
        served.bank_owner_voice().await;
        let withdrawal = served.decision(
            OWNER_VOICE,
            "doors-custody-owner-withdrawal",
            "withdrawn",
            "person",
        );
        let receipt = served
            .ok(Caller::Owner, RENDER_CONSENT, withdrawal.clone())
            .await;
        assert_eq!(receipt["state"], "withdrawn", "{receipt}");
        assert_eq!(receipt["sequence"], 2, "{receipt}");
        assert_eq!(receipt["replayed"], false, "{receipt}");

        let inspection = served.inspect(Caller::Owner, OWNER_VOICE).await;
        assert_eq!(
            inspection["render_consent"]["state"], "withdrawn",
            "the withdrawal is the current decision: {inspection}"
        );
        assert_eq!(
            inspection["identity"]["pack_ids"],
            json!([OWNER_PACK]),
            "the banked pack stays: {inspection}"
        );
        assert!(
            inspection["target"]["current"].is_null(),
            "no clone renders the voice: {inspection}"
        );
        let lineage = served.lineage(Caller::Owner, OWNER_VOICE).await;
        let states: Vec<&Value> = lineage
            .iter()
            .map(|event| &event["decision"]["state"])
            .collect();
        assert_eq!(
            states,
            [&json!("granted"), &json!("withdrawn")],
            "the grant and the withdrawal stay on record: {lineage:?}"
        );

        let (status, body) = served
            .post(
                Caller::Owner,
                PACKS_PUT,
                pack(
                    OWNER_VOICE,
                    "doors-custody-after-withdrawal",
                    captured(OWNER_GRANT),
                    AUDIO,
                ),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the withdrawn grant admits no captured pack: {body}"
        );

        let replay = served.ok(Caller::Owner, RENDER_CONSENT, withdrawal).await;
        assert_eq!(replay["replayed"], true, "{replay}");
        assert_eq!(replay["sequence"], 2, "{replay}");
        assert_eq!(
            served.lineage(Caller::Owner, OWNER_VOICE).await.len(),
            2,
            "a replay records nothing new"
        );
    });
}

/// A banked pack never changes: the same bytes again are a no-op, other
/// bytes under its id are refused, and the bank keeps the first. (P2: the
/// ref bank's lifecycle.)
#[test]
fn a_banked_pack_never_changes() {
    run_on_engine_stack("voices-immutable", || async {
        let served = served().await;
        served.bank_owner_voice().await;
        let before = served.inspect(Caller::Owner, OWNER_VOICE).await;
        let receipt = served
            .ok(
                Caller::Owner,
                PACKS_PUT,
                pack(OWNER_VOICE, OWNER_PACK, captured(OWNER_GRANT), AUDIO),
            )
            .await;
        assert_eq!(
            receipt["pack_id"], OWNER_PACK,
            "an identical retry: {receipt}"
        );
        let (status, body) = served
            .post(
                Caller::Owner,
                PACKS_PUT,
                pack(OWNER_VOICE, OWNER_PACK, captured(OWNER_GRANT), "AQIDBA=="),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "other bytes under a banked id are refused: {body}"
        );
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");
        let after = served.inspect(Caller::Owner, OWNER_VOICE).await;
        assert_eq!(after, before, "the bank keeps the first pack");
        assert_eq!(after["packs"][0]["clips"][0]["audio_bytes"], 3, "{after}");
    });
}

/// A clone is provisioned only at a target this host configures, and only
/// on the caller's own voice, judged before any target: an unknown target
/// is not found for the owner, another's voice is refused before the target
/// is looked up, and evicting an unprovisioned target drops nothing. (P1:
/// vendors are render targets only.)
#[test]
fn provisioning_reaches_only_a_configured_target_on_ones_own_voice() {
    run_on_engine_stack("voices-provision", || async {
        let served = served().await;
        served.bank_owner_voice().await;
        let target = json!({"voice_id": OWNER_VOICE, "target": NO_TARGET});
        let (status, body) = served.post(Caller::Owner, PROVISION, target.clone()).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "no configured target by that name: {body}"
        );
        assert_eq!(error_code(&body), Some("NOT_FOUND"), "{body}");
        for caller in [Caller::Person, Caller::Agent] {
            let (status, body) = served.post(caller, PROVISION, target.clone()).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{caller:?}: another's voice is refused before its target: {body}"
            );
        }
        let evicted = served.ok(Caller::Owner, EVICT, target).await;
        assert_eq!(evicted["evicted"], false, "{evicted}");
        assert_eq!(evicted["vendor"], "absent", "{evicted}");
        let inspection = served.inspect(Caller::Owner, OWNER_VOICE).await;
        assert!(
            inspection["target"]["current"].is_null(),
            "no clone was made: {inspection}"
        );
        assert_eq!(
            inspection["identity"]["pack_ids"],
            json!([OWNER_PACK]),
            "{inspection}"
        );
    });
}

/// The `/v1/ai/voices` routes answer the owner and refuse a second person
/// and an agent with `owner_required` at every method before any bank read
/// or write. (Door: the voice bank routes are the owner's.)
#[test]
fn the_voice_routes_are_the_owners_alone() {
    run_on_engine_stack("voices-routes", || async {
        let served = served().await;
        served.bank_owner_voice().await;
        let view = format!("/v1/ai/voices/{OWNER_VOICE}");
        let (status, before) = served.send(Caller::Owner, Method::GET, &view, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the voice: {before}"
        );

        let owner = served.owner_person.to_hex();
        let target = format!("/v1/ai/voices/{OWNER_VOICE}/targets/{NO_TARGET}");
        let requests = [
            (Method::GET, view.clone(), None),
            (
                Method::POST,
                format!("/v1/ai/voices/{OWNER_VOICE}/packs"),
                Some(json!({
                    "pack_id": "doors-custody-route-pack",
                    "owner": owner,
                    "origin": designed(),
                    "clips": clips(AUDIO),
                })),
            ),
            (
                Method::POST,
                format!("/v1/ai/voices/{OWNER_VOICE}/render_consent"),
                Some(json!({
                    "event_id": "doors-custody-route-withdrawal",
                    "subject": owner,
                    "recorded_by": owner,
                    "occurred_at": served.vault.now_recorded_at(),
                    "reach": "third_party",
                    "basis": {"ConversationalNotice": {"notice": "withdrawn by the route"}},
                    "state": "withdrawn",
                })),
            ),
            (Method::POST, target.clone(), Some(json!({}))),
            (Method::DELETE, target, None),
        ];
        for caller in [Caller::Person, Caller::Agent] {
            for (method, uri, body) in requests.clone() {
                let (status, answer) = served.send(caller, method.clone(), &uri, body).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{caller:?} {method} {uri}: {answer}"
                );
                assert_eq!(
                    error_code(&answer),
                    Some("owner_required"),
                    "{caller:?} {method} {uri}: {answer}"
                );
            }
        }

        let (status, after) = served.send(Caller::Owner, Method::GET, &view, None).await;
        assert_eq!(status, StatusCode::OK, "{after}");
        assert_eq!(after, before, "nothing of the voice changed");
    });
}

/// The owner withdraws recognition consent for their own voice at the door:
/// the print, its sample and its active pointer are deleted, so nothing
/// recognizes the voice any more, and the withdrawal stays in the consent
/// log, so the old grant enrolls nothing again and a replay deletes nothing.
/// The render bank keeps its own consent and packs. (promise-dura-13.)
#[test]
fn a_recognition_withdrawal_deletes_the_print_and_keeps_the_consent_record() {
    run_on_engine_stack("voices-recognition-withdrawal", || async {
        let served = served().await;
        served.bank_owner_voice().await;
        let now = served.vault.now_recorded_at();
        let owner = served.owner_person;
        served.enroll_print(owner, "owner-recognition-grant", &axis_vector(0), now);
        assert_eq!(
            served.recognized("before-withdrawal", &axis_vector(0)),
            Some(owner),
            "the enrolled print recognizes the owner"
        );

        let withdrawal = recognition_withdrawal("owner-recognition-withdrawal", now, None);
        let receipt = served
            .ok(Caller::Owner, RECOGNITION_WITHDRAW, withdrawal.clone())
            .await;
        assert_eq!(receipt["subject"], owner.to_hex(), "{receipt}");
        assert_eq!(receipt["recorded_by"], owner.to_hex(), "{receipt}");
        assert_eq!(receipt["replayed"], false, "{receipt}");
        assert_eq!(receipt["already_absent"], false, "{receipt}");
        assert_eq!(receipt["deleted_print"], true, "{receipt}");
        assert_eq!(receipt["deleted_sample_count"], 1, "{receipt}");
        assert!(
            receipt["deleted_vector_count"].as_u64() >= Some(1),
            "the sample's vector is deleted: {receipt}"
        );
        assert_eq!(receipt["deleted_active_pointer"], true, "{receipt}");
        assert_eq!(
            served.recognized("after-withdrawal", &axis_vector(0)),
            None,
            "no print recognizes the owner after the withdrawal"
        );

        // The withdrawal stays in the consent log: the grant it withdrew
        // enrolls nothing again, and its replay finds it recorded.
        assert!(
            served
                .vault
                .enroll_voice_print(&enrollment(
                    owner,
                    "owner-recognition-grant",
                    &axis_vector(0),
                    now,
                ))
                .is_err(),
            "the withdrawn grant enrolls no new print"
        );
        let replay = served
            .ok(Caller::Owner, RECOGNITION_WITHDRAW, withdrawal)
            .await;
        assert_eq!(replay["replayed"], true, "{replay}");
        assert_eq!(replay["deleted_print"], false, "{replay}");
        assert_eq!(replay["deleted_sample_count"], 0, "{replay}");

        // The render bank keeps its own consent and its pack.
        let inspection = served.inspect(Caller::Owner, OWNER_VOICE).await;
        assert_eq!(
            inspection["identity"]["pack_ids"],
            json!([OWNER_PACK]),
            "the banked pack stays: {inspection}"
        );
        assert_eq!(
            inspection["render_consent"]["state"], "granted",
            "the render grant stays: {inspection}"
        );
    });
}

/// A person withdraws recognition consent for their own voice, and only the
/// vault owner for another subject's, such as a counterparty who holds no
/// credential here. A person naming another subject and an agent with no
/// Grant are refused, and every print they named still recognizes its
/// subject.
#[test]
fn a_person_withdraws_their_own_voice_and_the_owner_any_subjects() {
    run_on_engine_stack("voices-recognition-who", || async {
        let served = served().await;
        let now = served.vault.now_recorded_at();
        let owner = served.owner_person;
        let person = served.person.actor;
        let counterparty = EntityId::now();
        served.enroll_print(owner, "owner-grant", &axis_vector(0), now);
        served.enroll_print(person, "person-grant", &axis_vector(1), now);
        served.enroll_print(counterparty, "counterparty-grant", &axis_vector(2), now);

        let refused = [
            (Caller::Person, Some(owner)),
            (Caller::Person, Some(counterparty)),
            (Caller::Agent, None),
            (Caller::Agent, Some(owner)),
            (Caller::Agent, Some(counterparty)),
        ];
        for (index, (caller, subject)) in refused.into_iter().enumerate() {
            let input = recognition_withdrawal(&format!("refused-{index}"), now, subject);
            let (status, body) = served.post(caller, RECOGNITION_WITHDRAW, input).await;
            assert!(
                !status.is_success(),
                "{caller:?} on {subject:?} is refused: {status} {body}"
            );
        }
        assert_eq!(
            served.recognized("after-refusals-owner", &axis_vector(0)),
            Some(owner)
        );
        assert_eq!(
            served.recognized("after-refusals-person", &axis_vector(1)),
            Some(person)
        );
        assert_eq!(
            served.recognized("after-refusals-counterparty", &axis_vector(2)),
            Some(counterparty)
        );

        let own = served
            .ok(
                Caller::Person,
                RECOGNITION_WITHDRAW,
                recognition_withdrawal("person-withdrawal", now, None),
            )
            .await;
        assert_eq!(own["subject"], person.to_hex(), "{own}");
        assert_eq!(own["recorded_by"], person.to_hex(), "{own}");
        assert_eq!(own["deleted_print"], true, "{own}");
        assert_eq!(
            served.recognized("after-person-withdrawal", &axis_vector(1)),
            None
        );

        let for_counterparty = served
            .ok(
                Caller::Owner,
                RECOGNITION_WITHDRAW,
                recognition_withdrawal("counterparty-withdrawal", now, Some(counterparty)),
            )
            .await;
        assert_eq!(
            for_counterparty["subject"],
            counterparty.to_hex(),
            "{for_counterparty}"
        );
        assert_eq!(
            for_counterparty["recorded_by"],
            owner.to_hex(),
            "the owner records the counterparty's word: {for_counterparty}"
        );
        assert_eq!(
            for_counterparty["deleted_print"], true,
            "{for_counterparty}"
        );
        assert_eq!(
            served.recognized("after-counterparty-withdrawal", &axis_vector(2)),
            None
        );
        assert_eq!(
            served.recognized("after-both-withdrawals", &axis_vector(0)),
            Some(owner),
            "the owner's own print is untouched"
        );
    });
}

/// An agent whose own Grant names the consent-log verb logs a
/// counterparty's spoken withdrawal on a call (VOICE-WITHDRAW-AGENT = C,
/// VOICE-WITHDRAW-AGENT-GRANT = A; lead: "the way out must never be harder
/// than the way in"): the print goes, the agent records the withdrawal,
/// and the owner is told in their inbox who asked and which consent it
/// was. An agent with no Grant, or with a conferring one that names the
/// withdraw verb but not the consent-log verb, is refused; the consent-log
/// Grant reaches no owner's voice and needs a subject. The withdrawal only
/// narrows: the withdrawn grant enrolls nothing again, every other print
/// still recognizes its subject, and a replay deletes nothing and tells no
/// one again.
#[test]
fn an_agent_with_the_consent_log_grant_logs_a_counterpartys_withdrawal_and_tells_the_owner() {
    run_on_engine_stack("voices-recognition-agent", || async {
        let served = served().await;
        let now = served.vault.now_recorded_at();
        let owner = served.owner_person;
        let person = served.person.actor;
        let agent = served.agent.actor;
        let counterparty = EntityId::now();
        served.enroll_print(owner, "owner-grant", &axis_vector(0), now);
        served.enroll_print(person, "person-grant", &axis_vector(1), now);
        served.enroll_print(counterparty, "counterparty-grant", &axis_vector(2), now);

        // No Grant, then a conferring Grant naming the withdraw verb and not
        // the consent-log verb: refused.
        for (index, verb) in [None, Some(RECOGNITION_WITHDRAW)].into_iter().enumerate() {
            if let Some(verb) = verb {
                served.grant_agent(&[verb]).await;
            }
            let input =
                recognition_withdrawal(&format!("ungranted-{index}"), now, Some(counterparty));
            let (status, body) = served
                .post(Caller::Agent, RECOGNITION_WITHDRAW, input)
                .await;
            assert_eq!(
                error_code(&body),
                Some("FORBIDDEN"),
                "an agent whose Grant names {verb:?} is refused: {status} {body}"
            );
        }
        assert_eq!(
            served.recognized("after-ungranted", &axis_vector(2)),
            Some(counterparty)
        );

        let grant = served.grant_agent(&[RECOGNITION_CONSENT]).await;
        // The consent-log Grant reaches no owner's voice and needs a subject.
        for (index, subject) in [Some(owner), None].into_iter().enumerate() {
            let input = recognition_withdrawal(&format!("out-of-reach-{index}"), now, subject);
            let (status, body) = served
                .post(Caller::Agent, RECOGNITION_WITHDRAW, input)
                .await;
            assert!(
                !status.is_success(),
                "the agent on {subject:?} is refused: {status} {body}"
            );
        }
        assert_eq!(
            served.recognized("after-out-of-reach", &axis_vector(0)),
            Some(owner)
        );
        assert!(
            served.withdrawal_notices().is_empty(),
            "a refusal tells no one"
        );

        let withdrawal =
            recognition_withdrawal("counterparty-spoken-withdrawal", now, Some(counterparty));
        let receipt = served
            .ok(Caller::Agent, RECOGNITION_WITHDRAW, withdrawal.clone())
            .await;
        assert_eq!(receipt["subject"], counterparty.to_hex(), "{receipt}");
        assert_eq!(
            receipt["recorded_by"],
            agent.to_hex(),
            "the agent records the counterparty's word: {receipt}"
        );
        assert_eq!(receipt["replayed"], false, "{receipt}");
        assert_eq!(receipt["deleted_print"], true, "{receipt}");
        assert_eq!(receipt["deleted_sample_count"], 1, "{receipt}");
        assert_eq!(receipt["deleted_active_pointer"], true, "{receipt}");
        assert_eq!(
            served.recognized("after-agent-withdrawal", &axis_vector(2)),
            None
        );

        // The owner is told, once, who asked and which consent it was.
        let notices = served.withdrawal_notices();
        assert_eq!(
            notices.len(),
            1,
            "one notice for the one owner: {notices:?}"
        );
        let (result, detail) = &notices[0];
        assert_eq!(result.as_deref(), Some("counterparty-spoken-withdrawal"));
        let detail = detail.as_deref().expect("the notice says who asked");
        assert!(
            detail.contains("asked to stop voice recognition on a call"),
            "{detail}"
        );
        assert!(detail.contains("recognition consent"), "{detail}");
        assert!(
            detail.contains(&agent.to_hex()) && detail.contains(&grant),
            "the notice names the agent and its Grant: {detail}"
        );

        // It only narrows: the withdrawn grant enrolls nothing again, every
        // other print still recognizes its subject, and a replay deletes
        // nothing and tells no one again.
        assert!(
            served
                .vault
                .enroll_voice_print(&enrollment(
                    counterparty,
                    "counterparty-grant",
                    &axis_vector(2),
                    now,
                ))
                .is_err(),
            "the withdrawn grant enrolls no new print"
        );
        assert_eq!(
            served.recognized("after-agent-owner", &axis_vector(0)),
            Some(owner)
        );
        assert_eq!(
            served.recognized("after-agent-person", &axis_vector(1)),
            Some(person)
        );
        let replay = served
            .ok(Caller::Agent, RECOGNITION_WITHDRAW, withdrawal)
            .await;
        assert_eq!(replay["replayed"], true, "{replay}");
        assert_eq!(replay["deleted_print"], false, "{replay}");
        assert_eq!(
            served.withdrawal_notices().len(),
            1,
            "a replay tells no one again"
        );
    });
}

/// A person logs voice-recognition consent for their own voice, and only the
/// vault owner for another subject's, such as a counterparty who holds no
/// credential here (VOICE-CONSENT-LOG-WHO = A). The door's consent enrols no
/// print itself, but enrolment reads it: the counterparty's print enrols on
/// the logged event id and is recognized. A replay answers replayed, a
/// different decision under the event id is refused, and person and owner
/// acts tell no one.
#[test]
fn a_person_logs_consent_for_their_own_voice_and_the_owner_any_subjects() {
    run_on_engine_stack("voices-recognition-consent-who", || async {
        let served = served().await;
        let now = served.vault.now_recorded_at();
        let owner = served.owner_person;
        let person = served.person.actor;
        let counterparty = EntityId::now();

        let own = served
            .ok(
                Caller::Person,
                RECOGNITION_CONSENT,
                recognition_consent("person-consent", now, None, &["meeting_attribution"]),
            )
            .await;
        assert_eq!(own["subject"], person.to_hex(), "{own}");
        assert_eq!(own["recorded_by"], person.to_hex(), "{own}");
        assert_eq!(own["replayed"], false, "{own}");
        assert_eq!(own["purposes"], json!(["meeting_attribution"]), "{own}");

        let (status, body) = served
            .post(
                Caller::Person,
                RECOGNITION_CONSENT,
                recognition_consent(
                    "person-for-counterparty",
                    now,
                    Some(counterparty),
                    &["meeting_attribution"],
                ),
            )
            .await;
        assert!(
            !status.is_success(),
            "the person naming another subject is refused: {status} {body}"
        );

        let grant_id = "counterparty-consent";
        let granted = served
            .ok(
                Caller::Owner,
                RECOGNITION_CONSENT,
                recognition_consent(grant_id, now, Some(counterparty), &["meeting_attribution"]),
            )
            .await;
        assert_eq!(granted["subject"], counterparty.to_hex(), "{granted}");
        assert_eq!(
            granted["recorded_by"],
            owner.to_hex(),
            "the owner records the counterparty's word: {granted}"
        );
        assert_eq!(granted["replayed"], false, "{granted}");
        assert_eq!(
            granted["purposes"],
            json!(["meeting_attribution"]),
            "{granted}"
        );

        served
            .vault
            .enroll_voice_print(&enrollment(
                counterparty,
                grant_id,
                &axis_vector(2),
                now + 10,
            ))
            .expect("the print enrols on the door's consent");
        assert_eq!(
            served.recognized("after-consent", &axis_vector(2)),
            Some(counterparty)
        );

        let replay = served
            .ok(
                Caller::Owner,
                RECOGNITION_CONSENT,
                recognition_consent(grant_id, now, Some(counterparty), &["meeting_attribution"]),
            )
            .await;
        assert_eq!(replay["replayed"], true, "{replay}");

        let (status, body) = served
            .post(
                Caller::Owner,
                RECOGNITION_CONSENT,
                recognition_consent(grant_id, now, Some(counterparty), &["live_interlocutor"]),
            )
            .await;
        assert!(
            !status.is_success(),
            "a different decision under the event id is refused: {status} {body}"
        );

        // A consent dated past the vault's clock is refused: it would outlive a
        // withdrawal logged before its date.
        let (status, body) = served
            .post(
                Caller::Owner,
                RECOGNITION_CONSENT,
                recognition_consent(
                    "future-dated-consent",
                    now + 3_600,
                    Some(counterparty),
                    &["meeting_attribution"],
                ),
            )
            .await;
        assert!(
            !status.is_success(),
            "a consent dated an hour ahead is refused: {status} {body}"
        );
        // Not even a minute ahead (REVIEW-9224 P1): a withdrawal the subject
        // then logs at the vault's time would be dated before the grant, and the
        // grant would outlive it.
        let (status, body) = served
            .post(
                Caller::Owner,
                RECOGNITION_CONSENT,
                recognition_consent(
                    "minute-ahead-consent",
                    now + 60,
                    Some(counterparty),
                    &["meeting_attribution"],
                ),
            )
            .await;
        assert!(
            !status.is_success(),
            "a consent dated a minute ahead is refused: {status} {body}"
        );

        assert!(
            served.consent_notices().is_empty(),
            "person and owner acts tell no one"
        );
    });
}

/// An agent whose own Grant names the consent-log verb logs a
/// counterparty's spoken consent on a call (VOICE-CONSENT-LOG-WHO = A;
/// oneiron-arch-0061 "the agent logs who/when/what"): the agent records the
/// consent, and the owner is told in their inbox who agreed, for which
/// purposes, and under which Grant. An agent with no Grant, or with a
/// conferring one that names the withdraw verb but not the consent-log verb,
/// is refused; the consent-log Grant reaches no live owner's voice and needs
/// a subject. A replay answers replayed and tells no one again, and the
/// counterparty's print then enrols on the logged event id and is recognized.
/// Logging consent enrols nothing.
#[test]
fn an_agent_with_the_consent_log_grant_logs_a_counterpartys_consent_and_tells_the_owner() {
    run_on_engine_stack("voices-recognition-consent-agent", || async {
        let served = served().await;
        let now = served.vault.now_recorded_at();
        let owner = served.owner_person;
        let agent = served.agent.actor;
        let counterparty = EntityId::now();

        // No Grant, then a conferring Grant naming the withdraw verb and not
        // the consent-log verb: refused.
        for (index, verb) in [None, Some(RECOGNITION_WITHDRAW)].into_iter().enumerate() {
            if let Some(verb) = verb {
                served.grant_agent(&[verb]).await;
            }
            let input = recognition_consent(
                &format!("ungranted-{index}"),
                now,
                Some(counterparty),
                &["meeting_attribution"],
            );
            let (status, body) = served.post(Caller::Agent, RECOGNITION_CONSENT, input).await;
            assert_eq!(
                error_code(&body),
                Some("FORBIDDEN"),
                "an agent whose Grant names {verb:?} is refused: {status} {body}"
            );
        }

        let grant = served.grant_agent(&[RECOGNITION_CONSENT]).await;
        // The consent-log Grant reaches no live owner's voice, nor the agent's
        // own, and needs a subject.
        for (index, subject) in [Some(owner), Some(agent), None].into_iter().enumerate() {
            let input = recognition_consent(
                &format!("out-of-reach-{index}"),
                now,
                subject,
                &["meeting_attribution"],
            );
            let (status, body) = served.post(Caller::Agent, RECOGNITION_CONSENT, input).await;
            assert!(
                !status.is_success(),
                "the agent on {subject:?} is refused: {status} {body}"
            );
        }
        assert!(
            served.consent_notices().is_empty(),
            "a refusal tells no one"
        );

        let consent_id = "counterparty-spoken-consent";
        let consent = recognition_consent(
            consent_id,
            now,
            Some(counterparty),
            &["meeting_attribution"],
        );
        let receipt = served
            .ok(Caller::Agent, RECOGNITION_CONSENT, consent.clone())
            .await;
        assert_eq!(receipt["subject"], counterparty.to_hex(), "{receipt}");
        assert_eq!(
            receipt["recorded_by"],
            agent.to_hex(),
            "the agent records the counterparty's word: {receipt}"
        );
        assert_eq!(receipt["replayed"], false, "{receipt}");
        assert_eq!(
            receipt["purposes"],
            json!(["meeting_attribution"]),
            "{receipt}"
        );

        // The owner is told, once, who agreed and for which purposes.
        let notices = served.consent_notices();
        assert_eq!(
            notices.len(),
            1,
            "one notice for the one owner: {notices:?}"
        );
        let (result, detail) = &notices[0];
        assert_eq!(result.as_deref(), Some(consent_id));
        let detail = detail.as_deref().expect("the notice says who agreed");
        assert!(
            detail.contains("agreed to voice recognition on a call"),
            "{detail}"
        );
        assert!(detail.contains("meeting_attribution"), "{detail}");
        assert!(
            detail.contains(&agent.to_hex()) && detail.contains(&grant),
            "the notice names the agent and its Grant: {detail}"
        );

        let replay = served.ok(Caller::Agent, RECOGNITION_CONSENT, consent).await;
        assert_eq!(replay["replayed"], true, "{replay}");
        assert_eq!(
            served.consent_notices().len(),
            1,
            "a replay tells no one again"
        );

        served
            .vault
            .enroll_voice_print(&enrollment(
                counterparty,
                consent_id,
                &axis_vector(2),
                now + 10,
            ))
            .expect("the print enrols on the agent-logged consent");
        assert_eq!(
            served.recognized("after-agent-consent", &axis_vector(2)),
            Some(counterparty)
        );
    });
}

impl Served {
    /// `person`'s own inbox notices that an agent logged their spoken
    /// recognition withdrawal, as (result, detail).
    fn subject_withdrawal_notices(
        &self,
        person: EntityId,
    ) -> Vec<(Option<String>, Option<String>)> {
        self.vault
            .memory(person, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the person's inbox")
            .rows
            .into_iter()
            .filter(|row| {
                serde_json::to_value(row.kind).ok()
                    == Some(json!("voice_recognition_withdrawal_logged_for_subject"))
            })
            .map(|row| (row.source.result, row.source.detail))
            .collect()
    }
}

/// An agent logs recognition consent only for a person who holds no
/// credential in this vault (VOICE-CONSENT-LOG-MEMBERS, consent = B): a live
/// member consents on their own proof. The refusal logs nothing and tells
/// no one, and the member's own consent on their own proof still lands.
#[test]
fn an_agent_never_logs_consent_for_a_live_member() {
    run_on_engine_stack("voices-recognition-consent-member", || async {
        let served = served().await;
        let now = served.vault.now_recorded_at();
        let member = served.person.actor;
        served.grant_agent(&[RECOGNITION_CONSENT]).await;

        let input = recognition_consent(
            "member-spoken-consent",
            now,
            Some(member),
            &["meeting_attribution"],
        );
        let (status, body) = served.post(Caller::Agent, RECOGNITION_CONSENT, input).await;
        assert_eq!(
            error_code(&body),
            Some("FORBIDDEN"),
            "the agent on a live member's voice is refused: {status} {body}"
        );
        assert!(
            served.consent_notices().is_empty(),
            "a refusal tells no one"
        );

        let own = served
            .ok(
                Caller::Person,
                RECOGNITION_CONSENT,
                recognition_consent("member-own-consent", now, None, &["meeting_attribution"]),
            )
            .await;
        assert_eq!(own["subject"], member.to_hex(), "{own}");
        assert_eq!(own["recorded_by"], member.to_hex(), "{own}");
    });
}

/// An agent's logged withdrawal of a live member's voice stands
/// (VOICE-CONSENT-LOG-MEMBERS, withdrawal = A: it only narrows), and the
/// member is told in the same write that the agent recorded they asked to
/// stop voice recognition. The owner is told as before; a counterparty, who
/// holds no credential here, gets no such notice; a replay tells no one
/// again.
#[test]
fn an_agent_logs_a_live_members_withdrawal_and_tells_the_member() {
    run_on_engine_stack("voices-recognition-withdraw-member", || async {
        let served = served().await;
        let now = served.vault.now_recorded_at();
        let owner = served.owner_person;
        let member = served.person.actor;
        let agent = served.agent.actor;
        let counterparty = EntityId::now();
        served.enroll_print(member, "member-grant", &axis_vector(1), now);
        served.enroll_print(counterparty, "counterparty-grant", &axis_vector(2), now);
        let grant = served.grant_agent(&[RECOGNITION_CONSENT]).await;

        let withdrawal = recognition_withdrawal("member-spoken-withdrawal", now, Some(member));
        let receipt = served
            .ok(Caller::Agent, RECOGNITION_WITHDRAW, withdrawal.clone())
            .await;
        assert_eq!(receipt["subject"], member.to_hex(), "{receipt}");
        assert_eq!(receipt["recorded_by"], agent.to_hex(), "{receipt}");
        assert_eq!(receipt["replayed"], false, "{receipt}");
        assert_eq!(
            served.recognized("after-member-withdrawal", &axis_vector(1)),
            None,
            "recognition of the member stops in the same write"
        );

        let told = served.subject_withdrawal_notices(member);
        assert_eq!(told.len(), 1, "one notice for the member: {told:?}");
        let (result, detail) = &told[0];
        assert_eq!(result.as_deref(), Some("member-spoken-withdrawal"));
        let detail = detail.as_deref().expect("the notice says who recorded it");
        assert!(
            detail.contains("recorded that you asked to stop voice recognition"),
            "{detail}"
        );
        assert!(
            detail.contains(&agent.to_hex()) && detail.contains(&grant),
            "the notice names the agent and its Grant: {detail}"
        );
        assert_eq!(
            served.withdrawal_notices().len(),
            1,
            "the owner is told as before"
        );
        assert!(
            served.subject_withdrawal_notices(owner).is_empty(),
            "the owner's notice is the owner's kind"
        );

        let counterparty_withdrawal =
            recognition_withdrawal("counterparty-spoken-withdrawal", now, Some(counterparty));
        served
            .ok(Caller::Agent, RECOGNITION_WITHDRAW, counterparty_withdrawal)
            .await;
        assert!(
            served.subject_withdrawal_notices(counterparty).is_empty(),
            "a counterparty who holds no credential here is not told"
        );

        let replay = served
            .ok(Caller::Agent, RECOGNITION_WITHDRAW, withdrawal)
            .await;
        assert_eq!(replay["replayed"], true, "{replay}");
        assert_eq!(
            served.subject_withdrawal_notices(member).len(),
            1,
            "a replay tells no one again"
        );
    });
}

impl Served {
    /// The taps `person`'s own notices of an agent-logged withdrawal offer,
    /// as their wire form.
    fn subject_withdrawal_taps(&self, person: EntityId) -> Vec<Value> {
        self.vault
            .memory(person, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the person's inbox")
            .rows
            .into_iter()
            .filter(|row| {
                serde_json::to_value(row.kind).ok()
                    == Some(json!("voice_recognition_withdrawal_logged_for_subject"))
            })
            .flat_map(|row| row.actions)
            .map(|action| serde_json::to_value(action).expect("the tap's wire form"))
            .collect()
    }
}

/// The member's "that wasn't me" on their notice of an agent-logged
/// withdrawal (VOICE-WITHDRAW-UNDO-SHAPE = B): one tap, on their own proof,
/// logs a new recognition grant for the purposes the withdrawal ended. It
/// restores consent only: the print stays deleted, and a fresh enrolment on
/// the restored grant recognizes the member again. An agent cannot send the
/// tap, and a tapped notice offers it no more.
#[test]
fn a_member_disowns_an_agent_logged_withdrawal_and_restores_consent_only() {
    run_on_engine_stack("voices-recognition-withdraw-disown", || async {
        let served = served().await;
        let now = served.vault.now_recorded_at();
        let member = served.person.actor;
        served.enroll_print(member, "member-grant", &axis_vector(1), now);
        served.grant_agent(&[RECOGNITION_CONSENT]).await;
        served
            .ok(
                Caller::Agent,
                RECOGNITION_WITHDRAW,
                // Spoken a moment before the agent logs it: the tap dates the
                // restore one second after the withdrawal, which must not be
                // past the vault's clock.
                recognition_withdrawal("member-spoken-withdrawal", now - 5, Some(member)),
            )
            .await;

        let taps = served.subject_withdrawal_taps(member);
        assert_eq!(taps.len(), 1, "one tap on the member's notice: {taps:?}");
        let tap = &taps[0];
        assert_eq!(tap["verb"], RECOGNITION_CONSENT, "{tap}");
        assert!(
            tap["args"].get("subject").is_none(),
            "the tap is of the member's own voice: {tap}"
        );
        let notices = served.subject_withdrawal_notices(member);
        let detail = notices[0].1.as_deref().expect("the notice's detail");
        assert!(detail.contains("fresh enrolment"), "{detail}");

        let (status, body) = served
            .post(Caller::Agent, RECOGNITION_CONSENT, tap["args"].clone())
            .await;
        assert!(
            !status.is_success(),
            "an agent cannot send the member's tap: {status} {body}"
        );

        let restored = served
            .ok(Caller::Person, RECOGNITION_CONSENT, tap["args"].clone())
            .await;
        assert_eq!(restored["subject"], member.to_hex(), "{restored}");
        assert_eq!(restored["recorded_by"], member.to_hex(), "{restored}");
        assert_eq!(restored["replayed"], false, "{restored}");
        let purposes: BTreeSet<&str> = restored["purposes"]
            .as_array()
            .expect("the restored purposes")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            purposes,
            BTreeSet::from(["live_interlocutor", "meeting_attribution"]),
            "the purposes the withdrawal ended: {restored}"
        );
        assert_eq!(
            served.recognized("after-disown", &axis_vector(1)),
            None,
            "the print stays deleted"
        );
        assert!(
            served.subject_withdrawal_taps(member).is_empty(),
            "a tapped notice offers it no more"
        );

        let event_id = tap["args"]["event_id"]
            .as_str()
            .expect("the restore's event id");
        let at = tap["args"]["occurred_at"]
            .as_u64()
            .expect("the restore's date");
        served
            .vault
            .enroll_voice_print(&enrollment(member, event_id, &axis_vector(1), at + 10))
            .expect("a fresh enrolment on the restored grant");
        assert_eq!(
            served.recognized("after-fresh-enrolment", &axis_vector(1)),
            Some(member)
        );
    });
}

/// A withdrawal dated past the vault's clock is refused at every door, as a
/// consent is: it would void every grant dated before it, a member's
/// restore among them, until the clock reached it. The refusal deletes
/// nothing and tells no one.
#[test]
fn a_withdrawal_dated_past_the_vault_clock_is_refused() {
    run_on_engine_stack("voices-recognition-withdraw-future", || async {
        let served = served().await;
        let now = served.vault.now_recorded_at();
        let member = served.person.actor;
        served.enroll_print(member, "member-grant", &axis_vector(1), now);
        served.grant_agent(&[RECOGNITION_CONSENT]).await;

        for (caller, subject) in [
            (Caller::Agent, Some(member)),
            (Caller::Person, None),
            (Caller::Owner, Some(member)),
        ] {
            let input = recognition_withdrawal(&format!("future-{caller:?}"), now + 60, subject);
            let (status, body) = served.post(caller, RECOGNITION_WITHDRAW, input).await;
            assert!(
                !status.is_success(),
                "{caller:?}: a withdrawal dated a minute ahead is refused: {status} {body}"
            );
        }
        assert_eq!(
            served.recognized("after-future-withdrawals", &axis_vector(1)),
            Some(member),
            "a refused withdrawal deletes nothing"
        );
        assert!(
            served.subject_withdrawal_notices(member).is_empty()
                && served.withdrawal_notices().is_empty(),
            "a refusal tells no one"
        );
    });
}
