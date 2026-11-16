//! Public-door promise tests for the `vault.voices` family (ruling L4-23 =
//! A: each test proves a promise at the door; DOOR-FAMILIES Part 2, row 12).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.voices.packs.put`,
//! `.render_consent`, `.targets.provision`, `.targets.evict`, `.inspect` and
//! `.lineage`, and the owner's voice-bank routes under `/v1/ai/voices`.
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
//!   (`oneiron-arch-0061-voice-loop-v1.md:124` keeps the record; the
//!   voiceprint half of that line is the recognition bank's, which no door
//!   reaches, see the PR body);
//! - the `/v1/ai/voices` routes are the owner's alone
//!   (`crates/oneiron-server/src/api/ai/voices.rs` `owner_only`).
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR.
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
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
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
