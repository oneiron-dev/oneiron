//! The `vault.questions.*` rows at the public door: each test proves one canon
//! promise of a standing question through the server's real router.
//!
//! All 13 rows are host doors (`crate::task_verb::sdk::host_only(...)`
//! in-process), so these tests drive `build_app` at
//! `POST /v1/core/facade/<verb>`. The self-hosted root credential
//! (`HostSlipIssuer::from_secret`) acts as the vault's embedded owner, which it
//! binds at genesis. Every body runs on the engine's stack, because the facade
//! dispatch overflows a test thread's. No test staffs a model: a standing
//! answer lands through the public `prepare` / `admit` pair, the external
//! provider's own route, and a refresh that no rung can answer answers nothing.
//!
//! Canon: `oneiron-arch-0076-typed-judgments-v1.md`.
//! - `an_outcome_fact_labels_its_answer_once`: "a standing question names the
//!   later fact that is its label" (:196 the Outcome binding row; :243 "One
//!   projector watches every binding and writes the label when the fact
//!   arrives") and promise-loop-15 (:202) "Replaying a label changes nothing".
//! - `a_question_reads_under_its_principals_grants`: "a question reads under
//!   its principal's grants" (:41). Another principal reads no record and no
//!   schedule, and pauses and lists nothing; the owner's narrowed credential
//!   reads only the units and answers its own lane reads (FIX 12060, 11827).
//! - `a_standing_question_is_one_record_with_a_schedule`: "One record with a
//!   schedule" (:35) and promise-loop-15 (:202) "An answer for the wrong
//!   judgment version or frontier is refused. A manual refresh keeps the
//!   schedule clock."
//! - `a_malformed_or_unsigned_question_act_is_refused`: each of the 13 rows.
//!
//! Seeded faults (each makes its test fail and leaves the crates compiling):
//! - red1: `oneiron/src/llm/decision/questions/arrival.rs:362`, the label-key
//!   guard made `if false && ..`, so a replayed projection binds again (the
//!   outcome test); `oneiron-verb-wire/src/receipt/questions.rs:109`,
//!   `deny_unknown_fields` deleted on `QuestionPauseRequest` (the refusal
//!   table). Green there: the grants and schedule tests, which never project
//!   and send no unknown field.
//! - red2: `oneiron/src/llm/decision/questions/answer_scope.rs:249`,
//!   `reads_as_principal` made `.. || true`, so a narrowed lane reads every
//!   unit and answer (the grants test); `questions/refresh/execution.rs:286`,
//!   the clock write made unconditional, so a manual refresh stamps
//!   `last_refresh` (the schedule test). Green there: the outcome test and the
//!   refusal table, which read only under the full owner lane and never
//!   refresh a known question.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test vault_questions_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::decision::questions::close_due_outcome_windows;
use oneiron::memory::ClaimInput;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "vault-questions-doors-secret";
/// The predicate of the later fact the outcome test binds.
const OUTCOME_PREDICATE: &str = "trial.outcome";
/// The outcome window, in seconds after the answer.
const HORIZON_SECS: u64 = 60;

fn seeded_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A `[u8; 32]` the door answered as 32 JSON numbers, as hex: the form an
/// `EvidenceVersion.body_hash` takes on the wire.
fn hash_hex(value: &Value) -> String {
    let bytes: Vec<u8> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().unwrap()).unwrap())
        .collect();
    assert_eq!(bytes.len(), 32, "a 32-byte hash: {value}");
    hex(&bytes)
}

/// A standing graph question over `units` with only the required keys, a
/// model-free dial (it starts at the rule rung, the one rung a bare test
/// server fills) and the host's default band. With `binding`, the question
/// learns from that outcome binding.
fn definition(units: &[&str], binding: Option<Value>) -> Value {
    let mut definition = json!({
        "question": {
            "text": "Is this unit relevant?",
            "class": "judgment",
            "contract": {"kind": "noul"},
            "accept_type": false,
        },
        "adapter": "graph",
        "units": units,
        "recipe": "unit",
        "profile": "fixture",
        "dial": {"first": "rule", "ceiling": "big", "band": {"low": 0.35, "high": 0.65}},
        "activation": "standing",
        "refresh": {"on_arrival": false, "every_seconds": null},
        "delivery": "now",
        "learning": binding.is_some(),
    });
    if let Some(binding) = binding {
        definition["binding"] = binding;
    }
    definition
}

/// A later claim on the unit itself, `trial.outcome` = "yes" or "no", is the label.
fn outcome_binding() -> Value {
    json!({
        "source": {"kind": "claim", "predicate": OUTCOME_PREDICATE},
        "horizon": HORIZON_SECS,
        "mapping": {"yes": true, "no": false},
        "noise_weight": 1.0,
        "linked_by": null,
    })
}

/// A slip a test minted and the key its holder proves it with.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// One rooted vault with two PERSON units, a second person, the server's
/// router and the self-hosted root credential.
struct Door {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
    unit_a: String,
    unit_b: String,
    member: EntityId,
}

impl Door {
    fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
        let unit_a = seeded_id(0xA1);
        let unit_b = seeded_id(0xB1);
        let member = seeded_id(0xC1);
        for (id, body) in [
            (unit_a, b"question unit a".as_slice()),
            (unit_b, b"question unit b".as_slice()),
            (member, b"another person".as_slice()),
        ] {
            vault
                .put_entity(
                    &id,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    body,
                )
                .unwrap();
        }
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        let vault = Arc::new(vault);
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(SECRET.to_owned()),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let root = vault.ensure_host_root_slip(&issuer).unwrap();
        Self {
            _dir: dir,
            app: build_app(server),
            vault,
            issuer,
            root,
            owner,
            unit_a: unit_a.to_hex(),
            unit_b: unit_b.to_hex(),
            member,
        }
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `POST /v1/core/facade/<verb>` with `body` as sent: signed by the root
    /// credential with a fresh proof when `signed`, else with no credential.
    async fn post_raw(&self, verb: &str, body: String, signed: bool) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json");
        if signed {
            let timestamp = self.vault.now_recorded_at();
            let nonce = EntityId::now().to_hex();
            let challenge = format!("oneiron-request:{timestamp}:{nonce}");
            let signature = self
                .issuer
                .binding_proof(&self.root, challenge.as_bytes())
                .unwrap();
            let binding =
                json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)});
            request = request
                .header(
                    "authorization",
                    format!("Bearer {}", self.root.to_token().unwrap()),
                )
                .header("x-oneiron-binding", binding.to_string());
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    /// `verb` as the owner, through the root credential.
    async fn post(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        self.post_raw(verb, body.to_string(), true).await
    }

    /// `verb` under `holder`'s slip, with a fresh holder proof.
    async fn post_as(&self, holder: &Holder, verb: &str, body: &Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = holder
            .key
            .sign(&holder.slip.binding_transcript(&challenge).unwrap())
            .to_bytes();
        let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", holder.slip.to_token().unwrap()),
            )
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(request).await
    }

    /// A slip this host mints `who` as a person, holding `read` and `write`:
    /// not owner-grade and not the host's own.
    fn mint(&self, who: EntityId, seed: u8) -> Holder {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [seed; 32];
        claims.holder_ref = who.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .unwrap();
        Holder { slip, key }
    }

    /// The owner's own slip, narrowed by its holder to read only `records`.
    fn narrowed_owner(&self, records: &[&str]) -> Holder {
        let mut holder = self.mint(self.owner, 0x62);
        holder
            .slip
            .attenuate(
                SlipCaveat {
                    records: Some(records.iter().map(|id| (*id).to_owned()).collect()),
                    ..Default::default()
                },
                &holder.key,
            )
            .unwrap();
        assert!(
            !holder.slip.caveats.is_empty(),
            "the owner's slip is caveated"
        );
        holder
    }

    /// A standing question over `units` the owner saved: its id.
    async fn create(&self, units: &[&str], binding: Option<Value>) -> String {
        let (status, record) = self
            .post(
                "vault.questions.create",
                &json!({"definition": definition(units, binding)}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{record}");
        assert_eq!(record["definition"]["question"]["version"], 1, "{record}");
        record["definition"]["question"]["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// `vault.questions.prepare` of `unit` with no evidence, as the owner.
    async fn prepare(&self, question: &str, unit: &str) -> Value {
        let (status, prepared) = self
            .post(
                "vault.questions.prepare",
                &json!({"id": question, "expected_version": 1, "input": {"unit": unit, "evidence": []}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{prepared}");
        assert_eq!(prepared["unit"], unit, "{prepared}");
        prepared
    }

    /// An external measurement of `prepared`'s unit: yes at 0.8, pinned at the
    /// big rung, naming every prepared source at its hash, unit first.
    fn measured(prepared: &Value) -> Value {
        let versions: Vec<Value> = prepared["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| json!({"id": source["id"], "body_hash": hash_hex(&source["hash"])}))
            .collect();
        json!({
            "answer": {"kind": "noul", "value": true},
            "probability": 0.8,
            "evidence": [],
            "in_band": false,
            "receipt": {
                "question": prepared["question"]["id"],
                "question_version": prepared["question"]["version"],
                "principal": prepared["principal"],
                "providers": [{"rung": "big", "model": "fixture-provider", "version": "v1"}],
                "band": {"low": 0.35, "high": 0.65},
                "evidence_versions": versions,
            },
            "human_ask": null,
        })
    }

    /// `vault.questions.admit` of `decision` over `prepared`, as the owner.
    async fn admit(
        &self,
        question: &str,
        prepared: &Value,
        decision: Value,
    ) -> (StatusCode, Value) {
        self.post(
            "vault.questions.admit",
            &json!({
                "id": question,
                "expected_version": 1,
                "input": {"unit": prepared["unit"], "evidence": []},
                "source_frontier": prepared["source_frontier"],
                "decision": decision,
            }),
        )
        .await
    }

    /// One answer on `unit` landed through prepare and admit: its claim and
    /// when it was answered.
    async fn answer(&self, question: &str, unit: &str) -> (String, u64) {
        let prepared = self.prepare(question, unit).await;
        let (status, answer) = self
            .admit(question, &prepared, Self::measured(&prepared))
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["unit"], unit, "{answer}");
        (
            answer["claim"].as_str().unwrap().to_owned(),
            answer["answered_at"].as_u64().unwrap(),
        )
    }
}

/// A refusal's (status, code): what a caller tells apart.
fn refusal(status: StatusCode, body: &Value) -> (StatusCode, Value) {
    (status, body["error"]["code"].clone())
}

/// :196, :243 and :202 "Replaying a label changes nothing": the later fact the
/// binding names labels the answer it follows, once; projecting again binds
/// nothing new, and the closed window reads as observed.
#[test]
fn an_outcome_fact_labels_its_answer_once() {
    run_on_engine_stack("questions-outcome-label", || async {
        let door = Door::open();
        let question = door
            .create(&[door.unit_a.as_str()], Some(outcome_binding()))
            .await;
        let (answer, answered_at) = door.answer(&question, &door.unit_a).await;

        // The later fact: the owner's own claim on the unit, at the answer's
        // second, its value one the mapping names.
        let fact = seeded_id(0xF1).to_hex();
        let receipt = door
            .vault
            .memory(door.owner, EdgeActorClass::Human)
            .claim_upsert(&ClaimInput {
                id: Some(fact.clone()),
                predicate: OUTCOME_PREDICATE.to_owned(),
                subject_ref: door.unit_a.clone(),
                value: json!("yes"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: Some(1),
                valid_to: Some(now_secs() + 86_400),
                occurred_at: Some(answered_at),
                learned_at: None,
                salience: None,
                confidence_details: None,
            })
            .expect("the owner's fact write");
        assert_eq!(
            receipt.approval, "auto",
            "the owner's own fact stands: {}",
            receipt.claim_short_id
        );

        // The projector binds it (the fact's own write may already have).
        let (status, projected) = door
            .post("vault.questions.outcomes.project", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{projected}");
        assert_eq!(projected["id"], question, "{projected}");
        assert!(projected["projected"].as_u64().unwrap() <= 1, "{projected}");
        let (status, outcomes) = door
            .post("vault.questions.outcomes", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{outcomes}");
        let labels = outcomes["labels"].as_array().unwrap();
        assert_eq!(labels.len(), 1, "one fact labels one answer: {outcomes}");
        assert_eq!(labels[0]["answer"], answer, "{outcomes}");
        assert_eq!(labels[0]["fact"], fact, "{outcomes}");
        assert_eq!(labels[0]["label"], true, "\"yes\" maps to true: {outcomes}");
        assert_eq!(labels[0]["noise_weight"], 1.0, "{outcomes}");
        assert_eq!(labels[0]["occurred_at"], answered_at, "{outcomes}");

        // Replaying the projection changes nothing.
        let (status, replayed) = door
            .post("vault.questions.outcomes.project", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{replayed}");
        assert_eq!(
            replayed,
            json!({"id": question, "projected": 0}),
            "a replay binds nothing: {replayed}"
        );
        let (status, again) = door
            .post("vault.questions.outcomes", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["labels"], outcomes["labels"], "{again}");

        // The window closes past its horizon as observed. Only the server's
        // question pump closes windows, and a bare test server runs none, so
        // the test closes it at a `now` just past the window's last second.
        assert_eq!(
            close_due_outcome_windows(&door.vault, answered_at + HORIZON_SECS + 1).unwrap(),
            1
        );
        let (status, windows) = door
            .post("vault.questions.outcome_windows", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{windows}");
        let windows = windows.as_array().unwrap();
        assert_eq!(windows.len(), 1, "{windows:?}");
        assert_eq!(windows[0]["answer"], answer, "{windows:?}");
        assert_eq!(windows[0]["question_version"], 1, "{windows:?}");
        assert_eq!(
            windows[0]["ends_at"],
            answered_at + HORIZON_SECS,
            "{windows:?}"
        );
        assert_eq!(windows[0]["outcome"], "observed", "{windows:?}");
    });
}

/// :41 "a question reads under its principal's grants": another person never
/// sees the owner's question, and the owner's narrowed credential reads only
/// the units and answers its own lane reads.
#[test]
fn a_question_reads_under_its_principals_grants() {
    run_on_engine_stack("questions-grants", || async {
        let door = Door::open();
        let question = door
            .create(&[door.unit_a.as_str(), door.unit_b.as_str()], None)
            .await;
        let (claim_a, _) = door.answer(&question, &door.unit_a).await;
        let (claim_b, _) = door.answer(&question, &door.unit_b).await;
        assert_ne!(claim_a, claim_b);

        // Another principal reads no record and no schedule, and its pause and
        // its answer listing find no question.
        let member = door.mint(door.member, 0x61);
        let (status, body) = door
            .post_as(&member, "vault.questions.read", &json!({"id": question}))
            .await;
        assert_eq!((status, &body), (StatusCode::OK, &Value::Null), "{body}");
        let (status, body) = door
            .post_as(
                &member,
                "vault.questions.schedule",
                &json!({"id": question}),
            )
            .await;
        assert_eq!((status, &body), (StatusCode::OK, &Value::Null), "{body}");
        let (status, body) = door
            .post_as(
                &member,
                "vault.questions.pause",
                &json!({"id": question, "paused": true}),
            )
            .await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::NOT_FOUND, json!("NOT_FOUND")),
            "{body}"
        );
        let (status, body) = door
            .post_as(&member, "vault.questions.answers", &json!({"id": question}))
            .await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::NOT_FOUND, json!("NOT_FOUND")),
            "{body}"
        );
        let (status, head) = door
            .post("vault.questions.schedule", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{head}");
        assert_eq!(
            head["paused"], false,
            "the refused pause paused nothing: {head}"
        );

        // The owner's credential narrowed to unit A and its answer reads that
        // unit alone and that answer alone.
        let narrowed = door.narrowed_owner(&[door.unit_a.as_str(), claim_a.as_str()]);
        let (status, record) = door
            .post_as(&narrowed, "vault.questions.read", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{record}");
        assert_eq!(record["definition"]["question"]["id"], question, "{record}");
        assert_eq!(
            record["definition"]["units"],
            json!([door.unit_a]),
            "{record}"
        );
        let (status, answers) = door
            .post_as(
                &narrowed,
                "vault.questions.answers",
                &json!({"id": question}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answers}");
        let answers = answers.as_array().unwrap();
        assert_eq!(answers.len(), 1, "{answers:?}");
        assert_eq!(answers[0]["kind"], "graph", "{answers:?}");
        assert_eq!(answers[0]["unit"], door.unit_a, "{answers:?}");
        assert_eq!(answers[0]["claim"], claim_a, "{answers:?}");

        // The full lane still reads both.
        let (status, record) = door
            .post("vault.questions.read", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{record}");
        assert_eq!(
            record["definition"]["units"],
            json!([door.unit_a, door.unit_b]),
            "{record}"
        );
        let (status, answers) = door
            .post("vault.questions.answers", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{answers}");
        assert_eq!(answers.as_array().unwrap().len(), 2, "{answers}");
    });
}

/// :35 "One record with a schedule" and :202 "An answer for the wrong judgment
/// version or frontier is refused. A manual refresh keeps the schedule clock."
#[test]
fn a_standing_question_is_one_record_with_a_schedule() {
    run_on_engine_stack("questions-schedule", || async {
        let door = Door::open();
        let question = door.create(&[door.unit_a.as_str()], None).await;

        let (status, head) = door
            .post("vault.questions.schedule", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{head}");
        assert_eq!(
            head,
            json!({"id": question, "version": 1, "paused": false, "last_refresh": null, "retry_at": null}),
            "one record, at version 1, never refreshed"
        );

        // Pausing and resuming move that one record.
        let (status, paused) = door
            .post(
                "vault.questions.pause",
                &json!({"id": question, "paused": true}),
            )
            .await;
        assert_eq!(
            (status, &paused),
            (StatusCode::OK, &json!({"id": question, "paused": true})),
            "{paused}"
        );
        let (status, head) = door
            .post("vault.questions.schedule", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{head}");
        assert_eq!(
            (&head["version"], &head["paused"]),
            (&json!(1), &json!(true)),
            "{head}"
        );
        let (status, resumed) = door
            .post(
                "vault.questions.pause",
                &json!({"id": question, "paused": false}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{resumed}");

        // A stale version is refused on edit and on backfill; the record stays.
        let (status, body) = door
            .post(
                "vault.questions.edit",
                &json!({"id": question, "expected_version": 99, "definition": definition(&[door.unit_a.as_str()], None)}),
            )
            .await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::CONFLICT, json!("INVALID_STATE")),
            "{body}"
        );
        let (status, body) = door
            .post(
                "vault.questions.backfill",
                &json!({"id": question, "expected_version": 99}),
            )
            .await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::CONFLICT, json!("INVALID_STATE")),
            "{body}"
        );
        let (status, backfill) = door
            .post(
                "vault.questions.backfill",
                &json!({"id": question, "expected_version": 1}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{backfill}");
        assert_eq!(
            (&backfill["question"], &backfill["version"]),
            (&json!(question), &json!(1)),
            "{backfill}"
        );
        let (status, head) = door
            .post("vault.questions.schedule", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{head}");
        assert_eq!(
            (&head["version"], &head["paused"], &head["last_refresh"]),
            (&json!(1), &json!(false), &Value::Null),
            "{head}"
        );

        // A manual refresh, which no rung of a bare server answers, keeps the
        // schedule clock.
        let (status, refreshed) = door
            .post("vault.questions.refresh", &json!({"id": question}))
            .await;
        assert_eq!(
            (status, &refreshed),
            (StatusCode::OK, &json!([])),
            "{refreshed}"
        );
        let (status, after) = door
            .post("vault.questions.schedule", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{after}");
        assert_eq!(after, head, "a manual refresh keeps the schedule clock");

        // Paused, a manual refresh answers nothing and moves nothing.
        let (status, _) = door
            .post(
                "vault.questions.pause",
                &json!({"id": question, "paused": true}),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, before) = door
            .post("vault.questions.schedule", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{before}");
        let (status, refreshed) = door
            .post("vault.questions.refresh", &json!({"id": question}))
            .await;
        assert_eq!(
            (status, &refreshed),
            (StatusCode::OK, &json!([])),
            "{refreshed}"
        );
        let (status, after) = door
            .post("vault.questions.schedule", &json!({"id": question}))
            .await;
        assert_eq!(status, StatusCode::OK, "{after}");
        assert_eq!(after, before, "{after}");

        // An answer measured for another judgment version, or over another
        // frontier, is refused, and lands no answer.
        let prepared = door.prepare(&question, &door.unit_a).await;
        let mut wrong_version = Door::measured(&prepared);
        wrong_version["receipt"]["question_version"] = json!(2);
        let (status, body) = door.admit(&question, &prepared, wrong_version).await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::BAD_REQUEST, json!("BAD_REQUEST")),
            "{body}"
        );
        let mut moved = prepared.clone();
        let first = moved["source_frontier"][0].as_u64().unwrap();
        moved["source_frontier"][0] = json!(first ^ 0x01);
        let (status, body) = door
            .admit(&question, &moved, Door::measured(&prepared))
            .await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::CONFLICT, json!("INVALID_STATE")),
            "{body}"
        );
        let (status, answers) = door
            .post("vault.questions.answers", &json!({"id": question}))
            .await;
        assert_eq!(
            (status, &answers),
            (StatusCode::OK, &json!([])),
            "{answers}"
        );
    });
}

/// Each of the 13 rows refuses a body missing its fields and a body with a
/// field it does not know, and refuses any body with no credential.
#[test]
fn a_malformed_or_unsigned_question_act_is_refused() {
    run_on_engine_stack("questions-refusals", || async {
        let door = Door::open();
        let unknown = seeded_id(0xD1).to_hex();
        let input = json!({"unit": door.unit_a, "evidence": []});
        let decision = json!({
            "answer": {"kind": "noul", "value": true},
            "probability": 0.8,
            "evidence": [],
            "in_band": false,
            "receipt": {
                "question": unknown,
                "question_version": 1,
                "principal": door.owner.to_hex(),
                "providers": [{"rung": "big", "model": "fixture-provider", "version": "v1"}],
                "band": {"low": 0.35, "high": 0.65},
            },
            "human_ask": null,
        });
        let rows: [(&str, Value); 13] = [
            (
                "vault.questions.create",
                json!({"definition": definition(&[door.unit_a.as_str()], None)}),
            ),
            (
                "vault.questions.edit",
                json!({"id": unknown, "expected_version": 1, "definition": definition(&[door.unit_a.as_str()], None)}),
            ),
            (
                "vault.questions.pause",
                json!({"id": unknown, "paused": true}),
            ),
            (
                "vault.questions.backfill",
                json!({"id": unknown, "expected_version": 1}),
            ),
            ("vault.questions.read", json!({"id": unknown})),
            ("vault.questions.refresh", json!({"id": unknown})),
            ("vault.questions.schedule", json!({"id": unknown})),
            ("vault.questions.answers", json!({"id": unknown})),
            ("vault.questions.outcomes", json!({"id": unknown})),
            ("vault.questions.outcomes.project", json!({"id": unknown})),
            ("vault.questions.outcome_windows", json!({"id": unknown})),
            (
                "vault.questions.prepare",
                json!({"id": unknown, "expected_version": 1, "input": input}),
            ),
            (
                "vault.questions.admit",
                json!({
                    "id": unknown,
                    "expected_version": 1,
                    "input": input,
                    "source_frontier": vec![0_u8; 32],
                    "decision": decision,
                }),
            ),
        ];
        let bad_request = (StatusCode::BAD_REQUEST, json!("BAD_REQUEST"));
        for (verb, body) in &rows {
            let (status, refused) = door.post(verb, &json!({})).await;
            assert_eq!(
                refusal(status, &refused),
                bad_request,
                "{verb} with no fields: {refused}"
            );
            let mut extra = body.clone();
            extra["unexpected"] = json!(1);
            let (status, refused) = door.post(verb, &extra).await;
            assert_eq!(
                refusal(status, &refused),
                bad_request,
                "{verb} with an unknown field: {refused}"
            );
            let (status, refused) = door.post_raw(verb, body.to_string(), false).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{verb} with no credential: {refused}"
            );
        }

        let (status, refused) = door
            .post_raw("vault.questions.create", "{not json".to_owned(), true)
            .await;
        assert_eq!(refusal(status, &refused), bad_request, "{refused}");
        assert_eq!(
            refused["error"]["message"], "invalid JSON request body",
            "{refused}"
        );

        // The refusals wrote nothing: the well-formed rows still answer as on
        // an empty vault, and the owner saves a question.
        let (status, body) = door
            .post("vault.questions.read", &json!({"id": unknown}))
            .await;
        assert_eq!((status, &body), (StatusCode::OK, &Value::Null), "{body}");
        door.create(&[door.unit_a.as_str()], None).await;
    });
}
