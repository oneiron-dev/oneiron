//! `vault.coach.training_offers.run` served over the real facade route
//! (LEARNING-08, COACH-OFFER-PASS): one Coach training-offer pass run now,
//! inside the request.
//!
//! * `owner_run_drafts_an_offer_from_the_hub_installed_offer_skill`: a seat
//!   with metered calls, a priced incumbent and a priced stock option, and
//!   the offer skill imported from the configured default hub (not at the
//!   bootstrap id). The owner's run answers `ran` / `drafted` with the one
//!   offer the Coach raised, which names that installed skill; the attempt
//!   completes.
//! * `a_run_with_no_installed_offer_skill_asks_no_model`: the same vault
//!   without the skill answers `missing` / `offer_skill` and calls no model.
//! * `an_agent_runs_the_pass_only_on_the_maintenance_cadence_grant`: a paired
//!   agent with no engine.controls grant is refused FORBIDDEN and no model is
//!   called; granted the maintenance-cadence class, it runs the pass.
//! * `two_runs_in_one_day_draw_on_one_day_budget`: the day's offer spend is
//!   read from the usage ledger. With the day nearly spent, the first run
//!   drafts on what is left and the second answers `missing` /
//!   `day_budget` with no model call; spend older than a day does not count.
//! * `a_run_over_a_dated_window_prices_the_receipts_dated_in_it`: a run that
//!   names a 20-day window which closed 40 days ago drafts its offer on the
//!   two calls dated in it, not on the last 30 days' calls: the offer's
//!   workload is that window and those two receipts, and its month is the
//!   window's bill scaled from 20 days.
//! * `a_run_names_only_a_dated_window_of_at_most_90_days_that_has_passed`: a
//!   window whose from is not before its until, whose until is after the
//!   vault's now, or which spans over 90 days is refused BAD_REQUEST with no
//!   model call. No window reads the last 30 days; exactly 90 days up to now
//!   is let in; a window with no seat's call in it ends `missing` /
//!   `metered_seat`.
//!
//! Reads JSON only (no engine type of the new verb), so on a main without the
//! verb every test fails on its first status assertion (404 NOT_FOUND). On a
//! head whose run takes no window, the last two fail on their first window:
//! the request does not decode.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! coach_offer_run`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::agent_dispatch::budget_doors::UsageEventOrigin;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{EngineControlClass, Scope, ScopeAxis};
use oneiron::llm::registry::{
    ModelBackendPin, ModelRegistryRow, ModelWireFormat, PricedModelBackend,
};
use oneiron::llm::run_admission::Payer;
use oneiron::llm::{LlmCatalogCost, LlmCatalogEntry, ModelId, ModelLocality};
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    CallerPermissions, HubFile, HubPackage, HubRef, RuleSkillFit, SkillCapabilitySurface,
    SkillHubAdapter, SkillHubKind,
};
use oneiron::skill_optimize::training_offer_skill_id;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::usage::{
    UnpricedReason, UsageEvent, UsageEventType, UsageLedger, UsageMode, UsageRun, UsageTokenCounts,
};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The verb under test and its result reader.
const VERB: &str = "vault.coach.training_offers.run";
const RESULT_VERB: &str = "vault.coach.training_offers.result";
/// The offer pass's day budget, in guard units (training_offer.rs
/// `DAY_BUDGET_UNITS`), and the reserve one paid call holds
/// (`oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS`).
const DAY_BUDGET_UNITS: u64 = 1 << 20;
const CALL_RESERVE_UNITS: u64 = 8_000;
/// The label the offer pass's calls are metered under
/// (`routing::purpose_key` of `CallPurpose::Other { name: "coach_training_offer" }`).
const OFFER_PURPOSE: &str = "other:coach_training_offer";
/// The seat whose workload the offer is about: `default` fills it, and the
/// Coach's own calls run on another seat (`generative_reasoner`).
const STUDIED_ROLE: &str = "checker";
/// The stock option the fixture prices beside the incumbent.
const CANDIDATE_MODEL: &str = "fixture/candidate-small@r1";
const DAY_SECS: u64 = 86_400;
/// The shipped offer skill, which the fixture's hub serves.
const OFFER_SKILL: &str = include_str!("../../../skills/training-offer/SKILL.md");

/// The Coach's answer: raise the first option.
fn raise_first_option() -> Reply {
    Reply::text(
        r#"{"offer":"option-1","losses":["slower replies"],"risk":null,"what_changed":null}"#,
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

/// FakeLlm as a paid seat on the operator's own server: keyed (`key_env`),
/// so its calls are paid work that settles units on the day budget. A
/// keyless local seat is free work (FIX 9482): it settles 0 units, and the
/// day budget caps spend only.
fn models_text(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         key_env = \"HOME\"\n"
    )
}

/// A host that judges the caller to hold every permission the skill asks.
struct HoldsAll;
impl CallerPermissions for HoldsAll {
    fn holds(&self, _permission: &str) -> bool {
        true
    }
}

/// The configured default hub's transport, in process: it serves the one
/// offer-skill package at whatever pinned folder is asked.
struct DefaultHubInProcess {
    hub: EntityId,
    kind: SkillHubKind,
    endpoint: String,
    package: HubPackage,
}
impl SkillHubAdapter for DefaultHubInProcess {
    fn hub_id(&self) -> EntityId {
        self.hub
    }
    fn kind(&self) -> SkillHubKind {
        self.kind
    }
    fn endpoint(&self) -> Option<&str> {
        Some(&self.endpoint)
    }
    fn fetch_package(&self, _: &HubRef) -> oneiron::error::Result<HubPackage> {
        Ok(self.package.clone())
    }
}

/// The offer skill as the hub folder ships it: the shipped SKILL.md with a
/// version line, code-free, no capability.
fn offer_skill_package() -> HubPackage {
    let markdown = OFFER_SKILL.replacen(
        "---\nname: training-offer\n",
        "---\nname: training-offer\nversion: 1.0.0\n",
        1,
    );
    assert_ne!(
        markdown, OFFER_SKILL,
        "the shipped SKILL.md opens with its name"
    );
    let record = SkillRecord::new(
        "training-offer",
        "training offer",
        "1.0.0",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("hub-folder"),
        )]),
    );
    HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", markdown.into_bytes())],
        SkillCapabilitySurface::default(),
    )
}

/// A priced registry row for `model`, served by one backend.
fn registry_row(model: &str, price: &str, licence: Option<&str>) -> ModelRegistryRow {
    let model = ModelId::new(model).expect("model id");
    let priced = PricedModelBackend {
        pin: ModelBackendPin {
            model: model.clone(),
            backend: "fixture-backend".to_owned(),
            serving_revision: "r1".to_owned(),
            quantization: None,
            context_window_tokens: 8192,
        },
        price: LlmCatalogCost {
            input_per_million: price.to_owned(),
            output_per_million: price.to_owned(),
            cache_read_per_million: None,
            cache_write_per_million: None,
            currency: Some("USD".to_owned()),
        },
    };
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "backends".to_owned(),
        serde_json::to_value(vec![&priced]).expect("backends JSON"),
    );
    if let Some(licence) = licence {
        metadata.insert("licence".to_owned(), json!(licence));
    }
    ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::OpenaiCompat,
        catalog: LlmCatalogEntry {
            model: model.clone(),
            display_name: model.as_str().to_owned(),
            locality: ModelLocality::OwnServer,
            context_window_tokens: 8192,
            max_output_tokens: None,
            cost: Some(priced.price.clone()),
            capabilities: Vec::new(),
            metadata,
        },
        scores: BTreeMap::new(),
        fetched_at: BTreeMap::new(),
        tokens_per_o200k: Some(1.0),
        stale_since: None,
        source_rows: None,
    }
}

/// One paired agent credential.
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    host: AiHost,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: AuthenticatedOwner,
    model: FakeLlm,
    /// The meter's billing owner and vault id.
    billing: (String, String),
}

impl Fixture {
    /// A rooted, metered vault served over the facade, its seats on a fake
    /// model answering `reply`, with a month of the studied seat's metered
    /// calls and a priced incumbent and stock option. The offer skill is not
    /// installed: [`Self::install_offer_skill`] imports it.
    async fn new(reply: Reply) -> Self {
        let model = FakeLlm::start(vec![], Some(reply)).await;
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("coach-offer-run".into()),
                ..Default::default()
            },
        )
        .expect("create server")
        .with_usage_metering("billing-owner")
        .expect("bind the usage meter");
        let usage = server.vault_usage().expect("the server meters its usage");
        let billing = (usage.owner().to_owned(), usage.vault_id().to_owned());
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let owner_slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let owner_token = owner_slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("authenticated owner");
        let models =
            ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let app = build_app(Arc::new(server));
        let fixture = Self {
            _dir: dir,
            vault,
            host,
            app,
            issuer,
            owner_slip,
            owner_token,
            owner,
            model,
            billing,
        };
        let seat = fixture.studied_seat_model().await;
        fixture.record_studied_seat_calls(&seat);
        fixture
            .vault
            .put_model_registry_row(&registry_row(&seat, "2", None))
            .expect("the incumbent's registry row");
        fixture
            .vault
            .put_model_registry_row(&registry_row(CANDIDATE_MODEL, "1", Some("apache-2.0")))
            .expect("the stock option's registry row");
        fixture
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }

    /// The fake model's calls that carry the offer skill's body as their
    /// System message: the offer pass's own Coach calls.
    fn offer_calls(&self) -> usize {
        self.model
            .seen()
            .iter()
            .filter(|call| {
                call.body["messages"][0]
                    .to_string()
                    .contains("# Training offer")
            })
            .count()
    }

    /// The engine's model id of the studied seat, from the served status.
    async fn studied_seat_model(&self) -> String {
        let request = Request::get("/v1/ai/status")
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .body(Body::empty())
            .expect("status request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("status response");
        assert_eq!(response.status(), StatusCode::OK, "AI status");
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("status body");
        let status: Value = serde_json::from_slice(&bytes).expect("status JSON");
        status["models"]["seats"]
            .as_array()
            .and_then(|seats| {
                seats
                    .iter()
                    .find(|seat| seat["role"] == STUDIED_ROLE)
                    .and_then(|seat| seat["seat_model"].as_str())
            })
            .unwrap_or_else(|| panic!("the {STUDIED_ROLE} seat is served: {status}"))
            .to_owned()
    }

    fn ledger(&self) -> UsageLedger {
        UsageLedger::new(Arc::clone(&self.vault))
    }

    fn record(&self, event: UsageEvent) {
        let recorded = self
            .ledger()
            .record_event(event, UsageMode::Local, UsageEventOrigin::Engine)
            .expect("record a usage event");
        assert!(recorded.recorded, "the ledger records the event");
    }

    /// Two metered calls of the studied seat inside the 30-day window, and
    /// one 31 days back, so the window reads as wholly metered.
    fn record_studied_seat_calls(&self, seat: &str) {
        let now = self.vault.now_recorded_at();
        for (key, occurred_at) in [
            ("studied-call-1", now - 100),
            ("studied-call-2", now - 50),
            ("studied-call-old", now - 31 * DAY_SECS),
        ] {
            self.record_studied_seat_call(seat, key, occurred_at);
        }
    }

    /// One metered call of the studied seat on `seat`'s model, of 40_000
    /// input and 8_000 output tokens, dated `occurred_at`.
    fn record_studied_seat_call(&self, seat: &str, key: &str, occurred_at: u64) {
        self.record(UsageEvent {
            owner: self.billing.0.clone(),
            vault_id: self.billing.1.clone(),
            idempotency_key: key.to_owned(),
            source: Some(UsageMode::Local),
            event_type: UsageEventType::Inference,
            role: Some(STUDIED_ROLE.to_owned()),
            occurred_at: Some(occurred_at),
            agent_id: None,
            model: Some(seat.to_owned()),
            service: None,
            token_counts: UsageTokenCounts {
                input_tokens: 40_000,
                output_tokens: 8_000,
                ..UsageTokenCounts::default()
            },
            cost_rates: None,
            unpriced: Some(UnpricedReason::UnpricedModel),
            service_amount: 0,
            run: None,
        });
    }

    /// One settled call of an earlier offer pass: `units` spent under the
    /// offer pass's metered purpose, `age` seconds ago.
    fn record_offer_spend(&self, key: &str, units: u64, age: u64) {
        let occurred_at = self.vault.now_recorded_at() - age;
        self.record(UsageEvent {
            owner: self.billing.0.clone(),
            vault_id: self.billing.1.clone(),
            idempotency_key: format!("run:{key}"),
            source: Some(UsageMode::Local),
            event_type: UsageEventType::Inference,
            // No seat: the spend alone, so no seat's workload grows.
            role: None,
            occurred_at: Some(occurred_at),
            agent_id: None,
            model: Some("local:test-model".to_owned()),
            service: None,
            token_counts: UsageTokenCounts {
                input_tokens: units,
                ..UsageTokenCounts::default()
            },
            cost_rates: None,
            unpriced: Some(UnpricedReason::UnpricedModel),
            service_amount: 0,
            run: Some(UsageRun {
                instance: EntityId::now().to_hex(),
                run: format!("coach-training-offer:{key}"),
                revision: 0,
                lease: key.to_owned(),
                offer: "fixture-offer".to_owned(),
                route: "fixture-route".to_owned(),
                catalog_revision: None,
                payer: Payer::Host,
                payer_person: None,
                payer_scope: None,
                payer_ask: None,
                purpose: Some(OFFER_PURPOSE.to_owned()),
                cycle: None,
                item: None,
                spend_scope: None,
                reserved_units: units,
                settled_units: units,
                unit: "tokens".to_owned(),
                usage_reported: true,
                service_quantity: None,
                service_cost: None,
                allocation: None,
                settlement_refused: false,
            }),
        });
    }

    /// The settled calls of one offer pass's Coach run, by the ledger: their
    /// units summed, and the purpose each was metered under.
    fn offer_run_settled(&self, attempt: &str) -> (u64, Vec<Option<String>>) {
        let rows = self
            .ledger()
            .run_settlements(
                &self.billing.0,
                &self.billing.1,
                &format!("coach-training-offer:{attempt}"),
            )
            .expect("read the run's settlements");
        (
            rows.iter().map(|row| row.settled_units).sum(),
            rows.into_iter().map(|row| row.purpose).collect(),
        )
    }

    /// The offer skill, imported Active from the configured default hub at
    /// its pinned `skills/training-offer` folder through a ready fit, as an
    /// owner's install from the first-party hub lands it. Returns its id.
    fn install_offer_skill(&self) -> EntityId {
        let default = self.vault.default_skill_hub().expect("the default hub");
        let source = HubRef::new(
            default.hub,
            "skills/training-offer",
            default.skills.hub_ref.pin.clone(),
        )
        .expect("the offer skill's hub ref");
        let publisher = self
            .vault
            .admit_skill_publisher(&self.owner, "publisher:offer-fixture", default.hub)
            .expect("admit the publisher");
        let adapter = DefaultHubInProcess {
            hub: default.hub,
            kind: default.record.kind,
            endpoint: default.record.endpoint.clone(),
            package: offer_skill_package(),
        };
        let now = self.vault.now_recorded_at();
        let skill = self
            .vault
            .import_marketplace_skill_from_adapter(
                &adapter,
                &source,
                &publisher,
                &RuleSkillFit::new(&HoldsAll),
                at(now),
                now,
            )
            .expect("import the offer skill");
        let record = self
            .vault
            .get_skill_record(&skill)
            .expect("read the offer skill")
            .expect("the imported offer skill");
        assert_eq!(record.lifecycle_status, SkillLifecycle::Active);
        assert_ne!(
            skill,
            training_offer_skill_id().expect("bootstrap id"),
            "the hub import has its own id, not the bootstrap one"
        );
        skill
    }

    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn agent_binding(&self, agent: &Agent) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let transcript = agent
            .slip
            .binding_transcript(challenge.as_bytes())
            .expect("agent binding transcript");
        let signature: String = hex(&agent.holder.sign(&transcript).to_bytes());
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    async fn post(
        &self,
        verb: &str,
        token: &str,
        binding: String,
        body: Value,
    ) -> (StatusCode, Value) {
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("facade response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    async fn as_owner(&self, verb: &str, body: Value) -> (StatusCode, Value) {
        self.post(verb, &self.owner_token, self.owner_binding(), body)
            .await
    }

    async fn as_agent(&self, agent: &Agent, verb: &str, body: Value) -> (StatusCode, Value) {
        self.post(verb, &agent.token, self.agent_binding(agent), body)
            .await
    }

    /// Pairs one agent the way `token agent` does (as
    /// `support/eval_authoring_fixture.rs` `pair_agent`).
    async fn pair_agent(&self, name: &str, seed: [u8; 32]) -> Agent {
        let principal = self
            .vault
            .ensure_agent_principal(name)
            .expect("agent principal");
        let holder = SigningKey::from_bytes(&seed);
        let binding_key = holder.verifying_key().to_bytes();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let link = self
            .vault
            .issue_pairing_link_for_principal(
                &self.issuer,
                scope,
                3600,
                PairingPrincipal {
                    holder_ref: Some(principal.to_hex()),
                    actor_class: Some("agent".to_owned()),
                    org_ref: None,
                    write_facet: None,
                    ..Default::default()
                },
            )
            .expect("pairing link");
        let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
            .expect("pairing transcript");
        let signature: String = hex(&holder.sign(&transcript).to_bytes());
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
        let response = self
            .app
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
        Agent {
            principal,
            holder,
            slip,
            token,
        }
    }

    /// The owner reads the attempt's state.
    async fn result_of(&self, attempt: &str) -> Value {
        let (status, body) = self
            .as_owner(RESULT_VERB, json!({"attempt": attempt}))
            .await;
        assert_eq!(status, StatusCode::OK, "read the result: {body}");
        body
    }
}

#[test]
fn owner_run_drafts_an_offer_from_the_hub_installed_offer_skill() {
    run_on_engine_stack("offer-run-owner-drafts", || async {
        let fixture = Fixture::new(raise_first_option()).await;
        let skill = fixture.install_offer_skill();

        let (status, answer) = fixture.as_owner(VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner run: {answer}");
        assert_eq!(answer["state"], "ran", "{answer}");
        assert_eq!(answer["end"]["end"], "drafted", "{answer}");
        let owner = fixture
            .vault
            .ensure_embedded_owner_actor()
            .expect("embedded owner")
            .to_hex();
        assert_eq!(answer["caller"]["kind"], "owner", "{answer}");
        assert_eq!(answer["caller"]["person"], owner.as_str(), "{answer}");
        let offers = answer["offers"].as_array().expect("offer ids");
        assert_eq!(
            offers.len(),
            1,
            "one offer for the one studied seat: {answer}"
        );
        assert_eq!(fixture.offer_calls(), 1, "the Coach was asked once");

        // The attempt completed; the owner's result reads that offer, which
        // names the hub-installed skill that drafted it.
        let attempt = answer["attempt"].as_str().expect("attempt id");
        let result = fixture.result_of(attempt).await;
        assert_eq!(result["state"], "Completed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        let read = result["offers"].as_array().expect("offers");
        assert_eq!(read.len(), 1, "{result}");
        assert_eq!(read[0]["id"], offers[0], "{result}");
        assert_eq!(
            read[0]["offer_skill"][0],
            skill.to_hex().as_str(),
            "the offer names the hub-installed skill: {result}"
        );
        assert_eq!(read[0]["offer_skill"][1], "1.0.0", "{result}");
        fixture.finish().await;
    });
}

#[test]
fn a_run_with_no_installed_offer_skill_asks_no_model() {
    run_on_engine_stack("offer-run-no-skill", || async {
        let fixture = Fixture::new(raise_first_option()).await;

        let (status, answer) = fixture.as_owner(VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner run: {answer}");
        assert_eq!(answer["state"], "ran", "{answer}");
        assert_eq!(answer["end"]["end"], "missing", "{answer}");
        assert_eq!(answer["end"]["prerequisite"], "offer_skill", "{answer}");
        assert_eq!(answer["offers"], json!([]), "{answer}");
        assert_eq!(fixture.offer_calls(), 0, "no model call");
        let attempt = answer["attempt"].as_str().expect("attempt id");
        let result = fixture.result_of(attempt).await;
        assert_eq!(result["state"], "Completed", "{result}");
        fixture.finish().await;
    });
}

#[test]
fn an_agent_runs_the_pass_only_on_the_maintenance_cadence_grant() {
    run_on_engine_stack("offer-run-agent-grant", || async {
        let fixture = Fixture::new(raise_first_option()).await;
        fixture.install_offer_skill();
        let agent = fixture.pair_agent("offer-run-agent", [0x62; 32]).await;

        let (status, body) = fixture.as_agent(&agent, VERB, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no grant: {body}");
        assert_eq!(body["error"]["code"], "FORBIDDEN", "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|text| text.contains(VERB)),
            "the refusal names the verb: {body}"
        );
        assert_eq!(fixture.offer_calls(), 0, "no model call");

        // Granted the maintenance-cadence class, the same agent runs it.
        fixture
            .vault
            .grant_engine_controls(
                &fixture.owner,
                agent.principal,
                &BTreeSet::from([EngineControlClass::MaintenanceCadence]),
            )
            .expect("grant the maintenance-cadence class");
        let (status, answer) = fixture.as_agent(&agent, VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "granted agent: {answer}");
        assert_eq!(answer["state"], "ran", "{answer}");
        assert_eq!(answer["caller"]["kind"], "holder", "{answer}");
        assert_eq!(
            answer["caller"]["actor"],
            agent.principal.to_hex().as_str(),
            "{answer}"
        );
        assert_eq!(answer["end"]["end"], "drafted", "{answer}");
        fixture.finish().await;
    });
}

#[test]
fn two_runs_in_one_day_draw_on_one_day_budget() {
    run_on_engine_stack("offer-run-day-budget", || async {
        let fixture = Fixture::new(raise_first_option()).await;
        fixture.install_offer_skill();
        // A whole day's budget spent 25 hours ago does not count today.
        fixture.record_offer_spend("yesterday", DAY_BUDGET_UNITS, 25 * 3600);
        // Earlier passes today left just over one call's reserve.
        let left = CALL_RESERVE_UNITS + 10;
        fixture.record_offer_spend("earlier-today", DAY_BUDGET_UNITS - left, 600);

        let (status, first) = fixture.as_owner(VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "first run: {first}");
        assert_eq!(first["state"], "ran", "{first}");
        assert_eq!(first["end"]["end"], "drafted", "{first}");
        assert_eq!(fixture.offer_calls(), 1, "the first run asked once");
        let attempt = first["attempt"].as_str().expect("attempt id");
        let (spent, purposes) = fixture.offer_run_settled(attempt);
        assert!(spent > 0, "the first run's call settled units: {first}");
        assert!(
            !purposes.is_empty()
                && purposes
                    .iter()
                    .all(|purpose| purpose.as_deref() == Some(OFFER_PURPOSE)),
            "the run's calls are metered under the purpose the day budget reads: {purposes:?}"
        );

        let (status, second) = fixture.as_owner(VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "second run: {second}");
        assert_eq!(second["state"], "ran", "{second}");
        assert_eq!(second["end"]["end"], "missing", "{second}");
        assert_eq!(second["end"]["prerequisite"], "day_budget", "{second}");
        assert_eq!(
            fixture.offer_calls(),
            1,
            "the second run opened no fresh allowance and asked no model"
        );
        assert!(
            DAY_BUDGET_UNITS - left + spent <= DAY_BUDGET_UNITS,
            "the day's offer spend stays within one day's budget: {spent} of {left} left"
        );
        fixture.finish().await;
    });
}

#[test]
fn a_run_over_a_dated_window_prices_the_receipts_dated_in_it() {
    run_on_engine_stack("offer-run-dated-window", || async {
        let fixture = Fixture::new(raise_first_option()).await;
        fixture.install_offer_skill();
        let seat = fixture.studied_seat_model().await;
        let now = fixture.vault.now_recorded_at();
        // A 20-day window that closed 40 days ago. Two of the seat's calls
        // are dated in it, and one before it shows the window was metered
        // throughout; the fixture's own calls (the last 31 days) come after.
        let (from, until) = (now - 60 * DAY_SECS, now - 40 * DAY_SECS);
        for (key, occurred_at) in [
            ("window-call-1", now - 50 * DAY_SECS),
            ("window-call-2", now - 45 * DAY_SECS),
            ("before-window", now - 61 * DAY_SECS),
        ] {
            fixture.record_studied_seat_call(&seat, key, occurred_at);
        }

        let window = json!({"from": from, "until": until});
        let (status, answer) = fixture
            .as_owner(VERB, json!({"window": window.clone()}))
            .await;
        assert_eq!(status, StatusCode::OK, "windowed run: {answer}");
        assert_eq!(answer["state"], "ran", "{answer}");
        assert_eq!(
            answer["window"], window,
            "the run read its window: {answer}"
        );
        assert_eq!(answer["end"]["end"], "drafted", "{answer}");
        assert_eq!(fixture.offer_calls(), 1, "the Coach was asked once");

        let attempt = answer["attempt"].as_str().expect("attempt id");
        let result = fixture.result_of(attempt).await;
        let offers = result["offers"].as_array().expect("offers");
        assert_eq!(offers.len(), 1, "{result}");
        let workload = &offers[0]["workload"];
        assert_eq!(workload["from"], from, "{result}");
        assert_eq!(workload["until"], until, "{result}");
        assert_eq!(
            workload["calls"], 2,
            "only the calls dated in the window: {result}"
        );
        assert_eq!(workload["complete"], true, "{result}");
        let mut receipts: Vec<&str> = workload["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        receipts.sort_unstable();
        assert_eq!(receipts, ["window-call-1", "window-call-2"], "{result}");
        // Two calls of 40_000 + 8_000 tokens at 2 USD a million tokens bill
        // 0.192 USD over 20 days: 0.288 USD a month.
        let monthly = offers[0]["cost"]["monthly_before"]
            .as_f64()
            .expect("the incumbent's month is priced");
        assert!(
            (monthly - 0.288).abs() < 1e-9,
            "the month is the window's bill scaled from its 20 days: {result}"
        );
        fixture.finish().await;
    });
}

#[test]
fn a_run_names_only_a_dated_window_of_at_most_90_days_that_has_passed() {
    run_on_engine_stack("offer-run-window-bounds", || async {
        // No offer skill: a run that is let in reads the seats' calls in its
        // window, then ends before any model call.
        let fixture = Fixture::new(raise_first_option()).await;
        let now = fixture.vault.now_recorded_at();
        for (window, bound) in [
            (
                json!({"from": now - DAY_SECS, "until": now - DAY_SECS}),
                "before its until",
            ),
            (
                json!({"from": now - DAY_SECS, "until": now + DAY_SECS}),
                "after the vault's now",
            ),
            (
                json!({"from": now - 91 * DAY_SECS, "until": now}),
                "at most 90 days",
            ),
        ] {
            let (status, body) = fixture
                .as_owner(VERB, json!({"window": window.clone()}))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{window}: {body}");
            assert_eq!(body["error"]["code"], "BAD_REQUEST", "{window}: {body}");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .is_some_and(|text| text.contains("evidence window") && text.contains(bound)),
                "{window}: the refusal names the bound it breaks: {body}"
            );
        }
        assert_eq!(fixture.offer_calls(), 0, "no model call");

        // No window: the nightly pass's last 30 days, which hold the seat's
        // calls.
        let (status, answer) = fixture.as_owner(VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "no window: {answer}");
        assert_eq!(answer["state"], "ran", "{answer}");
        let from = answer["window"]["from"].as_u64().expect("window from");
        let until = answer["window"]["until"].as_u64().expect("window until");
        assert!(until >= now, "the window ends at the vault's now: {answer}");
        assert_eq!(until - from, 30 * DAY_SECS, "{answer}");
        assert_eq!(
            answer["end"]["prerequisite"], "offer_skill",
            "the seat's calls were read: {answer}"
        );

        // Exactly 90 days up to now is let in, and reads the same calls.
        let window = json!({"from": now - 90 * DAY_SECS, "until": now});
        let (status, answer) = fixture
            .as_owner(VERB, json!({"window": window.clone()}))
            .await;
        assert_eq!(status, StatusCode::OK, "90 days: {answer}");
        assert_eq!(answer["window"], window, "{answer}");
        assert_eq!(answer["end"]["prerequisite"], "offer_skill", "{answer}");

        // A window no seat's call is dated in asks no Coach.
        let window = json!({"from": now - 70 * DAY_SECS, "until": now - 60 * DAY_SECS});
        let (status, answer) = fixture
            .as_owner(VERB, json!({"window": window.clone()}))
            .await;
        assert_eq!(status, StatusCode::OK, "an empty window: {answer}");
        assert_eq!(answer["window"], window, "{answer}");
        assert_eq!(answer["end"]["end"], "missing", "{answer}");
        assert_eq!(
            answer["end"]["prerequisite"], "metered_seat",
            "no seat's call is dated in it: {answer}"
        );
        assert_eq!(fixture.offer_calls(), 0, "no model call");
        fixture.finish().await;
    });
}
