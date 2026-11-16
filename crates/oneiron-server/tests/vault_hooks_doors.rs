//! Vault hook doors over HTTP: replay is a dry run, an undeclared outcome is
//! refused, cancel keeps the body.
//!
//! Proves `vault.hooks.replay` runs a fact hook over past facts and lands
//! nothing, `vault.hooks.regen.cancel` sets the waiting decision aside while
//! the hook keeps its body, and the owner-only hook doors refuse a person.
//!
//! The vault's keystore is a `MemoryKeystore`, which `oneiron/test-support`
//! forwards (`oneiron-keystore/test-keystore`); no cfg door is used.
//! Run: `cargo test --locked -p oneiron-server --all-features --features
//! oneiron/test-support --test vault_hooks_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::{
    HookBodyRun, HookBodyRuntime, HookRegenFailure, HookRegenOutcome, HookRegenRequest,
    HookRegenerator, HookRunContext,
};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{HookAuthor, PackInstallDisposition};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-hooks-doors".into()),
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
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
    }
}

fn owner_binding(fixture: &Fixture) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(&fixture.owner_slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every person credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

impl Fixture {
    /// A human credential this host mints `who`, holding `read` and `write`:
    /// a person's own slip, not owner-grade.
    fn credential(&self, who: EntityId) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a credential")
    }
}

/// A person's holder proof for one request.
fn person_binding(fixture: &Fixture, slip: &CapabilitySlip) -> String {
    holder_proof(slip, &holder_key(), fixture.vault.now_recorded_at())
        .expect("holder proof")
        .to_string()
}

/// An owner pack folder carrying one fact hook.
fn owner_pack_files(
    pack: &str,
    hook: &str,
    verbs_json: &str,
    outcomes_json: &str,
    intent: Option<&str>,
    body: &str,
) -> Vec<HubFile> {
    let pack_md = format!(
        "---\nname: {pack}\ndescription: Vault hook door fixture.\nversion: 1.0.0\nkind: capability\nhooks: [\"{hook}\"]\n---\nA pack whose one fact hook the owner binds.\n"
    );
    let hook_md = format!(
        "---\nname: {hook}\nversion: 1.0.0\nverbs: {verbs_json}\nphase: fact\noutcomes: {outcomes_json}\n---\n{hook} watches its input.\n"
    );
    let mut files = vec![
        HubFile::new("PACK.md", pack_md),
        HubFile::new(format!("hooks/{hook}/HOOK.md"), hook_md),
        HubFile::new(format!("hooks/{hook}/body.js"), body),
    ];
    if let Some(kept) = intent {
        files.push(HubFile::new(format!("hooks/{hook}/intent.md"), kept));
    }
    files
}

/// The owner's put of a pack with one hook; answers the binding id.
fn put_owner_hook_pack(
    fixture: &Fixture,
    pack: &str,
    hook: &str,
    verbs_json: &str,
    outcomes_json: &str,
    intent: Option<&str>,
    body: &str,
) -> EntityId {
    fixture
        .vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("owner actor");
    let proof = fixture
        .vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let files = owner_pack_files(pack, hook, verbs_json, outcomes_json, intent, body);
    match fixture
        .vault
        .put_pack(&proof, files)
        .expect("the owner puts the pack")
    {
        PackInstallDisposition::Installed(receipt) => {
            assert_eq!(receipt.pack_name, pack, "the put installs the pack");
        }
        other => panic!("the owner put installs the pack: {other:?}"),
    }
    let bindings = fixture.vault.pack_hook_bindings().expect("list bindings");
    let (binding_id, row) = bindings
        .into_iter()
        .find(|(_, row)| row.pack == pack && row.hook == hook)
        .expect("the owner hook binds");
    assert_eq!(row.author, HookAuthor::Owner, "the hook binds as the owner");
    assert!(row.enabled, "the new binding runs");
    binding_id
}

/// One landed claim with `predicate` about a fresh person; answers subject and claim.
fn land_fact_claim(vault: &Vault, predicate: &str) -> (EntityId, EntityId) {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"hook subject",
        )
        .expect("put the claim subject");
    let claim_id = EntityId::now();
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        rmpv::Value::from("fixture input"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("build the claim body");
    vault
        .put_claim(&claim_id, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("land the fact claim");
    (subject, claim_id)
}

/// A hook sandbox that always emits `nothing`, for regen goldens with no model.
struct AlwaysNothingRuntime;

impl HookBodyRuntime for AlwaysNothingRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        Ok(HookBodyRun {
            outcome_json: r#"{"kind":"nothing"}"#.to_owned(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// A regenerator that answers every intent with one fixed candidate body.
struct FixedBodyRegenerator {
    candidate: String,
}

impl HookRegenerator for FixedBodyRegenerator {
    fn regenerate(
        &self,
        _request: &HookRegenRequest,
    ) -> std::result::Result<String, HookRegenFailure> {
        Ok(self.candidate.clone())
    }
}

/// Replay is a dry run that lands nothing.
///
/// Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:113`
/// "A hook never sees the live vault." and verb row
/// `scripts/sdk/verbs/vault.hooks.replay.json:3`
/// "as a dry run where nothing lands".
#[test]
fn replay_is_a_dry_run_that_lands_nothing() {
    run_on_engine_stack("vault-hooks-replay-dry-run", || async {
        let fixture = setup().await;
        let hook_body = "return {\n  kind: \"propose\",\n  claim: {\n    subject: input.claim.subject,\n    predicate: \"example.replaydry.note\",\n    confidence: 1,\n    value: { note: input.claim.value }\n  }\n};\n";
        let binding = put_owner_hook_pack(
            &fixture,
            "example.replaydry",
            "fact-note",
            "[\"claim.landed:example.replaydry.input\"]",
            "[\"propose\"]",
            None,
            hook_body,
        );
        let (subject, input_claim) = land_fact_claim(&fixture.vault, "example.replaydry.input");
        let before = fixture
            .vault
            .claims_for_subject(&subject)
            .expect("list the subject claims");
        assert_eq!(before.len(), 1, "one input claim stands");
        assert!(before.contains(&input_claim), "the input claim stands");
        let binding_hex = binding.to_hex();
        let (status, answer) = post(
            &fixture,
            "/v1/core/facade/vault.hooks.replay",
            &fixture.owner_token,
            owner_binding(&fixture),
            json!({"binding": binding_hex, "limit": 10}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "replay answers: {answer}");
        let rows = answer["rows"].as_array().expect("replay rows");
        assert_eq!(rows.len(), 1, "one past fact replays: {answer}");
        let row = &rows[0];
        assert_eq!(
            row["case"]["on"].as_str(),
            Some("fact"),
            "a fact replays: {answer}"
        );
        assert_eq!(
            row["case"]["kind"].as_str(),
            Some("claim.landed"),
            "the landed claim replays: {answer}"
        );
        assert_eq!(
            row["case"]["entity"].as_str(),
            Some(input_claim.to_hex()).as_deref(),
            "the input claim replays: {answer}"
        );
        assert_eq!(
            row["case"]["source"].as_str(),
            Some("claim_changelog"),
            "the changelog sources the fact: {answer}"
        );
        assert_eq!(
            row["result"]["status"].as_str(),
            Some("ran"),
            "the body runs: {answer}"
        );
        assert_eq!(
            row["result"]["outcome"].as_str(),
            Some("propose"),
            "the body proposes: {answer}"
        );
        let outcome_json = row["result"]["outcome_json"]
            .as_str()
            .expect("the outcome JSON");
        assert!(
            outcome_json.contains("example.replaydry.note"),
            "the outcome names its note: {answer}"
        );
        assert_eq!(
            row["result"]["from_memo"].as_bool(),
            Some(false),
            "no run pinned the entry: {answer}"
        );
        assert_eq!(
            row["result"]["reads_live"].as_bool(),
            Some(true),
            "the entry reads live rows: {answer}"
        );
        assert_eq!(
            row["result"]["compare"].as_str(),
            Some("incomplete"),
            "no recorded outcome compares: {answer}"
        );
        assert_eq!(
            answer["done"].as_bool(),
            Some(true),
            "one page ends: {answer}"
        );
        assert_eq!(
            answer["effective_limit"].as_u64(),
            Some(10),
            "the page keeps its limit: {answer}"
        );
        assert_eq!(
            answer["limit_clamped"].as_bool(),
            Some(false),
            "the limit fits one page: {answer}"
        );
        let after = fixture
            .vault
            .claims_for_subject(&subject)
            .expect("list the subject claims again");
        assert_eq!(after, before, "the dry run lands no claim");
        for landed in &after {
            let kept = fixture
                .vault
                .get_claim(landed)
                .expect("read the kept claim")
                .expect("the kept claim stands");
            assert_eq!(
                kept.predicate, "example.replaydry.input",
                "no note claim lands"
            );
        }
    });
}

/// A hook outcome of an undeclared kind is refused.
///
/// Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:105`
/// "The engine refuses any other kind."
#[test]
fn a_hook_outcome_of_an_undeclared_kind_is_refused() {
    run_on_engine_stack("vault-hooks-undeclared-kind", || async {
        let fixture = setup().await;
        let hook_body = "return {\n  kind: \"propose\",\n  claim: {\n    subject: input.claim.subject,\n    predicate: \"example.refused.note\",\n    confidence: 1,\n    value: { note: input.claim.value }\n  }\n};\n";
        let binding = put_owner_hook_pack(
            &fixture,
            "example.refused",
            "fact-note",
            "[\"claim.landed:example.refused.input\"]",
            "[\"nothing\"]",
            None,
            hook_body,
        );
        let (subject, _input_claim) = land_fact_claim(&fixture.vault, "example.refused.input");
        let before = fixture
            .vault
            .claims_for_subject(&subject)
            .expect("list the subject claims");
        assert_eq!(before.len(), 1, "one input claim stands");
        let (status, answer) = post(
            &fixture,
            "/v1/core/facade/vault.hooks.replay",
            &fixture.owner_token,
            owner_binding(&fixture),
            json!({"binding": binding.to_hex(), "limit": 10}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "replay answers: {answer}");
        let rows = answer["rows"].as_array().expect("replay rows");
        assert_eq!(rows.len(), 1, "one past fact replays: {answer}");
        assert_eq!(
            rows[0]["result"]["status"].as_str(),
            Some("ran"),
            "the body runs: {answer}"
        );
        assert_eq!(
            rows[0]["result"]["outcome"].as_str(),
            Some("refused"),
            "the undeclared kind is refused: {answer}"
        );
        assert_eq!(
            rows[0]["result"]["reason"].as_str(),
            Some("the binding does not allow propose"),
            "the refusal names the kind: {answer}"
        );
        let after = fixture
            .vault
            .claims_for_subject(&subject)
            .expect("list the subject claims again");
        assert_eq!(after, before, "the refused outcome lands nothing");
    });
}

/// Cancel sets the decision aside and keeps the body.
///
/// Verb row `scripts/sdk/verbs/vault.hooks.regen.cancel.json:3`
/// "The hook keeps its body; its contract is declined until it moves again."
#[test]
fn cancel_sets_the_decision_aside_and_keeps_the_body() {
    run_on_engine_stack("vault-hooks-regen-cancel", || async {
        let fixture = setup().await;
        let last_good = "return {kind: \"nothing\"};";
        let candidate = "return {kind: \"nothing\"}; // regen candidate";
        let binding = put_owner_hook_pack(
            &fixture,
            "example.cancelkeep",
            "cancel-hook",
            "[\"claim.landed:example.cancelkeep.input\"]",
            "[\"nothing\"]",
            Some("Watch example.cancelkeep.input claims and do nothing."),
            last_good,
        );
        let decided = fixture
            .vault
            .regenerate_hook(
                &AlwaysNothingRuntime,
                &FixedBodyRegenerator {
                    candidate: candidate.to_owned(),
                },
                binding,
            )
            .expect("regen decides");
        assert!(
            matches!(decided, HookRegenOutcome::NeedsHumanStamp { .. }),
            "an empty golden set waits for a stamp: {decided:?}"
        );
        let bindings = fixture.vault.pack_hook_bindings().expect("list bindings");
        let row = bindings
            .iter()
            .find(|(id, _)| **id == binding)
            .map(|(_, row)| row)
            .expect("the binding stands");
        let kept_before = fixture
            .vault
            .pack_hook_body(row)
            .expect("read the body before cancel");
        assert_eq!(
            kept_before,
            last_good.as_bytes(),
            "the hook starts on its last good body"
        );
        let binding_hex = binding.to_hex();
        let (status, got) = post(
            &fixture,
            "/v1/core/facade/vault.hooks.regen.get",
            &fixture.owner_token,
            owner_binding(&fixture),
            json!({"binding": binding_hex}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "regen.get answers: {got}");
        let candidate_hash = got["candidate_hash"]
            .as_str()
            .expect("a candidate waits")
            .to_owned();
        assert_eq!(
            got["record"]["pending"]["outcome"].as_str(),
            Some("needs_human_stamp"),
            "the decision waits: {got}"
        );
        let (status, cancelled) = post(
            &fixture,
            "/v1/core/facade/vault.hooks.regen.cancel",
            &fixture.owner_token,
            owner_binding(&fixture),
            json!({"binding": binding_hex, "candidate_hash": candidate_hash}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "cancel answers: {cancelled}");
        assert_eq!(
            cancelled["candidate_hash"].as_str(),
            Some(candidate_hash.as_str()),
            "cancel sets aside the named candidate: {cancelled}"
        );
        assert_eq!(
            cancelled["declined"]["verb_table"].as_str().map(str::len),
            Some(64),
            "cancel declines the verb table: {cancelled}"
        );
        assert_eq!(
            cancelled["declined"]["sandbox"].as_str().map(str::len),
            Some(64),
            "cancel declines the sandbox: {cancelled}"
        );
        let bindings = fixture.vault.pack_hook_bindings().expect("list bindings");
        let row = bindings
            .iter()
            .find(|(id, _)| **id == binding)
            .map(|(_, row)| row)
            .expect("the binding still stands");
        let kept_after = fixture
            .vault
            .pack_hook_body(row)
            .expect("read the body after cancel");
        assert_eq!(kept_after, kept_before, "cancel keeps the hook body");
        let (status, got_again) = post(
            &fixture,
            "/v1/core/facade/vault.hooks.regen.get",
            &fixture.owner_token,
            owner_binding(&fixture),
            json!({"binding": binding_hex}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "regen.get answers again: {got_again}"
        );
        assert!(
            got_again
                .get("candidate_hash")
                .and_then(Value::as_str)
                .is_none(),
            "no candidate waits after cancel: {got_again}"
        );
        assert!(
            got_again["record"]["pending"].is_null(),
            "no decision waits after cancel: {got_again}"
        );
        assert!(
            got_again["record"]["declined"].is_object(),
            "the contract stands declined: {got_again}"
        );
        let (status, due) = post(
            &fixture,
            "/v1/core/facade/vault.hooks.regen.due",
            &fixture.owner_token,
            owner_binding(&fixture),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "regen.due answers: {due}");
        let listed = due.as_array().expect("the due list");
        assert!(
            !listed
                .iter()
                .any(|entry| entry.as_str() == Some(binding_hex.as_str())),
            "a declined hook is not due again: {due}"
        );
    });
}

/// Owner-only hook doors refuse a person.
///
/// Verb rows `scripts/sdk/verbs/vault.hooks.replay.json:3`,
/// `vault.hooks.checks.json:3`, `vault.hooks.regen.get.json:2`,
/// `vault.hooks.regen.due.json:2` and `vault.hooks.regen.cancel.json:2` are
/// the vault owner's; any other caller hears `FORBIDDEN`.
#[test]
fn owner_only_hook_doors_refuse_a_person() {
    run_on_engine_stack("vault-hooks-owner-only", || async {
        let fixture = setup().await;
        let binding = put_owner_hook_pack(
            &fixture,
            "example.owneronly",
            "fact-note",
            "[\"claim.landed:example.owneronly.input\"]",
            "[\"nothing\"]",
            None,
            "return {kind: \"nothing\"};",
        );
        let binding_hex = binding.to_hex();
        let person_id = EntityId::now();
        person(&fixture.vault, person_id);
        let person_slip = fixture.credential(person_id);
        let person_token = person_slip.to_token().expect("the person token");
        let cases: Vec<(&str, Value)> = vec![
            ("vault.hooks.replay", json!({"binding": binding_hex})),
            ("vault.hooks.checks", json!({})),
            ("vault.hooks.regen.get", json!({"binding": binding_hex})),
            ("vault.hooks.regen.due", json!({})),
            ("vault.hooks.regen.cancel", json!({"binding": binding_hex})),
        ];
        for (verb, input) in cases {
            let proof = person_binding(&fixture, &person_slip);
            let (status, answer) = post(
                &fixture,
                &format!("/v1/core/facade/{verb}"),
                &person_token,
                proof,
                input,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{verb} refuses a person: {answer}"
            );
            assert_eq!(
                answer["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "{verb} refusal code: {answer}"
            );
            assert_eq!(
                answer["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "{verb} refusal message: {answer}"
            );
        }
        let bindings = fixture.vault.pack_hook_bindings().expect("list bindings");
        assert_eq!(bindings.len(), 1, "refused calls change nothing");
    });
}
