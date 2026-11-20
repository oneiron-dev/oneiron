//! `vault.imports.hook_transcript` lands a Claude Code session a CLI on
//! another machine sends (census L10-17, PR 3a; Engine ruling Tue 17 Nov
//! 06:50, L10-17-PR3-MEMORY = B).
//!
//! The owner, or an agent whose live Grant names the verb, sends one session
//! log and its subagent logs, each gzip-compressed in base64. They land
//! through the same import `oneiron import claude-code <log>` runs: the same
//! dedupe, so a second send lands nothing new, and an answer that names the
//! session's CONVERSATION, which `vault.runners.continue` takes. An agent
//! with no Grant is refused before any log is read, and nothing lands; logs
//! that inflate past the verb's cap are refused by name, and nothing lands.
//!
//! Red/green facade test: it drives the real route
//! `POST /v1/core/facade/vault.imports.hook_transcript` with real paired
//! credentials, in process (`oneshot`, no TCP ports, no models). The agent
//! is a vault-registered named PERSON paired over real
//! `POST /v1/core/pairing/redeem`; its Grant is minted over real
//! `POST /v1/core/facade/vault.agents.grants.mint`. The logs are the
//! repository's Claude Code fixture session and its subagent. Each case owns
//! its vault. The test names nothing the PR adds, so it builds on the PR's
//! base, where every case's first call answers 404 (no route) and fails.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test hook_transcript_import_served`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::ingest::history::{HistoryFile, HistorySource};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tower::ServiceExt;

/// The verb under test, which the agent's Grant must name.
const VERB: &str = "vault.imports.hook_transcript";
/// The engine's authority refusal when no live Grant names the act.
const AUTHORITY_REFUSAL_MESSAGE: &str = "no live Grant of this agent names this act";
/// The fixture session's id: its log's file stem.
const SESSION: &str = "5d0c0a7e-1111-4222-8333-944455556666";
/// The fixture session's subagent log's stem.
const SUBAGENT: &str = "agent-a7f3";
/// The fixture session's log.
const SESSION_LOG: &str = include_str!(
    "fixtures/history/claude-code/projects/-Users-ana-code-garden-planner/5d0c0a7e-1111-4222-8333-944455556666.jsonl"
);
/// The fixture session's subagent log.
const SUBAGENT_LOG: &str = include_str!(
    "fixtures/history/claude-code/projects/-Users-ana-code-garden-planner/5d0c0a7e-1111-4222-8333-944455556666/subagents/agent-a7f3.jsonl"
);
/// The most bytes one call's logs inflate to (the engine's
/// `HOOK_TRANSCRIPT_MAX_BYTES`), written out so this test builds on the
/// PR's base.
const MAX_BYTES: usize = 64 * 1024 * 1024;

/// One paired agent credential: its registered principal, its holder
/// signing key, its redeemed slip and the token it presents.
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

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

async fn setup() -> (Fixture, Agent) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("hook-transcript-import-served".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    let app = build_app(Arc::new(server));
    let agent = pair_agent(&vault, &app, &issuer, "transcript-agent", [0x52; 32]).await;
    (
        Fixture {
            _dir: dir,
            vault,
            app,
            issuer,
            owner_slip,
            owner_token,
        },
        agent,
    )
}

/// Pairs one agent the way `token agent` does: a registered named PERSON
/// principal, a principal-bound link narrowed to the agent verb scope the
/// end-to-end suite pairs (`core:read`, `core:write`), redeemed over the
/// real pairing route with the holder-signed binding transcript.
async fn pair_agent(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    name: &str,
    seed: [u8; 32],
) -> Agent {
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
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
    Agent {
        principal,
        holder,
        slip,
        token,
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

fn agent_binding(fixture: &Fixture, agent: &Agent) -> String {
    let timestamp = fixture.vault.now_recorded_at();
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
    let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

async fn import_as(
    fixture: &Fixture,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    post(
        fixture,
        &format!("/v1/core/facade/{VERB}"),
        token,
        binding,
        body,
    )
    .await
}

/// The owner mints the agent a Grant naming the verb over actual HTTP and
/// reads back from the mint answer that it names the verb and confers.
async fn mint_import_grant(fixture: &Fixture, agent_hex: &str) {
    let (status, body) = post(
        fixture,
        "/v1/core/facade/vault.agents.grants.mint",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({
            "agent": agent_hex,
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": ["read", VERB]},
                "sensitivity": {"kind": "at_most", "value": "restricted"},
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint import grant: {body}");
    let verbs = body["grant"]["authority_scope"]["verbs"]["values"]
        .as_array()
        .expect("minted grant verbs");
    assert!(
        verbs.iter().any(|verb| verb.as_str() == Some(VERB)),
        "minted grant names the verb: {body}"
    );
    assert_eq!(
        body["grant"]["confers"].as_bool(),
        Some(true),
        "minted grant confers: {body}"
    );
}

/// `bytes` gzip-compressed, in standard base64.
fn gzip_base64(bytes: &[u8]) -> String {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("gzip write");
    let compressed = encoder.finish().expect("gzip finish");
    base64::engine::general_purpose::STANDARD.encode(compressed)
}

/// The request for the fixture session with its subagent.
fn session_body() -> Value {
    json!({
        "session": SESSION,
        "transcript_gzip_base64": gzip_base64(SESSION_LOG.as_bytes()),
        "subagents": [
            {"stem": SUBAGENT, "transcript_gzip_base64": gzip_base64(SUBAGENT_LOG.as_bytes())},
        ],
    })
}

/// How many messages the Claude Code reader keeps from the fixture
/// session's log (its main thread) and its subagent's log, read as the
/// local import reads them.
fn kept_messages() -> (usize, usize) {
    let main = HistorySource::ClaudeCode
        .decode(
            SESSION_LOG,
            &HistoryFile {
                stem: SESSION.to_owned(),
                parent: None,
            },
        )
        .expect("decode the session log");
    let main = main
        .iter()
        .find(|conversation| conversation.native_id == SESSION)
        .expect("the session's own conversation")
        .messages
        .len();
    let subagent = HistorySource::ClaudeCode
        .decode(
            SUBAGENT_LOG,
            &HistoryFile {
                stem: SUBAGENT.to_owned(),
                parent: Some(SESSION.to_owned()),
            },
        )
        .expect("decode the subagent log")
        .iter()
        .map(|conversation| conversation.messages.len())
        .sum();
    (main, subagent)
}

/// The answer's entry for the conversation whose Claude Code id is
/// `native_id`.
fn entry<'a>(body: &'a Value, native_id: &str) -> &'a Value {
    body["conversations"]
        .as_array()
        .expect("conversations")
        .iter()
        .find(|entry| entry["native_id"].as_str() == Some(native_id))
        .unwrap_or_else(|| panic!("an entry for {native_id}: {body}"))
}

/// The sum of `field` over the answer's conversations.
fn total(body: &Value, field: &str) -> u64 {
    body["conversations"]
        .as_array()
        .expect("conversations")
        .iter()
        .map(|entry| entry[field].as_u64().expect("a count"))
        .sum()
}

/// How many Claude Code messages the vault's import ledger holds.
fn ledger(fixture: &Fixture) -> usize {
    fixture
        .vault
        .history_import_ledger_len(HistorySource::ClaudeCode)
        .expect("read the import ledger")
}

/// Case 1: the owner sends the session with its subagent. Both land as the
/// local import lands them, the answer names the session's CONVERSATION,
/// which the vault holds, and the import's review; a second send of the same
/// logs lands nothing new.
#[test]
fn the_owner_lands_a_session_and_a_second_send_lands_nothing_new() {
    run_on_engine_stack("hook-transcript-owner", || async {
        let (fixture, _agent) = setup().await;
        let (main, subagent) = kept_messages();
        assert!(
            main > 0 && subagent > 0,
            "precondition: the fixture keeps messages"
        );
        let owner_token = fixture.owner_token.clone();

        let (status, body) = import_as(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            session_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner import: {body}");
        let session = entry(&body, SESSION);
        assert_eq!(session["kind"].as_str(), Some("main"), "{body}");
        assert_eq!(session["new"].as_u64(), Some(main as u64), "{body}");
        assert_eq!(
            session["conversation"], body["conversation"],
            "the answer names the session's own CONVERSATION: {body}"
        );
        let delegated = entry(&body, &format!("{SESSION}/{SUBAGENT}"));
        assert_eq!(delegated["kind"].as_str(), Some("subagent"), "{body}");
        assert_eq!(delegated["new"].as_u64(), Some(subagent as u64), "{body}");
        assert_eq!(total(&body, "refused"), 0, "{body}");
        assert!(
            body["review"]
                .as_str()
                .is_some_and(|review| review.starts_with("import:claude-code:")),
            "the import's review is named: {body}"
        );
        let landed = total(&body, "new");
        assert_eq!(
            ledger(&fixture) as u64,
            landed,
            "the ledger holds what landed"
        );

        let conversation = body["conversation"]
            .as_str()
            .expect("conversation id")
            .to_owned();
        let (status, read) = post(
            &fixture,
            "/v1/core/facade/vault.get",
            &owner_token,
            owner_binding(&fixture),
            json!({"entity_ref": conversation}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "read the CONVERSATION back: {read}");
        assert_eq!(
            read["value"]["kind"].as_str(),
            Some("CONVERSATION"),
            "{read}"
        );

        let (status, again) = import_as(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            session_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner second send: {again}");
        assert_eq!(again["conversation"], body["conversation"], "{again}");
        assert_eq!(total(&again, "new"), 0, "nothing lands twice: {again}");
        assert_eq!(total(&again, "changed"), 0, "{again}");
        assert_eq!(total(&again, "skipped"), landed, "{again}");
        assert!(again.get("review").is_none_or(Value::is_null), "{again}");
        assert_eq!(ledger(&fixture) as u64, landed, "the ledger is unchanged");
    });
}

/// Case 2: an agent whose Grant names the verb lands the session.
#[test]
fn an_agent_whose_grant_names_the_verb_lands_a_session() {
    run_on_engine_stack("hook-transcript-granted", || async {
        let (fixture, agent) = setup().await;
        let (main, _) = kept_messages();
        mint_import_grant(&fixture, &agent.principal.to_hex()).await;

        let (status, body) = import_as(
            &fixture,
            &agent.token,
            agent_binding(&fixture, &agent),
            session_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "granted agent import: {body}");
        assert_eq!(
            entry(&body, SESSION)["new"].as_u64(),
            Some(main as u64),
            "{body}"
        );
        assert_eq!(total(&body, "refused"), 0, "{body}");
        assert_eq!(ledger(&fixture) as u64, total(&body, "new"));
    });
}

/// Case 3: the paired agent with no Grant is refused before any log is read
/// (a log that is not base64 still answers the Grant refusal), and nothing
/// lands.
#[test]
fn an_agent_without_the_grant_is_refused_and_nothing_lands() {
    run_on_engine_stack("hook-transcript-refused", || async {
        let (fixture, agent) = setup().await;
        let (status, body) = import_as(
            &fixture,
            &agent.token,
            agent_binding(&fixture, &agent),
            session_body(),
        )
        .await;
        assert!(
            status.is_client_error() && status != StatusCode::NOT_FOUND,
            "ungranted import is refused 4xx, not 404: {status} {body}"
        );
        assert!(
            body.to_string().contains(AUTHORITY_REFUSAL_MESSAGE),
            "ungranted import names the missing Grant: {body}"
        );

        let (status, body) = import_as(
            &fixture,
            &agent.token,
            agent_binding(&fixture, &agent),
            json!({"session": SESSION, "transcript_gzip_base64": "not base64!"}),
        )
        .await;
        assert!(
            status.is_client_error() && status != StatusCode::NOT_FOUND,
            "ungranted import of a bad log is refused 4xx, not 404: {status} {body}"
        );
        assert!(
            body.to_string().contains(AUTHORITY_REFUSAL_MESSAGE),
            "the caller is judged before the log is read: {body}"
        );
        assert_eq!(ledger(&fixture), 0, "nothing landed");
    });
}

/// Case 4: logs that inflate past the cap are refused by the limit's name,
/// and nothing lands, not even the session's own log under the cap.
#[test]
fn logs_past_the_cap_are_refused_by_name_and_nothing_lands() {
    run_on_engine_stack("hook-transcript-cap", || async {
        let (fixture, _agent) = setup().await;
        let mut padded = SUBAGENT_LOG.as_bytes().to_vec();
        padded.resize(MAX_BYTES + 1 - SESSION_LOG.len(), b'\n');
        let owner_token = fixture.owner_token.clone();
        let (status, body) = import_as(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            json!({
                "session": SESSION,
                "transcript_gzip_base64": gzip_base64(SESSION_LOG.as_bytes()),
                "subagents": [
                    {"stem": SUBAGENT, "transcript_gzip_base64": gzip_base64(&padded)},
                ],
            }),
        )
        .await;
        assert!(
            status.is_client_error() && status != StatusCode::NOT_FOUND,
            "logs past the cap are refused 4xx, not 404: {status} {body}"
        );
        assert!(
            body.to_string().contains("HOOK_TRANSCRIPT_MAX_BYTES"),
            "the refusal names the limit: {body}"
        );
        assert_eq!(ledger(&fixture), 0, "nothing landed");
    });
}

/// The repository's current Codex rollout fixture's file stem, which the
/// hosted hand-over sends as the session (FIX
/// HOOK-HOSTED-HAND-OVER-OTHER-HOSTS).
const CODEX_STEM: &str = "rollout-2026-09-14T10-00-00-0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
/// That rollout.
const CODEX_LOG: &str = include_str!(
    "fixtures/history/codex/sessions/2026/09/14/rollout-2026-09-14T10-00-00-0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl"
);
/// A GitHub Copilot session's id, its transcript's file stem.
const COPILOT_SESSION: &str = "8f6c1d2e-3333-4444-8555-666677778888";
/// A Cursor conversation's id, its transcript's file stem.
const CURSOR_SESSION: &str = "c0ffee00-1111-4222-8333-444455556666";

/// A GitHub Copilot transcript: its session's start, a user message and the
/// assistant's answer, one event per line.
fn copilot_log() -> String {
    [
        json!({
            "type": "session.start",
            "data": {"sessionId": COPILOT_SESSION},
            "id": "evt0",
            "timestamp": "2026-11-20T01:00:00.000Z",
        }),
        json!({
            "type": "user.message",
            "data": {"content": "Keep the heron lantern timetable in pier nine order."},
            "id": "evt1",
            "timestamp": "2026-11-20T01:00:01.000Z",
        }),
        json!({
            "type": "assistant.message",
            "data": {"content": "Noted: the timetable stays in pier nine order."},
            "id": "evt2",
            "timestamp": "2026-11-20T01:00:05.000Z",
        }),
    ]
    .iter()
    .map(|event| format!("{event}\n"))
    .collect()
}

/// A Cursor agent transcript: a user message, its words in `<user_query>`,
/// and the assistant's answer.
fn cursor_log() -> String {
    [
        json!({
            "role": "user",
            "message": {"content": [{
                "type": "text",
                "text": "<user_query>\nWhere is the heron lantern ledger kept?\n</user_query>",
            }]},
        }),
        json!({
            "role": "assistant",
            "message": {"content": [{"type": "text", "text": "Beside the pier nine timetable."}]},
        }),
    ]
    .iter()
    .map(|record| format!("{record}\n"))
    .collect()
}

/// The first conversation `source`'s reader reads from `text`, a file named
/// `stem`, as the local import reads it: its id and how many messages it
/// keeps.
fn first_conversation(source: HistorySource, text: &str, stem: &str) -> (String, usize) {
    let read = source
        .decode(
            text,
            &HistoryFile {
                stem: stem.to_owned(),
                parent: None,
            },
        )
        .expect("decode the log");
    let first = read.first().expect("the log's conversation");
    (first.native_id.clone(), first.messages.len())
}

/// How many messages of `source` the vault's import ledger holds.
fn ledger_of(fixture: &Fixture, source: HistorySource) -> usize {
    fixture
        .vault
        .history_import_ledger_len(source)
        .expect("read the import ledger")
}

/// Case 5 (FIX HOOK-HOSTED-HAND-OVER-OTHER-HOSTS): a request that names its
/// source lands another host's one log as `oneiron import <source> <log>`
/// lands it: a Codex rollout by its file's stem, a Copilot and a Cursor hook
/// transcript by theirs. Each answer names the conversation the log holds,
/// which the vault holds, and the source's review; a second send lands
/// nothing new. On the PR's base the verb takes no `source`, and each first
/// send is refused.
#[test]
fn a_request_naming_its_source_lands_a_codex_rollout_and_hook_transcripts() {
    run_on_engine_stack("hook-transcript-sources", || async {
        let (fixture, _agent) = setup().await;
        let owner_token = fixture.owner_token.clone();
        let (copilot, cursor) = (copilot_log(), cursor_log());
        for (source, text, stem) in [
            (HistorySource::Codex, CODEX_LOG, CODEX_STEM),
            (
                HistorySource::HookTranscript,
                copilot.as_str(),
                COPILOT_SESSION,
            ),
            (
                HistorySource::HookTranscript,
                cursor.as_str(),
                CURSOR_SESSION,
            ),
        ] {
            let wire = source.source_id();
            let (native_id, kept) = first_conversation(source, text, stem);
            assert!(kept > 0, "precondition: {stem}'s log keeps messages");
            let request = json!({
                "session": stem,
                "transcript_gzip_base64": gzip_base64(text.as_bytes()),
                "source": wire,
            });
            let before = ledger_of(&fixture, source);

            let (status, body) = import_as(
                &fixture,
                &owner_token,
                owner_binding(&fixture),
                request.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{stem}: {body}");
            let own = entry(&body, &native_id);
            assert_eq!(own["kind"].as_str(), Some("main"), "{stem}: {body}");
            assert_eq!(own["new"].as_u64(), Some(kept as u64), "{stem}: {body}");
            assert_eq!(
                own["conversation"], body["conversation"],
                "{stem}: the answer names the log's own CONVERSATION: {body}"
            );
            assert_eq!(total(&body, "refused"), 0, "{stem}: {body}");
            assert!(
                body["review"]
                    .as_str()
                    .is_some_and(|review| review.starts_with(&format!("import:{wire}:"))),
                "{stem}: the import's review is the source's: {body}"
            );
            let landed = total(&body, "new");
            assert_eq!(
                (ledger_of(&fixture, source) - before) as u64,
                landed,
                "{stem}: the source's ledger holds what landed"
            );
            let (status, read) = post(
                &fixture,
                "/v1/core/facade/vault.get",
                &owner_token,
                owner_binding(&fixture),
                json!({"entity_ref": body["conversation"]}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{stem}: read it back: {read}");
            assert_eq!(
                read["value"]["kind"].as_str(),
                Some("CONVERSATION"),
                "{stem}: {read}"
            );

            let (status, again) =
                import_as(&fixture, &owner_token, owner_binding(&fixture), request).await;
            assert_eq!(status, StatusCode::OK, "{stem}: second send: {again}");
            assert_eq!(again["conversation"], body["conversation"], "{stem}");
            assert_eq!(
                total(&again, "new"),
                0,
                "{stem}: nothing lands twice: {again}"
            );
            assert_eq!(total(&again, "changed"), 0, "{stem}: {again}");
            assert_eq!(total(&again, "skipped"), landed, "{stem}: {again}");
        }
        assert_eq!(
            ledger(&fixture),
            0,
            "no log was read as a Claude Code session"
        );
    });
}

/// Case 6: another source's log holds its subagents, so its request takes
/// no subagent logs; its session is a plain file stem; and a source the
/// verb does not read is not taken. Each is refused by its own reason, and
/// nothing lands. On the PR's base each is refused for the `source` field
/// alone.
#[test]
fn another_sources_subagent_logs_a_path_for_its_session_or_an_unread_source_are_refused() {
    run_on_engine_stack("hook-transcript-source-refusals", || async {
        let (fixture, _agent) = setup().await;
        let owner_token = fixture.owner_token.clone();
        let codex = gzip_base64(CODEX_LOG.as_bytes());
        for (request, reason) in [
            (
                json!({
                    "session": CODEX_STEM,
                    "transcript_gzip_base64": codex,
                    "subagents": [{"stem": "agent-a7f3", "transcript_gzip_base64": codex}],
                    "source": "codex",
                }),
                "only a Claude Code session has subagent logs",
            ),
            (
                json!({
                    "session": format!("../{CODEX_STEM}"),
                    "transcript_gzip_base64": codex,
                    "source": "codex",
                }),
                "is not its log's file stem",
            ),
            (
                json!({
                    "session": CODEX_STEM,
                    "transcript_gzip_base64": codex,
                    "source": "slack",
                }),
                "unknown variant",
            ),
        ] {
            let (status, body) = import_as(
                &fixture,
                &owner_token,
                owner_binding(&fixture),
                request.clone(),
            )
            .await;
            assert!(
                status.is_client_error() && status != StatusCode::NOT_FOUND,
                "refused 4xx, not 404: {status} {body} for {request}"
            );
            assert!(
                body.to_string().contains(reason),
                "refused because {reason}: {body}"
            );
        }
        for source in HistorySource::ALL {
            assert_eq!(
                ledger_of(&fixture, source),
                0,
                "nothing landed as {source:?}"
            );
        }
    });
}
