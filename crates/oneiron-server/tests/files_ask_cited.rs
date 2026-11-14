//! `vault.files.sources.ask` (census L2-16 PR 2; ARCH-0027 #files-world:
//! "The owner can ask about a file and get an answer with citations"),
//! served over the real facade route: the owner's question is answered by
//! one call of the house chat role on a fake model, and fixed code keeps the
//! answer only when every citation names a file the model was given and
//! quotes its text exactly. A model off this install is sent none of the
//! Files world's text while the world is read on this install only.
//!
//! The vault's install is the owner's own machine, with one Files source
//! whose two files are handed to `rescan_folder_source` as a host's walk
//! would; the question goes through the host-root credential, which acts as
//! the vault's embedded owner. The fake model is a local OpenAI-compatible
//! server reached over HTTP, which this host places on its own server, not
//! on this install (`on_device` is derived, never configured:
//! `config/models/provider.rs`). So the tests that need an answer run with
//! the owner having widened the Files world to be read everywhere
//! (`set_world_privacy_as`), and the egress test keeps the world's shipped
//! read location, this install only. Reads JSON only, so on a base without
//! the verb every test fails on its first status assertion.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! files_ask_cited`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::{
    ActSurface, CapabilitySlip, HostSlipIssuer, MachineOwnership, MachineRole, ModelOrder,
    ReadLocation, SealedCopies, WorldPrivacy,
};
use oneiron::note::{FileFacts, FolderRescan, ImportedNote};
use oneiron::test_doors::steward;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const VERB: &str = "vault.files.sources.ask";

/// The words that open the ask's instruction: they mark its model calls.
const ASK_MARK: &str = "You answer the owner's question from the files given";

const BUDGET_PATH: &str = "budget.md";
const BUDGET_TEXT: &str = "We set the budget for the quarter at 40 thousand.\n";
const PLAN_PATH: &str = "budget-plan.md";
const PLAN_TEXT: &str = "The plan keeps travel under the budget until June.\n";

/// Where the Files world may be read.
#[derive(Clone, Copy)]
enum FilesRead {
    /// As it ships: on this install only.
    ThisInstall,
    /// Widened by the owner: everywhere, the fake model's server included.
    Everywhere,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    host: AiHost,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    model: FakeLlm,
    source: EntityId,
}

fn models_text(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    )
}

impl Fixture {
    /// A served vault whose install the owner answered is his, with one
    /// Files source holding `budget.md` and `budget-plan.md` as text, read
    /// where `read` says, and its chat role on a fake model that answers
    /// every call with `reply`.
    async fn new(read: FilesRead, reply: &str) -> Self {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text(reply))).await;
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("files-ask-cited".into()),
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
        let source = land_files(&vault, read);
        let models = ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let app = build_app(Arc::new(server));
        Self {
            _dir: dir,
            vault,
            host,
            app,
            issuer,
            owner_slip,
            owner_token,
            model,
            source,
        }
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }

    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// The owner's question, through the facade route.
    async fn ask(&self, body: Value) -> (StatusCode, Value) {
        let request = Request::post(format!("/v1/core/facade/{VERB}"))
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("facade request");
        let response =
            tokio::time::timeout(Duration::from_secs(120), self.app.clone().oneshot(request))
                .await
                .expect("the ask answers within two minutes")
                .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("facade response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    /// The bodies of the fake model's calls that carried the ask's
    /// instruction, as JSON text.
    fn ask_calls(&self) -> Vec<String> {
        self.model
            .seen()
            .into_iter()
            .map(|call| call.body.to_string())
            .filter(|body| body.contains(ASK_MARK))
            .collect()
    }
}

/// Makes this install the owner's own machine, attaches one Files source,
/// sets where the Files world may be read and lands the source's two text
/// files; the source's id.
fn land_files(vault: &Vault, read: FilesRead) -> EntityId {
    let owner = steward::owner(vault).expect("owner proof");
    let this_install = vault
        .local_machine()
        .expect("read this install")
        .expect("this install has a machine id")
        .id;
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            this_install,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner answers this install is his");
    let (_world, source) = vault
        .attach_files_source(
            &owner,
            ActSurface::ThisInstall,
            "/srv/files",
            Vec::new(),
            None,
            None,
        )
        .expect("attach the Files source");
    let placed = source.files.as_ref().expect("a Files placement").source;
    if let FilesRead::Everywhere = read {
        let world = vault
            .files_world()
            .expect("read the Files world")
            .expect("this install has a Files world")
            .world;
        vault
            .set_world_privacy_as(
                &owner,
                ActSurface::ThisInstall,
                world,
                WorldPrivacy {
                    read: ReadLocation::Everywhere,
                    sealed: SealedCopies::Off,
                    models: ModelOrder::Inherit,
                },
                None,
            )
            .expect("the owner widens the Files world");
    }
    let files = [
        (BUDGET_PATH, BUDGET_TEXT, 1_700_000_200_u64),
        (PLAN_PATH, PLAN_TEXT, 1_700_000_100_u64),
    ];
    let report = vault
        .rescan_folder_source(
            &owner,
            FolderRescan {
                folder: source.folder.clone(),
                new: files
                    .iter()
                    .map(|(path, markdown, written_at)| ImportedNote {
                        path: (*path).to_owned(),
                        kind: source.kind.clone(),
                        title: Some((*path).to_owned()),
                        written_at: *written_at,
                        markdown: (*markdown).to_owned(),
                        original: None,
                    })
                    .collect(),
                links: Vec::new(),
                present: Vec::new(),
                name_only: Vec::new(),
                missing: Vec::new(),
                raw_hashes: HashMap::new(),
                facts: files
                    .iter()
                    .map(|(path, markdown, written_at)| {
                        (
                            (*path).to_owned(),
                            FileFacts {
                                bytes: u64::try_from(markdown.len()).unwrap_or(u64::MAX),
                                modified_at: *written_at,
                            },
                        )
                    })
                    .collect(),
                whole: true,
            },
        )
        .expect("land the folder's files");
    assert_eq!(report.failed, 0, "no file may be refused: {report:?}");
    assert_eq!(report.landed, files.len(), "every file lands: {report:?}");
    placed
}

/// The model's answer, as the ask's instruction asks for it.
fn reply(answer: &str, citations: &[(u32, &str)]) -> String {
    let citations: Vec<Value> = citations
        .iter()
        .map(|(source, quote)| json!({"source": source, "quote": quote}))
        .collect();
    json!({"answer": answer, "citations": citations}).to_string()
}

fn read_paths(answer: &Value) -> Vec<&str> {
    answer["read"]
        .as_array()
        .expect("the files read")
        .iter()
        .map(|file| file["handle"]["path"].as_str().expect("a read file's path"))
        .collect()
}

#[test]
fn files_ask_returns_verified_citations() {
    run_on_engine_stack("files-ask-cited", || async {
        let fixture = Fixture::new(
            FilesRead::Everywhere,
            &reply(
                "The quarter's budget is 40 thousand [1].",
                &[(1, "budget for the quarter at 40 thousand")],
            ),
        )
        .await;
        let (status, answer) = fixture.ask(json!({"query": "budget"})).await;
        assert_eq!(status, StatusCode::OK, "owner ask: {answer}");
        let outcome = &answer["outcome"];
        assert_eq!(outcome["kind"], "cited", "{answer}");
        assert_eq!(
            outcome["answer"],
            "The quarter's budget is 40 thousand [1]."
        );
        let citations = outcome["citations"].as_array().expect("citations");
        assert_eq!(citations.len(), 1, "{answer}");
        let citation = &citations[0];
        assert_eq!(citation["source"], 1, "{answer}");
        assert_eq!(citation["handle"]["path"], BUDGET_PATH, "{answer}");
        assert_eq!(
            citation["handle"]["source"],
            fixture.source.to_hex().as_str(),
            "{answer}"
        );
        assert_eq!(citation["quote"], "budget for the quarter at 40 thousand");
        assert_eq!(
            read_paths(&answer),
            vec![BUDGET_PATH, PLAN_PATH],
            "{answer}"
        );
        let revision = citation["revision"].as_str().expect("a cited revision");
        assert!(!revision.is_empty(), "{answer}");
        assert_eq!(answer["read"][0]["revision"], revision, "{answer}");
        let calls = fixture.ask_calls();
        assert_eq!(calls.len(), 1, "one model call answers the ask");
        assert!(
            calls[0].contains("40 thousand") && calls[0].contains("until June"),
            "the call carries both files' text: {}",
            calls[0]
        );
        fixture.finish().await;
    });
}

#[test]
fn files_ask_drops_a_citation_whose_quote_is_not_in_the_file() {
    run_on_engine_stack("files-ask-misquote", || async {
        let fixture = Fixture::new(
            FilesRead::Everywhere,
            &reply(
                "The budget is 50 thousand [1].",
                &[(1, "budget for the year at 50 thousand")],
            ),
        )
        .await;
        let (status, answer) = fixture.ask(json!({"query": "budget"})).await;
        assert_eq!(status, StatusCode::OK, "owner ask: {answer}");
        assert_eq!(answer["outcome"]["kind"], "no_cited_answer", "{answer}");
        assert_eq!(answer["outcome"]["why"], "no_citation_held", "{answer}");
        assert!(answer["outcome"].get("answer").is_none(), "{answer}");
        assert_eq!(
            read_paths(&answer),
            vec![BUDGET_PATH, PLAN_PATH],
            "{answer}"
        );
        let hits: Vec<&str> = answer["hits"]
            .as_array()
            .expect("the search's hits")
            .iter()
            .map(|hit| hit["handle"]["path"].as_str().expect("a hit's path"))
            .collect();
        assert_eq!(hits, vec![BUDGET_PATH, PLAN_PATH], "{answer}");
        assert_eq!(fixture.ask_calls().len(), 1, "the model was asked once");
        fixture.finish().await;
    });
}

#[test]
fn files_ask_drops_a_citation_to_an_undelivered_source() {
    run_on_engine_stack("files-ask-undelivered", || async {
        let fixture = Fixture::new(
            FilesRead::Everywhere,
            &reply(
                "Travel stays under the budget [9].",
                &[(9, "keeps travel under the budget")],
            ),
        )
        .await;
        let (status, answer) = fixture.ask(json!({"query": "budget"})).await;
        assert_eq!(status, StatusCode::OK, "owner ask: {answer}");
        assert_eq!(answer["outcome"]["kind"], "no_cited_answer", "{answer}");
        assert_eq!(answer["outcome"]["why"], "no_citation_held", "{answer}");
        assert_eq!(
            read_paths(&answer).len(),
            2,
            "two files were given: {answer}"
        );
        fixture.finish().await;
    });
}

#[test]
fn files_ask_reads_only_the_named_file() {
    run_on_engine_stack("files-ask-named", || async {
        let fixture = Fixture::new(
            FilesRead::Everywhere,
            &reply(
                "Travel stays under the budget until June [1].",
                &[(1, "under the budget until June")],
            ),
        )
        .await;
        let (status, answer) = fixture
            .ask(json!({
                "query": "When does travel stop?",
                "file": {"source": fixture.source.to_hex(), "path": PLAN_PATH},
            }))
            .await;
        assert_eq!(status, StatusCode::OK, "owner ask: {answer}");
        assert_eq!(answer["outcome"]["kind"], "cited", "{answer}");
        assert_eq!(
            answer["outcome"]["citations"][0]["handle"]["path"], PLAN_PATH,
            "{answer}"
        );
        assert_eq!(read_paths(&answer), vec![PLAN_PATH], "{answer}");
        assert_eq!(answer["hits"], json!([]), "no search ran: {answer}");
        let calls = fixture.ask_calls();
        assert_eq!(calls.len(), 1, "one model call answers the ask");
        assert!(calls[0].contains("until June"), "{}", calls[0]);
        assert!(
            !calls[0].contains("40 thousand"),
            "a file not named is not read: {}",
            calls[0]
        );
        fixture.finish().await;
    });
}

/// The shipped Files world is read on this install only, and a model server
/// reached over HTTP is not this install: the call is held at every rung,
/// and the owner is told no model the text may go to answered.
#[test]
fn files_ask_sends_no_file_text_off_this_install() {
    run_on_engine_stack("files-ask-off-install", || async {
        let fixture = Fixture::new(
            FilesRead::ThisInstall,
            &reply(
                "The quarter's budget is 40 thousand [1].",
                &[(1, "budget for the quarter at 40 thousand")],
            ),
        )
        .await;
        let (status, answer) = fixture.ask(json!({"query": "budget"})).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
        let code = answer["error"]["code"]
            .as_str()
            .or_else(|| answer["code"].as_str());
        assert_eq!(code, Some("MODEL_UNAVAILABLE"), "{answer}");
        for call in fixture.model.seen() {
            let body = call.body.to_string();
            assert!(
                !body.contains("40 thousand") && !body.contains("until June"),
                "a Files world read on this install only reached a model server: {body}"
            );
        }
        fixture.finish().await;
    });
}
