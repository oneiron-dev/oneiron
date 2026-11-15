//! The `vault.summaries.*` rows at the public door: each test proves one canon
//! promise of scope summaries through the server's real router.
//!
//! Every row's `call` runs an engine `Memory` fn (`scripts/sdk/verbs/
//! vault.summaries.*.json`), but the Dreamer gate lives only in the served
//! create wrapper (`crates/oneiron-server/src/api/facade/summary_doors.rs:50-52`),
//! so this file drives `build_app` at `POST /v1/core/facade/<verb>`. The vault
//! holds a `MemoryKeystore` and this install's machine id before the server
//! starts, so the server bootstraps its own host issuer from that keystore,
//! roots the vault and provisions the engine's MACHINE writers; the test signs
//! with that issuer, loaded back (`Vault::load_host_slip_issuer`). The
//! self-hosted root credential acts as the vault's embedded owner. A summary is
//! minted with no model through `test_doors::scope_summary::mint_scope_summary`,
//! as the Dreamer writes one (`tests/disclosure_summary_word_sources.rs`). Every
//! body runs on the engine's stack, because the facade dispatch overflows a test
//! thread's stack.
//!
//! Canon: `oneiron/backend/oneiron-arch-0006a-conversations-api-core.md`
//! (`#dag-summaries-built`) and the SUMMARY invariants of
//! `oneiron/core/oneiron-arch-0002-structural-entities.md`.
//! - `no_one_but_the_dreamer_writes_a_summary_body` (0006a: an agent "never
//!   writes the summary text"): a SUMMARY body under any other byline is
//!   refused at the storage guard every door's write goes through.
//! - `a_text_field_on_create_is_refused_as_unknown` (0006a: "a `text` field is
//!   refused as unknown"): 400 `BAD_REQUEST`, decided before the Dreamer gate.
//! - `create_without_a_dreamer_answers_503` (0006a: "With no running Dreamer
//!   ... 503"): the facade answers 503 `MODEL_UNAVAILABLE`.
//! - `a_declaration_names_only_sources_its_caller_reads` (0006a: "A reader
//!   sees a summary ... only while it may read every source"): a NOTE the
//!   caller gets nothing back for is refused at declaration with the door's
//!   own NOT_FOUND.
//! - `an_owners_anchored_edit_moves_the_head` (0002: "A person edits a summary
//!   with ops, the same way"): the owner's anchored edit lands in the text.
//! - `a_regeneration_waits_for_a_verdict_its_opener_cannot_give` (0002: "A full
//!   regeneration is a declared rewrite, accepted by moving the head"): the
//!   rewrite waits as a pending proposal; the credential that opened it cannot
//!   merge it, and the text stays.
//! - `an_unknown_field_is_refused_on_every_row`: each of the 11 rows with an
//!   otherwise well-formed body plus an unknown field answers 400.
//!
//! Seeded faults (each leaves the crates compiling):
//! - red1, P1: `crates/oneiron/src/scope_summary/doors.rs:266`, current text
//!   `        if !cfg!(test) && !unchanged {`, replacement
//!   `        if false && !cfg!(test) && !unchanged {`: any byline mints.
//! - red1, P3: `crates/oneiron-server/src/ai_host/handle.rs:122`, current text
//!   `        if self.summaries {`, replacement `        if true || self.summaries {`:
//!   the writer always reports ready.
//! - red1, P5: `crates/oneiron/src/entity_doc/forks.rs:551`, current text
//!   `        if req.rewrite.is_none() && covered(vault, txn, authorization, &req.entity, req.actor)? {`,
//!   replacement with `false && ` after `if `: no anchored edit merges at open.
//! - red1, table: `crates/oneiron-store/src/scope_summary/public_types.rs:42`
//!   `#[serde(deny_unknown_fields)]` on `SummaryReadRequest`, deleted.
//!   Green on red1: P2, P4, P6.
//! - red2, P2: `crates/oneiron/src/scope_summary/public_types.rs:23`
//!   `#[serde(deny_unknown_fields)]` on `SummaryCreateRequest`, deleted: `text`
//!   is ignored and create reaches the Dreamer gate (503). The table's create
//!   row goes red with it (collateral; the table's own proof is red1).
//! - red2, P4: `crates/oneiron/src/scope_summary/public.rs:262`, current text
//!   `        if self.get_entity(reference)?.value.is_none() {`, replacement
//!   `        if false && self.get_entity(reference)?.value.is_none() {`.
//! - red2, P6: `crates/oneiron/src/entity_doc/proposal_lineage.rs:62`, current
//!   text `    if owner.answers_from_slip_lineage_in_txn(vault, txn, &frozen(bundle)?)? {`,
//!   replacement with `false && ` after `if `: the opener settles its own.
//!   Green on red2: P1, P3, P5.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! vault_summaries_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::registry::ENTITY_TYPE_SUMMARY;
use oneiron::scope_summary::{ScopeSummaryBody, SummaryCreateRequest, encode_scope_summary_body};
use oneiron::test_doors::scope_summary::mint_scope_summary;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "vault-summaries-doors-secret";

/// The minted summary's text.
const MINTED: &str = "The plan, and its first step.";

/// A full 32-hex id no row holds.
const ABSENT: &str = "ffffffffffffffffffffffffffffffff";

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One rooted vault, the server's router and the self-hosted root
/// credential (as `vault_files_doors.rs`).
struct Door {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
}

/// A conversation of two trunk records the owner wrote, and a summary of it
/// minted as the Dreamer writes one.
struct Minted {
    trunk: [EntityId; 2],
    summary: String,
}

impl Door {
    fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        // A machine install: the keystore, then this install's machine id.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault.prepare_install_signing().unwrap();
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
        let issuer = vault.load_host_slip_issuer().unwrap();
        let root = vault.ensure_host_root_slip(&issuer).unwrap();
        Self {
            _dir: dir,
            app: build_app(server),
            vault,
            issuer,
            root,
            owner,
        }
    }

    /// The owner's two-record trunk and the summary minted over it.
    fn mint(&self) -> Minted {
        let host = self.vault.memory(self.owner, EdgeActorClass::Human);
        let receipt = host
            .conversations_create(&ConversationCreateInput {
                id: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body: json!({}),
                text: None,
            })
            .unwrap();
        let conversation = EntityId::from_hex(&receipt.id).unwrap();
        let first = host
            .conversations_records_append(&trunk_record(conversation, None, "the plan"))
            .unwrap();
        let second = host
            .conversations_records_append(&trunk_record(
                conversation,
                Some(&first.id),
                "the first step",
            ))
            .unwrap();
        let summary = mint_scope_summary(
            &self.vault,
            &ScopeSelector {
                conversation,
                session: None,
                path: ScopePath::Canonical,
                include_forks: false,
            },
            MINTED,
        )
        .unwrap();
        Minted {
            trunk: [
                EntityId::from_hex(&first.id).unwrap(),
                EntityId::from_hex(&second.id).unwrap(),
            ],
            summary: summary.to_hex(),
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

    /// `verb` as the owner, through the root credential with a fresh proof.
    async fn post(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = self
            .issuer
            .binding_proof(&self.root, challenge.as_bytes())
            .unwrap();
        let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", self.root.to_token().unwrap()),
            )
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(request).await
    }

    /// `vault.summaries.read` of `summary` (with `spans`) as the owner: 200
    /// and a served view, or the test fails with the answer.
    async fn read(&self, summary: &str, spans: Value) -> Value {
        let (status, read) = self
            .post(
                "vault.summaries.read",
                &json!({"summary_ref": summary, "spans": spans}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{read}");
        assert!(
            read["value"].is_object(),
            "the owner reads its summary: {read}"
        );
        read["value"].clone()
    }

    /// The summary's served text.
    async fn text(&self, summary: &str) -> String {
        self.read(summary, json!([])).await["text"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

/// One trunk record that advances HEAD from `parent`
/// (`tests/disclosure_summary_word_sources.rs`).
fn trunk_record(conversation: EntityId, parent: Option<&str>, text: &str) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: parent.map(str::to_owned),
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": text, "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    }
}

/// A refusal's (status, code): what a caller tells apart.
fn refusal(status: StatusCode, body: &Value) -> (StatusCode, Value) {
    (status, body["error"]["code"].clone())
}

/// 0006a "it never writes the summary text": a SUMMARY body under any byline
/// but the Dreamer's is refused by the storage guard
/// (`scope_summary/doors.rs:244-273`, run by every put's carrier checks).
#[test]
fn no_one_but_the_dreamer_writes_a_summary_body() {
    run_on_engine_stack("summaries-dreamer-writes-the-body", || async {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        let now = vault.now_recorded_at();
        let body = encode_scope_summary_body(&ScopeSummaryBody {
            v: 1,
            scope: Some(ScopeSelector {
                conversation: EntityId::now(),
                session: None,
                path: ScopePath::Canonical,
                include_forks: false,
            }),
            text: "words the owner wrote".to_owned(),
            actor: owner.to_hex(),
            covers: Vec::new(),
            minted_at: now,
            messages: Vec::new(),
            memo: None,
            notes: Vec::new(),
        })
        .unwrap();
        let err = vault
            .put_entity(
                &EntityId::now(),
                ENTITY_TYPE_SUMMARY,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect_err("a SUMMARY body under the owner's byline is refused");
        assert!(
            err.to_string()
                .contains("only the Dreamer may mint a scope-summary body"),
            "{err}"
        );
    });
}

/// 0006a "a `text` field is refused as unknown": create with `text` answers
/// 400 before the Dreamer gate is asked.
#[test]
fn a_text_field_on_create_is_refused_as_unknown() {
    run_on_engine_stack("summaries-text-refused", || async {
        let door = Door::open();
        let (status, body) = door
            .post(
                "vault.summaries.create",
                &json!({
                    "scope": {"conversation_ref": door.owner.to_hex(), "path": "canonical"},
                    "text": "words the caller wrote",
                }),
            )
            .await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::BAD_REQUEST, json!("BAD_REQUEST")),
            "{body}"
        );
    });
}

/// 0006a "With no running Dreamer ... 503": the facade's create answers 503
/// `MODEL_UNAVAILABLE` naming the Dreamer (the REST routes' code is
/// `SUMMARY_WRITER_UNAVAILABLE`; the facade maps `MODEL_UNAVAILABLE`).
#[test]
fn create_without_a_dreamer_answers_503() {
    run_on_engine_stack("summaries-no-dreamer-503", || async {
        let door = Door::open();
        let (status, body) = door
            .post(
                "vault.summaries.create",
                &json!({"scope": {"conversation_ref": door.owner.to_hex(), "path": "canonical"}}),
            )
            .await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::SERVICE_UNAVAILABLE, json!("MODEL_UNAVAILABLE")),
            "{body}"
        );
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("Dreamer")),
            "{body}"
        );
    });
}

/// 0006a "A reader sees a summary ... only while it may read every source":
/// a declaration over a NOTE its caller gets nothing back for is refused by
/// the door's own source check (`scope_summary/public.rs:261-266`). The
/// served create asks the Dreamer first, so the engine fn the row calls is
/// driven directly.
#[test]
fn a_declaration_names_only_sources_its_caller_reads() {
    run_on_engine_stack("summaries-declared-sources-read", || async {
        let door = Door::open();
        let err = door
            .vault
            .memory(door.owner, EdgeActorClass::Human)
            .create_summary(&SummaryCreateRequest {
                scope: None,
                note_refs: vec![ABSENT.to_owned()],
                purpose: None,
                land_on: None,
                as_record: false,
            })
            .expect_err("a NOTE the caller cannot read is no source");
        assert_eq!(
            (err.code.as_str(), err.message.as_str()),
            (
                "NOT_FOUND",
                "SUMMARY or proposal member is absent or not readable"
            ),
            "{err:?}"
        );
    });
}

/// 0002 "A person edits a summary with ops": the owner's anchored edit merges
/// at once, and the served text carries it.
#[test]
fn an_owners_anchored_edit_moves_the_head() {
    run_on_engine_stack("summaries-owner-edit-lands", || async {
        let door = Door::open();
        let minted = door.mint();
        let text = door.text(&minted.summary).await;
        assert!(text.contains("The plan"), "{text}");
        let start = text.find("plan").unwrap();
        let read = door
            .read(
                &minted.summary,
                json!([{"start": start, "end": start + "plan".len()}]),
            )
            .await;
        let (status, edited) = door
            .post(
                "vault.summaries.edit",
                &json!({
                    "summary_ref": minted.summary,
                    "base": read["frontier"],
                    "edits": [{
                        "kind": "replace_quoted_span",
                        "span": read["anchors"][0],
                        "text": "goal",
                    }],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{edited}");
        let text = door.text(&minted.summary).await;
        assert!(
            text.contains("The goal") && !text.contains("The plan"),
            "the owner's edit is in the served text: {text}"
        );
    });
}

/// 0002 "A full regeneration is a declared rewrite, accepted by moving the
/// head": the rewrite waits as one pending proposal, the credential that
/// opened it cannot merge it (`entity_doc/proposal_lineage.rs:53-68`), and the
/// served text stays.
#[test]
fn a_regeneration_waits_for_a_verdict_its_opener_cannot_give() {
    run_on_engine_stack("summaries-regeneration-waits", || async {
        let door = Door::open();
        let minted = door.mint();
        let read = door.read(&minted.summary, json!([])).await;
        let rewrite = "A rewritten account of the plan.";
        let (status, regenerated) = door
            .post(
                "vault.summaries.regenerate",
                &json!({
                    "summary_ref": minted.summary,
                    "base": read["frontier"],
                    "keep": read["metadata"]["keep"],
                    "text": rewrite,
                    "read_refs": [minted.trunk[0].to_hex(), minted.trunk[1].to_hex()],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{regenerated}");
        let proposal = &regenerated["proposal"];
        assert_eq!(proposal["bundle"]["settled"], json!(false), "{regenerated}");
        assert!(
            proposal["forks"][0]["text"]
                .as_str()
                .is_some_and(|text| text.contains(rewrite)),
            "the pending fork holds the rewrite: {regenerated}"
        );
        assert_eq!(
            door.text(&minted.summary).await,
            read["text"].as_str().unwrap()
        );

        let proposal_ref = proposal["bundle"]["proposal"].clone();
        let (status, merged) = door
            .post(
                "vault.summaries.proposals.merge",
                &json!({"proposal_ref": proposal_ref}),
            )
            .await;
        assert!(status.is_client_error(), "{status} {merged}");
        assert!(
            merged["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("cannot settle it")),
            "{merged}"
        );
        assert_eq!(
            door.text(&minted.summary).await,
            read["text"].as_str().unwrap()
        );
        let (status, waiting) = door
            .post(
                "vault.summaries.proposals.read",
                &json!({"proposal_ref": proposal_ref}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{waiting}");
        assert_eq!(waiting["bundle"]["settled"], json!(false), "{waiting}");
    });
}

/// Every row, its body otherwise well formed, refuses an unknown field with
/// 400 at the decode. Read goes first: without its decode check its body
/// would read an absent summary as null (200).
#[test]
fn an_unknown_field_is_refused_on_every_row() {
    run_on_engine_stack("summaries-unknown-field", || async {
        let door = Door::open();
        let proposal = json!({"proposal_ref": ABSENT, "zzz": 1});
        for (verb, body) in [
            (
                "vault.summaries.read",
                json!({"summary_ref": ABSENT, "zzz": 1}),
            ),
            (
                "vault.summaries.status",
                json!({"attempt": ABSENT, "zzz": 1}),
            ),
            (
                "vault.summaries.create",
                json!({"scope": {"conversation_ref": ABSENT, "path": "canonical"}, "zzz": 1}),
            ),
            (
                "vault.summaries.keep",
                json!({"summary_ref": ABSENT, "frontier": [], "keep": "", "zzz": 1}),
            ),
            (
                "vault.summaries.edit",
                json!({"summary_ref": ABSENT, "base": [], "edits": [], "zzz": 1}),
            ),
            (
                "vault.summaries.patch",
                json!({"summary_ref": ABSENT, "base": [], "keep": "", "edits": [],
                       "read_refs": [], "zzz": 1}),
            ),
            (
                "vault.summaries.regenerate",
                json!({"summary_ref": ABSENT, "base": [], "keep": "", "text": "x",
                       "read_refs": [], "zzz": 1}),
            ),
            ("vault.summaries.proposals.read", proposal.clone()),
            ("vault.summaries.proposals.merge", proposal.clone()),
            ("vault.summaries.proposals.reject", proposal.clone()),
            ("vault.summaries.proposals.switch", proposal),
        ] {
            let (status, answer) = door.post(verb, &body).await;
            assert_eq!(
                refusal(status, &answer),
                (StatusCode::BAD_REQUEST, json!("BAD_REQUEST")),
                "{verb}: {answer}"
            );
        }
    });
}
