//! The `vault.files.sources.*` rows at the public door: each test proves one canon
//! promise of a folder attached to the Files world through the server's real router.
//!
//! Attach, convert and rescan refuse in-process (`host_walk_only`: an embedded
//! handle has no host walk), so these tests drive `build_app` at
//! `POST /v1/core/facade/<verb>`. The vault holds a `MemoryKeystore` and this
//! install's machine id before the server starts (an attach needs a machine:
//! `Vault::open_files_world`), so the server bootstraps its own host issuer from
//! that keystore and roots the vault with it (`SyncServer::new`); the test signs
//! with that issuer, loaded back (`Vault::load_host_slip_issuer`), as
//! `note_session_bind_reply.rs` does. The self-hosted root credential acts as the
//! vault's embedded owner. Every body runs on the engine's stack, because the
//! facade dispatch overflows a test thread's. Each test makes its own tempdir
//! folder with `std::fs`; a changed file always changes SIZE too (a rescan skips
//! a file whose size and mtime both match the last scan's record, and mtimes
//! have 1-second granularity).
//!
//! Canon: `oneiron/agents/oneiron-arch-0027-import-pipeline-v1.md`.
//! - `an_attached_folder_stays_attached`: "A local folder source keeps the folder
//!   attached" (:76). Attach lands, list names the source, a no-change rescan
//!   lands nothing and drops nothing, a gone folder errors without retracting,
//!   and a notes-attached folder converts and lands.
//! - `a_deleted_file_retracts_what_it_brought_in`: "A file removed from the folder
//!   retracts what it brought in" (:78). Deleting one of two files retracts one
//!   row and leaves the other landed.
//! - `retraction_is_never_erasure`: "Nothing is hard-erased; erasure stays a
//!   separate, explicit act" (:78). The retracted row keeps its note, an archived
//!   note reads as deleted, and restoring the file restores the same note's text.
//! - `import_runs_one_way_only`: "It imports one way, from the folder into the
//!   vault" (:80). The folder's names, bytes and mtimes never change under the
//!   vault; an owner-edited note (a whole-text edit at its read version, which
//!   lands in place) plus a changed file forks for review instead of overwriting
//!   the vault.
//! - `owner_only_rows_refuse_a_non_owner`: all seven rows answer a non-owner
//!   403 FORBIDDEN, including exclude (no precheck, but the door still runs the
//!   owner proof).
//! - `a_symlink_out_of_the_folder_is_never_followed`: a link out of the folder is
//!   neither a folder nor a file to the walk, so it lands nothing and reads nothing.
//! - `a_malformed_or_unsigned_files_act_is_refused`: each of the seven rows.
//!
//! Seeded faults (each makes its test fail and leaves the crates compiling; each
//! touches only its own test's path, so they share two red heads: red1 holds P1,
//! P3 and owner-only, red2 holds P2, P4, escape and refusals, and every test whose
//! fault is not on a head stays green there):
//! - P1: `crates/oneiron/src/note/files/source.rs:268`, current text
//!   `            .filter(|source| source.files.is_some())`, replacement
//!   `            .filter(|source| source.files.is_none())`: list and rescan-all
//!   see zero Files sources. Green under it: every other test, which never calls
//!   list or rescan-all.
//! - P2: `crates/oneiron/src/note/folder_source/reconcile.rs:849`, current text
//!   `        report.retracted += usize::from(retracted);`, replacement
//!   `        report.retracted += usize::from(false && retracted);`: the count
//!   stays 0 while the state still flips. Green under it: P1/P3/P4 (no deletes,
//!   no count assertions on retracted), escape, refusals.
//! - P3: `crates/oneiron/src/deletion/delete/markers.rs:79`, current text
//!   `        Ok(true)`, replacement `        Ok(false)`: the retract path drops
//!   the ledger's note name. Green under it: P1/P2/P4 (P2 asserts state plus
//!   counts only, never the retracted row's note), escape, refusals.
//! - P4: `crates/oneiron/src/note/folder_source/reconcile.rs:567`, current text
//!   `            current_hash == row.landed_hash || current_hash == row.file_hash`,
//!   replacement
//!   `            current_hash == row.landed_hash || current_hash == row.file_hash || true`:
//!   every changed file reads as untouched and supersedes instead of forking.
//!   Green under it: P1/P2/P3 (no owner edits), escape, refusals.
//! - owner-only: `crates/oneiron-server/src/api/facade/owner_binding.rs:123`,
//!   current text `            MEMORY_CODE_FORBIDDEN,`, replacement
//!   `            oneiron::memory::MEMORY_CODE_NOT_FOUND,`: non-owner calls answer
//!   404 instead of 403. Green under it: everything the owner does.
//! - escape: `crates/oneiron-server/src/files_intake/confined.rs:424`, current text
//!   `                entries.push((name.to_owned(), entry.file_type()));`,
//!   replacement
//!   `                entries.push((name.to_owned(), FileType::RegularFile));`:
//!   the link is held by name instead of skipped. Green under it: P1-P4 and
//!   refusals, whose fixtures are flat with no links.
//! - refusals: `crates/oneiron-verb-wire/src/verbs/files.rs:212`, current text
//!   `#[serde(deny_unknown_fields)]` on `FilesSourceListRequest`, deleted: list
//!   with an unknown field decodes. Green under it: every other row's
//!   unknown-field assertion and all other tests.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test vault_files_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "vault-files-doors-secret";

fn seeded_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
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

/// `folder` as a source names it: canonical, the form `canonical_folder`
/// answers (`crates/oneiron-server/src/files_intake/source.rs:621-629`).
fn canonical(folder: &Path) -> String {
    std::fs::canonicalize(folder)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

/// The folder's entry names, every file's bytes and every mtime, in name order:
/// what P4 compares to prove the vault wrote nothing back.
fn snapshot(folder: &Path) -> Vec<(String, Vec<u8>, SystemTime)> {
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let bytes = std::fs::read(folder.join(&name)).unwrap();
            let mtime = std::fs::metadata(folder.join(&name))
                .unwrap()
                .modified()
                .unwrap();
            (name, bytes, mtime)
        })
        .collect()
}

/// A slip a test minted and the key its holder proves it with.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// One rooted vault with a second person, the server's router and the
/// self-hosted root credential. The vault is a machine (a keystore plus
/// `prepare_install_signing`, as `agent_definition_served_batch.rs`), or no
/// attach lands.
struct Door {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
    member: EntityId,
}

impl Door {
    fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
        let member = seeded_id(0xC1);
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"another person",
            )
            .unwrap();
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        // A machine install: the keystore, then this install's machine id.
        // The server bootstraps its host issuer from this keystore and roots
        // the vault with it.
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
            member,
        }
    }

    /// The embedded owner authenticated for a direct engine seed (the convert
    /// flow's notes-attached folder): `authenticate_owner` is
    /// `crates/oneiron/src/consent/doors/owner.rs:29`, the
    /// authenticate-then-`attach_folder_source` seed is
    /// `crates/oneiron/tests/note_edit_lands_by_grant.rs:135-139`.
    fn owner_proof(&self) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .unwrap()
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

    /// `vault.files.sources.files` of `source` as the owner: 200, or the test
    /// fails with the refusal.
    async fn files_of(&self, source: &str) -> Value {
        let (status, files) = self
            .post("vault.files.sources.files", &json!({"source": source}))
            .await;
        assert_eq!(status, StatusCode::OK, "{files}");
        files
    }

    /// `vault.notes.read` of `note` as the owner: 200, or the test fails with
    /// the refusal. The answer is `{value, narrowing}`; `value` is the
    /// `NoteReadView` or null.
    async fn read_note(&self, note: &str) -> Value {
        let (status, read) = self
            .post("vault.notes.read", &json!({"note_ref": note}))
            .await;
        assert_eq!(status, StatusCode::OK, "{read}");
        read
    }
}

/// The files view's row for `path`, or the test fails naming the ledger.
fn row<'a>(files: &'a Value, path: &str) -> &'a Value {
    files["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["handle"]["path"] == path)
        .unwrap_or_else(|| panic!("no row for {path}: {files}"))
}

/// A refusal's (status, code): what a caller tells apart.
fn refusal(status: StatusCode, body: &Value) -> (StatusCode, Value) {
    (status, body["error"]["code"].clone())
}

/// :76 "A local folder source keeps the folder attached": attach lands, list
/// names the source, a no-change rescan lands nothing and drops nothing, a gone
/// folder errors without retracting, and a notes-attached folder converts.
#[test]
fn an_attached_folder_stays_attached() {
    run_on_engine_stack("files-stays-attached", || async {
        let door = Door::open();
        let scratch = tempfile::tempdir().unwrap();
        let folder = scratch.path().join("loop");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("a.md"), "# A\n\nAlpha file.\n").unwrap();
        std::fs::write(folder.join("b.md"), "# B\n\nBeta file.\n").unwrap();
        let folder_s = canonical(&folder);

        // Attach answers the canonical folder and lands both files. `include`
        // is absent (empty lists are skipped: verbs/files.rs:66-67); `exclude`
        // keeps the defaults (note/files/source.rs:29-66); `kind` defaults to
        // observation (FILES_DEFAULT_KIND at :22).
        let (status, attached) = door
            .post("vault.files.sources.attach", &json!({"path": folder_s}))
            .await;
        assert_eq!(status, StatusCode::OK, "{attached}");
        assert_eq!(attached["source"]["folder"], json!(folder_s), "{attached}");
        assert_eq!(
            attached["rescan"]["counts"]["landed"],
            json!(2),
            "{attached}"
        );
        assert!(attached["source"]["include"].is_null(), "{attached}");
        assert!(
            !attached["source"]["exclude"].as_array().unwrap().is_empty(),
            "{attached}"
        );
        assert_eq!(
            attached["source"]["kind"],
            json!("observation"),
            "{attached}"
        );
        let source = attached["source"]["source"].as_str().unwrap().to_owned();
        let world = attached["world"]["world"].as_str().unwrap().to_owned();

        // One row per file, landed as text. `state` is snake_case
        // (FilesFileState, verbs/files.rs:242-251); text readiness is the
        // string "text" (FileReadiness, note/files/metadata.rs:31-37).
        let files = door.files_of(&source).await;
        assert_eq!(files["files"].as_array().unwrap().len(), 2, "{files}");
        for path in ["a.md", "b.md"] {
            let file = row(&files, path);
            assert_eq!(file["state"], json!("landed"), "{files}");
            assert_eq!(file["readiness"], json!("text"), "{files}");
            assert!(file["note"].is_string(), "{files}");
        }

        // List names the world and the one source.
        let (status, listed) = door.post("vault.files.sources.list", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["world"]["world"], json!(world), "{listed}");
        assert_eq!(listed["sources"].as_array().unwrap().len(), 1, "{listed}");
        assert_eq!(listed["sources"][0]["source"], json!(source), "{listed}");

        // A rescan with no changes lands nothing and drops nothing.
        let (status, rescanned) = door
            .post("vault.files.sources.rescan", &json!({"source": source}))
            .await;
        assert_eq!(status, StatusCode::OK, "{rescanned}");
        assert_eq!(
            rescanned["rescans"].as_array().unwrap().len(),
            1,
            "{rescanned}"
        );
        assert_eq!(
            rescanned["rescans"][0]["counts"]["unchanged"],
            json!(2),
            "{rescanned}"
        );
        assert_eq!(
            rescanned["rescans"][0]["counts"]["landed"],
            json!(0),
            "{rescanned}"
        );
        let (status, listed) = door.post("vault.files.sources.list", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["sources"].as_array().unwrap().len(), 1, "{listed}");
        assert_eq!(listed["sources"][0]["source"], json!(source), "{listed}");

        // Rescan-all reaches the one source too.
        let (status, all) = door.post("vault.files.sources.rescan", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{all}");
        assert_eq!(all["rescans"].as_array().unwrap().len(), 1, "{all}");

        // A folder that is gone now errors (counts absent, error set: counts
        // and error are both skip-if-absent, verbs/files.rs:127-133) and the
        // source is still listed: a gone folder retracts nothing.
        std::fs::remove_dir_all(&folder).unwrap();
        let (status, gone) = door
            .post("vault.files.sources.rescan", &json!({"source": source}))
            .await;
        assert_eq!(status, StatusCode::OK, "{gone}");
        assert!(gone["rescans"][0]["counts"].is_null(), "{gone}");
        assert!(gone["rescans"][0]["error"].is_string(), "{gone}");
        let (status, listed) = door.post("vault.files.sources.list", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["sources"].as_array().unwrap().len(), 1, "{listed}");
        assert_eq!(listed["sources"][0]["source"], json!(source), "{listed}");

        // A notes-attached folder (seeded with a direct engine call, as the
        // house test seeds PERSON rows) converts through the door and lands.
        let notes = scratch.path().join("notes");
        std::fs::create_dir(&notes).unwrap();
        std::fs::write(notes.join("c.md"), "# C\n\nCharlie file.\n").unwrap();
        let notes_s = canonical(&notes);
        door.vault
            .attach_folder_source(&door.owner_proof(), &notes_s, Vec::new(), "observation")
            .unwrap();
        let (status, converted) = door
            .post("vault.files.sources.convert", &json!({"path": notes_s}))
            .await;
        assert_eq!(status, StatusCode::OK, "{converted}");
        assert_eq!(
            converted["rescan"]["counts"]["landed"],
            json!(1),
            "{converted}"
        );
        let (status, listed) = door.post("vault.files.sources.list", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["sources"].as_array().unwrap().len(), 2, "{listed}");
    });
}

/// :78 "A file removed from the folder retracts what it brought in": deleting
/// one of two files retracts one row and leaves the other landed. State plus
/// counts only: the retracted row's note name belongs to P3 (see NOTES.md).
#[test]
fn a_deleted_file_retracts_what_it_brought_in() {
    run_on_engine_stack("files-delete-retracts", || async {
        let door = Door::open();
        let scratch = tempfile::tempdir().unwrap();
        let folder = scratch.path().join("pair");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("stays.md"), "# Stays\n\nThe file that stays.\n").unwrap();
        std::fs::write(folder.join("goes.md"), "# Goes\n\nThe file that goes.\n").unwrap();

        let (status, attached) = door
            .post(
                "vault.files.sources.attach",
                &json!({"path": canonical(&folder)}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{attached}");
        let source = attached["source"]["source"].as_str().unwrap().to_owned();

        std::fs::remove_file(folder.join("goes.md")).unwrap();
        let (status, rescanned) = door
            .post("vault.files.sources.rescan", &json!({"source": source}))
            .await;
        assert_eq!(status, StatusCode::OK, "{rescanned}");
        assert_eq!(
            rescanned["rescans"][0]["counts"]["retracted"],
            json!(1),
            "{rescanned}"
        );
        assert_eq!(
            rescanned["rescans"][0]["counts"]["unchanged"],
            json!(1),
            "{rescanned}"
        );

        let files = door.files_of(&source).await;
        assert_eq!(
            row(&files, "goes.md")["state"],
            json!("retracted"),
            "{files}"
        );
        let survivor = row(&files, "stays.md");
        assert_eq!(survivor["state"], json!("landed"), "{files}");
        assert!(survivor["note"].is_string(), "{files}");
    });
}

/// :78 "Nothing is hard-erased; erasure stays a separate, explicit act": the
/// retracted row keeps its note, an archived note reads as deleted, and
/// restoring the file restores the same note's text.
#[test]
fn retraction_is_never_erasure() {
    run_on_engine_stack("files-retraction-not-erasure", || async {
        let door = Door::open();
        let scratch = tempfile::tempdir().unwrap();
        let folder = scratch.path().join("solo");
        std::fs::create_dir(&folder).unwrap();
        let text = "# Lighthouse\n\nThe keeper logs the tide.\n";
        std::fs::write(folder.join("log.md"), text).unwrap();

        let (status, attached) = door
            .post(
                "vault.files.sources.attach",
                &json!({"path": canonical(&folder)}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{attached}");
        let source = attached["source"]["source"].as_str().unwrap().to_owned();
        let note = row(&door.files_of(&source).await, "log.md")["note"]
            .as_str()
            .unwrap()
            .to_owned();

        // After landing, the note reads the file's text.
        let read = door.read_note(&note).await;
        assert!(
            read["value"]["markdown"]
                .as_str()
                .unwrap()
                .contains("The keeper logs the tide."),
            "{read}"
        );

        // Deleted and rescanned, the row is retracted under the same note id,
        // and the archived note reads as deleted (value null).
        std::fs::remove_file(folder.join("log.md")).unwrap();
        let (status, rescanned) = door
            .post("vault.files.sources.rescan", &json!({"source": source}))
            .await;
        assert_eq!(status, StatusCode::OK, "{rescanned}");
        let files = door.files_of(&source).await;
        let retracted = row(&files, "log.md");
        assert_eq!(retracted["state"], json!("retracted"), "{files}");
        assert_eq!(retracted["note"], json!(note), "{files}");
        let read = door.read_note(&note).await;
        assert!(read["value"].is_null(), "{read}");

        // Restored with the same bytes, the file restores its note: landed
        // again under the same id, the original markdown back.
        std::fs::write(folder.join("log.md"), text).unwrap();
        let (status, rescanned) = door
            .post("vault.files.sources.rescan", &json!({"source": source}))
            .await;
        assert_eq!(status, StatusCode::OK, "{rescanned}");
        assert_eq!(
            rescanned["rescans"][0]["counts"]["restored"],
            json!(1),
            "{rescanned}"
        );
        let files = door.files_of(&source).await;
        let landed = row(&files, "log.md");
        assert_eq!(landed["state"], json!("landed"), "{files}");
        assert_eq!(landed["note"], json!(note), "{files}");
        let read = door.read_note(&note).await;
        assert!(
            read["value"]["markdown"]
                .as_str()
                .unwrap()
                .contains("The keeper logs the tide."),
            "{read}"
        );
    });
}

/// :80 "It imports one way, from the folder into the vault": the folder's entry
/// set, bytes and mtimes are identical before and after every vault act, and an
/// owner-edited note plus a changed file forks for review instead of
/// overwriting the vault. The changed file changes SIZE (the mtime-size
/// shortcut would otherwise skip it).
#[test]
fn import_runs_one_way_only() {
    run_on_engine_stack("files-one-way", || async {
        let door = Door::open();
        let scratch = tempfile::tempdir().unwrap();
        let folder = scratch.path().join("oneway");
        std::fs::create_dir(&folder).unwrap();
        let before = "The lighthouse keeper logs the tide at dawn.\n";
        // A different size, so the rescan reads it again.
        let after = "The lighthouse keeper logs the tide at dawn.\nA second paragraph the folder added later.\n";
        assert_ne!(before.len(), after.len());
        let edited = "The keeper rewrote this note by hand.\n";
        std::fs::write(folder.join("tide.md"), before).unwrap();
        let folder_s = canonical(&folder);

        // Attach and rescan write nothing back.
        let snap0 = snapshot(&folder);
        let (status, attached) = door
            .post("vault.files.sources.attach", &json!({"path": folder_s}))
            .await;
        assert_eq!(status, StatusCode::OK, "{attached}");
        let source = attached["source"]["source"].as_str().unwrap().to_owned();
        let note = row(&door.files_of(&source).await, "tide.md")["note"]
            .as_str()
            .unwrap()
            .to_owned();
        let (status, _) = door
            .post("vault.files.sources.rescan", &json!({"source": source}))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            snapshot(&folder),
            snap0,
            "attach and rescan wrote nothing back"
        );

        // The owner edits the note in place: a whole-text edit at the version
        // it read lands as `edited` (a `rewrite` would only fork:
        // note/verbs.rs isolated_rewrite), and the note reads the owner's text.
        let read = door.read_note(&note).await;
        let version = read["value"]["version"].clone();
        assert!(version.is_object(), "{read}");
        let (status, outcome) = door
            .post(
                "vault.notes.edit",
                &json!({"note_ref": note, "edit": {
                    "kind": "whole_text", "text": edited, "timeout_ms": 1000, "base": version,
                }}),
            )
            .await;
        assert_eq!(
            (status, &outcome["outcome"]),
            (StatusCode::OK, &json!("edited")),
            "{outcome}"
        );
        let read = door.read_note(&note).await;
        let markdown = read["value"]["markdown"].as_str().unwrap().to_owned();
        assert!(markdown.contains("rewrote this note by hand"), "{read}");
        assert!(!markdown.contains("logs the tide"), "{read}");

        // The file changes on disk (the test's own write); the rescan forks
        // for review and the vault keeps the owner's text.
        std::fs::write(folder.join("tide.md"), after).unwrap();
        let snap1 = snapshot(&folder);
        let (status, rescanned) = door
            .post("vault.files.sources.rescan", &json!({"source": source}))
            .await;
        assert_eq!(status, StatusCode::OK, "{rescanned}");
        assert_eq!(
            rescanned["rescans"][0]["counts"]["proposed"],
            json!(1),
            "{rescanned}"
        );
        let files = door.files_of(&source).await;
        let proposed = row(&files, "tide.md");
        assert_eq!(proposed["state"], json!("proposed"), "{files}");
        assert!(proposed["fork"].is_string(), "{files}");
        let read = door.read_note(&note).await;
        let markdown = read["value"]["markdown"].as_str().unwrap().to_owned();
        assert!(
            markdown.contains("rewrote this note by hand"),
            "the import never overwrites the vault: {read}"
        );
        assert!(
            !markdown.contains("A second paragraph"),
            "the folder's new text waits in the fork: {read}"
        );

        // Detach lands and wrote nothing back either.
        let (status, detached) = door
            .post("vault.files.sources.detach", &json!({"source": source}))
            .await;
        assert_eq!(
            (status, &detached["detached"]),
            (StatusCode::OK, &json!(true)),
            "{detached}"
        );
        assert_eq!(detached["folder"], json!(folder_s), "{detached}");
        assert_eq!(
            snapshot(&folder),
            snap1,
            "rescan and detach wrote nothing back"
        );
    });
}

/// All seven rows answer a non-owner 403 FORBIDDEN: attach, convert, detach,
/// list, files, exclude and rescan. Exclude names no `host_door_proof` and its
/// precheck is off, but its door still runs the owner proof.
#[test]
fn owner_only_rows_refuse_a_non_owner() {
    run_on_engine_stack("files-owner-only", || async {
        let door = Door::open();
        let scratch = tempfile::tempdir().unwrap();
        let folder = scratch.path().join("denied");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("a.md"), "# A\n\nAlpha file.\n").unwrap();
        let folder_s = canonical(&folder);
        let unknown = seeded_id(0xD1).to_hex();

        let member = door.mint(door.member, 0x61);
        let forbidden = (StatusCode::FORBIDDEN, json!("FORBIDDEN"));
        let rows: [(&str, Value); 7] = [
            ("vault.files.sources.attach", json!({"path": folder_s})),
            ("vault.files.sources.convert", json!({"path": folder_s})),
            ("vault.files.sources.detach", json!({"source": unknown})),
            ("vault.files.sources.list", json!({})),
            ("vault.files.sources.files", json!({"source": unknown})),
            (
                "vault.files.sources.exclude",
                json!({"source": unknown, "include": ["*.md"]}),
            ),
            ("vault.files.sources.rescan", json!({})),
        ];
        for (verb, body) in &rows {
            let (status, refused) = door.post_as(&member, verb, body).await;
            assert_eq!(refusal(status, &refused), forbidden, "{verb}: {refused}");
        }

        // The refused calls changed nothing: the owner's list still answers.
        let (status, listed) = door.post("vault.files.sources.list", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["sources"], json!([]), "{listed}");
    });
}

/// A path outside the attached folder is reachable only through a link, and a
/// link is neither a folder nor a file to the walk (every open is relative
/// with NOFOLLOW): the link lands nothing and its target's bytes are never read.
#[test]
fn a_symlink_out_of_the_folder_is_never_followed() {
    run_on_engine_stack("files-host-walk-escape", || async {
        let door = Door::open();
        let scratch = tempfile::tempdir().unwrap();
        let folder = scratch.path().join("linked");
        std::fs::create_dir(&folder).unwrap();
        let inside = "The file inside the folder.\n";
        let outside = "The outside secret text that must never land.\n";
        std::fs::write(folder.join("real.md"), inside).unwrap();
        std::fs::write(scratch.path().join("outside.md"), outside).unwrap();
        std::os::unix::fs::symlink("../outside.md", folder.join("link.md")).unwrap();

        let (status, attached) = door
            .post(
                "vault.files.sources.attach",
                &json!({"path": canonical(&folder)}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{attached}");
        assert_eq!(
            attached["rescan"]["counts"]["landed"],
            json!(1),
            "{attached}"
        );
        let source = attached["source"]["source"].as_str().unwrap().to_owned();

        // Exactly the real file: no row for the link name.
        let files = door.files_of(&source).await;
        assert_eq!(files["files"].as_array().unwrap().len(), 1, "{files}");
        let real = row(&files, "real.md");
        assert_eq!(real["state"], json!("landed"), "{files}");
        let note = real["note"].as_str().unwrap().to_owned();

        // No note holds the outside text: the landed note holds the inside text.
        let read = door.read_note(&note).await;
        let markdown = read["value"]["markdown"].as_str().unwrap().to_owned();
        assert!(markdown.contains("The file inside the folder."), "{read}");
        assert!(
            !markdown.contains("outside secret"),
            "the outside bytes were never read: {read}"
        );
    });
}

/// Each of the seven rows refuses a body missing its fields and a body with a
/// field it does not know (every request struct carries
/// `deny_unknown_fields`), and refuses any body with no credential. List and
/// rescan-all take `{}`, so they skip the no-fields leg.
#[test]
fn a_malformed_or_unsigned_files_act_is_refused() {
    run_on_engine_stack("files-refusals", || async {
        let door = Door::open();
        let scratch = tempfile::tempdir().unwrap();
        let folder_a = scratch.path().join("a");
        let folder_b = scratch.path().join("b");
        let folder_c = scratch.path().join("c");
        for folder in [&folder_a, &folder_b, &folder_c] {
            std::fs::create_dir(folder).unwrap();
            std::fs::write(folder.join("a.md"), "# A\n\nAlpha file.\n").unwrap();
        }
        let dir_a = canonical(&folder_a);
        let dir_b = canonical(&folder_b);
        let dir_c = canonical(&folder_c);
        let missing = scratch.path().join("missing").to_str().unwrap().to_owned();
        let unknown = seeded_id(0xD1).to_hex();

        // On an empty vault, the two fieldless rows accept {}.
        let (status, listed) = door.post("vault.files.sources.list", &json!({})).await;
        assert_eq!(
            (status, &listed["sources"]),
            (StatusCode::OK, &json!([])),
            "{listed}"
        );
        assert!(listed["world"].is_null(), "{listed}");
        let (status, rescanned) = door.post("vault.files.sources.rescan", &json!({})).await;
        assert_eq!(
            (status, &rescanned["rescans"]),
            (StatusCode::OK, &json!([])),
            "{rescanned}"
        );

        let bad_request = (StatusCode::BAD_REQUEST, json!("BAD_REQUEST"));
        let attach = json!({"path": dir_a});
        let convert = json!({"path": dir_b});
        let detach = json!({"source": unknown});
        let files = json!({"source": unknown});
        let exclude = json!({"source": unknown, "include": ["*.md"], "exclude": []});
        // Rows with required fields refuse {}.
        for verb in [
            "vault.files.sources.attach",
            "vault.files.sources.convert",
            "vault.files.sources.detach",
            "vault.files.sources.files",
            "vault.files.sources.exclude",
        ] {
            let (status, refused) = door.post(verb, &json!({})).await;
            assert_eq!(
                refusal(status, &refused),
                bad_request,
                "{verb} with no fields: {refused}"
            );
        }
        // Every row refuses an unknown field.
        for (verb, body) in [
            ("vault.files.sources.attach", attach.clone()),
            ("vault.files.sources.convert", convert.clone()),
            ("vault.files.sources.detach", detach.clone()),
            ("vault.files.sources.list", json!({})),
            ("vault.files.sources.files", files.clone()),
            ("vault.files.sources.exclude", exclude.clone()),
            ("vault.files.sources.rescan", json!({})),
        ] {
            let mut extra = body.clone();
            extra["unexpected"] = json!(1);
            let (status, refused) = door.post(verb, &extra).await;
            assert_eq!(
                refusal(status, &refused),
                bad_request,
                "{verb} with an unknown field: {refused}"
            );
        }
        // Every row refuses a body with no credential.
        for (verb, body) in [
            ("vault.files.sources.attach", attach.clone()),
            ("vault.files.sources.convert", convert.clone()),
            ("vault.files.sources.detach", detach.clone()),
            ("vault.files.sources.list", json!({})),
            ("vault.files.sources.files", files.clone()),
            ("vault.files.sources.exclude", exclude.clone()),
            ("vault.files.sources.rescan", json!({})),
        ] {
            let (status, refused) = door.post_raw(verb, body.to_string(), false).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{verb} with no credential: {refused}"
            );
        }

        // A source that is not hex is a decode failure.
        for (verb, body) in [
            ("vault.files.sources.detach", json!({"source": "not-hex!"})),
            ("vault.files.sources.files", json!({"source": "not-hex!"})),
            ("vault.files.sources.exclude", json!({"source": "not-hex!"})),
            ("vault.files.sources.rescan", json!({"source": "not-hex!"})),
        ] {
            let (status, refused) = door.post(verb, &body).await;
            assert_eq!(
                refusal(status, &refused),
                bad_request,
                "{verb} with a bad-hex source: {refused}"
            );
        }

        // A well-formed but unknown source: detach says so with 200, files says
        // 404, exclude says 400, rescan-one says 200 with no rescans.
        let (status, detached) = door.post("vault.files.sources.detach", &detach).await;
        assert_eq!(status, StatusCode::OK, "{detached}");
        assert_eq!(detached["source"], json!(unknown), "{detached}");
        assert!(detached["folder"].is_null(), "{detached}");
        assert_eq!(detached["detached"], json!(false), "{detached}");
        let (status, refused) = door.post("vault.files.sources.files", &files).await;
        assert_eq!(
            refusal(status, &refused),
            (StatusCode::NOT_FOUND, json!("NOT_FOUND")),
            "{refused}"
        );
        let (status, refused) = door.post("vault.files.sources.exclude", &exclude).await;
        assert_eq!(
            refusal(status, &refused),
            bad_request,
            "exclude of an unknown source: {refused}"
        );
        let (status, rescanned) = door
            .post("vault.files.sources.rescan", &json!({"source": unknown}))
            .await;
        assert_eq!(
            (status, &rescanned["rescans"]),
            (StatusCode::OK, &json!([])),
            "{rescanned}"
        );

        // Attach refuses a missing path, a second attach of the same folder,
        // and an unknown kind. `invalid` maps to BAD_REQUEST through the
        // From-Error catch-all (oneiron-contracts/src/memory/error/engine.rs).
        let (status, refused) = door
            .post("vault.files.sources.attach", &json!({"path": missing}))
            .await;
        assert_eq!(
            refusal(status, &refused),
            bad_request,
            "attach of a missing path: {refused}"
        );
        let (status, attached) = door.post("vault.files.sources.attach", &attach).await;
        assert_eq!(status, StatusCode::OK, "{attached}");
        let source = attached["source"]["source"].as_str().unwrap().to_owned();
        let (status, refused) = door.post("vault.files.sources.attach", &attach).await;
        assert_eq!(
            refusal(status, &refused),
            bad_request,
            "attach twice: {refused}"
        );
        let (status, refused) = door
            .post(
                "vault.files.sources.attach",
                &json!({"path": dir_b, "kind": "no-such-kind"}),
            )
            .await;
        assert_eq!(
            refusal(status, &refused),
            bad_request,
            "attach with an unknown kind: {refused}"
        );

        // Exclude refuses a blank include pattern, then lands a real one.
        let (status, refused) = door
            .post(
                "vault.files.sources.exclude",
                &json!({"source": source, "include": [""]}),
            )
            .await;
        assert_eq!(
            refusal(status, &refused),
            bad_request,
            "exclude with a blank include: {refused}"
        );
        let (status, excluded) = door
            .post(
                "vault.files.sources.exclude",
                &json!({"source": source, "include": ["*.md"], "exclude": []}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{excluded}");
        assert_eq!(excluded["source"], json!(source), "{excluded}");
        assert_eq!(excluded["include"], json!(["*.md"]), "{excluded}");
        assert_eq!(excluded["exclude"], json!([]), "{excluded}");

        // Not JSON is 400, with the facade's message (as the house table).
        let (status, refused) = door
            .post_raw("vault.files.sources.attach", "{not json".to_owned(), true)
            .await;
        assert_eq!(refusal(status, &refused), bad_request, "{refused}");
        assert_eq!(
            refused["error"]["message"], "invalid JSON request body",
            "{refused}"
        );

        // The refusals wrote nothing: a fresh folder still attaches.
        let (status, attached) = door
            .post("vault.files.sources.attach", &json!({"path": dir_c}))
            .await;
        assert_eq!(status, StatusCode::OK, "{attached}");
        assert_eq!(
            attached["rescan"]["counts"]["landed"],
            json!(1),
            "{attached}"
        );
    });
}
