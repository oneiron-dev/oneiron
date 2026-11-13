#![cfg(oneiron_test_support)]
//! L4-06 PR 1 (research-1423 #gaps item 5: "import, export, stock clone and
//! check, change with stock Git, push back, re-export identical bytes"): the
//! code round trip of `examples/code-roundtrip/roundtrip.ts`, executed
//! through the served app with stock `git` for every clone, commit and push.
//! The owner admits a repo holding one skill folder by a stock push through
//! the served `/git` door, imports it, enrolls the checked queue on the host
//! checker backend, and exports it; a member holding a `git_push` Grant
//! commits one change on a stock clone of the export and pushes it back
//! through the same door; the queue checks it and lands it on green, and
//! the green export is byte-equal to the push. A member holding no such
//! Grant is refused at the door.
//!
//! Two departures from the example, both of transport only: the member
//! pushes through the direct door under a `git_push` Grant rather than a run
//! lease door (no live run is needed), and the queue's checker pass runs
//! through `oneiron_server::test_doors::merge_queue_checker_pass`, because
//! `build_app` starts no lifecycle; the pass is the served drain with the
//! server's own host executor and the repo's `checker.py` helper.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test code_roundtrip_served`. Stock `git` and `python3` must be on PATH.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderValue, Request, header::AUTHORIZATION};
use axum::middleware::{self, Next};
use axum::response::Response;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::config::{CheckerBackend, MergeQueueCheckerConfig, SyncServerConfig};
use oneiron_server::test_doors::merge_queue_checker_pass::run_merge_queue_checker_pass;
use oneiron_server::{ENGINE_THREAD_STACK_BYTES, build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SERVED_REPO: &str = "greeter-skill";
const BRANCH: &str = "main";
const REF: &str = "refs/heads/main";
/// Checker passes a wait may take before it fails. Each pass runs until
/// nothing moves, so one pass usually settles a step.
const PASSES: usize = 6;

const SKILL_V1: &[u8] = b"---\nname: greeter\ndescription: Greets the user.\n---\n\nSay hello.\n";
const SKILL_V2: &[u8] =
    b"---\nname: greeter\ndescription: Greets the user.\n---\n\nSay hello, then ask how the day went.\n";
const RUN_SH: &[u8] = b"#!/bin/sh\necho hello\n";

/// A slip and the key its holder signs each request's proof with.
#[derive(Clone)]
struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
    token: String,
}

impl Credential {
    /// A slip for `holder` minted under the vault's logged issuer, at the
    /// root's full scope or narrowed to `verbs`.
    fn mint(
        vault: &Vault,
        issuer: &HostSlipIssuer,
        root: &CapabilitySlip,
        holder: EntityId,
        seed: u8,
        verbs: Option<&[&str]>,
    ) -> TestResult<Self> {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [seed; 32];
        claims.holder_ref = holder.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        if let Some(verbs) = verbs {
            claims.scope.verbs =
                ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        }
        let slip = vault.mint_capability_slip(issuer, claims)?;
        Ok(Self {
            token: slip.to_token()?,
            slip,
            key,
        })
    }

    /// A fresh holder proof for one request (a proof stands for a minute).
    fn binding(&self, vault: &Vault) -> TestResult<String> {
        let timestamp = vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self
            .key
            .sign(&self.slip.binding_transcript(&challenge)?)
            .to_bytes();
        Ok(
            json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)})
                .to_string(),
        )
    }
}

/// The git client's signer: the served app spends each holder proof once
/// (`admit_http_binding`), and stock git sends one clone, fetch or push as
/// several HTTP requests with the same configured headers. So the app git
/// talks to signs a fresh proof onto each request whose bearer is one of the
/// fixture's two slips, as a signing client would; every gate still runs.
#[derive(Clone)]
struct GitSigner {
    owner: Credential,
    member: Credential,
    vault: Arc<Vault>,
}

async fn sign_git_request(
    State(signer): State<GitSigner>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let who = [&signer.owner, &signer.member]
        .into_iter()
        .find(|who| token == Some(who.token.as_str()));
    if let Some(who) = who {
        let binding = who
            .binding(&signer.vault)
            .expect("sign a fresh holder proof")
            .parse::<HeaderValue>()
            .expect("a holder proof is a header value");
        request.headers_mut().insert("x-oneiron-binding", binding);
    }
    next.run(request).await
}

struct Fixture {
    app: Router,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    /// `http://127.0.0.1:<port>/git`, the served door's base.
    endpoint: String,
    owner: Credential,
    member: Credential,
    member_person: EntityId,
    owner_actor: EntityId,
    work: tempfile::TempDir,
    serving: tokio::task::JoinHandle<()>,
    _vault_dir: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

impl Fixture {
    /// A rooted vault behind the served app on a loopback port, with the
    /// host checker backend; the embedded owner's full slip, and a second
    /// person's `core:read` + `core:write` slip.
    async fn new() -> TestResult<Self> {
        let vault_dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let owner_actor = vault.ensure_embedded_owner_actor()?;
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner_actor)?;
        let member_person = EntityId::now();
        vault.put_entity(
            &member_person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"yuki, who edits the skill",
        )?;
        let owner = Credential::mint(&vault, &issuer, &root, owner_actor, 0x71, None)?;
        let member = Credential::mint(
            &vault,
            &issuer,
            &root,
            member_person,
            0x72,
            Some(&["core:read", "core:write"]),
        )?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("code-roundtrip-served".into()),
                merge_queue: Some(MergeQueueCheckerConfig {
                    checker_backend: CheckerBackend::Host,
                    helper: Some(checker_helper_argv()?),
                    toolchain: BTreeMap::from([("posix".to_owned(), "host".to_owned())]),
                    ..MergeQueueCheckerConfig::default()
                }),
                ..Default::default()
            },
        )?);
        let app = build_app(Arc::clone(&server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/git", listener.local_addr()?);
        let signer = GitSigner {
            owner: owner.clone(),
            member: member.clone(),
            vault: Arc::clone(&vault),
        };
        let git_app = app
            .clone()
            .layer(middleware::from_fn_with_state(signer, sign_git_request));
        let serving = tokio::spawn(async move {
            let _ = axum::serve(listener, git_app).await;
        });
        Ok(Self {
            app,
            server,
            vault,
            endpoint,
            owner,
            member,
            member_person,
            owner_actor,
            work: tempfile::tempdir()?,
            serving,
            _vault_dir: vault_dir,
        })
    }

    fn repo_url(&self) -> String {
        format!("{}/{SERVED_REPO}.git", self.endpoint)
    }

    /// One facade call under `who`'s slip and a fresh proof: the HTTP
    /// status and the JSON body.
    async fn call(&self, who: &Credential, verb: &str, body: Value) -> TestResult<(u16, Value)> {
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", who.token))
            .header("x-oneiron-binding", who.binding(&self.vault)?)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, body))
    }

    /// The same call, which must answer 200; a failure names the step.
    async fn ok(&self, step: &str, who: &Credential, verb: &str, body: Value) -> TestResult<Value> {
        let (status, answer) = self.call(who, verb, body).await?;
        assert_eq!(status, 200, "{step}: {verb} answered {status}: {answer}");
        Ok(answer)
    }

    /// Stock git in `cwd`, under `who`'s slip when given (the served app
    /// signs each request's proof, [`GitSigner`]), with no user or system
    /// config.
    async fn git(&self, cwd: &Path, who: Option<&Credential>, args: &[&str]) -> TestResult<Output> {
        let mut command = Command::new("git");
        command
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.work.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["-c", "protocol.version=0"])
            .args(["-c", "http.followRedirects=false"])
            .args(["-c", "credential.helper="])
            .args(["-c", "commit.gpgSign=false"])
            .args(["-c", "push.gpgSign=false"]);
        if let Some(who) = who {
            let authorization = format!("http.extraHeader=Authorization: Bearer {}", who.token);
            command.args(["-c", authorization.as_str()]);
        }
        command.args(args);
        Ok(tokio::task::spawn_blocking(move || command.output()).await??)
    }

    /// The same git call, which must exit 0: its trimmed stdout.
    async fn git_ok(
        &self,
        step: &str,
        cwd: &Path,
        who: Option<&Credential>,
        args: &[&str],
    ) -> TestResult<String> {
        let output = self.git(cwd, who, args).await?;
        assert!(
            output.status.success(),
            "{step}: git {args:?} exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// A commit by `name` in `repo` of everything staged: its id.
    async fn commit(
        &self,
        step: &str,
        repo: &Path,
        name: &str,
        message: &str,
    ) -> TestResult<String> {
        let email = format!("{name}@example.com");
        let author = format!("user.name={name}");
        let address = format!("user.email={email}");
        let args = [
            "-c",
            author.as_str(),
            "-c",
            address.as_str(),
            "commit",
            "-q",
            "-m",
            message,
        ];
        self.git_ok(step, repo, None, &args).await?;
        self.git_ok(step, repo, None, &["rev-parse", "HEAD"]).await
    }

    /// One whole checker pass of the served drain, on a blocking thread.
    async fn checker_pass(&self) -> TestResult<usize> {
        let server = Arc::clone(&self.server);
        Ok(tokio::task::spawn_blocking(move || run_merge_queue_checker_pass(&server)).await??)
    }

    /// The owner's admission of `commit` on the default branch: its
    /// published publication row.
    async fn published(&self, step: &str, commit: &str) -> TestResult<Option<Value>> {
        let answer = self
            .ok(
                step,
                &self.owner,
                "vault.code.origin.publications",
                json!({"repo": SERVED_REPO, "ref_name": REF, "git_commit": commit}),
            )
            .await?;
        let rows = answer["publications"]
            .as_array()
            .ok_or_else(|| format!("{step}: no publications list: {answer}"))?;
        let published: Vec<&Value> = rows
            .iter()
            .filter(|row| row["status"] == json!("published"))
            .collect();
        assert!(
            published.len() <= 1,
            "{step}: one published row at most: {answer}"
        );
        Ok(published.first().map(|row| (*row).clone()))
    }

    /// A source repo holding the skill folder, its check plan and one
    /// executable file, committed by the owner and pushed through the
    /// served door: the pushed commit and the source repo's path.
    async fn admit_source(&self) -> TestResult<(String, PathBuf)> {
        let source = self.work.path().join("source");
        std::fs::create_dir(&source)?;
        self.git_ok("S1 init", &source, None, &["init", "-q"])
            .await?;
        write_file(&source.join("SKILL.md"), SKILL_V1, false)?;
        write_file(&source.join("run.sh"), RUN_SH, true)?;
        let check = json!({
            "argv": ["/usr/bin/test", "-f", "SKILL.md"],
            "env_allowlist": {},
            "platform": {},
            "declared_outputs": [],
            "secret_taint_refs": [],
            "class": "verify",
        });
        let plan = json!({"schema_version": 1, "fast": [check.clone()], "slow": [check]});
        std::fs::create_dir(source.join(".oneiron"))?;
        write_file(
            &source.join(".oneiron/checks.json"),
            serde_json::to_string_pretty(&plan)?.as_bytes(),
            false,
        )?;
        self.git_ok("S1 add", &source, None, &["add", "-A"]).await?;
        let commit = self
            .commit("S1 commit", &source, "owen", "greeter skill")
            .await?;
        let (url, refspec) = (self.repo_url(), format!("{commit}:{REF}"));
        self.git_ok(
            "S1 owner push",
            &source,
            Some(&self.owner),
            &["push", "-q", url.as_str(), refspec.as_str()],
        )
        .await?;
        Ok((commit, source))
    }

    /// `vault.code.import` of the admitted `commit` without acceptance: the
    /// manifest view.
    async fn import_manifest(&self, project: &str, commit: &str) -> TestResult<Value> {
        let admission = self
            .published("S1 admission", commit)
            .await?
            .ok_or("S1 admission: the owner's push has no published row")?;
        let request = json!({
            "repo": SERVED_REPO,
            "project": project,
            "source_ref": REF,
            "source_commit": commit,
            "admission_receipt": admission["receipt"],
            "accept": null,
        });
        let import = self
            .ok("S2 import", &self.owner, "vault.code.import", request)
            .await?;
        assert_eq!(
            import["state"],
            json!("manifest_ready"),
            "S2 import: {import}"
        );
        Ok(import)
    }

    /// A TASK the owner creates and assigns to themself, for the owner's
    /// checkout to claim: a claim is the assignee's act. The peer lane mints
    /// no local attempt, and the owner's own assignment witness makes the
    /// owner its assignee (an unassigned TASK goes to the Dreamer).
    fn owner_task(&self, label: &str) -> TestResult<String> {
        let created = oneiron::task_verb::sdk::tasks_create(
            &self.vault.memory(self.owner_actor, EdgeActorClass::Human),
            oneiron::task_verb::sdk::TaskCreateRequest {
                spec: json!(label),
                label: None,
                assignee: Some(oneiron::task_verb::TaskAssignee::Peer {
                    actor_ref: self.owner_actor,
                }),
                intent_key: None,
                brief: None,
                ttl: None,
                parent_ref: None,
                due_at: None,
                watch: false,
            },
        )
        .map_err(|error| format!("S2 task: {error:?}"))?;
        Ok(created.task_ref.ok_or("S2 task: no task_ref")?.to_hex())
    }
}

fn write_file(path: &Path, bytes: &[u8], executable: bool) -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes)?;
    let mode = if executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// The trusted helper's argv for the host backend: `python3` from PATH and
/// the repo's own `checker.py`.
fn checker_helper_argv() -> TestResult<Vec<String>> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let python = std::env::split_paths(&path)
        .map(|dir| dir.join("python3"))
        .find(|candidate| candidate.is_file())
        .ok_or("python3 is not on PATH")?;
    let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron-container/guest/checker/checker.py")
        .canonicalize()?;
    Ok(vec![
        python.display().to_string(),
        helper.display().to_string(),
    ])
}

/// A commit's whole tree: path to (mode, blob id), from `git ls-tree`.
async fn tree(
    fx: &Fixture,
    repo: &Path,
    commit: &str,
) -> TestResult<BTreeMap<String, (String, String)>> {
    let listed = fx
        .git_ok(
            "tree",
            repo,
            None,
            &["ls-tree", "-r", "--full-tree", commit],
        )
        .await?;
    let mut entries = BTreeMap::new();
    for line in listed.lines() {
        let (meta, path) = line.split_once('\t').ok_or("ls-tree line")?;
        let fields: Vec<&str> = meta.split(' ').collect();
        let [mode, _kind, oid] = fields[..] else {
            return Err(format!("ls-tree fields: {line}").into());
        };
        entries.insert(path.to_owned(), (mode.to_owned(), oid.to_owned()));
    }
    Ok(entries)
}

async fn blob(fx: &Fixture, repo: &Path, oid: &str) -> TestResult<Vec<u8>> {
    let output = fx.git(repo, None, &["cat-file", "blob", oid]).await?;
    assert!(output.status.success(), "cat-file {oid}");
    Ok(output.stdout)
}

/// Every path, mode and blob byte of `left` equals `right`'s.
async fn assert_same_tree(
    fx: &Fixture,
    step: &str,
    (left_repo, left): (&Path, &str),
    (right_repo, right): (&Path, &str),
) -> TestResult {
    let left_tree = tree(fx, left_repo, left).await?;
    let right_tree = tree(fx, right_repo, right).await?;
    assert_eq!(left_tree, right_tree, "{step}: paths, modes and blob ids");
    for (path, (_, oid)) in &left_tree {
        assert_eq!(
            blob(fx, left_repo, oid).await?,
            blob(fx, right_repo, oid).await?,
            "{step}: bytes of {path}"
        );
    }
    Ok(())
}

fn text<'a>(step: &str, value: &'a Value, field: &str) -> TestResult<&'a str> {
    Ok(value[field]
        .as_str()
        .ok_or_else(|| format!("{step}: no {field}: {value}"))?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn imported_repo_survives_a_stock_change_and_reexports_byte_equal() -> TestResult {
    on_engine_stack(round_trip)
}

async fn round_trip() -> TestResult {
    let fx = Fixture::new().await?;
    let project = fx.vault.root_project()?.to_hex();
    let registered = fx
        .ok(
            "S1 register",
            &fx.owner,
            "vault.code.origin.register",
            json!({"repo": SERVED_REPO, "default_branch": BRANCH}),
        )
        .await?;
    assert_eq!(
        registered["repo"],
        json!(SERVED_REPO),
        "S1 register: {registered}"
    );
    let (source_commit, source) = fx.admit_source().await?;
    let import = fx.import_manifest(&project, &source_commit).await?;
    let anchor = &import["manifest"]["anchor"];
    let code_repo = text("S2 import", anchor, "repo")?.to_owned();
    let snapshot = text("S2 import", anchor, "snapshot")?.to_owned();
    let manifest_digest = text("S2 import", &import["manifest"], "digest")?.to_owned();

    // The owner's checkout, which every export names.
    let checkout = EntityId::now().to_hex();
    let lease = fx
        .ok(
            "S2 checkout claim",
            &fx.owner,
            "vault.code.checkout.claim",
            json!({
                "checkout": checkout,
                "repo": snapshot,
                "task": fx.owner_task("export the greeter skill")?,
                "task_class": "edit",
                "ttl_seconds": 3600,
                "declared_idempotent": false,
            }),
        )
        .await?;
    let epoch = lease["epoch"].clone();
    fx.ok(
        "S2 checkout bind",
        &fx.owner,
        "vault.code.checkout.bind",
        json!({"repo": SERVED_REPO, "checkout": checkout, "epoch": epoch, "endpoint": fx.endpoint}),
    )
    .await?;

    // S3: the checked queue on the imported baseline; the host checker
    // runs the plan's `test -f SKILL.md` and seals the baseline green.
    let init = fx
        .ok(
            "S3 queue init",
            &fx.owner,
            "vault.code.merge_queue.init",
            json!({"repo": code_repo, "baseline_commit": source_commit, "contract_baseline_ref": null}),
        )
        .await?;
    let work_ref = text("S3 queue init", &init, "work_ref")?.to_owned();
    let mut status = Value::Null;
    for _ in 0..PASSES {
        fx.checker_pass().await?;
        status = fx
            .ok(
                "S3 check status",
                &fx.owner,
                "vault.code.merge_queue.check_status",
                json!({"repo": code_repo, "work_ref": work_ref}),
            )
            .await?;
        if matches!(status["status"].as_str(), Some("passed" | "settled")) {
            break;
        }
    }
    assert!(
        matches!(status["status"].as_str(), Some("passed" | "settled")),
        "S3 baseline check after {PASSES} passes: {status}"
    );
    let repo = fx
        .ok(
            "S3 repos.get",
            &fx.owner,
            "vault.code.repos.get",
            json!({"repo": code_repo}),
        )
        .await?;
    assert_eq!(
        repo["queue"]["green_commit"],
        json!(source_commit),
        "S3 green: {repo}"
    );
    let baseline = text("S3 repos.get", &repo, "green_revision")?.to_owned();

    // S4: the owner accepts the manifest with no critic lens.
    let accepted = fx
        .ok(
            "S4 import accept",
            &fx.owner,
            "vault.code.import",
            json!({
                "repo": SERVED_REPO,
                "project": project,
                "source_ref": REF,
                "source_commit": source_commit,
                "admission_receipt": import["manifest"]["anchor"]["admission_receipt"],
                "accept": {
                    "manifest_digest": manifest_digest,
                    "baseline_revision": baseline,
                    "catalog": {"schema_version": 1, "lenses": []},
                    "review_verdict": null,
                },
            }),
        )
        .await?;
    assert_eq!(
        accepted["state"],
        json!("promoted"),
        "S4 import accept: {accepted}"
    );

    // S6: the baseline's first export, cloned with stock git.
    let first = fx
        .ok(
            "S6 export",
            &fx.owner,
            "vault.code.export",
            json!({
                "repo": SERVED_REPO,
                "checkout": checkout,
                "epoch": epoch,
                "revision": baseline,
                "ref_name": REF,
                "expected_old_oid": source_commit,
                "endpoint": fx.endpoint,
            }),
        )
        .await?;
    assert_eq!(
        first["publication"]["status"],
        json!("published"),
        "S6 export: {first}"
    );
    assert_eq!(first["wire_rejected"], json!(false), "S6 export: {first}");
    let first_commit = text("S6 export", &first, "git_commit")?.to_owned();
    let clone = fx.work.path().join("clone");
    let clone_path = clone.display().to_string();
    let first_url = text("S6 export", &first, "remote_url")?.to_owned();
    fx.git_ok(
        "S7 clone",
        fx.work.path(),
        Some(&fx.owner),
        &[
            "clone",
            "-q",
            "--branch",
            BRANCH,
            first_url.as_str(),
            clone_path.as_str(),
        ],
    )
    .await?;
    let head = fx
        .git_ok("S7 clone", &clone, None, &["rev-parse", "HEAD"])
        .await?;
    assert_eq!(head, first_commit, "S7 the clone's head is the export");
    assert_same_tree(
        &fx,
        "S7 export equals import",
        (&clone, &head),
        (&source, &source_commit),
    )
    .await?;

    // S8: the member's Grant over the imported repo, one stock change,
    // and the push back through the same door.
    let mint = fx
        .ok(
            "S8 git_push mint",
            &fx.owner,
            "vault.repo.git_push.mint",
            json!({
                "member": fx.member_person.to_hex(),
                "repos": [{"repo": code_repo, "project": project}],
            }),
        )
        .await?;
    assert!(
        mint["grant"]["grant_ref"].is_string(),
        "S8 git_push mint: {mint}"
    );
    let policy = fx
        .ok(
            "S8 review policy",
            &fx.owner,
            "vault.code.merge_queue.review_policy.get",
            json!({}),
        )
        .await?;
    assert_eq!(
        policy["mode"],
        json!("land_on_green"),
        "S8 review policy: {policy}"
    );
    write_file(&clone.join("SKILL.md"), SKILL_V2, false)?;
    fx.git_ok("S8 add", &clone, None, &["add", "-A"]).await?;
    let pushed = fx
        .commit("S8 commit", &clone, "yuki", "greeter asks back")
        .await?;
    let (url, refspec) = (fx.repo_url(), format!("{pushed}:{REF}"));
    fx.git_ok(
        "S8 member push",
        &clone,
        Some(&fx.member),
        &["push", "-q", url.as_str(), refspec.as_str()],
    )
    .await?;
    let receipt = fx
        .published("S9 push admission", &pushed)
        .await?
        .ok_or("S9 push admission: the member's push has no published row")?;
    let provenance = receipt["provenance_receipt"].clone();

    // S9-S10: the queue takes the received push as a proposal, checks it
    // and seals it green, with no review policy.
    let mut ingress = Value::Null;
    let mut seal = None;
    for _ in 0..PASSES {
        fx.checker_pass().await?;
        let (_, answer) = fx
            .call(
                &fx.owner,
                "vault.code.ingress.get",
                json!({"repo": code_repo, "provenance": provenance, "ref_name": REF}),
            )
            .await?;
        ingress = answer;
        let revisions = ingress["candidate"]["revision_refs"].as_array().cloned();
        let Some(last) = revisions.and_then(|refs| refs.last().cloned()) else {
            continue;
        };
        let repo = fx
            .ok(
                "S10 repos.get",
                &fx.owner,
                "vault.code.repos.get",
                json!({"repo": code_repo}),
            )
            .await?;
        if repo["green_revision"] == last {
            seal = Some(last);
            break;
        }
    }
    let seal =
        seal.ok_or_else(|| format!("S10 no sealed green after {PASSES} passes: {ingress}"))?;
    assert_eq!(
        ingress["old_oid"],
        json!(first_commit),
        "S9 ingress: {ingress}"
    );
    assert_eq!(ingress["new_oid"], json!(pushed), "S9 ingress: {ingress}");
    let proposals = ingress["candidate"]["proposal_refs"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(proposals.len(), 1, "S9 one proposal: {ingress}");
    let view = fx
        .ok(
            "S9 proposal view",
            &fx.owner,
            "vault.code.proposal_view",
            json!({"proposal_ref": proposals[0]}),
        )
        .await?;
    assert_eq!(
        view["operation_kind"],
        json!("received_files"),
        "S9 proposal view: {view}"
    );

    // S11: the green export, cloned again: the pushed tree, byte for byte.
    let green = fx
        .ok(
            "S11 export_green",
            &fx.owner,
            "vault.code.merge_queue.export_green",
            json!({
                "repo": code_repo,
                "served_repo": SERVED_REPO,
                "checkout": checkout,
                "epoch": epoch,
                "ref_name": REF,
                "expected_old_oid": pushed,
                "endpoint": fx.endpoint,
            }),
        )
        .await?;
    assert_eq!(green["revision"], seal, "S11 export_green: {green}");
    assert_eq!(
        green["publication"]["status"],
        json!("published"),
        "S11 export_green: {green}"
    );
    assert_eq!(
        green["wire_rejected"],
        json!(false),
        "S11 export_green: {green}"
    );
    let green_commit = text("S11 export_green", &green, "git_commit")?.to_owned();
    let reclone = fx.work.path().join("reclone");
    let reclone_path = reclone.display().to_string();
    let green_url = text("S11 export_green", &green, "remote_url")?.to_owned();
    fx.git_ok(
        "S11 reclone",
        fx.work.path(),
        Some(&fx.owner),
        &[
            "clone",
            "-q",
            "--branch",
            BRANCH,
            green_url.as_str(),
            reclone_path.as_str(),
        ],
    )
    .await?;
    let head = fx
        .git_ok("S11 reclone", &reclone, None, &["rev-parse", "HEAD"])
        .await?;
    assert_eq!(
        head, green_commit,
        "S11 the reclone's head is the green export"
    );
    assert_same_tree(
        &fx,
        "S11 green export equals push",
        (&reclone, &head),
        (&clone, &pushed),
    )
    .await?;
    for ancestor in [&source_commit, &pushed] {
        let output = fx
            .git(
                &reclone,
                None,
                &[
                    "merge-base",
                    "--is-ancestor",
                    ancestor.as_str(),
                    head.as_str(),
                ],
            )
            .await?;
        assert!(
            output.status.success(),
            "S11 {ancestor} is an ancestor of the green export"
        );
    }
    // The file no one touched keeps the import's bytes and its mode.
    let exported = tree(&fx, &reclone, &head).await?;
    let imported = tree(&fx, &source, &source_commit).await?;
    assert_eq!(
        exported["run.sh"], imported["run.sh"],
        "S11 run.sh mode and blob"
    );
    assert_eq!(
        exported["run.sh"].0, "100755",
        "S11 run.sh stays executable"
    );
    assert_eq!(blob(&fx, &reclone, &exported["run.sh"].1).await?, RUN_SH);

    // The same sealed revision exported again answers the same tree.
    let again = fx
        .ok(
            "S11 re-export",
            &fx.owner,
            "vault.code.export",
            json!({
                "repo": SERVED_REPO,
                "checkout": checkout,
                "epoch": epoch,
                "revision": seal,
                "ref_name": REF,
                "expected_old_oid": green_commit,
                "endpoint": fx.endpoint,
            }),
        )
        .await?;
    assert_eq!(
        again["wire_rejected"],
        json!(false),
        "S11 re-export: {again}"
    );
    let again_commit = text("S11 re-export", &again, "git_commit")?.to_owned();
    fx.git_ok(
        "S11 refetch",
        &reclone,
        Some(&fx.owner),
        &["fetch", "-q", "origin", REF],
    )
    .await?;
    assert_same_tree(
        &fx,
        "S11 re-export equals push",
        (&reclone, &again_commit),
        (&clone, &pushed),
    )
    .await?;
    Ok(())
}

#[test]
fn a_push_without_a_git_push_grant_is_refused() -> TestResult {
    on_engine_stack(refused_push)
}

async fn refused_push() -> TestResult {
    let fx = Fixture::new().await?;
    let project = fx.vault.root_project()?.to_hex();
    fx.ok(
        "S1 register",
        &fx.owner,
        "vault.code.origin.register",
        json!({"repo": SERVED_REPO, "default_branch": BRANCH}),
    )
    .await?;
    let (source_commit, source) = fx.admit_source().await?;
    fx.import_manifest(&project, &source_commit).await?;

    // The member clones the owner's admitted commit and changes it, but
    // holds no `git_push` Grant over the repo.
    let clone = fx.work.path().join("clone");
    let clone_path = clone.display().to_string();
    let source_path = source.display().to_string();
    fx.git_ok(
        "clone",
        fx.work.path(),
        None,
        &["clone", "-q", source_path.as_str(), clone_path.as_str()],
    )
    .await?;
    write_file(&clone.join("SKILL.md"), SKILL_V2, false)?;
    fx.git_ok("add", &clone, None, &["add", "-A"]).await?;
    let pushed = fx
        .commit("commit", &clone, "yuki", "greeter asks back")
        .await?;
    let (url, refspec) = (fx.repo_url(), format!("{pushed}:{REF}"));
    let refused = fx
        .git(
            &clone,
            Some(&fx.member),
            &["push", "-q", url.as_str(), refspec.as_str()],
        )
        .await?;
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success(),
        "a push with no git_push Grant is refused: {stderr}"
    );
    assert!(
        stderr.contains("403") || stderr.contains("git_push"),
        "the refusal is the door's: {stderr}"
    );
    assert!(
        fx.published("no admission", &pushed).await?.is_none(),
        "a refused push publishes nothing"
    );
    // The served ref still names the owner's commit.
    let listed = fx
        .git_ok(
            "ls-remote",
            &clone,
            Some(&fx.owner),
            &["ls-remote", url.as_str(), REF],
        )
        .await?;
    assert!(
        listed.starts_with(&source_commit),
        "the served ref is unmoved: {listed}"
    );
    Ok(())
}

/// Runs `test` as the server's binary runs its app: on a multi-thread
/// runtime whose threads, blocking ones included, have the engine's stack,
/// driven from a thread that has it too (`ENGINE_THREAD_STACK_BYTES`).
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
