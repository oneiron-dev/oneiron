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
//! Grant is refused at the door. After the same loop, the owner reads what
//! the live workbench shows (repo, task, fork and proposal, head and green,
//! check results, the exact public diff) through the served verbs, and
//! each answer names the loop's own ids.
//!
//! Two departures from the example, both of transport only: the member
//! pushes through the direct door under a `git_push` Grant rather than a run
//! lease door (no live run is needed), and the queue's checker pass runs
//! through `oneiron_server::test_doors::merge_queue_checker_pass`, because
//! `build_app` starts no lifecycle; the pass is the served drain with the
//! server's own host executor and the repo's `checker.py` helper.
//!
//! L4-06 PR 3 (one-origin, two-device code continuity): the vault owner has
//! two devices, A and B, each with its own credential, TASK, checkout lease
//! and stock-git worktree, and each device reaches the one served origin
//! only through its own lease door (`vault.code.checkout.bind`'s
//! `remote_url`). An edit on one device is seen on the other, a stale lease
//! cannot publish after an authority cutover, offline work on a fenced lease
//! is not lost, a restart keeps proposals, review state and head, and the
//! owner's push on a lease whose TASK he cancelled is refused. The owner
//! pushes on his own lease under its fence alone, with no run Grant
//! (L4-06-OWNER-LEASE-PUSH).
//! Proposals are read at the origin's door (RA2: the PROPOSAL side table is
//! origin-local), as refs are; no replica copy exists. Named remainder: two
//! enrolled machines' device sync still needs the E2E `startDevicePeer`
//! fixture, which no in-process Rust test can host.
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
    creds: Vec<Credential>,
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
    let who = signer
        .creds
        .iter()
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
    device_a: Credential,
    device_b: Credential,
    keystore: Arc<oneiron_keystore::MemoryKeystore>,
    work: tempfile::TempDir,
    serving: ServingTask,
    _vault_dir: tempfile::TempDir,
}

/// The task that serves the git doors on the loopback port; dropping it
/// stops it.
struct ServingTask(tokio::task::JoinHandle<()>);

impl Drop for ServingTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Fixture {
    /// A rooted vault behind the served app on a loopback port, with the
    /// host checker backend; the embedded owner's full slip, and a second
    /// person's `core:read` + `core:write` slip.
    async fn new() -> TestResult<Self> {
        let vault_dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::device())?);
        let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
        vault.install_device_keystore(Arc::clone(&keystore));
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
        let device_a = Credential::mint(&vault, &issuer, &root, owner_actor, 0x73, None)?;
        let device_b = Credential::mint(&vault, &issuer, &root, owner_actor, 0x74, None)?;
        let server = Arc::new(SyncServer::new(Arc::clone(&vault), server_config()?)?);
        let app = build_app(Arc::clone(&server));
        let mut fx = Self {
            app,
            server,
            vault,
            endpoint: String::new(),
            owner,
            member,
            member_person,
            owner_actor,
            device_a,
            device_b,
            keystore,
            work: tempfile::tempdir()?,
            serving: ServingTask(tokio::spawn(async {})),
            _vault_dir: vault_dir,
        };
        fx.listen().await?;
        Ok(fx)
    }

    /// Serves the app's git doors on a new loopback port, signing every
    /// fixture credential's holder proof, and points `endpoint` at them.
    async fn listen(&mut self) -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        self.endpoint = format!("http://{}/git", listener.local_addr()?);
        let signer = GitSigner {
            creds: vec![
                self.owner.clone(),
                self.member.clone(),
                self.device_a.clone(),
                self.device_b.clone(),
            ],
            vault: Arc::clone(&self.vault),
        };
        let git_app = self
            .app
            .clone()
            .layer(middleware::from_fn_with_state(signer, sign_git_request));
        // The old serving task, if any, stops as it drops here.
        self.serving = ServingTask(tokio::spawn(async move {
            let _ = axum::serve(listener, git_app).await;
        }));
        Ok(())
    }

    /// Restarts the served origin as a process restart does: the serving
    /// task, the app and the server drop, and with them the last
    /// `Arc<Vault>`; the same vault dir opens again with the same keystore,
    /// and a new server, app and loopback listener serve it. Proposals, the
    /// queue, leases, authority and the served refs are vault rows and
    /// files. Engine rows (machines, root slip, owner, binds) persist too,
    /// and `SyncServer::new` runs their ensures again itself, so this
    /// re-runs none of them.
    async fn restart(self) -> TestResult<Self> {
        let Self {
            app,
            server,
            vault,
            endpoint: _,
            owner,
            member,
            member_person,
            owner_actor,
            device_a,
            device_b,
            keystore,
            work,
            mut serving,
            _vault_dir: vault_dir,
        } = self;
        serving.0.abort();
        // The aborted task's future, and the signer's `Arc<Vault>` in it,
        // is dropped before its handle answers.
        let _ = (&mut serving.0).await;
        drop(serving);
        drop(app);
        drop(server);
        // The reader runner and the message stream upgrade a Weak<Vault>
        // for one store read each tick, so take the vault back by value:
        // once that succeeds no Weak upgrades again, and the drop closes
        // the store before it is opened again.
        let mut vault = vault;
        let mut tries = 0_u32;
        let old = loop {
            match Arc::try_unwrap(vault) {
                Ok(old) => break old,
                Err(shared) if tries < 100_000 => {
                    tries += 1;
                    vault = shared;
                    std::thread::yield_now();
                    tokio::task::yield_now().await;
                }
                Err(shared) => {
                    return Err(format!(
                        "C3 restart: {} other Arc<Vault> holders outlive the old server and app",
                        Arc::strong_count(&shared) - 1
                    )
                    .into());
                }
            }
        };
        drop(old);
        let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::clone(&keystore));
        let server = Arc::new(SyncServer::new(Arc::clone(&vault), server_config()?)?);
        let app = build_app(Arc::clone(&server));
        let mut fx = Self {
            app,
            server,
            vault,
            endpoint: String::new(),
            owner,
            member,
            member_person,
            owner_actor,
            device_a,
            device_b,
            keystore,
            work,
            serving: ServingTask(tokio::spawn(async {})),
            _vault_dir: vault_dir,
        };
        fx.listen().await?;
        Ok(fx)
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

/// The served app's config: the host checker backend with the repo's own
/// `checker.py` helper, shared by a fresh fixture and a restart.
fn server_config() -> TestResult<SyncServerConfig> {
    Ok(SyncServerConfig {
        auth_secret: Some("code-roundtrip-served".into()),
        merge_queue: Some(MergeQueueCheckerConfig {
            checker_backend: CheckerBackend::Host,
            helper: Some(checker_helper_argv()?),
            toolchain: BTreeMap::from([("posix".to_owned(), "host".to_owned())]),
            ..MergeQueueCheckerConfig::default()
        }),
        ..Default::default()
    })
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
    on_engine_stack(|| async { round_trip().await.map(drop) })
}

/// What one round trip leaves for the reads after it: the served app and
/// the ids the loop made.
struct RoundTrip {
    fx: Fixture,
    project: String,
    code_repo: String,
    snapshot: String,
    source_commit: String,
    task: String,
    checkout: String,
    epoch: Value,
    work_ref: String,
    baseline: String,
    first_commit: String,
    provenance: Value,
    candidate: Value,
    proposal: Value,
    seal: Value,
}

/// What PR 3's tests start from: S1-S4 of [`round_trip`] (register, admit,
/// import, the owner's checkout, the checked baseline, the accepted
/// import), with the served `main` still at the admitted commit.
struct Baseline {
    fx: Fixture,
    project: String,
    code_repo: String,
    snapshot: String,
    source_commit: String,
    source: PathBuf,
    task: String,
    checkout: String,
    epoch: Value,
    work_ref: String,
    baseline: String,
}

async fn imported_baseline() -> TestResult<Baseline> {
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
    let task = fx.owner_task("export the greeter skill")?;
    let lease = fx
        .ok(
            "S2 checkout claim",
            &fx.owner,
            "vault.code.checkout.claim",
            json!({
                "checkout": checkout,
                "repo": snapshot,
                "task": task,
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
    Ok(Baseline {
        fx,
        project,
        code_repo,
        snapshot,
        source_commit,
        source,
        task,
        checkout,
        epoch,
        work_ref,
        baseline,
    })
}

async fn round_trip() -> TestResult<RoundTrip> {
    let Baseline {
        fx,
        project,
        code_repo,
        snapshot,
        source_commit,
        source,
        task,
        checkout,
        epoch,
        work_ref,
        baseline,
    } = imported_baseline().await?;

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
    let candidate = ingress["candidate"].clone();
    let proposal = proposals[0].clone();
    Ok(RoundTrip {
        fx,
        project,
        code_repo,
        snapshot,
        source_commit,
        task,
        checkout,
        epoch,
        work_ref,
        baseline,
        first_commit,
        provenance,
        candidate,
        proposal,
        seal,
    })
}

/// L4-06 PR 2 (FIX 6869: the engine must "expose every read the workbench
/// needs through the SDK (repo, task, fork/proposal, head/green, check
/// result, exact public diff), typed"): after one round trip the owner
/// reads each through its served verb, and each answer names the loop's
/// own ids. Every read is checked and every miss is listed, so one run
/// names each read that is missing or wrong.
#[test]
fn workbench_reads_name_the_loops_repo_task_fork_head_check_and_diff() -> TestResult {
    on_engine_stack(workbench_reads)
}

/// The reads that answered wrong or not at all, each with its answer.
#[derive(Default)]
struct Misses(Vec<String>);

impl Misses {
    /// One facade read as the owner; a refusal is a miss and reads as null.
    async fn read(
        &mut self,
        fx: &Fixture,
        read: &str,
        verb: &str,
        body: Value,
    ) -> TestResult<Value> {
        let (status, answer) = fx.call(&fx.owner, verb, body).await?;
        if status == 200 {
            return Ok(answer);
        }
        self.0
            .push(format!("{read}: {verb} answered {status}: {answer}"));
        Ok(Value::Null)
    }

    fn check(&mut self, read: &str, what: &str, holds: bool, answer: &Value) {
        if !holds {
            self.0.push(format!("{read}: {what}: {answer}"));
        }
    }
}

/// Whether `list` is an array with an item that `matches`.
fn any(list: &Value, matches: impl Fn(&Value) -> bool) -> bool {
    list.as_array()
        .is_some_and(|items| items.iter().any(matches))
}

fn names(list: &Value, id: &Value) -> bool {
    any(list, |item| item == id)
}

async fn workbench_reads() -> TestResult {
    let rt = round_trip().await?;
    let fx = &rt.fx;
    let mut misses = Misses::default();
    let fork_session = rt.candidate["fork_session"].clone();
    let batches = rt.candidate["batch_refs"].clone();
    let mut works = vec![json!(rt.work_ref)];
    works.extend(
        rt.candidate["check_work_refs"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
    );

    // Repo: the anchor, its import, its green, and its links to the
    // loop's fork, push and checks.
    let repo = misses
        .read(
            fx,
            "repo",
            "vault.code.repos.get",
            json!({"repo": rt.code_repo}),
        )
        .await?;
    misses.check(
        "repo",
        "repo, project and served name",
        repo["repo"] == json!(rt.code_repo)
            && repo["project"] == json!(rt.project)
            && repo["served_repo"] == json!(SERVED_REPO),
        &repo,
    );
    misses.check(
        "repo",
        "the loop's import",
        any(&repo["imports"], |import| {
            import["anchor"]["snapshot"] == json!(rt.snapshot)
                && import["anchor"]["source_commit"] == json!(rt.source_commit)
        }),
        &repo,
    );
    misses.check(
        "repo",
        "green is the seal; the push's fork, ingress and checks are linked",
        repo["green_revision"] == rt.seal
            && names(&repo["fork_sessions"], &fork_session)
            && any(&repo["ingress"], |ingress| {
                ingress["provenance"] == rt.provenance && ingress["ref_name"] == json!(REF)
            })
            && works
                .iter()
                .all(|work| names(&repo["check_work_refs"], work)),
        &repo,
    );

    // Task: the checkout the exports name holds the loop's TASK, and the
    // TASKS section and the TASK's card read it by its id.
    let lease = misses
        .read(
            fx,
            "task",
            "vault.code.checkout.get",
            json!({"checkout": rt.checkout}),
        )
        .await?;
    misses.check(
        "task",
        "the checkout names the TASK, its holder and its epoch",
        lease["value"]["task"] == json!(rt.task)
            && lease["value"]["checkout"] == json!(rt.checkout)
            && lease["value"]["holder"] == json!(fx.owner_actor.to_hex())
            && lease["value"]["epoch"] == rt.epoch,
        &lease,
    );
    let section = misses.read(fx, "task", "describe", json!({})).await?;
    misses.check(
        "task",
        "the TASKS section has the TASK's row, open and assigned",
        section["kind"] == json!("tasks_section")
            && any(&section["rows"], |row| {
                row["id"] == json!(rt.task)
                    && row["is_intent"] == json!(true)
                    && matches!(
                        row["status"].as_str(),
                        Some("queued" | "scheduled" | "running")
                    )
                    && row["assignee"].is_string()
            }),
        &section,
    );
    let card = misses
        .read(fx, "task", "describe", json!({"task_ref": rt.task}))
        .await?;
    misses.check(
        "task",
        "the TASK's card",
        card["kind"] == json!("task_card")
            && card["lines"][0]
                .as_str()
                .is_some_and(|line| line.contains(rt.task.as_str())),
        &card,
    );

    // Fork and proposal: the push's fork on the baseline, its proposal
    // and its sealed revision.
    let fork = misses
        .read(
            fx,
            "fork",
            "vault.code.forks.get",
            json!({"repo": rt.code_repo, "fork_session": fork_session}),
        )
        .await?;
    misses.check(
        "fork",
        "the push's fork on the baseline",
        fork["repo"] == json!(rt.code_repo)
            && fork["fork_session"] == fork_session
            && fork["base_revision"] == json!(rt.baseline)
            && rt.candidate["base_revision"] == json!(rt.baseline),
        &fork,
    );
    misses.check(
        "fork",
        "its proposal, sealed revision, push and SKILL.md",
        names(&fork["proposal_refs"], &rt.proposal)
            && names(&fork["revision_refs"], &rt.seal)
            && fork["ingress"]["provenance"] == rt.provenance
            && fork["ingress"]["ref_name"] == json!(REF)
            && any(&fork["documents"], |document| {
                document["path"] == json!("SKILL.md") && document["proposal_ref"] == rt.proposal
            }),
        &fork,
    );
    let proposal = misses
        .read(
            fx,
            "proposal",
            "vault.code.proposal_view",
            json!({"proposal_ref": rt.proposal}),
        )
        .await?;
    misses.check(
        "proposal",
        "the received SKILL.md change, applied",
        proposal["proposal_ref"] == rt.proposal
            && proposal["operation_kind"] == json!("received_files")
            && proposal["status"] == json!("Applied")
            && any(&proposal["files"], |file| file["path"] == json!("SKILL.md")),
        &proposal,
    );

    // Head and green: the queue's pointers, its green export, and the
    // push's batch.
    let observed = misses
        .read(
            fx,
            "head/green",
            "vault.code.merge_queue.observe",
            json!({"repo": rt.code_repo, "batches": batches}),
        )
        .await?;
    misses.check(
        "head/green",
        "head and green are the repo's queue pointers, nothing pending",
        observed["head_commit"] == repo["queue"]["head_commit"]
            && observed["green_commit"] == repo["queue"]["green_commit"]
            && observed["head_commit"] == observed["green_commit"]
            && observed["pending_slow_batch_refs"] == json!([]),
        &observed,
    );
    misses.check(
        "head/green",
        "the green export is the seal, unheld",
        observed["green_export"]["tested_revision"] == rt.seal
            && observed["green_export"]["green_commit"] == observed["green_commit"]
            && observed["green_export"]["hold"].is_null(),
        &observed,
    );
    misses.check(
        "head/green",
        "the push's batch carries its proposal",
        any(&batches, |batch| {
            any(&observed["batches"], |view| {
                view["batch_ref"] == *batch && names(&view["proposals"], &rt.proposal)
            })
        }),
        &observed,
    );

    // Check results: the baseline's and the push's checks passed, each
    // with a completed receipt whose tests passed.
    misses.check(
        "check",
        "the push has a check",
        works.len() > 1,
        &rt.candidate,
    );
    for work in &works {
        let status = misses
            .read(
                fx,
                "check",
                "vault.code.merge_queue.check_status",
                json!({"repo": rt.code_repo, "work_ref": work}),
            )
            .await?;
        misses.check(
            "check",
            "the work passed",
            status["work_ref"] == *work
                && matches!(status["status"].as_str(), Some("passed" | "settled"))
                && (*work != json!(rt.work_ref)
                    || status["baseline_commit"] == json!(rt.source_commit)),
            &status,
        );
        let Some(receipt_ref) = status["receipt_refs"][0].as_str() else {
            misses.check("check", "the work names a receipt", false, &status);
            continue;
        };
        let receipts = misses
            .read(
                fx,
                "check",
                "vault.code.checks.get",
                json!({"repo": rt.code_repo, "work_ref": work, "receipt_ref": receipt_ref}),
            )
            .await?;
        misses.check(
            "check",
            "a completed receipt whose tests passed",
            receipts["receipt_ref"] == json!(receipt_ref)
                && any(&receipts["receipts"], |attempt| {
                    attempt["completed"] == json!(true) && attempt["tests_passed"] == json!(true)
                }),
            &receipts,
        );
    }

    // The exact public diff: the first export's tree against the sealed
    // push, one changed file, each side's bytes.
    let preview_request = json!({
        "repo": SERVED_REPO,
        "code_repo": rt.code_repo,
        "checkout": rt.checkout,
        "epoch": rt.epoch,
        "revision": rt.seal,
        "ref_name": REF,
        "expected_old_oid": rt.first_commit,
        "endpoint": fx.endpoint,
    });
    let preview = misses
        .read(
            fx,
            "diff",
            "vault.code.export.preview",
            preview_request.clone(),
        )
        .await?;
    let delta = &preview["preview"];
    misses.check(
        "diff",
        "ready and exact, one change: SKILL.md",
        preview["state"] == json!("ready")
            && delta["exact"] == json!(true)
            && delta["files"].as_array().map(Vec::len) == Some(1)
            && delta["files"][0]["path"] == json!("SKILL.md"),
        &preview,
    );
    for (side, bytes) in [("before", SKILL_V1), ("after", SKILL_V2)] {
        let file = misses
            .read(
                fx,
                "diff",
                "vault.code.export.preview.read",
                json!({"preview": preview_request, "handle": delta["files"][0][side]["handle"]}),
            )
            .await?;
        misses.check(
            "diff",
            side,
            file["state"] == json!("ready") && file["file"]["bytes"] == json!(bytes),
            &file,
        );
    }

    assert!(
        misses.0.is_empty(),
        "{} workbench read(s) missing or wrong:\n{}",
        misses.0.len(),
        misses.0.join("\n")
    );
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

const NOTES_V1: &[u8] = b"# Notes\n\nDevice B was here.\n";

/// One device of the vault owner: its own credential, TASK, checkout lease
/// and stock-git worktree, reaching the origin only through its lease door.
struct Device {
    cred: Credential,
    task: String,
    checkout: String,
    epoch: Value,
    url: String,
    dir: PathBuf,
}

/// What one landed lease push leaves: its ingress row, its single
/// proposal and the sealed green revision.
struct Landed {
    ingress: Value,
    proposal: Value,
    seal: Value,
}

/// A device on the baseline: its own TASK, its own checkout lease claim
/// (the same JSON as S2), its bind, and a stock clone of its lease door
/// at the baseline head.
async fn device(baseline: &Baseline, name: &str, cred: &Credential) -> TestResult<Device> {
    let fx = &baseline.fx;
    let label = format!("{name} works the greeter skill");
    let task = fx.owner_task(&label)?;
    let checkout = EntityId::now().to_hex();
    let lease = fx
        .ok(
            &format!("C1 {name} checkout claim"),
            cred,
            "vault.code.checkout.claim",
            json!({
                "checkout": checkout,
                "repo": baseline.snapshot,
                "task": task,
                "task_class": "edit",
                "ttl_seconds": 3600,
                "declared_idempotent": false,
            }),
        )
        .await?;
    let epoch = lease["epoch"].clone();
    let bind = fx
        .ok(
            &format!("C1 {name} checkout bind"),
            cred,
            "vault.code.checkout.bind",
            json!({"repo": SERVED_REPO, "checkout": checkout, "epoch": epoch, "endpoint": fx.endpoint}),
        )
        .await?;
    let url = text(&format!("C1 {name} checkout bind"), &bind, "remote_url")?.to_owned();
    let dir = fx.work.path().join(name);
    let path = dir.display().to_string();
    fx.git_ok(
        &format!("C1 {name} clone"),
        fx.work.path(),
        Some(cred),
        &[
            "clone",
            "-q",
            "--branch",
            BRANCH,
            url.as_str(),
            path.as_str(),
        ],
    )
    .await?;
    let head = fx
        .git_ok(
            &format!("C1 {name} clone"),
            &dir,
            None,
            &["rev-parse", "HEAD"],
        )
        .await?;
    assert_eq!(
        head, baseline.source_commit,
        "C1 {name}: the clone starts at the baseline head"
    );
    Ok(Device {
        cred: cred.clone(),
        task,
        checkout,
        epoch,
        url,
        dir,
    })
}

/// Waits for a lease push's landing, as S9-S10 do for the member's direct
/// push: the push's published row, its ingress, and checker passes until
/// `repos.get` green_revision is the candidate's last revision; the one
/// proposal is a received_files proposal.
async fn land(
    fx: &Fixture,
    baseline: &Baseline,
    commit: &str,
    expected_old: &str,
    step: &str,
) -> TestResult<Landed> {
    let receipt = fx
        .published(&format!("{step} push admission"), commit)
        .await?
        .ok_or_else(|| format!("{step} push admission: the push has no published row"))?;
    let provenance = receipt["provenance_receipt"].clone();
    let mut ingress = Value::Null;
    let mut seal = None;
    for _ in 0..PASSES {
        fx.checker_pass().await?;
        let (_, answer) = fx
            .call(
                &fx.owner,
                "vault.code.ingress.get",
                json!({"repo": baseline.code_repo, "provenance": provenance, "ref_name": REF}),
            )
            .await?;
        ingress = answer;
        let revisions = ingress["candidate"]["revision_refs"].as_array().cloned();
        let Some(last) = revisions.and_then(|refs| refs.last().cloned()) else {
            continue;
        };
        let repo = fx
            .ok(
                &format!("{step} repos.get"),
                &fx.owner,
                "vault.code.repos.get",
                json!({"repo": baseline.code_repo}),
            )
            .await?;
        if repo["green_revision"] == last {
            seal = Some(last);
            break;
        }
    }
    let seal =
        seal.ok_or_else(|| format!("{step} no sealed green after {PASSES} passes: {ingress}"))?;
    assert_eq!(
        ingress["old_oid"],
        json!(expected_old),
        "{step} ingress: {ingress}"
    );
    assert_eq!(
        ingress["new_oid"],
        json!(commit),
        "{step} ingress: {ingress}"
    );
    let proposals = ingress["candidate"]["proposal_refs"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(proposals.len(), 1, "{step} one proposal: {ingress}");
    let view = fx
        .ok(
            &format!("{step} proposal view"),
            &fx.owner,
            "vault.code.proposal_view",
            json!({"proposal_ref": proposals[0]}),
        )
        .await?;
    assert_eq!(
        view["operation_kind"],
        json!("received_files"),
        "{step} proposal view: {view}"
    );
    Ok(Landed {
        ingress,
        proposal: proposals[0].clone(),
        seal,
    })
}

/// L4-06 PR 3 T1: an edit on one device is seen on the other, through the
/// served lease doors. RA2 makes proposals origin rows (the PROPOSAL side
/// table, `repo_mutation/proposal.rs:68`), so a device reads them at the
/// origin's door, as it reads refs; no replica copy exists.
#[test]
fn an_edit_on_one_device_is_seen_on_the_other() -> TestResult {
    on_engine_stack(devices_share_an_edit)
}

async fn devices_share_an_edit() -> TestResult {
    let baseline = imported_baseline().await?;
    let fx = &baseline.fx;
    let a = device(&baseline, "device-a", &fx.device_a).await?;
    let b = device(&baseline, "device-b", &fx.device_b).await?;

    // C2: A's edit lands.
    write_file(&a.dir.join("SKILL.md"), SKILL_V2, false)?;
    fx.git_ok("C2 A add", &a.dir, None, &["add", "-A"]).await?;
    let a_commit = fx
        .commit("C2 A commit", &a.dir, "owen", "device A greets back")
        .await?;
    fx.git_ok(
        "C2 A push",
        &a.dir,
        Some(&a.cred),
        &["push", "-q", a.url.as_str(), "HEAD:refs/heads/main"],
    )
    .await?;
    let a_landed = land(
        fx,
        &baseline,
        &a_commit,
        &baseline.source_commit,
        "C2 A land",
    )
    .await?;

    // C3: B's concurrent edit cannot push over A's: the push fails and the
    // origin still names A's commit.
    write_file(&b.dir.join("NOTES.md"), NOTES_V1, false)?;
    fx.git_ok("C3 B add", &b.dir, None, &["add", "-A"]).await?;
    let _b_stale = fx
        .commit("C3 B commit", &b.dir, "yuki", "device B notes")
        .await?;
    let refused = fx
        .git(
            &b.dir,
            Some(&b.cred),
            &["push", "-q", b.url.as_str(), "HEAD:refs/heads/main"],
        )
        .await?;
    let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(
        !refused.status.success() && stderr.contains("rejected"),
        "C3 B's stale push is rejected as not a fast-forward: {stderr}"
    );
    let origin = fx
        .git_ok(
            "C3 origin",
            &b.dir,
            Some(&b.cred),
            &["ls-remote", b.url.as_str(), REF],
        )
        .await?;
    assert!(
        origin.starts_with(&a_commit),
        "C3 the origin is unchanged at A's commit: {origin}"
    );

    // C4: B fetches A's commit, rebases onto it, pushes and lands.
    fx.git_ok(
        "C4 B fetch",
        &b.dir,
        Some(&b.cred),
        &["fetch", "-q", "origin"],
    )
    .await?;
    let fetched = fx
        .git_ok("C4 B fetch", &b.dir, None, &["rev-parse", "origin/main"])
        .await?;
    assert_eq!(fetched, a_commit, "C4 B's fetch sees A's commit");
    fx.git_ok(
        "C4 B rebase",
        &b.dir,
        None,
        &[
            "-c",
            "user.name=yuki",
            "-c",
            "user.email=yuki@example.com",
            "rebase",
            "origin/main",
        ],
    )
    .await?;
    let b_commit = fx
        .git_ok("C4 B rebase", &b.dir, None, &["rev-parse", "HEAD"])
        .await?;
    fx.git_ok(
        "C4 B push",
        &b.dir,
        Some(&b.cred),
        &["push", "-q", b.url.as_str(), "HEAD:refs/heads/main"],
    )
    .await?;
    land(fx, &baseline, &b_commit, &a_commit, "C4 B land").await?;

    // C5: B reads A's proposal at the origin under its own credential.
    let view = fx
        .ok(
            "C5 B reads A's proposal",
            &b.cred,
            "vault.code.proposal_view",
            json!({"proposal_ref": a_landed.proposal}),
        )
        .await?;
    assert_eq!(
        view["operation_kind"],
        json!("received_files"),
        "C5 B reads A's proposal: {view}"
    );
    Ok(())
}

/// L4-06 PR 3 T2: a stale lease cannot publish after a cutover. The owner
/// cuts the served origin's authority to another writer, the live lease's
/// push is refused and the ref is unchanged, the owner cuts back to this
/// host's writer, and a fresh lease lands; the pre-cutover lease stays
/// refused.
#[test]
fn a_stale_lease_cannot_publish_after_a_cutover() -> TestResult {
    on_engine_stack(stale_lease_cutover)
}

async fn stale_lease_cutover() -> TestResult {
    let baseline = imported_baseline().await?;
    let fx = &baseline.fx;
    let a = device(&baseline, "device-a", &fx.device_a).await?;
    write_file(&a.dir.join("NOTES.md"), NOTES_V1, false)?;
    fx.git_ok("C1 A add", &a.dir, None, &["add", "-A"]).await?;
    fx.commit("C1 A commit", &a.dir, "owen", "device A notes")
        .await?;
    let before = fx
        .ok(
            "C1 authority get",
            &fx.owner,
            "vault.code.origin.authority.get",
            json!({"repo": SERVED_REPO}),
        )
        .await?;
    assert_eq!(
        before["authority"],
        Value::Null,
        "C1 no cutover yet: {before}"
    );
    let host = before["host"]
        .as_str()
        .ok_or("C1 authority get: this host names no machine id")?
        .to_owned();

    // C1: the owner cuts authority to another writer at the current epoch.
    let other = EntityId::now().to_hex();
    let cut = fx
        .ok(
            "C1 cutover",
            &fx.owner,
            "vault.code.origin.authority.set",
            json!({
                "repo": SERVED_REPO,
                "expected_epoch": before["authority"]["epoch"].clone(),
                "residence": "local-vault",
                "writer": other,
                "mirror": false,
            }),
        )
        .await?;
    let e1 = cut["authority"]["epoch"]
        .as_u64()
        .ok_or("C1 cutover: no authority epoch")?;
    assert_eq!(
        cut["authority"]["writer"],
        json!(other),
        "C1 cutover: {cut}"
    );

    // C2: A's push through its still-live lease is refused, and the origin
    // ref is unchanged.
    let refused = fx
        .git(
            &a.dir,
            Some(&a.cred),
            &["push", "-q", a.url.as_str(), "HEAD:refs/heads/main"],
        )
        .await?;
    let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(
        !refused.status.success(),
        "C2 A's push after the cutover is refused"
    );
    assert!(
        stderr.contains("another host writes") || stderr.contains("403"),
        "C2 the refusal is the door's: {stderr}"
    );
    let origin = fx
        .git_ok(
            "C2 origin",
            &a.dir,
            Some(&a.cred),
            &["ls-remote", a.url.as_str(), REF],
        )
        .await?;
    assert!(
        origin.starts_with(&baseline.source_commit),
        "C2 the origin ref is unchanged: {origin}"
    );

    // C3: the owner cuts back to this host's writer; a fresh lease lands.
    let back = fx
        .ok(
            "C3 cutover",
            &fx.owner,
            "vault.code.origin.authority.set",
            json!({
                "repo": SERVED_REPO,
                "expected_epoch": e1,
                "residence": "local-vault",
                "writer": host,
                "mirror": false,
            }),
        )
        .await?;
    let e2 = back["authority"]["epoch"]
        .as_u64()
        .ok_or("C3 cutover: no authority epoch")?;
    assert!(e2 > e1, "C3 the epoch advances: {back}");
    let b = device(&baseline, "device-b", &fx.device_b).await?;
    write_file(&b.dir.join("SKILL.md"), SKILL_V2, false)?;
    fx.git_ok("C3 B add", &b.dir, None, &["add", "-A"]).await?;
    let b_commit = fx
        .commit("C3 B commit", &b.dir, "yuki", "device B greets back")
        .await?;
    fx.git_ok(
        "C3 B push",
        &b.dir,
        Some(&b.cred),
        &["push", "-q", b.url.as_str(), "HEAD:refs/heads/main"],
    )
    .await?;
    land(
        fx,
        &baseline,
        &b_commit,
        &baseline.source_commit,
        "C3 B land",
    )
    .await?;

    // C4: A's ORIGINAL lease, claimed before C1, refuses a fast-forward
    // push. A first fetches B's landed commit through that lease and
    // rebases onto it, so git's own non-fast-forward check cannot be the
    // refusal.
    fx.git_ok(
        "C4 A fetch",
        &a.dir,
        Some(&a.cred),
        &["fetch", "-q", "origin"],
    )
    .await?;
    fx.git_ok(
        "C4 A rebase",
        &a.dir,
        None,
        &[
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "rebase",
            "origin/main",
        ],
    )
    .await?;
    let parent = fx
        .git_ok("C4 A rebase", &a.dir, None, &["rev-parse", "HEAD~1"])
        .await?;
    assert_eq!(parent, b_commit, "C4 A's commit sits on B's landed commit");
    let again = fx
        .git(
            &a.dir,
            Some(&a.cred),
            &["push", "-q", a.url.as_str(), "HEAD:refs/heads/main"],
        )
        .await?;
    let origin = fx
        .git_ok(
            "C4 origin",
            &b.dir,
            Some(&b.cred),
            &["ls-remote", b.url.as_str(), REF],
        )
        .await?;
    assert!(
        !again.status.success() && origin.starts_with(&b_commit),
        "C4 a lease claimed before the cutover still publishes after it: {} / {origin}",
        String::from_utf8_lossy(&again.stderr)
    );
    Ok(())
}

/// L4-06 PR 3 T3: offline work on a fenced lease is not lost (owner ruling
/// L4-06-FENCED = B: the refused push records nothing, the commit stays in
/// the device's worktree, and the device pushes it again under a new
/// lease; the engine adds nothing).
#[test]
fn offline_work_on_a_fenced_lease_is_not_lost() -> TestResult {
    on_engine_stack(fenced_lease_keeps_work)
}

async fn fenced_lease_keeps_work() -> TestResult {
    let baseline = imported_baseline().await?;
    let fx = &baseline.fx;
    let a = device(&baseline, "device-a", &fx.device_a).await?;
    let b = device(&baseline, "device-b", &fx.device_b).await?;

    // C1: A commits offline; B takes A's checkout over at its epoch.
    write_file(&a.dir.join("SKILL.md"), SKILL_V2, false)?;
    fx.git_ok("C1 A add", &a.dir, None, &["add", "-A"]).await?;
    let a_commit = fx
        .commit("C1 A commit", &a.dir, "owen", "device A greets back")
        .await?;
    let a_epoch = a
        .epoch
        .as_u64()
        .ok_or("C1 takeover: A's epoch is no number")?;
    let taken = fx
        .ok(
            "C1 takeover",
            &b.cred,
            "vault.code.checkout.takeover",
            json!({"checkout": a.checkout, "expected_epoch": a.epoch}),
        )
        .await?;
    assert_eq!(
        taken["epoch"],
        json!(a_epoch + 1),
        "C1 takeover moves the epoch: {taken}"
    );

    // C2: A's push through its old lease is refused; the origin is
    // unchanged; A's worktree still holds the commit.
    let refused = fx
        .git(
            &a.dir,
            Some(&a.cred),
            &["push", "-q", a.url.as_str(), "HEAD:refs/heads/main"],
        )
        .await?;
    assert!(
        !refused.status.success(),
        "C2 A's push on the fenced lease is refused"
    );
    let origin = fx
        .git_ok(
            "C2 origin",
            &b.dir,
            Some(&b.cred),
            &["ls-remote", b.url.as_str(), REF],
        )
        .await?;
    assert!(
        origin.starts_with(&baseline.source_commit),
        "C2 the origin ref is unchanged: {origin}"
    );
    let commit_arg = format!("{a_commit}^{{commit}}");
    fx.git_ok(
        "C2 worktree",
        &a.dir,
        None,
        &["cat-file", "-e", commit_arg.as_str()],
    )
    .await?;
    let head = fx
        .git_ok("C2 worktree", &a.dir, None, &["rev-parse", "HEAD"])
        .await?;
    assert_eq!(head, a_commit, "C2 A's worktree still holds the commit");
    assert!(
        fx.published("C2 no admission", &a_commit).await?.is_none(),
        "C2 the refused push records nothing"
    );

    // C3: A claims a new lease and pushes the SAME commit id through it.
    let task = fx.owner_task("device A retries the greeter skill")?;
    let checkout = EntityId::now().to_hex();
    let lease = fx
        .ok(
            "C3 A checkout claim",
            &a.cred,
            "vault.code.checkout.claim",
            json!({
                "checkout": checkout,
                "repo": baseline.snapshot,
                "task": task,
                "task_class": "edit",
                "ttl_seconds": 3600,
                "declared_idempotent": false,
            }),
        )
        .await?;
    let epoch = lease["epoch"].clone();
    let bind = fx
        .ok(
            "C3 A checkout bind",
            &a.cred,
            "vault.code.checkout.bind",
            json!({"repo": SERVED_REPO, "checkout": checkout, "epoch": epoch, "endpoint": fx.endpoint}),
        )
        .await?;
    let url = text("C3 A checkout bind", &bind, "remote_url")?;
    let refspec = format!("{a_commit}:{REF}");
    fx.git_ok(
        "C3 A push",
        &a.dir,
        Some(&a.cred),
        &["push", "-q", url, refspec.as_str()],
    )
    .await?;
    // `land` asserts the ingress new_oid is A's commit and its one
    // received_files proposal.
    land(
        fx,
        &baseline,
        &a_commit,
        &baseline.source_commit,
        "C3 A land",
    )
    .await?;
    Ok(())
}

/// L4-06 PR 3 T5 (ruling L4-06-OWNER-LEASE-PUSH): the owner's push on a
/// lease of his own that lapsed is refused. The owner cancels the TASK his
/// device's lease was claimed for, and the lease's fence holds for him as
/// it does for a run: nothing lands and nothing is published.
#[test]
fn an_owner_push_on_a_lapsed_lease_of_his_own_is_refused() -> TestResult {
    on_engine_stack(owner_lapsed_lease_refused)
}

async fn owner_lapsed_lease_refused() -> TestResult {
    let baseline = imported_baseline().await?;
    let fx = &baseline.fx;
    let a = device(&baseline, "device-a", &fx.device_a).await?;
    write_file(&a.dir.join("SKILL.md"), SKILL_V2, false)?;
    fx.git_ok("C1 A add", &a.dir, None, &["add", "-A"]).await?;
    let a_commit = fx
        .commit("C1 A commit", &a.dir, "owen", "device A greets back")
        .await?;

    // C2: the owner cancels the TASK A's lease was claimed for. A cancel is
    // an external effect the gate allows only under the owner's standing
    // cancel grant, which he mints first (task_authority_convergence.rs).
    let owner_proof = fx
        .vault
        .authenticate_owner(
            fx.owner_actor,
            &fx.owner_actor.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .map_err(|error| format!("C2 owner proof: {error:?}"))?;
    fx.vault
        .mint_standing_outbound_grant(
            &owner_proof,
            EntityId::from_bytes([0xC5; 16]).map_err(|_| "C2 cancel grant id")?,
            &oneiron::genui::GrantMintIntent {
                principal_ref: fx.owner_actor.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "cancel".to_owned(),
                origin_receipt_ref: None,
                scope: oneiron::genui::GrantMintIntentScope::VerbClass {
                    verb_class: oneiron::task_verb::sdk::AgentVerb::Cancel
                        .as_str()
                        .to_owned(),
                },
            },
        )
        .map_err(|error| format!("C2 cancel grant: {error:?}"))?;
    let cancelled = fx
        .vault
        .memory(fx.owner_actor, EdgeActorClass::Human)
        .cancel(oneiron::task_verb::TaskCancelTarget::Task(
            EntityId::from_hex(&a.task).map_err(|_| "C2 cancel: A's TASK id is no hex")?,
        ))
        .map_err(|error| format!("C2 cancel: {error:?}"))?;
    assert!(
        cancelled.effected,
        "C2 the owner's cancel of his own TASK takes effect: {cancelled:?}"
    );

    // C3: A's push through that lease is refused; nothing lands.
    let refused = fx
        .git(
            &a.dir,
            Some(&a.cred),
            &["push", "-q", a.url.as_str(), "HEAD:refs/heads/main"],
        )
        .await?;
    let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(
        !refused.status.success(),
        "C3 a push on a lease whose TASK is cancelled is refused: {stderr}"
    );
    assert!(
        stderr.contains("checkout lease is not live") || stderr.contains("403"),
        "C3 the refusal is the door's: {stderr}"
    );
    assert!(
        fx.published("C3 no admission", &a_commit).await?.is_none(),
        "C3 the refused push publishes nothing"
    );
    let origin = fx
        .git_ok(
            "C3 origin",
            &a.dir,
            Some(&a.cred),
            &["ls-remote", a.url.as_str(), REF],
        )
        .await?;
    assert!(
        origin.starts_with(&baseline.source_commit),
        "C3 the origin ref is unchanged: {origin}"
    );
    Ok(())
}

/// L4-06 PR 3 T4: a restart keeps proposals, review state and head. The
/// app, the server and the serving task are dropped and rebuilt on the
/// same vault dir with the same keystore; every `Arc<Vault>` is gone
/// before the reopen.
#[test]
fn a_restart_keeps_proposals_review_state_and_head() -> TestResult {
    on_engine_stack(restart_keeps_state)
}

async fn restart_keeps_state() -> TestResult {
    let mut baseline = imported_baseline().await?;
    let cred_a = baseline.fx.device_a.clone();
    let cred_b = baseline.fx.device_b.clone();
    let a = device(&baseline, "device-a", &cred_a).await?;
    let mut b = device(&baseline, "device-b", &cred_b).await?;

    // C1: A's edit lands.
    write_file(&a.dir.join("SKILL.md"), SKILL_V2, false)?;
    baseline
        .fx
        .git_ok("C1 A add", &a.dir, None, &["add", "-A"])
        .await?;
    let a_commit = baseline
        .fx
        .commit("C1 A commit", &a.dir, "owen", "device A greets back")
        .await?;
    baseline
        .fx
        .git_ok(
            "C1 A push",
            &a.dir,
            Some(&a.cred),
            &["push", "-q", a.url.as_str(), "HEAD:refs/heads/main"],
        )
        .await?;
    let a_landed = land(
        &baseline.fx,
        &baseline,
        &a_commit,
        &baseline.source_commit,
        "C1 A land",
    )
    .await?;

    // C2: record the pre-restart answers.
    let fx = &baseline.fx;
    let repos = fx
        .ok(
            "C2 repos.get",
            &fx.owner,
            "vault.code.repos.get",
            json!({"repo": baseline.code_repo}),
        )
        .await?;
    let proposal = fx
        .ok(
            "C2 proposal view",
            &fx.owner,
            "vault.code.proposal_view",
            json!({"proposal_ref": a_landed.proposal}),
        )
        .await?;
    assert_eq!(
        repos["green_revision"], a_landed.seal,
        "C2 green is A's sealed revision"
    );
    let observed = fx
        .ok(
            "C2 observe",
            &fx.owner,
            "vault.code.merge_queue.observe",
            json!({"repo": baseline.code_repo, "batches": a_landed.ingress["candidate"]["batch_refs"].clone()}),
        )
        .await?;
    let lease = fx
        .ok(
            "C2 checkout get",
            &fx.owner,
            "vault.code.checkout.get",
            json!({"checkout": b.checkout}),
        )
        .await?;
    assert_eq!(
        lease["value"]["state"],
        json!("active"),
        "C2 B's lease is active: {lease}"
    );
    let head = fx
        .git_ok(
            "C2 origin",
            &b.dir,
            Some(&b.cred),
            &["ls-remote", b.url.as_str(), REF],
        )
        .await?;
    assert!(
        head.starts_with(&a_commit),
        "C2 B's lease door names A's commit: {head}"
    );
    for (what, value) in [
        (
            "repos.get queue.green_commit",
            &repos["queue"]["green_commit"],
        ),
        ("observe green_commit", &observed["green_commit"]),
        (
            "observe green_export.tested_revision",
            &observed["green_export"]["tested_revision"],
        ),
        ("checkout.get epoch", &lease["value"]["epoch"]),
    ] {
        assert!(!value.is_null(), "C2 {what} is present before the restart");
    }

    // C3: restart on the same dir with the same keystore, and point B's
    // worktree at the new endpoint, same path.
    baseline.fx = baseline.fx.restart().await?;
    let suffix = b
        .url
        .split_once("/lease/")
        .ok_or("C3 B's lease URL names no lease")?
        .1
        .to_owned();
    b.url = format!("{}/lease/{suffix}", baseline.fx.endpoint);
    baseline
        .fx
        .git_ok(
            "C3 B set-url",
            &b.dir,
            None,
            &["remote", "set-url", "origin", b.url.as_str()],
        )
        .await?;

    // C4: every pre-restart answer still reads the same.
    let fx = &baseline.fx;
    let repos_after = fx
        .ok(
            "C4 repos.get",
            &fx.owner,
            "vault.code.repos.get",
            json!({"repo": baseline.code_repo}),
        )
        .await?;
    assert_eq!(
        repos_after["green_revision"], repos["green_revision"],
        "C4 green_revision is unchanged"
    );
    assert_eq!(
        repos_after["queue"]["green_commit"], repos["queue"]["green_commit"],
        "C4 green_commit is unchanged"
    );
    let proposal_after = fx
        .ok(
            "C4 proposal view",
            &fx.owner,
            "vault.code.proposal_view",
            json!({"proposal_ref": a_landed.proposal}),
        )
        .await?;
    assert_eq!(proposal_after, proposal, "C4 the proposal reads the same");
    let observed_after = fx
        .ok(
            "C4 observe",
            &fx.owner,
            "vault.code.merge_queue.observe",
            json!({"repo": baseline.code_repo, "batches": a_landed.ingress["candidate"]["batch_refs"].clone()}),
        )
        .await?;
    assert_eq!(
        observed_after["green_commit"], observed["green_commit"],
        "C4 observe names the same green"
    );
    assert_eq!(
        observed_after["green_export"]["tested_revision"],
        observed["green_export"]["tested_revision"],
        "C4 observe names the same tested revision"
    );
    let lease_after = fx
        .ok(
            "C4 checkout get",
            &fx.owner,
            "vault.code.checkout.get",
            json!({"checkout": b.checkout}),
        )
        .await?;
    assert_eq!(
        lease_after["value"]["epoch"], lease["value"]["epoch"],
        "C4 B's checkout keeps its epoch"
    );
    assert_eq!(
        lease_after["value"]["task"],
        json!(b.task),
        "C4 B's checkout keeps its TASK"
    );
    assert_eq!(
        lease_after["value"]["state"],
        json!("active"),
        "C4 B's checkout is still active: {lease_after}"
    );
    let head_after = fx
        .git_ok(
            "C4 origin",
            &b.dir,
            Some(&b.cred),
            &["ls-remote", b.url.as_str(), REF],
        )
        .await?;
    assert_eq!(head_after, head, "C4 the lease door answers the same head");
    let kept = fx
        .git_ok("C4 worktree", &a.dir, None, &["rev-parse", "HEAD"])
        .await?;
    assert_eq!(kept, a_commit, "C4 A's worktree still holds its commit");
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
