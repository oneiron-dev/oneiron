//! RSG-006's paid leg (ARCH-0069 `#broker-design`, ARCH-0053
//! `#training-fixture-cases`) on the real `oneiron-broker` binary, run as its
//! own OS user, and the vault's real custody door, against a local TLS fake
//! provider. The key is a synthetic sentinel, made fresh for each case, so no
//! binary holds it.
//!
//! - P2: a declared run's teacher call goes out once, with the key, and
//!   settles its exact usage. Its dispatch row names the broker's isolation.
//! - N4a: a call the run's admission refuses reads no key and sends nothing.
//! - N4b: a runner that holds only the handle calls the provider directly and
//!   carries no key. The key is nowhere in its environment, its files or its
//!   memory, and the broker's memory is closed to it.
//! - N5: a redirect off the provider's origin gets no second send, and a
//!   lookalike host gets no request at all.
//! - N11: a provider that echoes the key gets it back redacted.
//! - A provider set to `response_format = "none"` sends a JSON call with no
//!   `response_format`, as the direct transport does.
//!
//! Every refusal asserts the five checks: no provider send, no send with the
//! key, no key read at the door, no change in units used or reserved, and one
//! more denial row. No receipt row ever holds the key.
//!
//! P2 and N4b run again with the same-user child of `#broker-same-user-open`
//! (BROKER-MAC = A), which the runtime starts from the same binary. Its
//! receipts say `same_user`, and neither the runner nor the daemon that
//! started it can read its memory, though both share its uid. The child binds
//! no path and holds no listening socket, and a listener at the old child
//! socket path gets nothing: the daemon reaches the child only over the
//! channel it made at the start.
//!
//! The broker runs as the first uid of this user's `/etc/subuid` range, in a
//! user namespace that maps that uid and this one to themselves. A host that
//! cannot make such a namespace (no `unshare` or `newuidmap`, no range, or a
//! kernel that refuses) has each case say why and pass, unless
//! `ONEIRON_BROKER_FIXTURE=require`, which makes it fail instead. A broker
//! that does not start on a host that can always fails.
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use oneiron::llm::BrokerIsolation;
use oneiron::llm::run_admission::{
    BudgetLine, DeclaredTeachers, LeaseUnit, MemoryReceipts, RunDeclaration, RunDenied, RunEvent,
};
use oneiron::secret_custody::{CustodyTier, SECRET_SCOPE_READ, SecretBinding};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, Vault, VaultConfig,
};
use oneiron_broker::testing::{FakeProvider, FakeReply, SeenRequest};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{BROKER_EFFECTOR, DeclaredRun, KeyDoor, ModelRuntime, VaultKeyDoor};
use serde_json::json;
use zeroize::Zeroizing;

/// The vault secret the provider's key is registered under: the handle.
const HANDLE: &str = "provider-key";
const SMALL: &str = "paid/teacher-small@v1";
const LARGE: &str = "paid/teacher-large@v1";
/// What the runner child reads its task from. Unset, the child case is a
/// no-op, as it is in a normal test run.
const RUNNER_ENV: &str = "ONEIRON_BROKER_FIXTURE_RUNNER";

/// A fresh key for one case: made at run time, so neither this binary nor a
/// child that re-runs it holds the bytes.
fn sentinel() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("test-sentinel-{nanos:x}-{:x}", std::process::id())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// The first id of this user's range in `/etc/subuid` or `/etc/subgid`.
fn subordinate(file: &str, user: &str, id: u32) -> Result<u32, String> {
    let text = std::fs::read_to_string(file).map_err(|error| format!("{file}: {error}"))?;
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split(':');
            let (name, start, count) = (parts.next()?, parts.next()?, parts.next()?);
            let matches = name == user || name == id.to_string();
            let start: u32 = start.parse().ok()?;
            (matches && count.parse::<u32>().ok()? > 0).then_some(start)
        })
        .next()
        .ok_or_else(|| format!("{file} grants {user} no range"))
}

/// This user and the subordinate one the broker runs as, on a host that can
/// run a process as the second in a user namespace.
struct SecondUser {
    uid: u32,
    gid: u32,
    broker_uid: u32,
    broker_gid: u32,
}

impl SecondUser {
    /// The ids, once a trivial process ran as the second user; or why this
    /// host cannot.
    fn probe() -> Result<Self, String> {
        // A file this process makes carries its own uid and gid.
        let dir = tempfile::tempdir().map_err(|error| error.to_string())?;
        let meta = std::fs::metadata(dir.path()).map_err(|error| error.to_string())?;
        let (uid, gid) = (meta.uid(), meta.gid());
        let user = Command::new("id")
            .arg("-un")
            .output()
            .map_err(|error| format!("id -un: {error}"))?;
        let user = String::from_utf8_lossy(&user.stdout).trim().to_owned();
        let second = Self {
            uid,
            gid,
            broker_uid: subordinate("/etc/subuid", &user, uid)?,
            broker_gid: subordinate("/etc/subgid", &user, gid)?,
        };
        let ran = second
            .command("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| format!("unshare: {error}"))?;
        if !ran.status.success() {
            return Err(format!(
                "unshare as uid {} failed ({}): {}",
                second.broker_uid,
                ran.status,
                String::from_utf8_lossy(&ran.stderr).trim()
            ));
        }
        Ok(second)
    }

    /// `program` to run as the second user, with a bare environment.
    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let Self {
            uid,
            gid,
            broker_uid,
            broker_gid,
        } = self;
        let mut command = Command::new("unshare");
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .arg("--user")
            // One `--map-user` and one `--map-users`: util-linux 2.39 (Ubuntu
            // 24.04) keeps only the last `--map-users`, which would leave this
            // user unmapped (65534) to the broker's peer check.
            .arg(format!("--map-user={uid}"))
            .arg(format!("--map-users={broker_uid}:{broker_uid}:1"))
            .arg(format!("--map-group={gid}"))
            .arg(format!("--map-groups={broker_gid}:{broker_gid}:1"))
            .arg(format!("--setuid={broker_uid}"))
            .arg(format!("--setgid={broker_gid}"))
            .arg("--")
            .arg(program);
        command
    }
}

/// The broker binary, run as a uid of its own.
struct Broker {
    child: Child,
    socket: PathBuf,
    uid: u32,
    _dir: tempfile::TempDir,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Broker {
    /// Starts the broker as `second`'s subordinate uid, serving this
    /// process's uid and trusting `ca_pem`.
    fn start(second: &SecondUser, ca_pem: &[u8]) -> Result<Self, String> {
        // Under /tmp: the second user must pass through every directory above
        // these files, and a fleet job's TMPDIR sits in a home it cannot enter.
        let dir = tempfile::Builder::new()
            .prefix("broker-fixture-")
            .tempdir_in("/tmp")
            .map_err(|error| error.to_string())?;
        set_mode(dir.path(), 0o755);
        // The broker's user reads the binary and the CA from here, and makes
        // its socket in a directory it may write.
        let binary = dir.path().join("oneiron-broker");
        std::fs::copy(env!("CARGO_BIN_EXE_oneiron-broker"), &binary)
            .map_err(|error| error.to_string())?;
        set_mode(&binary, 0o755);
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, ca_pem).map_err(|error| error.to_string())?;
        set_mode(&ca, 0o644);
        let sockets = dir.path().join("socket");
        std::fs::create_dir(&sockets).map_err(|error| error.to_string())?;
        set_mode(&sockets, 0o777);
        let socket = sockets.join("broker.sock");
        let mut child = second
            .command(&binary)
            .arg("serve")
            .arg("--socket")
            .arg(&socket)
            .arg("--client-uid")
            .arg(second.uid.to_string())
            .arg("--extra-roots")
            .arg(&ca)
            .arg("--timeout-secs")
            .arg("20")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("unshare: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            if let Ok(Some(status)) = child.try_wait() {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                return Err(format!("the broker exited ({status}): {}", stderr.trim()));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                return Err("the broker made no socket in 10 s".to_owned());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(Self {
            child,
            socket,
            uid: second.broker_uid,
            _dir: dir,
        })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

/// The real custody door, counted.
struct CountingDoor {
    door: VaultKeyDoor,
    reads: AtomicUsize,
}

impl KeyDoor for CountingDoor {
    fn check(&self, name: &str) -> anyhow::Result<()> {
        self.door.check(name)
    }

    fn read(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.door.read(name)
    }
}

/// Where the fixture's broker runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// As a second OS user (OSH-2).
    SeparateUser,
    /// As the runtime's own child, under this process's uid.
    SameUser,
}

struct Fixture {
    key: String,
    fake: FakeProvider,
    /// The separate-user broker; `None` for the runtime's same-user child.
    broker: Option<Broker>,
    /// The `[broker]` table the runtime was built with.
    table: String,
    keys: Arc<CountingDoor>,
    receipts: Arc<MemoryReceipts>,
    runtime: ModelRuntime,
    _vault_dir: tempfile::TempDir,
    _files: tempfile::TempDir,
    /// A same-user fixture's hold on [`ONE_CHILD`].
    _one_child: Option<std::sync::MutexGuard<'static, ()>>,
}

/// Held while a same-user child of this process may live, so that, even with
/// every case in one process, a scan finds only the child of the case that
/// holds it.
static ONE_CHILD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_child() -> std::sync::MutexGuard<'static, ()> {
    ONE_CHILD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The fixture, or `None` (with the reason printed) where this host cannot
/// run a process as a second user.
fn fixture() -> Option<Fixture> {
    fixture_in(Mode::SeparateUser)
}

/// The fixture with its broker run as `mode` says. A same-user child needs
/// no second user, so that fixture is never skipped.
fn fixture_in(mode: Mode) -> Option<Fixture> {
    let second = match mode {
        Mode::SeparateUser => match SecondUser::probe() {
            Ok(second) => Some(second),
            Err(reason) => {
                let reason = format!("this host cannot run a second user: {reason}");
                assert!(
                    std::env::var("ONEIRON_BROKER_FIXTURE").as_deref() != Ok("require"),
                    "{reason}"
                );
                eprintln!("skipped: {reason}");
                return None;
            }
        },
        Mode::SameUser => None,
    };
    let one = (mode == Mode::SameUser).then(one_child);
    let key = sentinel();
    let fake = FakeProvider::start(FakeReply::json(401, &json!({})));
    answer_with_key(&fake, &key, "an answer");
    let files = tempfile::tempdir().expect("fixture dir");
    let (broker, table) = match &second {
        Some(second) => {
            let broker = Broker::start(second, fake.ca_pem()).unwrap_or_else(|reason| {
                panic!("the broker did not start as a second user: {reason}")
            });
            let table = separate_user_table(&broker);
            (Some(broker), table)
        }
        None => {
            let ca = files.path().join("ca.pem");
            std::fs::write(&ca, fake.ca_pem()).expect("ca");
            (None, same_user_table(&ca))
        }
    };
    let vault_dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::default()).expect("vault"));
    vault
        .register_test_secret(
            HANDLE,
            key.as_bytes(),
            vec![SecretBinding {
                effector: BROKER_EFFECTOR.to_owned(),
                tier_ceiling: CustodyTier::T0Doored,
                scopes: vec![SECRET_SCOPE_READ.to_owned()],
            }],
            1_700_000_000,
        )
        .expect("register the key");
    let keys = Arc::new(CountingDoor {
        door: VaultKeyDoor::new(vault),
        reads: AtomicUsize::new(0),
    });
    let receipts = Arc::new(MemoryReceipts::default());
    let runtime = runtime(fake.origin(), &table, &keys, &receipts, "");
    Some(Fixture {
        key,
        fake,
        broker,
        table,
        keys,
        receipts,
        runtime,
        _vault_dir: vault_dir,
        _files: files,
        _one_child: one,
    })
}

/// The `[broker]` table of a broker run as a second user.
fn separate_user_table(broker: &Broker) -> String {
    format!(
        "[broker]\nsocket = \"{}\"\nuid = {}\n",
        broker.socket.display(),
        broker.uid
    )
}

/// The `[broker]` table of a same-user child run from the built binary,
/// trusting `ca`.
fn same_user_table(ca: &Path) -> String {
    format!(
        "[broker]\nprogram = \"{}\"\nextra_roots = [\"{}\"]\n",
        env!("CARGO_BIN_EXE_oneiron-broker"),
        ca.display()
    )
}

/// A runtime whose `paid` provider at `base_url` sends through the broker
/// `table` names, with the extra `provider` lines.
fn runtime(
    base_url: &str,
    table: &str,
    keys: &Arc<CountingDoor>,
    receipts: &Arc<MemoryReceipts>,
    provider: &str,
) -> ModelRuntime {
    let config = ModelsConfig::from_toml(
        &format!(
            r#"
[providers.paid]
kind = "openai-compat"
base_url = "{base_url}"
key_secret = "{HANDLE}"
revision = "v1"
timeout_secs = 20
{provider}
[roles.checker]
rungs = [{{ model = "paid:teacher-small" }}, {{ model = "paid:teacher-large" }}]

{table}"#,
        ),
        None,
    )
    .expect("models config");
    let keys: Arc<dyn KeyDoor> = keys.clone();
    ModelRuntime::build_with_keys(Some(&config), Some(keys)).with_receipts(receipts.clone())
}

/// The fake answers a call that carries `key` with `text`, and anything
/// else with 401: it counts only keyed calls as served.
fn answer_with_key(fake: &FakeProvider, key: &str, text: &str) {
    let expected = format!("Bearer {key}");
    let text = text.to_owned();
    fake.respond_with(move |request| {
        if request.header("authorization") == Some(expected.as_str()) {
            chat_answer(&text)
        } else {
            FakeReply::json(401, &json!({"error": {"message": "no key"}}))
        }
    });
}

/// An OpenAI-compatible answer: 3 tokens in, 1 out.
fn chat_answer(text: &str) -> FakeReply {
    FakeReply::json(
        200,
        &json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "model": "teacher-small",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}
        }),
    )
}

fn request(model: &str, text: &str) -> LlmRequest {
    LlmRequest {
        model: ModelId::new(model).expect("model id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("answer".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text: text.into() }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

fn text_of(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// What every refusal must leave as it was.
struct Before {
    sends: usize,
    keyed: usize,
    reads: usize,
    used: u64,
    reserved: u64,
    denials: usize,
}

impl Fixture {
    /// A run that declares the small teacher on a line of `limit` units,
    /// reserving 6 per call.
    fn run(&self, name: &str, limit: u64) -> DeclaredRun {
        self.run_on(&self.runtime, name, limit)
    }

    fn run_on(&self, runtime: &ModelRuntime, name: &str, limit: u64) -> DeclaredRun {
        let declaration = RunDeclaration::declared(BudgetLine {
            limit_units: limit,
            reserve_units: 6,
            unit: LeaseUnit::tokens(),
        })
        .with_teachers(
            DeclaredTeachers::new(
                [ModelId::new(SMALL).expect("model id")],
                [],
                "student",
                "distillation",
            )
            .expect("teachers"),
        );
        runtime.declared_run(name, declaration, None)
    }

    fn keyed(&self, seen: &[SeenRequest]) -> usize {
        seen.iter()
            .filter(|request| {
                request
                    .headers
                    .iter()
                    .any(|(_, value)| value.contains(&self.key))
            })
            .count()
    }

    fn reads(&self) -> usize {
        self.keys.reads.load(Ordering::SeqCst)
    }

    fn denials(&self) -> usize {
        self.receipts
            .rows()
            .iter()
            .filter(|row| matches!(row.event, RunEvent::Denied { .. }))
            .count()
    }

    fn before(&self, run: &DeclaredRun) -> Before {
        let seen = self.fake.seen();
        let read = run.admission().read();
        Before {
            sends: seen.len(),
            keyed: self.keyed(&seen),
            reads: self.reads(),
            used: read.used_units,
            reserved: read.reserved_units,
            denials: self.denials(),
        }
    }

    fn assert_refused_cleanly(&self, run: &DeclaredRun, before: &Before) {
        let seen = self.fake.seen();
        assert_eq!(seen.len(), before.sends, "a send reached the provider");
        assert_eq!(self.keyed(&seen), before.keyed, "a send carried the key");
        assert_eq!(self.reads(), before.reads, "the key was read at the door");
        let read = run.admission().read();
        assert_eq!(read.used_units, before.used, "units were spent");
        assert_eq!(read.reserved_units, before.reserved, "a reservation leaked");
        assert_eq!(self.denials(), before.denials + 1, "one denial row");
        self.assert_no_key_in_receipts();
    }

    /// The broker's pid: the second user's process, or the runtime's child,
    /// which a call has started.
    fn broker_pid(&self) -> u32 {
        match &self.broker {
            Some(broker) => broker.pid(),
            None => child_broker_pid().expect("the runtime started its broker child"),
        }
    }

    /// No receipt row holds the key, raw or base64.
    fn assert_no_key_in_receipts(&self) {
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.key);
        for row in self.receipts.rows() {
            let row = serde_json::to_string(&row).expect("receipt json");
            assert!(!row.contains(&self.key), "the key is in a receipt: {row}");
            assert!(!row.contains(encoded.trim_end_matches('=')));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn p2_a_declared_teacher_call_goes_out_once_with_the_key_and_settles_its_usage() {
    p2(Mode::SeparateUser).await;
}

/// BROKER-MAC: the same call through the same-user child works the same, and
/// its receipt says `same_user`.
#[tokio::test(flavor = "multi_thread")]
async fn p2_same_user_the_child_sends_the_call_and_its_receipt_says_so() {
    p2(Mode::SameUser).await;
}

async fn p2(mode: Mode) {
    let Some(f) = fixture_in(mode) else { return };
    let isolation = match mode {
        Mode::SeparateUser => BrokerIsolation::SeparateUser,
        Mode::SameUser => BrokerIsolation::SameUser,
    };
    // The owner's status names the mode, and the same-user child's badge.
    let provider = &f.runtime.status().providers[0];
    assert_eq!(
        (provider.broker_isolation, provider.unproven),
        (Some(isolation), mode == Mode::SameUser)
    );
    let run = f.run("p2", 20);
    let answer = run
        .generate(SMALL, request(SMALL, "hi"))
        .await
        .expect("answered through the broker");
    assert_eq!(text_of(&answer.message), "an answer");
    let seen = f.fake.seen();
    assert_eq!(seen.len(), 1, "one send");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {}", f.key).as_str()),
        "the broker added the key"
    );
    assert_eq!(seen[0].path, "/v1/chat/completions");
    assert_eq!(f.reads(), 1, "one key read at the door");
    let read = run.admission().read();
    assert_eq!(
        (read.used_units, read.reserved_units),
        (4, 0),
        "settled 3 + 1"
    );
    // The permit bound the digest of exactly the bytes that arrived.
    let digest = oneiron_broker::request_digest(
        "POST",
        "/v1/chat/completions",
        &[("content-type".to_owned(), "application/json".to_owned())],
        &seen[0].body,
    );
    let rows = f.receipts.rows();
    assert!(
        rows.iter().any(|row| matches!(
            &row.event,
            RunEvent::Dispatched {
                request_digest,
                broker_isolation: Some(named),
                answered: true,
                ..
            } if *request_digest == digest && *named == isolation
        )),
        "{rows:?}"
    );
    assert!(rows.iter().any(|row| matches!(
        &row.event,
        RunEvent::Admitted(facts) if facts.rules_enforced && facts.subject == SMALL
    )));
    assert!(
        rows.iter()
            .any(|row| matches!(row.event, RunEvent::Settled { units: 4, .. }))
    );
    f.assert_no_key_in_receipts();
}

#[tokio::test(flavor = "multi_thread")]
async fn n4a_a_call_the_run_does_not_admit_reads_no_key_and_sends_nothing() {
    let Some(f) = fixture() else { return };
    // An undeclared teacher at the same broker provider.
    let run = f.run("n4a-teacher", 20);
    let before = f.before(&run);
    let refused = run.generate(LARGE, request(LARGE, "hi")).await;
    assert!(refused.is_err());
    f.assert_refused_cleanly(&run, &before);

    // A route picked through a param.
    let mut routed = request(SMALL, "hi");
    routed
        .params
        .insert("provider".to_owned(), json!("elsewhere"));
    let before = f.before(&run);
    assert!(run.generate(SMALL, routed).await.is_err());
    f.assert_refused_cleanly(&run, &before);

    // A call past the run's line: the first one spends 4 of 6, and the
    // second cannot reserve its 6.
    let run = f.run("n4a-budget", 6);
    run.generate(SMALL, request(SMALL, "hi"))
        .await
        .expect("the first call fits");
    let before = f.before(&run);
    assert!(run.generate(SMALL, request(SMALL, "hi")).await.is_err());
    f.assert_refused_cleanly(&run, &before);
    let denied: Vec<RunDenied> = f
        .receipts
        .rows()
        .into_iter()
        .filter_map(|row| match row.event {
            RunEvent::Denied { reason, .. } => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        matches!(
            denied.as_slice(),
            [
                RunDenied::UndeclaredTeacher { .. },
                RunDenied::RouteOverride { .. },
                RunDenied::Budget { .. }
            ]
        ),
        "{denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn n5_a_redirect_gets_no_second_send_and_a_lookalike_host_gets_nothing() {
    let Some(f) = fixture() else { return };
    let elsewhere = FakeProvider::start(chat_answer("moved"));
    let location = format!("{}/v1/chat/completions", elsewhere.origin());
    f.fake.respond_with(move |_| FakeReply {
        status: 307,
        headers: vec![("location".to_owned(), location.clone())],
        body: Vec::new(),
    });
    let run = f.run("n5-redirect", 20);
    assert!(run.generate(SMALL, request(SMALL, "hi")).await.is_err());
    assert_eq!(f.fake.seen().len(), 1, "the one send");
    assert_eq!(
        elsewhere.connections(),
        0,
        "no second send, with or without the key"
    );

    // `localhost` reaches the same fake, whose certificate names only
    // 127.0.0.1: the TLS check fails before any request is written.
    let lookalike = f.fake.origin().replace("127.0.0.1", "localhost");
    let runtime = runtime(&lookalike, &f.table, &f.keys, &f.receipts, "");
    let run = runtime.declared_run(
        "n5-lookalike",
        RunDeclaration::declared(BudgetLine {
            limit_units: 20,
            reserve_units: 6,
            unit: LeaseUnit::tokens(),
        })
        .with_teachers(
            DeclaredTeachers::new(
                [ModelId::new(SMALL).expect("model id")],
                [],
                "student",
                "distillation",
            )
            .expect("teachers"),
        ),
        None,
    );
    let connections = f.fake.connections();
    assert!(run.generate(SMALL, request(SMALL, "hi")).await.is_err());
    assert!(
        f.fake.connections() > connections,
        "the lookalike reached the host"
    );
    assert_eq!(f.fake.seen().len(), 1, "and sent it no request");
    f.assert_no_key_in_receipts();
}

/// Engine ruling 2026-10-14 (NIGHTLY-SWITCH), Sol r3: a `key_secret`
/// provider set to `response_format = "none"` sends a JSON call through the
/// broker with no `response_format`; the default still sends the schema.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_set_to_no_schema_sends_no_response_format_through_the_broker() {
    let Some(f) = fixture() else { return };
    answer_with_key(&f.fake, &f.key, "{}");
    for (line, sends) in [("", true), ("response_format = \"none\"", false)] {
        let runtime = runtime(f.fake.origin(), &f.table, &f.keys, &f.receipts, line);
        let mut call = request(SMALL, "extract");
        call.envelope.response_format = ResponseFormat::Json {
            schema: json!({"type": "object"}),
        };
        f.run_on(&runtime, &format!("schema-{sends}"), 20)
            .generate(SMALL, call)
            .await
            .expect("answered through the broker");
        let seen = f.fake.seen();
        let body: serde_json::Value =
            serde_json::from_slice(&seen.last().expect("a send").body).expect("a JSON body");
        assert_eq!(body.get("response_format").is_some(), sends, "{body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn n11_a_key_the_provider_echoes_comes_back_redacted() {
    let Some(f) = fixture() else { return };
    let run = f.run("n11", 20);
    // An answer that quotes the key, raw and base64.
    f.fake.respond_with(|request| {
        let auth = request
            .header("authorization")
            .unwrap_or_default()
            .to_owned();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&auth);
        chat_answer(&format!("you sent {auth} ({encoded})"))
    });
    let answer = run
        .generate(SMALL, request(SMALL, "hi"))
        .await
        .expect("answered");
    let text = text_of(&answer.message);
    assert!(!text.contains(&f.key), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(&f.key);
    assert!(!text.contains(encoded.trim_end_matches('=')), "{text}");

    // An error that echoes it, in the body and in a header.
    f.fake.respond_with(|request| {
        let auth = request
            .header("authorization")
            .unwrap_or_default()
            .to_owned();
        FakeReply {
            status: 401,
            headers: vec![("x-echo".to_owned(), auth.clone())],
            body: json!({"error": {"message": format!("invalid key {auth}")}})
                .to_string()
                .into_bytes(),
        }
    });
    let error = run
        .generate(SMALL, request(SMALL, "hi"))
        .await
        .expect_err("refused by the provider");
    assert!(!format!("{error:?} {error}").contains(&f.key));
    assert_eq!(f.fake.seen().len(), 2);
    f.assert_no_key_in_receipts();
}

#[tokio::test(flavor = "multi_thread")]
async fn n4b_a_runner_holding_the_handle_carries_no_key() {
    n4b(Mode::SeparateUser).await;
}

/// BROKER-MAC: a runner of the same user as the child broker still carries
/// no key and cannot read or trace the child.
#[tokio::test(flavor = "multi_thread")]
async fn n4b_same_user_a_runner_of_the_childs_user_cannot_read_it() {
    n4b(Mode::SameUser).await;
}

async fn n4b(mode: Mode) {
    let Some(f) = fixture_in(mode) else { return };
    // The daemon's own call goes out with the key first.
    let run = f.run("n4b", 20);
    run.generate(SMALL, request(SMALL, "hi"))
        .await
        .expect("the daemon's call");
    let reads = f.reads();
    let read = run.admission().read();
    let rows = f.receipts.rows().len();

    // The runner: this test binary again, with a clean environment, its own
    // empty directory, and only the handle.
    let workdir = tempfile::tempdir().expect("runner dir");
    let ca = workdir.path().join("ca.pem");
    std::fs::write(&ca, f.fake.ca_pem()).expect("ca");
    let broker = f.broker_pid();
    let mut runner = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "broker_paid_leg::n4b_runner", "--nocapture"])
        .env_clear()
        .env(
            RUNNER_ENV,
            format!(
                "{}\n{}\n{}\n{}",
                f.fake.origin(),
                HANDLE,
                ca.display(),
                broker
            ),
        )
        .current_dir(workdir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("runner");
    let mut lines = BufReader::new(runner.stdout.take().expect("stdout")).lines();
    let mut report = Vec::new();
    for line in lines.by_ref() {
        let line = line.expect("runner line");
        let done = line == "RUNNER DONE";
        report.push(line);
        if done {
            break;
        }
    }
    assert!(
        report.iter().any(|line| line == "BROKER ENVIRON DENIED")
            && report.iter().any(|line| line == "BROKER MEM DENIED"),
        "the runner read the broker: {report:?}"
    );
    // It was the live broker that refused.
    assert!(alive(broker), "the broker is gone");
    assert_eq!(f.broker_pid(), broker);
    // The second user here lives in a user namespace this uid made, and a
    // namespace's maker may trace inside it, so only the same-user child's
    // trace check says something about the broker.
    if mode == Mode::SameUser {
        assert!(
            report.iter().any(|line| line == "BROKER PTRACE DENIED"),
            "the runner could trace the broker: {report:?}"
        );
    }
    assert!(
        report.iter().any(|line| line == "SENT 401"),
        "the provider served the runner: {report:?}"
    );

    // While it waits, nothing of it holds the key.
    let pid = runner.id();
    let key = f.key.as_bytes();
    let environ = std::fs::read(format!("/proc/{pid}/environ")).expect("runner environ");
    assert!(
        !contains(&environ, key),
        "the key is in the runner's environment"
    );
    for entry in walk(workdir.path()) {
        let bytes = std::fs::read(&entry).expect("runner file");
        assert!(!contains(&bytes, key), "the key is in {}", entry.display());
    }
    let scanned = scan_memory(pid, key);
    assert!(scanned > 0, "no runner memory was readable");
    drop(runner.stdin.take());
    // Drained to the end, so the harness's last lines never meet a closed pipe.
    lines.for_each(drop);
    assert!(runner.wait().expect("runner exit").success());

    // Its direct call reached the provider without the key, through no door.
    let seen = f.fake.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(f.keyed(&seen), 1, "only the daemon's call carried the key");
    assert!(!contains(&format!("{:?}", seen[1]).into_bytes(), key));
    assert_eq!(f.reads(), reads, "the runner's call read no key");
    let now = run.admission().read();
    assert_eq!(
        (now.used_units, now.reserved_units),
        (read.used_units, read.reserved_units)
    );
    // The daemon never saw the runner's call, so it wrote no row for it.
    assert_eq!(f.receipts.rows().len(), rows);
    f.assert_no_key_in_receipts();
}

/// The runner child of `n4b_a_runner_holding_the_handle_carries_no_key`: a
/// no-op unless that case started it.
#[test]
fn n4b_runner() {
    let Ok(task) = std::env::var(RUNNER_ENV) else {
        return;
    };
    let mut task = task.lines();
    let (origin, handle, ca, broker) = (
        task.next().expect("origin"),
        task.next().expect("handle"),
        task.next().expect("ca"),
        task.next().expect("broker pid"),
    );
    // The broker is another user, or a same-user child that closed itself:
    // its environment and memory are closed, and it cannot be traced.
    // Reading `mem` needs a mapped address, so a `mem` that opens is open.
    // Only a refusal counts as closed: a broker that is gone proves nothing.
    for (what, path) in [("ENVIRON", "environ"), ("MEM", "mem")] {
        let state = match std::fs::File::open(format!("/proc/{broker}/{path}")) {
            Ok(_) if path == "mem" => Ok(()),
            Ok(mut file) => file.read(&mut [0; 1]).map(drop),
            Err(error) => Err(error),
        };
        println!("BROKER {what} {}", closing(state));
    }
    let traced = broker
        .parse::<u32>()
        .map_err(std::io::Error::other)
        .and_then(seize);
    println!("BROKER PTRACE {}", closing(traced));
    // A direct call with what the runner holds: the handle, not the key.
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(ca).expect("ca")).expect("ca pem"),
        )
        .build()
        .expect("client");
    let status = client
        .post(format!("{origin}/v1/chat/completions"))
        .header("authorization", format!("Bearer {handle}"))
        .json(&json!({"model": "teacher-small", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .map(|reply| reply.status().as_u16())
        .unwrap_or_default();
    println!("SENT {status}");
    println!("RUNNER DONE");
    std::io::stdout().flush().expect("flush");
    // Held open until the case has scanned this process.
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

/// Reads every readable mapping of `pid` and asserts `needle` is in none of
/// them; returns the bytes read.
fn scan_memory(pid: u32, needle: &[u8]) -> usize {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("maps");
    let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).expect("runner mem");
    let mut scanned = 0;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(perms)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !perms.starts_with('r') || line.ends_with("[vvar]") || line.ends_with("[vsyscall]") {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let Ok(len) = usize::try_from(end - start) else {
            continue;
        };
        let mut bytes = vec![0; len];
        if mem.seek(SeekFrom::Start(start)).is_err() || mem.read_exact(&mut bytes).is_err() {
            continue;
        }
        assert!(
            !contains(&bytes, needle),
            "the key is in the runner's memory at {range}"
        );
        scanned += len;
    }
    scanned
}

/// BROKER-MAC: the same-user child shares the daemon's uid, so only its own
/// closing keeps its memory from the daemon. The daemon, its parent, can open
/// and trace a child that did not close itself, and not the broker.
#[tokio::test(flavor = "multi_thread")]
async fn same_user_the_child_is_closed_to_the_daemon_that_started_it() {
    let Some(f) = fixture_in(Mode::SameUser) else {
        return;
    };
    f.run("closed", 20)
        .generate(SMALL, request(SMALL, "hi"))
        .await
        .expect("the child's call");
    let mut open = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .spawn()
        .expect("an open child");
    let control =
        std::fs::File::open(format!("/proc/{}/mem", open.id())).is_ok() && seize(open.id()).is_ok();
    let _ = open.kill();
    let _ = open.wait();
    if !control {
        let reason = "this host closes a child's memory to its parent, so it cannot tell the broker's own closing";
        assert!(
            std::env::var("ONEIRON_BROKER_FIXTURE").as_deref() != Ok("require"),
            "{reason}"
        );
        eprintln!("skipped: {reason}");
        return;
    }
    let pid = f.broker_pid();
    for path in ["mem", "environ"] {
        let opened = std::fs::File::open(format!("/proc/{pid}/{path}")).map(drop);
        assert_eq!(closing(opened), "DENIED", "the child's {path}");
    }
    assert_eq!(closing(seize(pid)), "DENIED", "a trace of the child");
    // It was the live broker child that refused.
    assert!(alive(pid), "the child is gone");
    assert_eq!(child_broker_pid(), Some(pid));
}

/// How a probe of the broker's memory ended: `DENIED` only for a refusal.
fn closing(probe: std::io::Result<()>) -> &'static str {
    match probe {
        Ok(()) => "OPEN",
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => "DENIED",
        Err(_) => "FAILED",
    }
}

/// The pid of this process's one live `oneiron-broker` child under its own
/// uid: the runtime's same-user child, while [`ONE_CHILD`] is held.
fn child_broker_pid() -> Option<u32> {
    let parent = std::process::id().to_string();
    let uid = std::fs::metadata("/proc/self").ok()?.uid().to_string();
    let mut children: Vec<u32> = std::fs::read_dir("/proc")
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            // `pid (comm) state ppid …`: comm may hold spaces and parentheses.
            let (head, rest) = stat.rsplit_once(')')?;
            let mut fields = rest.split_whitespace();
            let (state, ppid) = (fields.next()?, fields.next()?);
            let status = std::fs::read_to_string(entry.path().join("status")).ok()?;
            let owner = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))?
                .split_whitespace()
                .next()?;
            (head.ends_with("(oneiron-broker")
                && ppid == parent
                && owner == uid
                && !matches!(state, "Z" | "X"))
            .then_some(pid)
        })
        .collect();
    assert!(children.len() <= 1, "broker children {children:?}");
    children.pop()
}

/// Whether `pid` is a process that has not exited: a zombie's memory files
/// refuse like a closed process's do.
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| !matches!(state, "Z" | "X"))
    })
}

/// Traces `pid`, or why not. A seize stops nothing, and a seized process is
/// let go when this one ends.
fn seize(pid: u32) -> std::io::Result<()> {
    let pid = libc::pid_t::try_from(pid).map_err(std::io::Error::other)?;
    // SAFETY: PTRACE_SEIZE reads and writes no memory through its null
    // address and data.
    let seized = unsafe {
        libc::ptrace(
            libc::PTRACE_SEIZE,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if seized == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// What a channel case's runner reads its case from. Unset, the runner is a
/// no-op, as it is in a normal test run.
const CHANNEL_RUNNER_ENV: &str = "ONEIRON_BROKER_CHANNEL_RUNNER";

/// BROKER-MAC: the same-user child binds no path and holds no listening
/// socket; it takes its calls over the channel the daemon made. The case runs
/// in a user and network namespace of its own, where every Unix socket is the
/// case's or the child's, so the child's own sockets can be told apart.
#[test]
fn same_user_the_child_binds_no_path_and_holds_no_listener() {
    if let Err(reason) = own_network() {
        let reason = format!("this host cannot give a case its own network: {reason}");
        assert!(
            std::env::var("ONEIRON_BROKER_FIXTURE").as_deref() != Ok("require"),
            "{reason}"
        );
        eprintln!("skipped: {reason}");
        return;
    }
    run_channel_case("census", true);
}

/// BROKER-MAC: a listener of this uid at the old child socket path, put
/// there after the child served, gets no connection and no bytes during a
/// full paid call, which the real child sends.
#[test]
fn same_user_a_listener_at_the_old_child_path_gets_nothing() {
    run_channel_case("impostor", false);
}

/// Runs the channel `case` in this test binary again, with a temporary
/// directory of its own, inside a new user and network namespace when
/// `namespace`, and asserts it passed.
fn run_channel_case(case: &str, namespace: bool) {
    // Under /tmp: the old child socket path below it must fit a Unix socket
    // address, which a fleet job's long TMPDIR could overrun.
    let tmp = tempfile::Builder::new()
        .prefix("broker-channel-")
        .tempdir_in("/tmp")
        .expect("runner tmp");
    let exe = std::env::current_exe().expect("test binary");
    let mut runner = if namespace {
        let mut unshare = Command::new("unshare");
        unshare
            .args(["--user", "--map-root-user", "--net", "--"])
            .arg(&exe);
        unshare
    } else {
        Command::new(&exe)
    };
    runner
        .args(["--exact", "broker_paid_leg::channel_runner", "--nocapture"])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .env("TMPDIR", tmp.path())
        .env(CHANNEL_RUNNER_ENV, case)
        .stdin(Stdio::null());
    let ran = runner.output().expect("runner");
    let (stdout, stderr) = (
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr),
    );
    assert!(
        ran.status.success() && stdout.lines().any(|line| line == "RUNNER DONE"),
        "the {case} case failed ({}):\n{stdout}\n{stderr}",
        ran.status
    );
}

/// Whether this user can make a user and network namespace and bring its
/// loopback up, or why not.
fn own_network() -> Result<(), String> {
    let ran = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .args(["ip", "link", "set", "lo", "up"])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("unshare: {error}"))?;
    if ran.status.success() {
        Ok(())
    } else {
        Err(format!(
            "unshare --net failed ({}): {}",
            ran.status,
            String::from_utf8_lossy(&ran.stderr).trim()
        ))
    }
}

/// The runner of the channel cases: a no-op unless one of them started it.
#[tokio::test(flavor = "multi_thread")]
async fn channel_runner() {
    let Ok(case) = std::env::var(CHANNEL_RUNNER_ENV) else {
        return;
    };
    match case.as_str() {
        "census" => census().await,
        "impostor" => impostor().await,
        other => panic!("no channel case {other}"),
    }
    // On a line of its own: a serial harness prints the test's name, with no
    // line end, before the test runs.
    println!("\nRUNNER DONE");
}

/// In a network namespace of its own, after a full paid call: some socket
/// is the live child's (its end of the channel), none of the child's sockets
/// listens or is bound to a path, and the daemon's temporary directory holds
/// no socket file.
async fn census() {
    let up = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .expect("ip");
    assert!(up.success(), "the namespace's loopback did not come up");
    let f = fixture_in(Mode::SameUser).expect("the same-user fixture");
    f.run("census", 20)
        .generate(SMALL, request(SMALL, "hi"))
        .await
        .expect("the child's call");
    let child = f.broker_pid();
    // Read on both sides of the table, so a socket of this process that
    // opened or closed meanwhile is never counted as the child's.
    let before = own_sockets();
    let table = unix_sockets();
    let after = own_sockets();
    let child_sockets: Vec<&UnixSocket> = table
        .iter()
        .filter(|socket| !before.contains(&socket.inode) && !after.contains(&socket.inode))
        .collect();
    assert!(
        !child_sockets.is_empty(),
        "no socket of the child: {table:?}"
    );
    for socket in &child_sockets {
        assert!(
            !socket.listening,
            "the child holds a listening socket: {socket:?}"
        );
        assert!(socket.path.is_empty(), "the child bound a path: {socket:?}");
    }
    let tmp = std::env::temp_dir();
    let files: Vec<PathBuf> = walk(&tmp)
        .into_iter()
        .filter(|path| {
            std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_socket())
        })
        .collect();
    assert!(
        files.is_empty(),
        "socket files under the daemon's temporary directory: {files:?}"
    );
    assert!(alive(child), "the child is gone");
}

/// After the child served a first call, a listener of this uid is renamed
/// over the old child socket path. A second paid call goes out with the key
/// through the real child, and the listener gets no connection.
async fn impostor() {
    let f = fixture_in(Mode::SameUser).expect("the same-user fixture");
    let run = f.run("impostor", 20);
    run.generate(SMALL, request(SMALL, "first"))
        .await
        .expect("the first call");
    let path = old_child_socket(&std::env::temp_dir());
    let parked = path.with_file_name("impostor.sock");
    let impostor = std::os::unix::net::UnixListener::bind(&parked).expect("impostor");
    impostor.set_nonblocking(true).expect("nonblocking");
    std::fs::rename(&parked, &path).expect("over the old child socket path");
    let second = run.generate(SMALL, request(SMALL, "second")).await;
    match impostor.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((mut stream, _)) => {
            let mut got = Vec::new();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("timeout");
            let _ = stream.read_to_end(&mut got);
            panic!(
                "the daemon connected to the listener at {} and sent it {} bytes",
                path.display(),
                got.len()
            );
        }
        Err(error) => panic!("accept: {error}"),
    }
    let answer = second.expect("the second call, through the child");
    assert_eq!(text_of(&answer.message), "an answer");
    assert_eq!(f.keyed(&f.fake.seen()), 2, "both calls carried the key");
    assert_eq!(f.reads(), 2, "one key read per call");
}

/// The old child socket path: `broker.sock` in the `oneiron-broker-<id>`
/// directory under the daemon's temporary directory `tmp`, where the child
/// listened before it took its calls over a channel. A daemon that made no
/// such directory gets one made here, empty.
fn old_child_socket(tmp: &Path) -> PathBuf {
    let made = std::fs::read_dir(tmp)
        .expect("tmp")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("oneiron-broker-"))
        });
    let dir = made.unwrap_or_else(|| {
        let dir = tmp.join("oneiron-broker-0000000000000000");
        std::fs::create_dir(&dir).expect("the old child directory");
        set_mode(&dir, 0o700);
        dir
    });
    dir.join("broker.sock")
}

/// A Unix socket of this network namespace, as `/proc/net/unix` lists it.
#[derive(Debug)]
struct UnixSocket {
    inode: u64,
    listening: bool,
    path: String,
}

/// Every Unix socket of this network namespace.
fn unix_sockets() -> Vec<UnixSocket> {
    // `__SO_ACCEPTCON`: the Flags of a listening socket.
    const ACCEPTING: u32 = 1 << 16;
    let table = std::fs::read_to_string("/proc/net/unix").expect("/proc/net/unix");
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            // `Num RefCount Protocol Flags Type St Inode [Path]`
            let fields: Vec<&str> = line.split_whitespace().collect();
            let flags = u32::from_str_radix(fields.get(3)?, 16).ok()?;
            Some(UnixSocket {
                inode: fields.get(6)?.parse().ok()?,
                listening: flags & ACCEPTING != 0,
                path: fields.get(7..).unwrap_or_default().join(" "),
            })
        })
        .collect()
}

/// The inodes of the sockets this process holds.
fn own_sockets() -> std::collections::HashSet<u64> {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let target = std::fs::read_link(entry.path()).ok()?;
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}
