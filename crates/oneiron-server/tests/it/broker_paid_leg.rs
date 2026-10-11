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
//!
//! Every refusal asserts the five checks: no provider send, no send with the
//! key, no key read at the door, no change in units used or reserved, and one
//! more denial row. No receipt row ever holds the key.
//!
//! The broker runs as the first uid of this user's `/etc/subuid` range, in a
//! user namespace that maps that uid and this one to themselves. A host that
//! cannot make such a namespace (no `unshare` or `newuidmap`, no range, or a
//! kernel that refuses) has each case say why and pass, unless
//! `ONEIRON_BROKER_FIXTURE=require`, which makes it fail instead. A broker
//! that does not start on a host that can always fails.
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

struct Fixture {
    key: String,
    fake: FakeProvider,
    broker: Broker,
    keys: Arc<CountingDoor>,
    receipts: Arc<MemoryReceipts>,
    runtime: ModelRuntime,
    _vault_dir: tempfile::TempDir,
}

/// The fixture, or `None` (with the reason printed) where this host cannot
/// run a process as a second user.
fn fixture() -> Option<Fixture> {
    let second = match SecondUser::probe() {
        Ok(second) => second,
        Err(reason) => {
            let reason = format!("this host cannot run a second user: {reason}");
            assert!(
                std::env::var("ONEIRON_BROKER_FIXTURE").as_deref() != Ok("require"),
                "{reason}"
            );
            eprintln!("skipped: {reason}");
            return None;
        }
    };
    let key = sentinel();
    let fake = FakeProvider::start(FakeReply::json(401, &json!({})));
    answer_with_key(&fake, &key, "an answer");
    let broker = Broker::start(&second, fake.ca_pem())
        .unwrap_or_else(|reason| panic!("the broker did not start as a second user: {reason}"));
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
    let runtime = runtime(fake.origin(), &broker, &keys, &receipts);
    Some(Fixture {
        key,
        fake,
        broker,
        keys,
        receipts,
        runtime,
        _vault_dir: vault_dir,
    })
}

/// A runtime whose `paid` provider at `base_url` sends through `broker`.
fn runtime(
    base_url: &str,
    broker: &Broker,
    keys: &Arc<CountingDoor>,
    receipts: &Arc<MemoryReceipts>,
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

[roles.checker]
rungs = [{{ model = "paid:teacher-small" }}, {{ model = "paid:teacher-large" }}]

[broker]
socket = "{socket}"
uid = {uid}
"#,
            socket = broker.socket.display(),
            uid = broker.uid,
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
        self.runtime.declared_run(name, declaration, None)
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
    let Some(f) = fixture() else { return };
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
                broker_isolation: Some(BrokerIsolation::SeparateUser),
                answered: true,
                ..
            } if *request_digest == digest
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
    let runtime = runtime(&lookalike, &f.broker, &f.keys, &f.receipts);
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
    let Some(f) = fixture() else { return };
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
                f.broker.pid()
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
    // The broker is another user: its environment and memory are closed.
    // Reading `mem` needs a mapped address, so a `mem` that opens is open.
    for (what, path) in [("ENVIRON", "environ"), ("MEM", "mem")] {
        let open = match std::fs::File::open(format!("/proc/{broker}/{path}")) {
            Err(_) => false,
            Ok(_) if path == "mem" => true,
            Ok(mut file) => file.read(&mut [0; 1]).is_ok(),
        };
        println!("BROKER {what} {}", if open { "OPEN" } else { "DENIED" });
    }
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
