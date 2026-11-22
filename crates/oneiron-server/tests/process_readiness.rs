//! L8-11 (runtime `#provider-health`, decision `scour:S25`; figures A): a
//! process's readiness follows its event loop. Lag marks it degraded and it
//! still takes work; a sustained hang drains it, and a watchdog that sheds
//! intake (managed serve) then answers new work with a typed 503 and
//! `Retry-After`; the first sample after the hang starts its recovery, still
//! refused; and a stabilization window of clean samples makes it ready, when
//! the same request is served again. A watchdog that only reports (plain
//! serve) refuses nothing. `/api/health` names the state throughout.
//!
//! Each served case runs on a runtime with one worker: a task that sleeps on
//! that worker is the hang. While it sleeps the runtime's timers do not fire,
//! so the case waits with `std::thread::sleep` and sends its requests on the
//! test thread, which the health route and the gate's refusal need no worker
//! for.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test process_readiness`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::header::RETRY_AFTER;
use axum::http::{Request, StatusCode};
use oneiron::{Vault, VaultConfig};
use oneiron_server::process_readiness::{ProcessHealthSettings, ReadinessMachine};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use oneiron_vault_contract::ProcessState;
use serde_json::Value;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Small figures, so a stall of a second or two walks every state: a probe
/// every 25 ms, degraded at 250 ms of lag, draining after 1 s with no
/// sample, ready after 1 s of clean samples. Managed serve's shedding.
const SHEDDING: ProcessHealthSettings = ProcessHealthSettings {
    probe_interval: Duration::from_millis(25),
    lag_threshold: Duration::from_millis(250),
    hang_threshold: Duration::from_secs(1),
    stabilization_window: Duration::from_secs(1),
    sheds_intake: true,
};

/// The same figures, reporting only: plain serve's watchdog.
const REPORTING: ProcessHealthSettings = ProcessHealthSettings {
    sheds_intake: false,
    ..SHEDDING
};

/// A hang: well past the 1 s hang threshold, so the process drains and
/// stays draining long enough to be asked.
const HANG_STALL: Duration = Duration::from_millis(2_500);

/// Lag without a hang: past the 250 ms lag threshold, far under the hang
/// threshold of [`LAGGING`].
const LAG_STALL: Duration = Duration::from_millis(600);

/// [`SHEDDING`] with a 2 s hang threshold, so a loaded host's 600 ms stall
/// never reads as a hang.
const LAGGING: ProcessHealthSettings = ProcessHealthSettings {
    hang_threshold: Duration::from_secs(2),
    ..SHEDDING
};

/// How long any one state may take to show on `/api/health`.
const STATE_DEADLINE: Duration = Duration::from_secs(10);

/// New work: authenticated discovery, sent with no credential.
const WORK_PATH: &str = "/api/core/discover";

struct Fixture {
    app: Router,
    server: Arc<SyncServer>,
    _dir: tempfile::TempDir,
}

/// One answer to the work request.
struct Answer {
    status: StatusCode,
    retry_after: Option<String>,
    body: Value,
}

impl Answer {
    /// The intake gate's refusal, naming `readiness` and a wait of at least
    /// one second, the same in the body and in `Retry-After`.
    fn assert_refused(&self, readiness: ProcessState) {
        let body = &self.body;
        assert_eq!(self.status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["code"], "PROCESS_NOT_READY", "{body}");
        assert_eq!(body["details"]["readiness"], readiness.as_str(), "{body}");
        let wait = body["details"]["retryAfterSecs"].as_u64().unwrap_or(0);
        assert!(
            wait >= 1,
            "the refusal names a wait of at least 1 s: {body}"
        );
        assert_eq!(
            self.retry_after.as_deref(),
            Some(wait.to_string().as_str()),
            "Retry-After says the body's wait: {body}"
        );
    }

    /// Served as the ready process served it: past the gate.
    fn assert_served_as(&self, ready: &Self, when: &str) {
        let body = &self.body;
        assert_eq!(self.status, ready.status, "{when}: {body}");
        assert_ne!(body["code"], "PROCESS_NOT_READY", "{when}: {body}");
        assert!(self.retry_after.is_none(), "{when}: {body}");
    }
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        let server = Arc::new(SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some("process-readiness".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(Arc::clone(&server)),
            server,
            _dir: dir,
        })
    }

    async fn health(&self) -> TestResult<ProcessState> {
        let request = Request::get("/api/health").body(Body::empty())?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(status, StatusCode::OK, "health always answers: {body}");
        Ok(serde_json::from_value(body["process_readiness"].clone())?)
    }

    async fn work(&self) -> TestResult<Answer> {
        let request = Request::get(WORK_PATH).body(Body::empty())?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()?;
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok(Answer {
            status,
            retry_after,
            body,
        })
    }

    /// Reads `/api/health` until it says `want`, and returns each state it
    /// read on the way, in order, without repeats.
    async fn await_state(&self, want: ProcessState) -> TestResult<Vec<ProcessState>> {
        let deadline = Instant::now() + STATE_DEADLINE;
        let mut read = Vec::new();
        loop {
            let state = self.health().await?;
            if read.last() != Some(&state) {
                read.push(state);
            }
            if state == want {
                return Ok(read);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "health never read {want:?} in {STATE_DEADLINE:?}; it read {read:?}"
                )
                .into());
            }
            // The runtime's timers may be stalled: wait on this thread.
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Holds the runtime's one worker for `length`: the event loop hangs.
fn stall_the_worker(length: Duration) {
    drop(tokio::spawn(async move { std::thread::sleep(length) }));
}

/// Runs `case` on a multi-thread runtime with one worker, as the server's
/// binary runs its app (every thread with the engine's stack), driven from
/// a thread of its own: the test thread `await_state` waits on.
fn on_one_worker<F, Fut>(case: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(case())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn event_loop_hang_drains_new_work_and_recovers_after_the_window() -> TestResult {
    on_one_worker(hang_drains_and_recovers)
}

async fn hang_drains_and_recovers() -> TestResult {
    let fixture = Fixture::new()?;
    let _watchdog = fixture.server.start_process_watchdog(SHEDDING);
    fixture.await_state(ProcessState::Ready).await?;
    let ready = fixture.work().await?;
    assert_ne!(
        ready.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "FIXTURE: a ready process serves the work request: {}",
        ready.body
    );

    stall_the_worker(HANG_STALL);
    let hung = fixture.await_state(ProcessState::Draining).await?;
    assert!(
        !hung.contains(&ProcessState::Recovering),
        "the process drains while the hang holds: {hung:?}"
    );
    fixture.work().await?.assert_refused(ProcessState::Draining);

    fixture.await_state(ProcessState::Recovering).await?;
    fixture
        .work()
        .await?
        .assert_refused(ProcessState::Recovering);

    let recovered = fixture.await_state(ProcessState::Ready).await?;
    assert!(
        !recovered.contains(&ProcessState::Draining)
            && !recovered.contains(&ProcessState::Degraded),
        "recovering goes ready, never back to draining or through degraded: {recovered:?}"
    );
    fixture
        .work()
        .await?
        .assert_served_as(&ready, "ready after the window");
    Ok(())
}

#[test]
fn event_loop_lag_marks_degraded_and_still_takes_work() -> TestResult {
    on_one_worker(lag_degrades_and_serves)
}

async fn lag_degrades_and_serves() -> TestResult {
    let fixture = Fixture::new()?;
    let _watchdog = fixture.server.start_process_watchdog(LAGGING);
    fixture.await_state(ProcessState::Ready).await?;
    let ready = fixture.work().await?;

    stall_the_worker(LAG_STALL);
    let mut read = fixture.await_state(ProcessState::Degraded).await?;
    fixture
        .work()
        .await?
        .assert_served_as(&ready, "degraded takes work");
    read.extend(fixture.await_state(ProcessState::Ready).await?);
    assert!(
        !read.contains(&ProcessState::Draining) && !read.contains(&ProcessState::Recovering),
        "lag under the hang threshold never drains: {read:?}"
    );
    fixture
        .work()
        .await?
        .assert_served_as(&ready, "ready after the window");
    Ok(())
}

#[test]
fn report_only_watchdog_reports_a_hang_and_sheds_nothing() -> TestResult {
    on_one_worker(report_only_sheds_nothing)
}

async fn report_only_sheds_nothing() -> TestResult {
    let fixture = Fixture::new()?;
    let _watchdog = fixture.server.start_process_watchdog(REPORTING);
    fixture.await_state(ProcessState::Ready).await?;
    let ready = fixture.work().await?;

    stall_the_worker(HANG_STALL);
    fixture.await_state(ProcessState::Draining).await?;
    fixture
        .work()
        .await?
        .assert_served_as(&ready, "draining, reporting only");
    fixture.await_state(ProcessState::Recovering).await?;
    fixture
        .work()
        .await?
        .assert_served_as(&ready, "recovering, reporting only");
    fixture.await_state(ProcessState::Ready).await?;
    Ok(())
}

#[test]
fn readiness_machine_follows_the_ruled_transitions() {
    use ProcessState::{Degraded, Draining, Ready, Recovering};

    // The Engine's figures (L8-11 = A): managed serve sheds, plain serve
    // reports only, on the same figures.
    let figures = ProcessHealthSettings::managed();
    assert_eq!(figures.probe_interval, Duration::from_millis(250));
    assert_eq!(figures.lag_threshold, Duration::from_millis(500));
    assert_eq!(figures.hang_threshold, Duration::from_secs(5));
    assert_eq!(figures.stabilization_window, Duration::from_secs(30));
    assert!(figures.sheds_intake);
    assert_eq!(
        ProcessHealthSettings::default(),
        ProcessHealthSettings {
            sheds_intake: false,
            ..figures
        }
    );

    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    let ms = Duration::from_millis;
    let (clean, lagging, tick) = (ms(10), ms(600), ms(250));
    let mut machine = ReadinessMachine::new(&figures, start);
    assert_eq!(machine.state(), Ready);

    // Ready: a lag under the threshold is clean; one at it degrades.
    machine.observe_sample(at(250), ms(499));
    assert_eq!(machine.state(), Ready);
    machine.observe_sample(at(500), ms(500));
    assert_eq!(machine.state(), Degraded);

    // Degraded: clean samples start the window, a lagging one restarts it,
    // and only a full window of clean samples makes it ready. It never goes
    // to recovering.
    machine.observe_sample(at(750), clean);
    machine.observe_sample(at(20_000), lagging);
    assert_eq!(machine.state(), Degraded);
    machine.observe_sample(at(20_250), clean);
    machine.observe_sample(at(50_000), clean);
    assert_eq!(machine.state(), Degraded, "29.75 s of clean samples");
    machine.observe_sample(at(50_250), clean);
    assert_eq!(machine.state(), Ready, "30 s of clean samples");

    // Ready -> draining: no sample for the hang threshold.
    machine.observe_watchdog_check(at(55_000), tick);
    assert_eq!(machine.state(), Ready, "4.75 s without a sample");
    machine.observe_watchdog_check(at(55_250), tick);
    assert_eq!(machine.state(), Draining, "5 s without a sample");
    assert_eq!(machine.retry_after(at(55_250)), Duration::from_secs(30));

    // Draining -> recovering on the first sample, laggy or not; it never
    // goes straight to ready. A laggy first sample starts no window.
    machine.observe_sample(at(56_000), ms(750));
    assert_eq!(machine.state(), Recovering);
    assert_eq!(machine.last_lag(), ms(750));
    assert_eq!(machine.retry_after(at(56_000)), Duration::from_secs(30));
    machine.observe_sample(at(56_250), clean);
    assert_eq!(machine.retry_after(at(70_250)), Duration::from_secs(16));

    // Recovering: a lagging sample restarts the window and stays recovering.
    machine.observe_sample(at(70_250), lagging);
    assert_eq!(machine.state(), Recovering);
    assert_eq!(machine.retry_after(at(70_250)), Duration::from_secs(30));
    machine.observe_sample(at(70_500), clean);
    machine.observe_sample(at(100_250), clean);
    assert_eq!(machine.state(), Recovering, "29.75 s of clean samples");
    assert_eq!(
        machine.retry_after(at(100_250)),
        Duration::from_secs(1),
        "the wait is never under 1 s"
    );
    machine.observe_sample(at(100_500), clean);
    assert_eq!(machine.state(), Ready, "30 s of clean samples");

    // Degraded and recovering drain on a hang too.
    machine.observe_sample(at(100_750), lagging);
    assert_eq!(machine.state(), Degraded);
    machine.observe_watchdog_check(at(105_750), tick);
    assert_eq!(machine.state(), Draining);
    machine.observe_sample(at(106_000), clean);
    assert_eq!(machine.state(), Recovering);
    assert_eq!(machine.retry_after(at(106_000)), Duration::from_secs(30));
    machine.observe_watchdog_check(at(111_000), tick);
    assert_eq!(machine.state(), Draining);
    machine.observe_watchdog_check(at(112_000), tick);
    assert_eq!(machine.state(), Draining, "draining stays draining");
    machine.observe_sample(at(112_250), clean);
    machine.observe_sample(at(142_250), clean);
    assert_eq!(machine.state(), Ready);

    // A stop of the whole process (the check itself a hang threshold past
    // its interval) is no hang: the silence counts from that check.
    machine.observe_watchdog_check(at(200_000), ms(57_750));
    assert_eq!(machine.state(), Ready, "a stopped process does not drain");
    machine.observe_watchdog_check(at(204_750), tick);
    assert_eq!(machine.state(), Ready, "4.75 s since the stop ended");
    machine.observe_watchdog_check(at(205_000), tick);
    assert_eq!(machine.state(), Draining, "5 s since the stop ended");
}
