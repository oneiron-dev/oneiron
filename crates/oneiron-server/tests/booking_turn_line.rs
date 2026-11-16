#![cfg(oneiron_test_support)]
//! Census L3-11 (canon ARCH-0062 #booking-turn-divergence): an authenticated
//! booking request past a window waits in a fair queue, first in, first out
//! per window, not a timed retry that a later request can overtake. The one
//! window an authenticated request still waits on is its page session's
//! active-hold cap, which answers "the window opens in n seconds".
//!
//! Each request here runs through the executor's own turn
//! (`oneiron_server::test_doors::booking_turn_line`), and the hold cap's
//! admission pass is scripted: a page session with room for so many holds,
//! and a log of every pass and answer in the order they came.
//!
//! On main a request that arrives while an earlier one waits runs admission
//! at once. It takes the hold the earlier one was waiting for, and the
//! earlier one waits out its deadline. On the head the later request waits
//! behind the earlier one and runs no admission until it is answered.
//!
//! Real time, short: a queue wait of 6 s and a window that answers "again in
//! 2 s"; each case ends in under 7 s.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test booking_turn_line`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oneiron::{Vault, VaultConfig};
use oneiron_server::config::{LimitsConfig, SyncServerConfig};
use oneiron_server::test_doors::booking_turn_line::{
    DroppedWaiter, Pass, TurnEnd, authenticated_hold, lines_held,
    waiter_dropped_after_the_head_leaves,
};
use oneiron_server::{ENGINE_THREAD_STACK_BYTES, server::SyncServer};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The queue wait every booking turn carries.
const WAIT_MS: u64 = 6_000;
/// When the hold cap says the window may open again.
const RECHECK_SECS: u64 = 2;
/// Two page sessions (their 32-byte session keys).
const SESSION: [u8; 32] = [0x11; 32];
const OTHER_SESSION: [u8; 32] = [0x22; 32];

/// A server over a fresh device vault, with the short queue wait.
fn server() -> TestResult<(tempfile::TempDir, Arc<SyncServer>)> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            limits: LimitsConfig {
                queue_wait_timeout_ms: WAIT_MS,
                ..LimitsConfig::default()
            },
            ..Default::default()
        },
    )?;
    Ok((dir, Arc::new(server)))
}

/// One page session's hold cap as the scripted passes see it: the holds it
/// has room for, and every pass and answer in the order they came.
#[derive(Default)]
struct HoldCap {
    room: u32,
    log: Vec<String>,
}

#[derive(Clone, Default)]
struct Window(Arc<Mutex<HoldCap>>);

impl Window {
    fn with<T>(&self, act: impl FnOnce(&mut HoldCap) -> T) -> T {
        act(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// A hold on the session is freed: one more request may be admitted.
    fn free_one(&self) {
        self.with(|cap| {
            cap.room += 1;
            cap.log.push("freed".to_owned());
        });
    }

    /// `who`'s admission pass: admitted while there is room (taking it),
    /// else told to wait.
    fn pass(&self, who: &'static str) -> impl FnMut() -> Pass + use<> {
        let window = self.clone();
        move || {
            window.with(|cap| {
                cap.log.push(format!("{who} pass"));
                if cap.room > 0 {
                    cap.room -= 1;
                    cap.log.push(format!("{who} admitted"));
                    Pass::Admitted
                } else {
                    Pass::Wait {
                        seconds: RECHECK_SECS,
                    }
                }
            })
        }
    }

    fn note(&self, line: String) {
        self.with(|cap| cap.log.push(line));
    }

    fn log(&self) -> Vec<String> {
        self.with(|cap| cap.log.clone())
    }
}

/// `who`'s hold on `session`, started `after` from now; its answer is
/// logged as `<who> <answer>` the moment it comes.
async fn hold(
    server: &SyncServer,
    window: &Window,
    who: &'static str,
    session: [u8; 32],
    after: Duration,
) -> TurnEnd {
    tokio::time::sleep(after).await;
    let end = authenticated_hold(server, session, window.pass(who)).await;
    window.note(format!("{who} {end:?}"));
    end
}

fn position(log: &[String], line: &str) -> Option<usize> {
    log.iter().position(|logged| logged == line)
}

#[test]
fn a_later_hold_never_takes_the_window_ahead_of_an_earlier_waiter() -> TestResult {
    on_engine_stack(later_hold_waits_behind_the_earlier)
}

/// A waits on a full session. A hold on it is freed, and only then C
/// arrives. The freed place is A's: C waits behind A, runs admission once A
/// is answered, finds the session full again, and waits its deadline out.
async fn later_hold_waits_behind_the_earlier() -> TestResult {
    let (_dir, server) = server()?;
    let window = Window::default();
    let (a, (), c) = tokio::join!(
        hold(&server, &window, "A", SESSION, Duration::ZERO),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            window.free_one();
        },
        hold(&server, &window, "C", SESSION, Duration::from_millis(500)),
    );
    let log = window.log();
    assert_eq!(
        (&a, &c),
        (&TurnEnd::Admitted, &TurnEnd::WaitedOut),
        "the earlier waiter A takes the freed hold; C, which came later, waits its deadline out behind it: {log:?}"
    );
    assert!(
        position(&log, "A admitted").is_some() && position(&log, "C admitted").is_none(),
        "only A is admitted: {log:?}"
    );
    Ok(())
}

#[test]
fn a_hold_behind_a_waiter_runs_no_admission_until_the_waiter_is_answered() -> TestResult {
    on_engine_stack(behind_a_waiter_no_admission_runs)
}

/// The session stays full. A waits and is answered `booking_turn_waited_out`
/// at its deadline; B, which came 500 ms later, waits in line behind it the
/// whole time, runs its first admission pass only after A's answer, and is
/// answered `booking_turn_waited_out` at its own deadline. Nothing is
/// admitted.
async fn behind_a_waiter_no_admission_runs() -> TestResult {
    let (_dir, server) = server()?;
    let window = Window::default();
    let (a, b) = tokio::join!(
        hold(&server, &window, "A", SESSION, Duration::ZERO),
        hold(&server, &window, "B", SESSION, Duration::from_millis(500)),
    );
    let log = window.log();
    assert_eq!(
        (&a, &b),
        (&TurnEnd::WaitedOut, &TurnEnd::WaitedOut),
        "a full session admits nobody, and each waits its own deadline out: {log:?}"
    );
    let a_answered = position(&log, "A WaitedOut").ok_or("A's answer is logged")?;
    let b_first_pass = position(&log, "B pass");
    assert!(
        b_first_pass.is_none_or(|first| first > a_answered),
        "B, behind A in the session's line, runs no admission pass before A is answered: {log:?}"
    );
    Ok(())
}

#[test]
fn holds_on_two_sessions_never_wait_on_each_other() -> TestResult {
    on_engine_stack(two_sessions_two_lines)
}

/// A waits on a full session; D, on another session with room, is admitted
/// at once, before A's first recheck: the lines are per window, not one line
/// for every hold.
async fn two_sessions_two_lines() -> TestResult {
    let (_dir, server) = server()?;
    let full = Window::default();
    let open = Window::default();
    open.free_one();
    let (a, d) = tokio::join!(
        hold(&server, &full, "A", SESSION, Duration::ZERO),
        hold(
            &server,
            &open,
            "D",
            OTHER_SESSION,
            Duration::from_millis(300)
        ),
    );
    assert_eq!(
        (&a, &d),
        (&TurnEnd::WaitedOut, &TurnEnd::Admitted),
        "D, on a session with room, is admitted; A waits its own deadline out: full {:?}, open {:?}",
        full.log(),
        open.log()
    );
    Ok(())
}

#[test]
fn a_hold_dropped_while_it_waits_leaves_no_line_behind() -> TestResult {
    on_engine_stack(dropped_waiter_leaves_no_line)
}

/// Round 1 of #7658: A holds the head of the session's line and B waits
/// behind it. A is answered, so its head passes to B, and B's request is
/// dropped before it is polled again. Nobody is in the line any more, so
/// the server holds no line for the session. A line kept here would be
/// kept for good, one per page session that played this order.
async fn dropped_waiter_leaves_no_line() -> TestResult {
    let (_dir, server) = server()?;
    let seen = waiter_dropped_after_the_head_leaves(&server, SESSION).await?;
    assert_eq!(
        seen,
        DroppedWaiter {
            waited: true,
            lines_held: 0,
        },
        "B waited behind A, and once both are gone no line is left"
    );
    // The session's next hold finds an empty line and is admitted at once.
    let window = Window::default();
    window.free_one();
    let next = hold(&server, &window, "E", SESSION, Duration::ZERO).await;
    assert_eq!(next, TurnEnd::Admitted, "{:?}", window.log());
    assert_eq!(lines_held(&server), 0, "an answered hold leaves no line");
    Ok(())
}

/// Runs `test` on a runtime whose threads have the engine's stack, as the
/// served engine's do.
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
