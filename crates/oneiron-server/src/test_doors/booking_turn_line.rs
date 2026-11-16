//! Door for `tests/booking_turn_line.rs` (census L3-11, ARCH-0062
//! #booking-turn-divergence): authenticated hold requests on a page
//! session's hold cap, each run through the booking executor's own turn
//! (`api::booking::turn::Turn`) over an admission pass the test scripts.

use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use oneiron::booking::SessionKey;

use crate::api::{BookingHttpDisposition, BookingTurn, write_holding_line_place};
use crate::error::{ApiError, ApiErrorDetails};
use crate::server::SyncServer;

/// What one admission pass answers, as the test scripts it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pass {
    /// Admitted: the request goes on to its write.
    Admitted,
    /// Refused for the window, which opens in `seconds` (the hold cap's
    /// answer, as `booking_anti_abuse::guards::enforce_hold` gives it).
    Wait { seconds: u64 },
}

/// How one request's turn ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnEnd {
    /// Admitted by a pass.
    Admitted,
    /// Answered `booking_turn_waited_out`: its deadline came first.
    WaitedOut,
    /// Any other answer, with its message.
    Refused(String),
}

/// Runs one authenticated hold request on `server` for the page session
/// `session` (its 32-byte session key) as the executor runs a hold: it takes
/// its place in the session's line, then runs one `pass` per admission pass
/// and waits as its turn says, until it is answered. Its place is given up
/// when this returns, as the executor gives it up after the hold's write.
pub async fn authenticated_hold(
    server: &SyncServer,
    session: [u8; 32],
    mut pass: impl FnMut() -> Pass,
) -> TurnEnd {
    let mut turn = BookingTurn::new(server, true);
    let answered: Result<(), ApiError> = async {
        turn.line_up(SessionKey(session)).await?;
        loop {
            let disposition = match pass() {
                Pass::Admitted => BookingHttpDisposition::Continue,
                Pass::Wait { seconds } => BookingHttpDisposition::RetryAfter { seconds, bound: 1 },
            };
            if turn.after(disposition).await?.is_some() {
                return Ok::<(), ApiError>(());
            }
        }
    }
    .await;
    match answered {
        Ok(()) => TurnEnd::Admitted,
        Err(error) => match error.details() {
            ApiErrorDetails::InvalidState { state }
                if state.as_deref() == Some("booking_turn_waited_out") =>
            {
                TurnEnd::WaitedOut
            }
            _ => TurnEnd::Refused(error.message().to_owned()),
        },
    }
}

/// How many page sessions have a line on `server`. A line nobody holds or
/// waits in is forgotten, so this is 0 once every hold was answered or
/// dropped.
pub fn lines_held(server: &SyncServer) -> usize {
    server.booking_turn_lines.held()
}

/// What [`waiter_dropped_after_the_head_leaves`] saw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DroppedWaiter {
    /// The second hold was still waiting in line after its first poll.
    pub waited: bool,
    /// The lines `server` holds once both holds are gone.
    pub lines_held: usize,
}

/// Plays one order by hand, as no scheduler would promise it: a hold takes
/// the head of `session`'s line; a second joins and is polled once, so it
/// waits behind the first; the first is answered, and its head passes to the
/// waiter; the waiter's request is dropped before it is polled again (its
/// client went away). Both are gone at the end. `Err` is the head's
/// refusal, with its message.
pub async fn waiter_dropped_after_the_head_leaves(
    server: &SyncServer,
    session: [u8; 32],
) -> Result<DroppedWaiter, String> {
    let window = SessionKey(session);
    let mut head = BookingTurn::new(server, true);
    head.line_up(window)
        .await
        .map_err(|error| error.message().to_owned())?;
    let mut waiter = BookingTurn::new(server, true);
    let waited = {
        let mut waiting = std::pin::pin!(waiter.line_up(window));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let waited = waiting.as_mut().poll(&mut context).is_pending();
        drop(head);
        waited
    };
    drop(waiter);
    Ok(DroppedWaiter {
        waited,
        lines_held: lines_held(server),
    })
}

/// What [`hold_dropped_during_its_write`] saw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetachedWrite {
    /// The lines `server` held once the first hold's request was dropped,
    /// its write still running.
    pub lines_held_while_writing: usize,
    /// The second hold was still waiting in line after its first poll, the
    /// first hold's write still running.
    pub second_waited: bool,
    /// The second hold took the head once the first hold's write returned.
    pub second_took_the_head: bool,
    /// The lines `server` held once the write had returned and the second
    /// hold was gone.
    pub lines_held_after: usize,
}

/// How long the door waits for a step the test drives to happen.
const STEP_WAIT: Duration = Duration::from_secs(5);

/// Plays one order by hand (FIX BOOKING-CANCELLED-HOLD-DETACHED-WRITE): a
/// hold takes the head of `session`'s line and starts its write, as the
/// executor writes a hold; the write is held still; the hold's request is
/// dropped (its client went away), and the write runs on. A second hold
/// joins the line and is polled once; then the write is let go, and the
/// second hold is awaited. `Err` is the first hold's refusal, with its
/// message, or a step that never came.
pub async fn hold_dropped_during_its_write(
    server: &SyncServer,
    session: [u8; 32],
) -> Result<DetachedWrite, String> {
    let window = SessionKey(session);
    let mut first = BookingTurn::new(server, true);
    first
        .line_up(window)
        .await
        .map_err(|error| error.message().to_owned())?;
    let (started, write_started) = tokio::sync::oneshot::channel::<()>();
    let (release, released) = std::sync::mpsc::channel::<()>();
    {
        let mut request = std::pin::pin!(hold_write(first, move || {
            let _ = started.send(());
            // Held still until the test lets it go, or its sender is gone.
            let _ = released.recv();
        }));
        let mut context = Context::from_waker(Waker::noop());
        if request.as_mut().poll(&mut context).is_ready() {
            return Err("the hold's write returned before it was let go".to_owned());
        }
        tokio::time::timeout(STEP_WAIT, write_started)
            .await
            .map_err(|_| "the hold's write never started".to_owned())?
            .map_err(|_| "the hold's write stopped before it started".to_owned())?;
        // The request is dropped here, its write still running.
    }
    let lines_held_while_writing = lines_held(server);
    let mut second = BookingTurn::new(server, true);
    let (second_waited, second_took_the_head) = {
        let mut waiting = std::pin::pin!(second.line_up(window));
        let mut context = Context::from_waker(Waker::noop());
        let first_poll = waiting.as_mut().poll(&mut context);
        let _ = release.send(());
        match first_poll {
            Poll::Ready(answer) => (false, answer.is_ok()),
            Poll::Pending => (
                true,
                tokio::time::timeout(STEP_WAIT, waiting)
                    .await
                    .is_ok_and(|answer| answer.is_ok()),
            ),
        }
    };
    drop(second);
    // The write returns on the blocking pool; the line it held goes with it.
    let deadline = tokio::time::Instant::now() + STEP_WAIT;
    while lines_held(server) > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(DetachedWrite {
        lines_held_while_writing,
        second_waited,
        second_took_the_head,
        lines_held_after: lines_held(server),
    })
}

/// A hold's write as the executor runs it once admitted
/// (`api::booking::lifecycle::run_booking_verb`): `write` on the blocking
/// pool through the executor's own [`write_holding_line_place`], which holds
/// the turn's place in the line until `write` returns.
async fn hold_write(
    mut turn: BookingTurn<'_>,
    write: impl FnOnce() + Send + 'static,
) -> Result<(), String> {
    write_holding_line_place(turn.take_place(), write)
        .await
        .map_err(|error| error.message().to_owned())
}
