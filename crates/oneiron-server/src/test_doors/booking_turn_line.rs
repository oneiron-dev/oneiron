//! Door for `tests/booking_turn_line.rs` (census L3-11, ARCH-0062
//! #booking-turn-divergence): authenticated hold requests on a page
//! session's hold cap, each run through the booking executor's own turn
//! (`api::booking::turn::Turn`) over an admission pass the test scripts.

use oneiron::booking::SessionKey;

use crate::api::{BookingHttpDisposition, BookingTurn};
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
