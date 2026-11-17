//! Rule five at the owner's booking windows: authenticated work past one
//! waits for it to open and is never answered "retry after". Since FIX
//! 128-131 an authenticated caller spends none of the per-minute windows
//! (its calls are counted against `[limits]` rows that ask and serve), and
//! its quarantine admission is never rate limited, so what it can still wait
//! on is a hold's one-active-per-session rule. Its wait keeps its arrival
//! place (ARCH-0062 #booking-turn-divergence): an authenticated hold waits in
//! its page session's line, first in, first out, behind every hold that came
//! first.
//! An anonymous hold never waits there, and never goes ahead of a hold that
//! does: it takes the line only when nobody is in it.

use std::time::Duration;

use oneiron::booking::SessionKey;
use tokio::time::Instant;

use crate::api::booking_anti_abuse::{BookingHttpDisposition, SESSION_HOLD_RETRY_SECS};
use crate::error::ApiError;
use crate::server::{LinePlace, SyncServer};
use crate::wire_telemetry::LimitRow;

/// One request's wait past the owner's windows.
///
/// An anonymous visitor past a window is answered `RetryAfter`, as before:
/// pre-auth work stays sheddable. An authenticated caller past one is never
/// refused for it: its crossing asks once, and it is admitted again as the
/// window opens, until `limits.queue_wait_timeout_ms` runs out. Before its
/// first admission it takes its place in its window's line
/// ([`Self::line_up`]), and it runs admission only at the line's head, so a
/// later request never takes the window ahead of it. A refused window spends
/// nothing, so a request that waits holds nothing but its place.
pub(crate) struct Turn<'a> {
    server: &'a SyncServer,
    authenticated: bool,
    deadline: Instant,
    asked: bool,
    /// Its place at the head of its window's line, held until the request is
    /// answered: for a hold that reaches its write, the executor hands it to
    /// the write, which gives it up as the write returns, even when the
    /// request was dropped first; a hold answered before its write gives it
    /// up with the turn.
    place: Option<LinePlace>,
}

impl<'a> Turn<'a> {
    pub(crate) fn new(server: &'a SyncServer, authenticated: bool) -> Self {
        Self {
            server,
            authenticated,
            deadline: Instant::now() + server.config.limits.queue_wait(),
            asked: false,
            place: None,
        }
    }

    /// Takes this authenticated request's place in `window`'s line and
    /// waits there for every request on that window that came first, until
    /// the deadline. Past the deadline it is answered
    /// `booking_turn_waited_out` before any admission ran, so nothing was
    /// spent.
    ///
    /// An anonymous request is never made to wait (ARCH-0062
    /// #rate-wait-built): it takes the head of an empty line and holds it as
    /// an authenticated request does, and a line someone is in answers it
    /// `booking_retry_after_60s`, the session hold cap's own hint, before any
    /// admission ran. So it never takes the window ahead of a request that
    /// waits for it (FIX BOOKING-ANON-HOLD-OVERTAKES-LINE).
    pub(crate) async fn line_up(&mut self, window: SessionKey) -> Result<(), ApiError> {
        if self.place.is_some() {
            return Ok(());
        }
        if !self.authenticated {
            self.place = Some(
                self.server
                    .booking_turn_lines
                    .try_join(window)
                    .ok_or_else(line_busy)?,
            );
            return Ok(());
        }
        match self
            .server
            .booking_turn_lines
            .join(window, self.deadline)
            .await
        {
            Some(place) => {
                self.place = Some(place);
                Ok(())
            }
            None => Err(waited_out()),
        }
    }

    /// This request's place in its window's line, taken for the write it was
    /// admitted for: the write holds it until it returns (FIX
    /// BOOKING-CANCELLED-HOLD-DETACHED-WRITE). `None` when it holds none.
    pub(crate) fn take_place(&mut self) -> Option<LinePlace> {
        self.place.take()
    }

    /// What admission's `disposition` comes to: `Some` to act on, or `None`
    /// once this request has waited and should be admitted again.
    pub(crate) async fn after(
        &mut self,
        disposition: BookingHttpDisposition,
    ) -> Result<Option<BookingHttpDisposition>, ApiError> {
        let BookingHttpDisposition::RetryAfter { seconds, bound } = disposition else {
            return Ok(Some(disposition));
        };
        if !self.authenticated {
            return Ok(Some(disposition));
        }
        if !self.asked {
            self.asked = true;
            self.server.wire_telemetry.limit_questions().ask(
                LimitRow::BookingWindows,
                bound,
                bound.saturating_add(1),
            );
        }
        let open = Instant::now() + Duration::from_secs(seconds);
        tokio::time::sleep_until(open.min(self.deadline)).await;
        // Admission runs again only before the deadline: past it, nothing
        // more is spent.
        if Instant::now() >= self.deadline {
            return Err(waited_out());
        }
        Ok(None)
    }
}

/// A busy line's answer to an anonymous hold: the typed answer admission
/// gives an anonymous request past a window (`admission_short_circuit`,
/// `booking_retry_after_<n>s`, ARCH-0062 #rate-wait-built), byte for byte,
/// with the session hold cap's own hint. Nothing was spent.
fn line_busy() -> ApiError {
    let seconds = SESSION_HOLD_RETRY_SECS;
    ApiError::new(
        format!("booking admission is rate limited; retry after {seconds} seconds"),
        crate::error::ApiErrorDetails::InvalidState {
            state: Some(format!("booking_retry_after_{seconds}s")),
        },
        [format!(
            "Wait {seconds} seconds before retrying this booking request."
        )],
    )
}

/// The deadline came before the window opened for this request. Nothing was
/// spent, and it may be sent again.
fn waited_out() -> ApiError {
    ApiError::new(
        "booking admission waited past limits.queue_wait_timeout_ms for its window; nothing was spent",
        crate::error::ApiErrorDetails::InvalidState {
            state: Some("booking_turn_waited_out".to_owned()),
        },
        ["Send this booking request again."],
    )
}
