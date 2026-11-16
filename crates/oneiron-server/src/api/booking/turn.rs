//! Rule five at the owner's booking windows: authenticated work past one
//! waits for it to open and is never answered "retry after". Since FIX
//! 128-131 an authenticated caller spends none of the per-minute windows
//! (its calls are counted against `[limits]` rows that ask and serve), and
//! its quarantine admission is never rate limited, so what it can still wait
//! on is a hold's one-active-per-session rule. Its wait keeps its arrival
//! place (ARCH-0062 #booking-turn-divergence): a hold waits in its page
//! session's line, first in, first out, behind every hold that came first.

use std::time::Duration;

use oneiron::booking::SessionKey;
use tokio::time::Instant;

use crate::api::booking_anti_abuse::BookingHttpDisposition;
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
    /// answered: the executor drops it with the turn, after its write.
    place: Option<LinePlace<'a>>,
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

    /// Takes this request's place in `window`'s line and waits there for
    /// every authenticated request on that window that came first, until the
    /// deadline. An anonymous request keeps no place: it is never made to
    /// wait. Past the deadline it is answered `booking_turn_waited_out`
    /// before any admission ran, so nothing was spent.
    pub(crate) async fn line_up(&mut self, window: SessionKey) -> Result<(), ApiError> {
        if !self.authenticated || self.place.is_some() {
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
