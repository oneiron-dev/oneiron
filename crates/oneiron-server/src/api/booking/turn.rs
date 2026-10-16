//! Rule five at the owner's booking windows: authenticated work past one
//! waits for it to open, in turn, and is never answered "retry after".

use std::time::Duration;

use tokio::time::Instant;

use super::BookingTransportContext;
use crate::admission::Permit;
use crate::api::booking_anti_abuse::BookingHttpDisposition;
use crate::error::ApiError;
use crate::server::SyncServer;
use crate::wire_telemetry::LimitRow;

/// One request's place among authenticated work past the owner's windows.
///
/// An anonymous visitor past a window is answered `RetryAfter`, as before:
/// pre-auth work stays sheddable. An authenticated caller past one is never
/// refused for it: its crossing asks, it takes its credential's turn in a fair
/// queue, and it is admitted again as the window opens, until
/// `limits.queue_wait_timeout_ms` runs out. A refused window spends no token,
/// so a request that waits holds nothing but its turn.
pub(super) struct Turn<'a> {
    server: &'a SyncServer,
    credential: Option<&'a str>,
    deadline: Instant,
    held: Option<Permit>,
}

impl<'a> Turn<'a> {
    pub(super) fn new(server: &'a SyncServer, transport: &'a BookingTransportContext) -> Self {
        Self {
            server,
            credential: transport.credential.as_deref(),
            deadline: Instant::now() + server.config.limits.queue_wait(),
            held: None,
        }
    }

    /// What admission's `disposition` comes to: `Some` to act on, or `None`
    /// once this request has waited and should be admitted again.
    pub(super) async fn after(
        &mut self,
        disposition: BookingHttpDisposition,
    ) -> Result<Option<BookingHttpDisposition>, ApiError> {
        let (BookingHttpDisposition::RetryAfter { seconds }, Some(credential)) =
            (&disposition, self.credential)
        else {
            return Ok(Some(disposition));
        };
        if Instant::now() >= self.deadline {
            return Err(waited_out());
        }
        let open = Instant::now() + Duration::from_secs(*seconds);
        if self.held.is_none() {
            let waiting = u64::try_from(self.server.booking_turns.waiting()).unwrap_or(u64::MAX);
            self.server.wire_telemetry.limit_questions().ask(
                LimitRow::BookingWindows,
                1,
                waiting.saturating_add(1),
            );
            let turn = tokio::time::timeout_at(
                self.deadline,
                self.server.booking_turns.admit(credential.to_owned()),
            )
            .await;
            self.held = Some(turn.ok().and_then(Result::ok).ok_or_else(waited_out)?);
        }
        tokio::time::sleep_until(open.min(self.deadline)).await;
        Ok(None)
    }
}

/// The deadline came before the window opened for this request. Nothing was
/// spent, and it may be sent again.
fn waited_out() -> ApiError {
    ApiError::new(
        "booking admission waited past limits.queue_wait_timeout_ms for its turn; nothing was spent",
        crate::error::ApiErrorDetails::InvalidState {
            state: Some("booking_turn_waited_out".to_owned()),
        },
        ["Send this booking request again."],
    )
}
