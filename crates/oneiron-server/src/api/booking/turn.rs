//! Rule five at the owner's booking windows: authenticated work past one
//! waits for it to open and is never answered "retry after".

use std::time::Duration;

use tokio::time::Instant;

use super::BookingAdmissionContext;
use crate::api::booking_anti_abuse::BookingHttpDisposition;
use crate::error::ApiError;
use crate::server::SyncServer;
use crate::wire_telemetry::LimitRow;

/// One request's wait past the owner's windows.
///
/// An anonymous visitor past a window is answered `RetryAfter`, as before:
/// pre-auth work stays sheddable. An authenticated caller past one is never
/// refused for it: its crossing asks once, and it is admitted again as the
/// window opens, until `limits.queue_wait_timeout_ms` runs out. Its credential
/// keys windows of its own (`BookingTransportContext::actor_key`), so no
/// caller's wait is spent on another's requests, and a refused window spends
/// nothing, so a request that waits holds nothing.
pub(super) struct Turn<'a> {
    server: &'a SyncServer,
    authenticated: bool,
    deadline: Instant,
    asked: bool,
}

impl<'a> Turn<'a> {
    pub(super) fn new(
        server: &'a SyncServer,
        transport: impl Into<BookingAdmissionContext>,
    ) -> Self {
        let transport = transport.into();
        Self {
            server,
            authenticated: transport.credential.is_some(),
            deadline: Instant::now() + server.config.limits.queue_wait(),
            asked: false,
        }
    }

    /// What admission's `disposition` comes to: `Some` to act on, or `None`
    /// once this request has waited and should be admitted again.
    pub(super) async fn after(
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
