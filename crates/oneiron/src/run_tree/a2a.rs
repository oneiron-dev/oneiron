//! Attempt-record to A2A task projection with cancel/landing extensions.

use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::consult_ladder::{A2aBaseTaskState, A2aTaskProjection, OneironA2aExtensions};

use super::render::attempt_id_hex;

/// Projects one ATTEMPT row onto A2A task vocabulary, preserving the two-rung
/// graceful-cancel distinctions A2A itself cannot express.
///
/// The invariant this exists to hold: a LANDING attempt projects as `working`
/// carrying `cancel_mode = "landing"`, never as `completed` and never as
/// `cancelled`. A peer reading only the base state sees honest live work; a
/// peer reading the extensions can tell an accepted landing from a refusal,
/// from a designed stop, and from a hard kill.
///
/// The resume point is exported WHOLE — cursor and artifact reference both —
/// because a successor given only the cursor has lost the identity of the work
/// already produced. Both are typed refs; no payload body crosses this seam.
#[must_use]
pub fn project_attempt_to_a2a(record: &AttemptRecord) -> A2aTaskProjection {
    let mut extensions = OneironA2aExtensions {
        cancel_rejections: record.cancel_pressure().rejections,
        resume_point: record
            .resume_point()
            .map(|resume_point| resume_point.marker.clone()),
        // The WHOLE durable resume point, not just its marker: exporting the
        // cursor alone silently dropped the artifact identity a successor needs
        // to read before it continues, and a peer cannot recover a reference it
        // was never given.
        resume_artifact_ref: record
            .resume_point()
            .and_then(|resume_point| resume_point.artifact_ref.clone()),
        ..OneironA2aExtensions::default()
    };
    if let Some(landing) = record.landing() {
        extensions.landing_trigger = Some(landing.trigger.as_str().to_owned());
    }
    let base = match record.state {
        AttemptState::Queued | AttemptState::Scheduled | AttemptState::Leased => {
            A2aBaseTaskState::Working
        }
        AttemptState::Paused => A2aBaseTaskState::InputRequired,
        AttemptState::Landing => {
            extensions.cancel_mode = Some(ATTEMPT_A2A_CANCEL_MODE_LANDING.to_owned());
            A2aBaseTaskState::Working
        }
        AttemptState::Completed => A2aBaseTaskState::Completed,
        AttemptState::Failed => A2aBaseTaskState::Failed,
        AttemptState::Cancelled => A2aBaseTaskState::Cancelled,
        // A2A's base vocabulary is closed and holds no abandoned token, so
        // this is the one projection that must lose the distinction. `failed`
        // is the lossy target that keeps the only fact a peer can act on —
        // this task will never deliver. `cancelled` is refused for the same
        // reason the native surfaces refuse it: it would assert to the peer
        // that somebody decided to stop the work, and nobody did.
        AttemptState::Abandoned => A2aBaseTaskState::Failed,
    };
    if let Some(cancellation) = record.cancellation() {
        extensions.cancel_mode = Some(cancellation.mode.as_str().to_owned());
        if let Some(trigger) = cancellation.trigger {
            extensions.landing_trigger = Some(trigger.as_str().to_owned());
        }
    } else if base == A2aBaseTaskState::Working
        && extensions.cancel_mode.is_none()
        && record.cancel_pressure().requests > 0
    {
        // Asked but not yet settled: refusal outranks a bare outstanding ask,
        // because a peer needs to know the worker ANSWERED and said no.
        extensions.cancel_mode = Some(if extensions.cancel_rejections > 0 {
            ATTEMPT_A2A_CANCEL_MODE_REJECTED.to_owned()
        } else {
            ATTEMPT_A2A_CANCEL_MODE_REQUESTED.to_owned()
        });
    }
    A2aTaskProjection {
        id: attempt_id_hex(record),
        state: base,
        extensions,
    }
}

/// Wire tokens for [`OneironA2aExtensions::cancel_mode`] that have no durable
/// [`crate::attempt_queue::CancelMode`] behind them because the attempt has not
/// settled yet.
const ATTEMPT_A2A_CANCEL_MODE_LANDING: &str = "landing";

const ATTEMPT_A2A_CANCEL_MODE_REQUESTED: &str = "requested";

const ATTEMPT_A2A_CANCEL_MODE_REJECTED: &str = "rejected";
