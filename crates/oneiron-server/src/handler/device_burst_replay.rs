//! An own device's retained burst, landed by its home (L7-41). The home's
//! UPDATE arm answers a device's write that the burst core defers, or
//! isolates and proposes, as held, and lands nothing of it. Once the
//! device's rate is back at its baseline, the home's drain lands it here as
//! the arm lands an allowed write, with no human step (arch-0023b
//! `#decision-federation-26`: "Defer replays the burst later"; "It never
//! pauses for a human").

use oneiron::sync::WindowKey;
use oneiron::sync::federation_burst::DeviceBurstWork;

use super::window_sync::{land_device_update, map_update_admission_err};
use crate::protocol::ProtocolError;
use crate::server::SyncServer;

/// Why an own device's update did not land at its home (L7-41), and whether
/// its bytes were durable by then.
#[derive(Debug)]
pub(crate) struct DeviceLandingError {
    error: ProtocolError,
    durable: bool,
}

impl DeviceLandingError {
    /// A failure after the update's bytes persisted: its import or its relay.
    /// The window reloads the durable bytes on its next access.
    pub(super) fn durable(error: ProtocolError) -> Self {
        Self {
            error,
            durable: true,
        }
    }

    /// The error's closed name, for a log line.
    pub(crate) fn kind(&self) -> &'static str {
        self.error.kind()
    }

    /// The error the device's socket is answered with.
    pub(super) fn into_protocol(self) -> ProtocolError {
        self.error
    }
}

impl From<ProtocolError> for DeviceLandingError {
    /// A failure before anything of the update persisted.
    fn from(error: ProtocolError) -> Self {
        Self {
            error,
            durable: false,
        }
    }
}

/// How an own device's burst batch ends after its landing (L7-41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceBurstEnd {
    /// Landed, held on a copy edit's ruled cause, or durable with its import
    /// or relay failed after: its receipt reads `Imported`, and the window
    /// holds the bytes, or reloads them on its next access.
    Complete,
    /// Nothing of it persisted because a load, a read of the window's
    /// admission state, the copy translation or the persist failed, a Write
    /// credential refused in the persist's writer among them: it stays
    /// retained, and its device's streak counts nothing. The drain lands it
    /// later, or ends it `StaleAuthority` once its device no longer stands
    /// as it did.
    Retained,
    /// The window refused the device's own bytes: its receipt reads
    /// `Rejected`, a structural failure on the device's streak.
    Rejected,
}

impl DeviceBurstEnd {
    /// The end `landing` gives its batch.
    pub(crate) fn of<T>(landing: &Result<T, DeviceLandingError>) -> Self {
        match landing {
            Ok(_) | Err(DeviceLandingError { durable: true, .. }) => Self::Complete,
            Err(DeviceLandingError {
                error: ProtocolError::Persistence(_) | ProtocolError::AdmissionReadFailed(_),
                ..
            }) => Self::Retained,
            Err(_) => Self::Rejected,
        }
    }

    /// Ends `work` so.
    ///
    /// # Errors
    /// A store error ending the batch, or a batch that is not its device's.
    pub(crate) fn settle(
        self,
        vault: &oneiron::Vault,
        work: &DeviceBurstWork,
    ) -> oneiron::Result<()> {
        match self {
            Self::Complete => work.complete(vault),
            Self::Retained => Ok(()),
            Self::Rejected => work.reject(vault),
        }
    }
}

/// Lands `work`, an own device's retained window update that is due: checked
/// against its window as the window is now, its copy edits taken onto their
/// sources, persisted, imported under the live-window turn and relayed to
/// every socket, the device's own included. No socket sent it, so no Write
/// credential is rechecked here: the burst core ended the batch
/// `StaleAuthority` before this if its device no longer stands as it did,
/// its machine on the same key and the slip of its Write credential
/// unexpired, unrevoked, and its grant and member scope standing (FIX 7999).
/// A copy edit held on its ruled cause keeps its held record and lands
/// nothing.
///
/// # Errors
/// What [`DeviceBurstEnd::of`] reads: the window's load or the persist,
/// which the next pass retries; the device's bytes refused as they are now;
/// an import or relay failure after the bytes persisted.
pub(crate) async fn land_retained_device_update(
    server: &SyncServer,
    work: &DeviceBurstWork,
) -> Result<(), DeviceLandingError> {
    let key = WindowKey::try_new(work.window_key())
        .ok_or(ProtocolError::InvalidPayload("invalid window key"))?;
    let window = server
        .serve_window(&key)
        .await
        .map_err(|e| ProtocolError::Persistence(format!("window load failed: {e}")))?;
    let doc = window.doc.clone();
    oneiron::sync::window::validate_window_update_residence_with_vault(
        server.vault.as_ref(),
        &doc,
        work.update(),
        &key,
    )
    .map_err(map_update_admission_err)?;
    land_device_update(
        server,
        (0, work.peer().machine()),
        (&key, &doc),
        work.update(),
        None,
    )
    .await?;
    // The relayed ask intents it landed go to their consumer now, as the
    // UPDATE arm's do (FIX 20468).
    oneiron::sync::ask_forward::consume_landed_intents(server.vault());
    Ok(())
}
