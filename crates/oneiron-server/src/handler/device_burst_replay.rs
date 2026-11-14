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

/// Lands `work`, an own device's retained window update that is due: checked
/// against its window as the window is now, its copy edits taken onto their
/// sources, persisted, imported under the live-window turn and relayed to
/// every socket, the device's own included. No socket sent it, so no Write
/// credential is rechecked: the burst core ended the batch `StaleAuthority`
/// before this if its device no longer stands as it did (FIX 7999). A copy
/// edit held on its ruled cause keeps its held record and lands nothing.
///
/// # Errors
/// [`ProtocolError::Persistence`] for the window's load or the persist,
/// which the next pass retries; any other error refuses the device's bytes
/// as they are now.
pub(crate) async fn land_retained_device_update(
    server: &SyncServer,
    work: &DeviceBurstWork,
) -> Result<(), ProtocolError> {
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
