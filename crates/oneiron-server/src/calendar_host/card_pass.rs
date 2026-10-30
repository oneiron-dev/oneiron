//! The host's meeting-card pass (FIX 12004): on the elected home node, each
//! tick delivers the prep packs and check-ins that have come due to the
//! owners' INBOX, and asks an unanswered check-in once more on the owner's
//! next morning. The engine plans every instant; this worker is the clock.

use std::sync::Arc;
use std::time::Duration;

use oneiron::calendar::{
    CalendarCardCopy, CalendarCardPass, CheckInCopy, PrepLensCopy, run_calendar_card_pass,
};

use crate::server::{HousekeepingAdmission, SyncServer};

/// How often the worker looks for a card that has come due.
const CARD_TICK: Duration = Duration::from_secs(60);

/// The words on the cards the host delivers.
fn card_copy() -> CalendarCardCopy {
    CalendarCardCopy {
        prep: PrepLensCopy {
            title: "Before your meeting".to_owned(),
            commitment_heading: "What you promised".to_owned(),
            thread_heading: "Recent threads".to_owned(),
            dossier_heading: "What changed".to_owned(),
        },
        check_in: CheckInCopy {
            title: "How did the meeting go?".to_owned(),
            body: "Did it go ahead?".to_owned(),
            held_label: "Went ahead".to_owned(),
            no_show_label: "No-show".to_owned(),
            rescheduled_label: "Rescheduled".to_owned(),
            recording_label: "Add a recording".to_owned(),
        },
    }
}

/// Starts the pass. Each pass is admitted through `admit`, the way a
/// housekeeping pass is, and runs only while this server holds the vault's
/// home-node election.
pub(crate) fn spawn_calendar_card_pass(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let copy = Arc::new(card_copy());
        let mut interval = tokio::time::interval(CARD_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(admission) = admit() else {
                continue;
            };
            let server = Arc::clone(&server);
            let copy = Arc::clone(&copy);
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                let now = server.vault().now_recorded_at();
                if !crate::decision_graph::at_home(&server, now)? {
                    return Ok(CalendarCardPass::default());
                }
                run_calendar_card_pass(server.vault(), now, &copy)
            })
            .await;
            match pass {
                Ok(Ok(pass)) if pass != CalendarCardPass::default() => tracing::info!(
                    prepped = pass.prepped,
                    asked = pass.asked,
                    re_asked = pass.re_asked,
                    withdrawn = pass.withdrawn,
                    "meeting cards delivered"
                ),
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, "meeting card pass failed");
                }
                Err(error) => {
                    tracing::warn!(%error, "meeting card pass panicked");
                }
            }
        }
    })
}
