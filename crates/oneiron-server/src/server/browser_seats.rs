//! The run browsers live on this host (CUA-001), each in its run's seat as
//! the run desktops do ([`super::desktop_seats`]): the owner's door reaches
//! the same guest a run's door drives, to sign in or pay inside it, and the
//! run's next door (an MCP `execute_code` run's next entry, a pumped run's
//! resume) finds the browser its last one left, cart and login with it. The
//! browser ends when its run ends, or once it sits idle with no door of the
//! run bound.
//!
//! An agent's handover raises the owners' inbox Ask ("Needs you") with guest
//! `browser`; the owner's take or return clears it, and so does the seat's
//! end.

mod handles;

use std::sync::Arc;

use oneiron::secret_custody::RunSecretSeat;
use oneiron::{EntityId, Vault};
use oneiron_browser::{
    AbandonedTakeover, BrowserError, BrowserSession, DemonstrationOutput, Takeover,
};

use super::SyncServer;
use super::desktop_seats::{RunSeats, Seat, SeatGuest};

pub(crate) use handles::HandleLine;

/// One run's browser seat.
pub(crate) type BrowserSeat = Seat<BrowserSession>;

/// The run browsers' seats.
pub(crate) type BrowserSeats = RunSeats<BrowserSession>;

impl SeatGuest for BrowserSession {
    const GUEST: &'static str = "browser";
    const NOUN: &'static str = "run browser";
    const TAKE_ROUTE: &'static str = "/v1/owner/browsers/take";
    const SECRETS: RunSecretSeat = RunSecretSeat::Browser;

    fn seats(server: &SyncServer) -> &Arc<RunSeats<Self>> {
        &server.browser_seats
    }

    fn takeover(&self) -> &Takeover {
        Self::takeover(self)
    }

    fn awaits_owner(&self) -> bool {
        self.awaits_press_answer()
    }

    fn abandon_takeover(&mut self) -> Option<AbandonedTakeover> {
        Self::abandon_takeover(self)
    }

    fn abandoned_demonstration(&mut self) -> Option<DemonstrationOutput> {
        self.take_abandoned_demonstration()
    }

    fn land_abandoned(
        vault: &Vault,
        run: EntityId,
        record: &serde_json::Value,
    ) -> oneiron::Result<String> {
        vault.append_browser_takeover_abandoned_receipt(run, record)
    }

    /// The tabs beside the front tab's viewport: a popup the person opened
    /// shows in the list, and in front once found.
    fn watch(&mut self) -> (Option<serde_json::Value>, Result<Vec<u8>, BrowserError>) {
        match self.person_view() {
            Ok((tabs, png)) => (serde_json::to_value(tabs).ok(), Ok(png)),
            Err(error) => (None, Err(error)),
        }
    }
}
