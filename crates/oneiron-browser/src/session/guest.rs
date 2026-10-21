//! A session's engine guest (FIX 6680, BROWSER-SPLIT PR3): the browser
//! guest, its lease and manifest, and the CDP driver attached to it, as the
//! one group an engine switch replaces. Everything else a session holds
//! belongs to its run and stays across a switch.
//!
//! The host hands a session it can switch a [`BrowserGuestStarter`]: the
//! host's own start path, so a switch's target guest gets its own proved
//! fence, egress door and live-handle charge, as the first guest did.

use super::storage::Sink;
use crate::BrowserEngine;
use crate::BrowserError;
use crate::cdp::Pipe;
use crate::driver::CdpDriver;
use crate::request::Custody;
use crate::retention::HandleRetention;
use oneiron_container::{EgressRelay, SessionLease, SessionManifest, SessionTransport};
use std::sync::Arc;
use std::time::Duration;

/// A browser guest the host started, as a session attaches it: its
/// transport, its run's egress relay, and a fresh charge on the host's
/// retained line for its live handles.
pub struct StartedGuest {
    pub transport: SessionTransport,
    pub relay: Arc<dyn EgressRelay>,
    pub retention: Box<dyn HandleRetention>,
}

/// How the host starts a browser guest for a session's engine switch: on
/// the same path its first guest started on, for the same run.
pub trait BrowserGuestStarter: Send {
    /// Starts a guest on `engine`.
    fn start(&mut self, engine: BrowserEngine) -> Result<StartedGuest, BrowserError>;

    /// A charge on the host's retained line, holding nothing yet, for page
    /// state the session holds: its per-origin storage snapshots, taken
    /// once at attach, and the state a switch holds while it carries it;
    /// apart from every driver's live-handle charge.
    fn state_charge(&self) -> Box<dyn HandleRetention>;
}

/// The engine group of a session: what one engine switch replaces whole.
pub(crate) struct EngineGuest {
    pub(crate) driver: CdpDriver,
    pub(crate) lease: Box<dyn SessionLease>,
    pub(crate) manifest: SessionManifest,
}

impl EngineGuest {
    /// Attaches the driver for `engine` to a started guest whose fence the
    /// backend proved: its pipe on the engine's transport, behind the run's
    /// relay or the host's request handler the session's `custody` holds
    /// (FIX 7122), keeping its pages' storage reads through `sink` when the
    /// session keeps snapshots, and its first page readied as every page is.
    pub(crate) fn attach(
        engine: BrowserEngine,
        started: StartedGuest,
        wait_cap: Duration,
        sink: Option<Sink>,
        custody: Custody,
    ) -> Result<Self, BrowserError> {
        let StartedGuest {
            transport,
            relay,
            retention,
        } = started;
        if transport.manifest.fence_unproven || transport.manifest.fence_proof.is_none() {
            return Err(BrowserError::Unavailable(
                "browser session fence unproven".to_owned(),
            ));
        }
        let SessionTransport {
            reader,
            writer,
            manifest,
            lease,
        } = transport;
        let pipe = Pipe::for_engine(engine, reader, writer, Some(relay), custody)?;
        if let Some(sink) = sink {
            pipe.collect(sink);
        }
        let driver = CdpDriver::attach(pipe, engine, wait_cap, retention)?;
        Ok(Self {
            driver,
            lease,
            manifest,
        })
    }
}
