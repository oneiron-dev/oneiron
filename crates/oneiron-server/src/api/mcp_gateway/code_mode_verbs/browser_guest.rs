//! A run browser's guests (FIX 6680, BROWSER-SPLIT PR3): its first guest
//! and every engine switch's target start on one path, the run's
//! `start_run_guest`, so each gets its own proved fence, its run's egress
//! door and its own live-handle charge, and its manifest is receipted. The
//! starter a session keeps for its switches holds the run, its vault, the
//! host's browser guest and the host's retained line; never the seat, the
//! library or the receipt sink, which stay with the session.
//!
//! A guest's command names its engine and the largest CDP message its
//! browser takes, derived from the egress door's largest answer body, so
//! one setting moves both (FIX 6815).
//!
//! A browser verb the guest refuses answers its stable code; a host caller
//! is worded the code, and for `browser_unsupported` the engine's own words,
//! which name the verb that serves it (FIX 6862).

use std::ffi::OsString;
use std::sync::Arc;

use oneiron::code_run::AgentVerbRefusalWords;
use oneiron::code_sandbox::egress::EgressConfig;
use oneiron::{EntityId, Vault};
use oneiron_browser::{
    BrowserEngine, BrowserError, BrowserGuest, BrowserGuestStarter, BrowserSession,
    HandleRetention, StartedGuest,
};

use super::start_run_guest;
use crate::server::HandleLine;

/// Starts one run's browser guests on the host's own path.
struct RunGuestStarter {
    vault: Arc<Vault>,
    run_id: EntityId,
    guest: BrowserGuest,
    handles: HandleLine,
}

impl BrowserGuestStarter for RunGuestStarter {
    fn start(&mut self, engine: BrowserEngine) -> Result<StartedGuest, BrowserError> {
        let (transport, relay) = start_run_guest(
            &self.vault,
            self.run_id,
            &self.guest.runtime,
            &self.guest.image,
            self.guest.limits,
            self.guest.fixture.as_ref(),
            &guest_argv(engine)?,
        )?;
        Ok(StartedGuest {
            transport,
            relay,
            retention: self.handles.charge(),
        })
    }

    fn state_charge(&self) -> Box<dyn HandleRetention> {
        self.handles.charge()
    }
}

/// Starts run `run_id`'s browser on the engine the host's `guest` names and
/// attaches it, with the starter its engine switches take.
pub(super) fn start_run_browser(
    vault: &Arc<Vault>,
    run_id: EntityId,
    guest: &BrowserGuest,
    handles: &HandleLine,
) -> Result<BrowserSession, BrowserError> {
    let mut starter = RunGuestStarter {
        vault: Arc::clone(vault),
        run_id,
        guest: guest.clone(),
        handles: handles.clone(),
    };
    let StartedGuest {
        transport,
        relay,
        retention,
    } = starter.start(guest.engine)?;
    BrowserSession::attach(guest, transport, relay, retention, Some(Box::new(starter)))
}

/// The command that starts a run's browser guest on `engine`: the image's
/// entrypoint, told the engine and the CDP message bound the run's egress
/// door sets (FIX 6815).
fn guest_argv(engine: BrowserEngine) -> Result<[OsString; 3], BrowserError> {
    let egress = EgressConfig::from_env().map_err(|e| BrowserError::Unavailable(e.to_string()))?;
    Ok(engine.guest_argv(egress.max_response_bytes))
}

/// A browser verb's refusal as the run door words it (FIX 6862): its code,
/// and for `browser_unsupported` alone the error's own words, which name
/// the verb that serves what was refused (`self.browser.switch_engine` to
/// the other engine). They are engine text, never page content. Every other
/// code is worded by its code, as before.
pub(super) fn refusal_words(error: &BrowserError) -> AgentVerbRefusalWords {
    match error {
        BrowserError::Unsupported(_) => AgentVerbRefusalWords {
            code: error.code().to_owned(),
            message: error.to_string(),
            suggestions: Vec::new(),
        },
        _ => code_words(error.code().to_owned()),
    }
}

/// A refusal worded by its code alone.
pub(super) fn code_words(code: String) -> AgentVerbRefusalWords {
    AgentVerbRefusalWords {
        message: code.clone(),
        code,
        suggestions: Vec::new(),
    }
}
