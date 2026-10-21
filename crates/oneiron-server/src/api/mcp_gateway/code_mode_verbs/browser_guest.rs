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
//! which name the verb that serves it (FIX 6862), with that verb as a bare
//! suggestion where they name it (FIX 6966). A destination refusal of the
//! host's request handler answers the host's own reason and words (FIX
//! 7122). A run's guests keep those words from its newest browser call, for
//! the run's door to carry them to the guest's program as well
//! ([`KeptRefusal`], FIX 6887).

use std::ffi::OsString;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::code_run::AgentVerbRefusalWords;
use oneiron::code_sandbox::egress::EgressConfig;
use oneiron::{EntityId, Vault};
use oneiron_browser::{
    BrowserEngine, BrowserError, BrowserGuest, BrowserGuestStarter, BrowserRequestHandler,
    BrowserSession, HandleRetention, StartedGuest,
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
/// attaches it, with the starter its engine switches take, and the host's
/// `requests` handler where the host gives one (FIX 7122): it then performs
/// every request of the run's pages in place of the run's relay.
pub(super) fn start_run_browser(
    vault: &Arc<Vault>,
    run_id: EntityId,
    guest: &BrowserGuest,
    handles: &HandleLine,
    requests: Option<Arc<dyn BrowserRequestHandler>>,
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
    let starter: Box<dyn BrowserGuestStarter> = Box::new(starter);
    BrowserSession::attach(guest, transport, relay, retention, Some(starter), requests)
}

/// The command that starts a run's browser guest on `engine`: the image's
/// entrypoint, told the engine and the CDP message bound the run's egress
/// door sets (FIX 6815).
fn guest_argv(engine: BrowserEngine) -> Result<[OsString; 3], BrowserError> {
    let egress = EgressConfig::from_env().map_err(|e| BrowserError::Unavailable(e.to_string()))?;
    Ok(engine.guest_argv(egress.max_response_bytes))
}

/// The verb an engine's refusal names as the way out, as its bare
/// suggestion (FIX 6966).
const SWITCH_ENGINE_VERB: &str = "self.browser.switch_engine";

/// A browser verb's refusal as the run door words it (FIX 6862): its code,
/// and for `browser_unsupported` the error's own words, which name the verb
/// that serves what was refused (`self.browser.switch_engine` to the other
/// engine), that verb also its one bare suggestion where they name it (FIX
/// 6966). They are engine text, never page content. A destination refusal
/// of the host's request handler (FIX 7122) is worded by the host: its
/// reason as the code, its message as the words. Every other code is worded
/// by its code, as before.
pub(super) fn refusal_words(error: &BrowserError) -> AgentVerbRefusalWords {
    match error {
        BrowserError::Unsupported(_) => {
            let message = error.to_string();
            let named = message.contains(SWITCH_ENGINE_VERB);
            AgentVerbRefusalWords {
                code: error.code().to_owned(),
                suggestions: named
                    .then(|| SWITCH_ENGINE_VERB.to_owned())
                    .into_iter()
                    .collect(),
                message,
            }
        }
        BrowserError::DestinationRefused(refused) => AgentVerbRefusalWords {
            code: refused.reason.clone(),
            message: refused.message.clone(),
            suggestions: Vec::new(),
        },
        _ => code_words(error.code().to_owned()),
    }
}

/// The words a run's newest browser call was refused with, for the run's
/// door to copy into the program's answer (FIX 6887): kept where they say
/// more than their code, as [`refusal_words`] words `browser_unsupported`,
/// naming the verb that serves what was refused, and a destination refusal
/// in the host's own words (FIX 7122). A call that answered, or was refused
/// another way, keeps none.
#[derive(Default)]
pub(super) struct KeptRefusal(Mutex<Option<AgentVerbRefusalWords>>);

impl KeptRefusal {
    /// Keeps the newest call's refusal words, `None` when it was not
    /// refused, in place of the last call's.
    pub(super) fn keep(&self, refused: Option<&AgentVerbRefusalWords>) {
        let kept = refused.filter(|words| words.message != words.code);
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = kept.cloned();
    }

    /// The words kept, if any.
    pub(super) fn words(&self) -> Option<AgentVerbRefusalWords> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
