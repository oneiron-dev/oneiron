//! Starts and records a separate attached session for proposal replay.

use super::scripted_chromium::{Request, ScriptedChromium};
use super::secret_custody::RecordingSecretCustody;
use super::session_fixture::{SessionFixture, Unmetered, attach_replay_session};
use oneiron_browser::{
    BrowserEngine, BrowserError, BrowserRequestHandler, BrowserSession, FreshGuest, HandleRetention,
};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

/// The engine and request handler passed to one fresh start.
#[derive(Clone)]
pub(crate) struct StartCall {
    engine: BrowserEngine,
    requests: Option<Arc<dyn BrowserRequestHandler>>,
}

impl PartialEq for StartCall {
    fn eq(&self, other: &Self) -> bool {
        self.engine == other.engine
            && match (&self.requests, &other.requests) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }
}

impl fmt::Debug for StartCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartCall")
            .field("engine", &self.engine)
            .field("has_request_handler", &self.requests.is_some())
            .finish()
    }
}

/// The peer remains inspectable after the fresh session has gone.
struct ReplayPeer {
    peer: ScriptedChromium,
    mark: usize,
}

/// The optional input on the fresh fixture page.
#[derive(Clone, Copy, Default)]
enum ReplayField {
    #[default]
    None,
    Password,
    Otp,
}

/// Each clone sees the whole start log and the independently attached peer.
#[derive(Clone, Default)]
pub(crate) struct RecordingFreshGuest {
    refusal: bool,
    labels: Option<(String, String)>,
    field: ReplayField,
    custody: Option<RecordingSecretCustody>,
    calls: Arc<Mutex<Vec<StartCall>>>,
    replay: Arc<Mutex<Option<ReplayPeer>>>,
}

impl RecordingFreshGuest {
    /// Starts an empty scripted peer when the door asks.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Refuses the start after recording its arguments.
    pub(crate) fn refusing() -> Self {
        Self {
            refusal: true,
            ..Self::default()
        }
    }

    /// Sets the fresh page's title and heading independently of the proposer.
    pub(crate) fn with_page(mut self, title: &str, heading: &str) -> Self {
        self.labels = Some((title.to_owned(), heading.to_owned()));
        self
    }

    /// Shows a blank password field on the fresh peer.
    pub(crate) fn with_password_field(mut self) -> Self {
        self.field = ReplayField::Password;
        self
    }

    /// Shows a blank one-time-code field on the fresh peer.
    pub(crate) fn with_otp_field(mut self) -> Self {
        self.field = ReplayField::Otp;
        self
    }

    /// Gives the replay its own recording custody before it adopts the run.
    pub(crate) fn with_custody(mut self, custody: RecordingSecretCustody) -> Self {
        self.custody = Some(custody);
        self
    }

    /// Installs this start path on the real proposing session.
    pub(crate) fn install(&self, session: &mut BrowserSession) {
        session.set_fresh_guest(Box::new(self.clone()));
    }

    /// Returns every start request, including refusals.
    pub(crate) fn calls(&self) -> Vec<StartCall> {
        self.calls.lock().expect("fresh start log locks").clone()
    }

    /// Returns the fresh peer, marked just after its attach and before replay.
    fn replay_peer(&self) -> MutexGuard<'_, Option<ReplayPeer>> {
        self.replay.lock().expect("fresh replay peer locks")
    }
}

impl FreshGuest for RecordingFreshGuest {
    fn start(
        &mut self,
        engine: BrowserEngine,
        requests: Option<Arc<dyn BrowserRequestHandler>>,
    ) -> Result<BrowserSession, BrowserError> {
        self.calls
            .lock()
            .expect("fresh start log locks")
            .push(StartCall {
                engine,
                requests: requests.clone(),
            });
        if self.refusal {
            return Err(BrowserError::Unavailable(
                "fixture disallows start".to_owned(),
            ));
        }
        let (mut session, peer) = attach_replay_session(engine, requests);
        let mark = peer.mark();
        if let Some((title, heading)) = &self.labels {
            peer.set_page_labels(title, heading);
        }
        match self.field {
            ReplayField::None => {}
            ReplayField::Password => peer.show_password_field(),
            ReplayField::Otp => peer.show_otp_field(None),
        }
        if let Some(custody) = &self.custody {
            session.set_secret_custody(Arc::new(custody.clone()));
        }
        *self.replay_peer() = Some(ReplayPeer { peer, mark });
        Ok(session)
    }

    fn state_charge(&self) -> Box<dyn HandleRetention> {
        Box::new(Unmetered)
    }
}

/// One check: follow, capture.
const CHECK_METHODS: [&str; 8] = [
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
];
/// The carry: page, cookies, two stores.
const CARRY_METHODS: [&str; 4] = [
    "Target.getTargetInfo",
    "Network.getAllCookies",
    "Runtime.evaluate",
    "Runtime.evaluate",
];

/// Hidden observation: the capture, then the page's shown URL and title.
fn observation_methods() -> impl Iterator<Item = &'static str> {
    CHECK_METHODS.into_iter().chain(["Target.getTargetInfo"])
}

/// The proposer's hidden read, solved checks and carry, with any OTP origin reads.
fn proposer_methods(checks: usize, otp: bool) -> Vec<&'static str> {
    let origin = otp.then_some("Target.getTargetInfo");
    CHECK_METHODS
        .into_iter()
        .chain(origin)
        .chain(["Target.getTargetInfo"])
        .chain((0..checks).flat_map(|_| CHECK_METHODS.into_iter().chain(origin)))
        .chain(CARRY_METHODS)
        .collect()
}

/// Both door windows, with stable fresh boundaries around its settle polls.
pub(crate) fn replay_requests(
    fixture: &SessionFixture,
    fresh: &RecordingFreshGuest,
    mark: usize,
    checks: usize,
    otp: bool,
    final_read: bool,
    url: &str,
) -> Vec<Request> {
    fixture.assert_methods(mark, &proposer_methods(checks, otp));
    assert_eq!(
        fresh.calls(),
        [StartCall {
            engine: BrowserEngine::Chromium,
            requests: None
        }]
    );
    let fresh_peer = fresh.replay_peer();
    let fresh_peer = fresh_peer.as_ref().expect("the second peer attached");
    assert_eq!(
        fresh_peer.peer.unanswered(),
        Vec::<String>::new(),
        "fresh unanswered methods"
    );
    let requests = fresh_peer.peer.requests_since(fresh_peer.mark);
    let methods: Vec<_> = requests
        .iter()
        .map(|request| request.method.as_str())
        .collect();
    let prefix: Vec<_> = observation_methods()
        .chain([
            "Runtime.evaluate",
            "Target.getTargets",
            "Target.getTargetInfo",
            "Page.navigate",
            "Runtime.evaluate",
        ])
        .collect();
    let suffix: Vec<_> = (0..checks)
        .flat_map(|_| CHECK_METHODS)
        .chain(final_read.then(observation_methods).into_iter().flatten())
        .collect();
    assert!(
        methods.starts_with(&prefix) && methods.ends_with(&suffix),
        "replay read boundaries: {methods:?}"
    );
    let urls: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "Page.navigate")
        .map(|request| request.params["url"].as_str())
        .collect();
    assert_eq!(urls, [Some(url)], "only the fresh replay navigates");
    requests
}
