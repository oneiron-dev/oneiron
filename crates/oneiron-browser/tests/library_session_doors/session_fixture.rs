//! Attaches the real browser session without starting a guest or allowing egress.

use super::scripted_chromium::ScriptedChromium;
use super::workflow_store::{StoreState, WorkflowStore};
use oneiron_browser::{
    BrowserEngine, BrowserError, BrowserGuest, BrowserSession, GuestLimits, HandleRetention,
    SendPolicy,
};
use oneiron_container::{
    EgressRelay, FenceProof, GuestSeccomp, HostNetFloor, HttpRequest, HttpResponse, SessionLease,
    SessionManifest, SessionTransport, UnmeteredFloor,
};
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const IMAGE: &str = concat!(
    "guest.example/browser@sha256:",
    "0000000000000000000000000000000000000000000000000000000000000000",
);

/// One real session and the two fakes whose boundary calls a test can inspect.
pub(crate) struct SessionFixture {
    pub(crate) session: BrowserSession,
    pub(crate) peer: ScriptedChromium,
    pub(crate) store: Arc<Mutex<StoreState>>,
}

impl SessionFixture {
    /// Attaches Chromium on a socket pair and installs an empty library.
    pub(crate) fn attach(url: &str) -> Self {
        let (stream, peer) = ScriptedChromium::start(url, false);
        let config = BrowserGuest {
            runtime: PathBuf::from("no-runtime"),
            image: IMAGE.to_owned(),
            limits: GuestLimits {
                memory_mib: 256,
                cpu_millis: 1000,
                pids: 64,
                tmpfs_mib: 64,
            },
            wait_cap: Duration::from_secs(2),
            policy: SendPolicy::default(),
            fixture: None,
            fixture_forward: None,
            engine: BrowserEngine::Chromium,
        };
        let attached = BrowserSession::attach(
            &config,
            transport(stream),
            Arc::new(NoEgress),
            Box::new(Unmetered),
            None,
            None,
        );
        let mut session = expect_answer(&peer, attached, "the scripted Chromium session attaches");
        let store = Arc::new(Mutex::new(StoreState::default()));
        session.set_library(Box::new(WorkflowStore(Arc::clone(&store))));
        Self {
            session,
            peer,
            store,
        }
    }

    /// Requires a successful door result and prints unanswered calls on failure.
    pub(crate) fn expect_ok<T>(&self, result: Result<T, BrowserError>, expected: &str) -> T {
        expect_answer(&self.peer, result, expected)
    }

    /// Checks all methods since a mark for a path without poll-dependent sends.
    pub(crate) fn assert_methods(&self, mark: usize, methods: &[&str]) {
        assert_eq!(
            self.peer.unanswered(),
            Vec::<String>::new(),
            "unanswered CDP calls"
        );
        let requests = self.peer.requests_since(mark);
        let actual: Vec<_> = requests
            .iter()
            .map(|request| request.method.as_str())
            .collect();
        assert_eq!(actual, methods, "CDP methods since the mark");
    }
}

/// Reports a failed answer together with methods the peer could not answer.
fn expect_answer<T>(peer: &ScriptedChromium, result: Result<T, BrowserError>, expected: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!(
            "{expected}: {error:?}; unanswered CDP calls: {:?}",
            peer.unanswered()
        ),
    }
}

/// Names the fixture's accepted attach fence without running a fence or a guest.
fn manifest() -> SessionManifest {
    let generation = "generation-1".to_owned();
    SessionManifest {
        backend: "test".to_owned(),
        runtime: "test".to_owned(),
        image: IMAGE.to_owned(),
        argv_digest: "argv".to_owned(),
        network: "none".to_owned(),
        seccomp: GuestSeccomp::RuntimeDefault,
        fence_proof: Some(FenceProof {
            ruleset_hash: "ruleset".to_owned(),
            seccomp_hash: "seccomp".to_owned(),
            network_routes: Vec::new(),
            network_evidence_digest: "evidence".to_owned(),
            sandbox_generation: generation.clone(),
            launcher_digest: "launcher".to_owned(),
        }),
        generation,
        fence_unproven: false,
        image_release: Default::default(),
        guest_pressure: None,
    }
}

/// Splits the host end into the public attach transport's reader and writer.
fn transport(stream: UnixStream) -> SessionTransport {
    SessionTransport {
        reader: Box::new(stream.try_clone().expect("the host reader socket clones")),
        writer: Box::new(stream),
        manifest: manifest(),
        lease: Box::new(RunningLease),
    }
}

/// The attached fixture guest stays up throughout the test.
struct RunningLease;

impl SessionLease for RunningLease {
    fn is_running(&mut self) -> bool {
        true
    }
}

/// Allows the session to retain handles without a host memory floor.
struct Unmetered;

impl HandleRetention for Unmetered {
    fn resize(&mut self, _bytes: usize) -> bool {
        true
    }
}

/// Refuses every attempt to reach the network.
struct NoEgress;

/// The refusal used by every network method on the fixture relay.
fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "this test has no egress")
}

impl EgressRelay for NoEgress {
    fn connect(&self, _target: SocketAddr) -> io::Result<TcpStream> {
        Err(refused())
    }

    fn authorize_datagram(&self, _target: SocketAddr) -> io::Result<()> {
        Err(refused())
    }

    fn record_session(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    fn record_abandoned(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    fn datagram(&self, _target: SocketAddr, _bytes: &[u8]) -> io::Result<Vec<u8>> {
        Err(refused())
    }

    fn fetch(&self, _request: HttpRequest) -> io::Result<HttpResponse> {
        Err(refused())
    }

    fn transferred(&self, _target: SocketAddr, _content_hash: [u8; 32], _bytes: u64) {}

    fn host_net_floor(&self) -> &dyn HostNetFloor {
        &UnmeteredFloor
    }
}
