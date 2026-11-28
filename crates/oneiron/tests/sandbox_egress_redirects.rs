//! FIX 7945: a code sandbox's egress HTTP fetch follows every redirect inside
//! its request deadline, each hop's policy run again; the redirect count is
//! measured on `limits.sandbox_egress_redirects` (Rule 5), never refused. On
//! main the fetch refused the redirect after its third (`max_redirects`, 3)
//! with "egress redirect bound or location", well inside the deadline.
//!
//! The egress resolves only public addresses, so each test serves its hops
//! from a local HTTP server and reaches it through the door
//! `test_doors::egress_redirects::fetch_resolved_to`, which looks up every
//! hop's host as that server's address; the rest of the fetch is a guest's.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test sandbox_egress_redirects`.
#![cfg(oneiron_test_support)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::code_sandbox::egress::{EgressConfig, OpenEgressProxy};
use oneiron::limit_ask::{EngineLimit, LimitAsk};
use oneiron::test_doors::egress_redirects::fetch_resolved_to;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_container::{HttpRequest, HttpResponse};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The redirect row's key, named as a string so this file builds on main too.
const REDIRECT_ROW: &str = "limits.sandbox_egress_redirects";
/// The redirects main followed before it refused the next.
const OLD_BOUND: u64 = 3;
/// Hops `/hop/0` .. `/hop/4` redirect; `/hop/5` answers.
const LAST_HOP: u64 = 5;
/// The body `/hop/5` answers.
const LANDED: &[u8] = b"landed";
/// The request deadline of the redirect-loop test.
const LOOP_DEADLINE: Duration = Duration::from_secs(2);

/// A local HTTP/1.1 server: `/hop/<n>` redirects to `/hop/<n + 1>` until
/// [`LAST_HOP`], which answers [`LANDED`]; `/loop` redirects to itself. It
/// counts every request it answers.
struct Hops {
    address: SocketAddr,
    served: Arc<AtomicU64>,
}

impl Hops {
    fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let served = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&served);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                if answer(stream).is_ok() {
                    counted.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        Ok(Self { address, served })
    }

    fn served(&self) -> u64 {
        self.served.load(Ordering::SeqCst)
    }

    fn url(&self, path: &str) -> String {
        // reqwest takes the port from the URL, never from a resolved address.
        format!("http://redirects.test:{}{path}", self.address.port())
    }
}

fn answer(mut stream: TcpStream) -> io::Result<()> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let redirect = |to: &str| {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    };
    let reply = match path
        .strip_prefix("/hop/")
        .and_then(|n| n.parse::<u64>().ok())
    {
        Some(n) if n < LAST_HOP => redirect(&format!("/hop/{}", n + 1)),
        Some(_) => format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            LANDED.len(),
            String::from_utf8_lossy(LANDED)
        ),
        None if path == "/loop" => redirect("/loop"),
        None => {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
        }
    };
    stream.write_all(reply.as_bytes())?;
    stream.flush()
}

/// Every crossing of the redirect row the vault asks about: `(bound, measured)`.
#[derive(Default)]
struct Asked(Mutex<Vec<(u64, u64)>>);

impl Asked {
    fn crossings(&self) -> Vec<(u64, u64)> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl LimitAsk for Asked {
    fn crossed(&self, row: EngineLimit, bound: u64, measured: u64) {
        if row.key() == REDIRECT_ROW {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((bound, measured));
        }
    }
}

struct Fixture {
    _vault_dir: tempfile::TempDir,
    proxy: OpenEgressProxy,
    asked: Arc<Asked>,
    hops: Hops,
}

impl Fixture {
    fn new(request_timeout: Duration) -> Result<Self, Box<dyn std::error::Error>> {
        let vault_dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::device())?);
        let asked = Arc::new(Asked::default());
        vault.set_limit_ask(Arc::clone(&asked) as Arc<dyn LimitAsk>);
        let config = EgressConfig {
            request_timeout,
            ..EgressConfig::default()
        };
        let proxy = OpenEgressProxy::new(vault, EntityId::now(), config);
        Ok(Self {
            _vault_dir: vault_dir,
            proxy,
            asked,
            hops: Hops::start()?,
        })
    }

    fn fetch(&self, path: &str) -> io::Result<HttpResponse> {
        fetch_resolved_to(
            &self.proxy,
            HttpRequest {
                url: self.hops.url(path),
                method: "GET".to_owned(),
                headers: Vec::new(),
                body: Vec::new(),
                follow_redirects: true,
            },
            self.hops.address,
        )
    }
}

#[test]
fn redirects_past_the_old_bound_are_followed_to_the_answer() -> TestResult {
    let fixture = Fixture::new(Duration::from_secs(30))?;
    let answer = fixture.fetch("/hop/0").map_err(|error| {
        format!("a fetch of {LAST_HOP} redirects, past the old bound of {OLD_BOUND}, was refused: {error}")
    })?;
    assert_eq!(answer.status, 200, "the last hop's answer is delivered");
    assert_eq!(answer.body.as_ref(), LANDED);
    assert!(
        answer.url.ends_with(&format!("/hop/{LAST_HOP}")),
        "the answer names the URL it came from: {}",
        answer.url
    );
    assert_eq!(
        fixture.hops.served(),
        LAST_HOP + 1,
        "every hop is fetched once"
    );
    assert_eq!(
        fixture.asked.crossings(),
        vec![(OLD_BOUND, LAST_HOP)],
        "the {LAST_HOP} redirects are measured once on {REDIRECT_ROW}, which asks past its default of {OLD_BOUND}"
    );
    Ok(())
}

#[test]
fn a_redirect_loop_ends_at_the_request_deadline() -> TestResult {
    let fixture = Fixture::new(LOOP_DEADLINE)?;
    let started = Instant::now();
    let error = match fixture.fetch("/loop") {
        Ok(answer) => {
            return Err(format!(
                "a redirect loop answered status {} instead of ending at its deadline",
                answer.status
            )
            .into());
        }
        Err(error) => error,
    };
    let elapsed = started.elapsed();
    assert_eq!(
        error.kind(),
        io::ErrorKind::TimedOut,
        "only the request deadline ends a fetch that keeps redirecting, after {elapsed:?} and {} hops: {error}",
        fixture.hops.served()
    );
    assert!(
        elapsed + Duration::from_millis(100) >= LOOP_DEADLINE,
        "the loop ran until its {LOOP_DEADLINE:?} deadline, not {elapsed:?}"
    );
    assert!(
        elapsed < LOOP_DEADLINE + Duration::from_secs(10),
        "the loop ended near its deadline, not after {elapsed:?}"
    );
    let served = fixture.hops.served();
    assert!(
        served > OLD_BOUND + 1,
        "the loop went past the old bound's {} requests: {served}",
        OLD_BOUND + 1
    );
    let crossings = fixture.asked.crossings();
    assert!(
        matches!(crossings.as_slice(), [(OLD_BOUND, measured)] if *measured > OLD_BOUND),
        "the loop's redirects are measured once on {REDIRECT_ROW} past {OLD_BOUND}: {crossings:?}"
    );
    Ok(())
}
