//! UC-13 PR 5 (UC13-PAGE-FIXES = A, Engine TASK 17:45).
//!
//! (1) `vault.skill_hubs.clawhub.search` refuses a negative limit as a bad
//! request before any fetch. On main the limit went upstream as written: the
//! hub was asked `limit=-1`. A loopback hub records the request line of every
//! request it is sent and answers each with an empty result list.
//!
//! (2) `self.inbox.list` and `vault.receipts` report the clamp their limit
//! rule makes. Neither page has had a ceiling since #5059, so a page asked
//! past the 1,000 rows the inbox once stopped at reports the whole ask as
//! `effective_limit` and `limit_clamped: false`, on main and on the head. A
//! zero ask keeps each page's own refusal text.
//!
//! Run with: `cargo test --locked -p oneiron --all-features --test page_fixes`.

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryError;
use oneiron::skill_hub::{
    ClawHubSearchReply, HubSyncPolicy, SkillHubKind, SkillHubRecord, SkillHubTrustTier,
};
use oneiron::verbs::{ClawHubSearchRequest, skill_hub_clawhub_search_as_owner};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

/// A page size far past the 1,000-row ceiling the inbox had before #5059
/// (Engine RULING UC13-LIMIT-CLAMPED-NO-CEILING = A, 22:00 15 Nov).
const PAST_THE_OLD_CEILING: usize = 1_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_id: EntityId,
    owner: AuthenticatedOwner,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner_id,
            "principal:page-fixes-owner",
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("authenticated owner");
    Fixture {
        _dir: dir,
        vault,
        owner_id,
        owner,
    }
}

/// A loopback HTTP hub. It answers every request with an empty ClawHub
/// result list and keeps each request line, in the order they came.
struct LoopbackHub {
    endpoint: String,
    stop: Arc<AtomicBool>,
    server: thread::JoinHandle<Vec<String>>,
}

impl LoopbackHub {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("non-blocking listener");
        let endpoint = format!(
            "http://{}/",
            listener.local_addr().expect("listener address")
        );
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let mut request_lines = Vec::new();
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking stream");
                        let mut reader =
                            BufReader::new(stream.try_clone().expect("stream for reading"));
                        let mut request_line = String::new();
                        reader.read_line(&mut request_line).expect("request line");
                        loop {
                            let mut header = String::new();
                            let read = reader.read_line(&mut header).expect("header line");
                            if read == 0 || header == "\r\n" {
                                break;
                            }
                        }
                        request_lines.push(request_line.trim_end().to_owned());
                        let body = br#"{"results":[]}"#;
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                             content-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        )
                        .expect("response head");
                        stream.write_all(body).expect("response body");
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("loopback hub accept failed: {error}"),
                }
            }
            request_lines
        });
        Self {
            endpoint,
            stop,
            server,
        }
    }

    /// Stops the hub and returns the request lines it was sent.
    fn request_lines(self) -> Vec<String> {
        self.stop.store(true, Ordering::SeqCst);
        self.server.join().expect("loopback hub thread")
    }
}

fn configured_hub(fixture: &Fixture, endpoint: &str) -> EntityId {
    let id = EntityId::now();
    let record = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        endpoint,
        SkillHubTrustTier::Community,
        HubSyncPolicy::ContentHashFrozen,
    )
    .expect("hub record");
    fixture
        .vault
        .configure_skill_hub(
            &fixture.owner,
            &id,
            &record,
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("configure hub");
    id
}

fn search(hub: EntityId, limit: Option<i64>) -> ClawHubSearchRequest {
    ClawHubSearchRequest {
        hub,
        q: "notes".to_owned(),
        limit,
        highlighted_only: None,
        non_suspicious_only: None,
        response_limit_bytes: None,
    }
}

/// Red on main: the hub is asked `limit=-1` and the search answers its
/// results. Green on the head: the bad request, and the hub is never asked.
#[test]
fn clawhub_search_refuses_a_negative_limit_before_any_fetch() {
    let fixture = fixture();
    let hub = LoopbackHub::start();
    let id = configured_hub(&fixture, &hub.endpoint);
    let answer =
        skill_hub_clawhub_search_as_owner(&fixture.vault, &fixture.owner, &search(id, Some(-1)));
    let request_lines = hub.request_lines();
    assert_eq!(
        request_lines,
        Vec::<String>::new(),
        "a negative limit reached the hub"
    );
    assert_eq!(
        answer.err(),
        Some(MemoryError::bad_request_with(
            "limit must be at least 0",
            &["Omit limit for the hub's own page size, or ask 0 or more."],
        )),
    );
}

/// Green on main and on the head: a zero or positive limit goes upstream as
/// written, and an absent one is not sent.
#[test]
fn clawhub_search_sends_a_zero_or_positive_limit_and_omits_an_absent_one() {
    let fixture = fixture();
    let hub = LoopbackHub::start();
    let id = configured_hub(&fixture, &hub.endpoint);
    for limit in [Some(0), Some(25), None] {
        let answer =
            skill_hub_clawhub_search_as_owner(&fixture.vault, &fixture.owner, &search(id, limit))
                .expect("search answered");
        assert!(
            matches!(
                &answer,
                ClawHubSearchReply::Results { results: Some(hits) } if hits.is_empty()
            ),
            "limit {limit:?}: {answer:?}"
        );
    }
    assert_eq!(
        hub.request_lines(),
        vec![
            "GET /api/v1/search?q=notes&limit=0 HTTP/1.1".to_owned(),
            "GET /api/v1/search?q=notes&limit=25 HTTP/1.1".to_owned(),
            "GET /api/v1/search?q=notes HTTP/1.1".to_owned(),
        ],
    );
}

#[test]
fn an_inbox_page_asked_past_the_old_ceiling_reports_no_clamp() {
    let fixture = fixture();
    let page = fixture
        .vault
        .memory(fixture.owner_id, EdgeActorClass::Human)
        .inbox_list(None, PAST_THE_OLD_CEILING)
        .expect("inbox page");
    assert_eq!(page.effective_limit, PAST_THE_OLD_CEILING);
    assert!(!page.limit_clamped);
}

#[test]
fn an_inbox_page_refuses_a_zero_limit_with_its_own_text() {
    let fixture = fixture();
    let refused = fixture
        .vault
        .memory(fixture.owner_id, EdgeActorClass::Human)
        .inbox_list(None, 0)
        .err();
    assert_eq!(
        refused,
        Some(MemoryError::bad_request_with(
            "limit must be at least 1",
            &["Request one row or more and continue from next_after."],
        )),
    );
}

#[test]
fn a_receipts_page_asked_past_the_old_ceiling_reports_no_clamp() {
    let fixture = fixture();
    let page = fixture
        .vault
        .memory(fixture.owner_id, EdgeActorClass::Human)
        .receipts_page(PAST_THE_OLD_CEILING, &[], None)
        .expect("receipts page");
    assert_eq!(page.effective_limit, PAST_THE_OLD_CEILING);
    assert!(!page.limit_clamped);
}

#[test]
fn a_receipts_page_refuses_a_zero_limit_with_its_own_text() {
    let fixture = fixture();
    let refused = fixture
        .vault
        .memory(fixture.owner_id, EdgeActorClass::Human)
        .receipts_page(0, &[], None)
        .err();
    assert_eq!(
        refused,
        Some(MemoryError::bad_request_with(
            "limit must be at least 1",
            &["Request one receipt or more and continue from next_after."],
        )),
    );
}
