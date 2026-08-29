use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use serde_json::{Value, json};

use super::*;

// ---------------------------------------------------------------------------
// Fixture renderers
// ---------------------------------------------------------------------------

type CallLog = Arc<Mutex<Vec<RendererKind>>>;

fn call_log() -> CallLog {
    Arc::new(Mutex::new(Vec::new()))
}

/// A rung whose single outcome is scripted, so ladder order is observable.
struct ScriptedRenderer {
    kind: RendererKind,
    outcome: RendererResult<RenderedPage>,
    calls: AtomicUsize,
    log: CallLog,
}

impl ScriptedRenderer {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Renderer for ScriptedRenderer {
    fn kind(&self) -> RendererKind {
        self.kind
    }

    fn render(&self, _url: &str) -> RendererResult<RenderedPage> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.log.lock().expect("call log").push(self.kind);
        self.outcome.clone()
    }
}

fn scripted(
    log: &CallLog,
    kind: RendererKind,
    outcome: RendererResult<RenderedPage>,
) -> Arc<ScriptedRenderer> {
    Arc::new(ScriptedRenderer {
        kind,
        outcome,
        calls: AtomicUsize::new(0),
        log: Arc::clone(log),
    })
}

fn rung(renderer: &Arc<ScriptedRenderer>) -> Arc<dyn Renderer> {
    let handle: Arc<ScriptedRenderer> = Arc::clone(renderer);
    handle
}

const LADDER_MARKDOWN: &str =
    "# Ladder fixture\n\nBody text well past the injected minimum-content threshold.";

fn ladder_page(markdown: &str, final_url: &str) -> RenderedPage {
    RenderedPage {
        markdown: markdown.to_string(),
        title: "Ladder Fixture".to_string(),
        canonical_url: final_url.to_string(),
        final_url: final_url.to_string(),
        discovered_links: Vec::new(),
    }
}

fn ladder_minimum() -> MinExtractedContentBytes {
    MinExtractedContentBytes::new(16).expect("ladder minimum content")
}

/// A whole fixture site keyed by the exact URL the ladder requests. Unknown
/// URLs behave like a 404 on every rung.
struct SiteRenderer {
    kind: RendererKind,
    pages: HashMap<String, RenderedPage>,
    attempts: Mutex<Vec<String>>,
}

impl SiteRenderer {
    fn attempts(&self) -> Vec<String> {
        self.attempts.lock().expect("site attempts").clone()
    }
}

impl Renderer for SiteRenderer {
    fn kind(&self) -> RendererKind {
        self.kind
    }

    fn render(&self, url: &str) -> RendererResult<RenderedPage> {
        self.attempts
            .lock()
            .expect("site attempts")
            .push(url.to_string());
        match self.pages.get(url) {
            Some(page) => Ok(page.clone()),
            None => Err(RendererError::transport(format!(
                "fixture {} 404 for {url}",
                self.kind.as_str()
            ))),
        }
    }
}

fn site_renderer(kind: RendererKind, pages: &[(String, RenderedPage)]) -> Arc<SiteRenderer> {
    Arc::new(SiteRenderer {
        kind,
        pages: pages.iter().cloned().collect(),
        attempts: Mutex::new(Vec::new()),
    })
}

fn site_rung(site: &Arc<SiteRenderer>) -> Arc<dyn Renderer> {
    let handle: Arc<SiteRenderer> = Arc::clone(site);
    handle
}

/// Builds a page entry whose `canonical_url` echoes the requested URL, so a
/// crawl result can be read back by identity.
fn page_entry(requested: &str, final_url: &str, links: &[&str]) -> (String, RenderedPage) {
    page_entry_with_canonical(requested, final_url, requested, links)
}

fn page_entry_with_canonical(
    requested: &str,
    final_url: &str,
    canonical_url: &str,
    links: &[&str],
) -> (String, RenderedPage) {
    let mut discovered_links = Vec::new();
    for link in links {
        discovered_links.push(String::from(*link));
    }
    (
        requested.to_string(),
        RenderedPage {
            markdown: format!("markdown body for {final_url}"),
            title: format!("title for {final_url}"),
            canonical_url: canonical_url.to_string(),
            final_url: final_url.to_string(),
            discovered_links,
        },
    )
}

/// Wires the same fixture site into all three rungs and returns the rung-1
/// handle (whose attempt log is the walk's attempt order, because rung 1 always
/// runs first).
fn fixture_site(pages: &[(String, RenderedPage)]) -> (Arc<SiteRenderer>, WebFetcher) {
    let readability = site_renderer(RendererKind::Readability, pages);
    let headless = site_renderer(RendererKind::Headless, pages);
    let firecrawl = site_renderer(RendererKind::Firecrawl, pages);
    let fetcher = WebFetcher::new(site_rung(&readability))
        .expect("readability slot")
        .with_headless(site_rung(&headless))
        .expect("headless slot")
        .with_firecrawl(site_rung(&firecrawl))
        .expect("firecrawl slot")
        .with_minimum_content(MinExtractedContentBytes::new(8).expect("site minimum content"));
    (readability, fetcher)
}

fn budget(value: usize) -> CrawlPageBudget {
    CrawlPageBudget::new(value).expect("crawl page budget")
}

fn canonical_urls(result: &CrawlResult) -> Vec<String> {
    result
        .pages
        .iter()
        .map(|page| page.canonical_url.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Hand-rolled fixture HTTP server (no dev-dependency may be added)
// ---------------------------------------------------------------------------

fn spawn_fixture_server<H>(handler: H) -> String
where
    H: Fn(&str) -> String + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture listener");
    let port = listener
        .local_addr()
        .expect("fixture listener address")
        .port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let request = read_http_request(&mut stream);
            let response = handler(&request);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return String::from_utf8_lossy(&head).into_owned(),
        }
    }
    let head_text = String::from_utf8_lossy(&head).into_owned();
    let length = declared_content_length(&head_text);
    if length == 0 {
        return head_text;
    }
    let mut body = vec![0_u8; length];
    if stream.read_exact(&mut body).is_err() {
        return head_text;
    }
    format!("{head_text}{}", String::from_utf8_lossy(&body))
}

fn declared_content_length(head: &str) -> usize {
    for line in head.lines() {
        let lowered = line.to_ascii_lowercase();
        if let Some(value) = lowered.strip_prefix("content-length:") {
            return value.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn request_line_field(request: &str, index: usize) -> String {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(index))
        .unwrap_or_default()
        .to_string()
}

fn request_method(request: &str) -> String {
    request_line_field(request, 0)
}

fn request_path(request: &str) -> String {
    request_line_field(request, 1)
}

fn request_body(request: &str) -> String {
    match request.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_string(),
        None => String::new(),
    }
}

fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn http_redirect(location: &str) -> String {
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

/// A loopback port nothing is listening on, for the connection-refused leg.
const REFUSED_ENDPOINT: &str = "http://127.0.0.1:1/v1/scrape";

// ---------------------------------------------------------------------------
// HTML fixtures
// ---------------------------------------------------------------------------

const ARTICLE_BODY: &str = r##"
    <p>The acquisition primitive turns exactly one address into exactly one
    closed result, and the closed result is the entire contract. Everything a
    renderer learns beyond those six fields stays inside the renderer boundary,
    where a later consumer can ask for it deliberately rather than inherit it by
    accident. That is the whole design intent behind keeping this surface small.</p>
    <p>A ladder is not a race. The first rung runs, and only a typed failure or
    an extraction below the configured floor promotes the request to the second
    rung. Nothing speculative happens, nothing runs in parallel, and no rung is
    skipped because another rung looked more promising. The trace of what was
    tried is preserved so that an operator can tell an empty page apart from a
    broken transport apart from a rung that was never configured at all.</p>
    <p>Content identity is computed over the extracted Markdown under a fixed
    domain prefix, because the three rungs share no uniform notion of fetched
    bytes. A browser snapshot is a rendered document, and a hosted scrape
    envelope carries Markdown only. Hashing the returned Markdown is what makes
    the identity renderer independent, which is the property the pipeline
    actually needs downstream.</p>
    <p><strong>Containment</strong> is decided by the response-final host, never
    by author-supplied metadata. A canonical annotation changes what the result
    reports as its canonical address and nothing else at all.</p>
"##;

fn article_html() -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Fixture Article Title</title>
  <base href="https://cdn.fixture.test/assets/">
  <script type="application/ld+json">
  {{"@context":"https://schema.org","@type":"Article","name":"Fixture Article Title","url":"https://canonical.fixture.test/article"}}
  </script>
</head>
<body>
  <nav><a href="nav-target">navigation</a></nav>
  <article>
    <h1>Fixture Article Title</h1>
    {ARTICLE_BODY}
    <p>
      <a href="relative-page">relative</a>
      <a href="https://absolute.fixture.test/page">absolute</a>
      <a href="#section">fragment</a>
      <a href="mailto:someone@fixture.test">mail</a>
      <a href="javascript:void(0)">script</a>
    </p>
  </article>
</body>
</html>"##
    )
}

/// The same article without a `<base>` and with a relative JSON-LD canonical,
/// so link and canonical resolution are observed against the redirect-final URL.
fn served_article_html() -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Served Article Title</title>
  <script type="application/ld+json">
  {{"@context":"https://schema.org","@type":"Article","name":"Served Article Title","url":"/canonical-target"}}
  </script>
</head>
<body>
  <article>
    <h1>Served Article Title</h1>
    {ARTICLE_BODY}
    <p><a href="next">next page</a></p>
  </article>
</body>
</html>"##
    )
}

fn fixture_url(raw: &str) -> Url {
    Url::parse(raw).expect("fixture URL")
}

/// A host browser that returns pre-rendered HTML and its navigation-final URL.
struct FakeHeadless {
    html: String,
    final_url: String,
}

impl HeadlessRenderer for FakeHeadless {
    fn render_html(&self, _url: &str) -> RendererResult<HeadlessDocument> {
        Ok(HeadlessDocument {
            html: self.html.clone(),
            final_url: self.final_url.clone(),
        })
    }
}

/// A host browser that reports a navigation-final URL which is not a web transport.
struct BadHeadless;

impl HeadlessRenderer for BadHeadless {
    fn render_html(&self, _url: &str) -> RendererResult<HeadlessDocument> {
        Ok(HeadlessDocument {
            html: "<html><body>x</body></html>".to_string(),
            final_url: "about:blank".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Wire shape and content identity
// ---------------------------------------------------------------------------

#[test]
fn fetch_result_wire_shape_is_exactly_six_fields() {
    let result = FetchResult {
        markdown: "# Heading\n\nBody.".to_string(),
        title: "Title".to_string(),
        canonical_url: "https://example.test/page".to_string(),
        fetched_at: 1_700_000_000,
        content_hash: content_hash("# Heading\n\nBody."),
        renderer: RendererKind::Readability,
    };

    let value = serde_json::to_value(&result).expect("serialize fetch result");
    let object = value.as_object().expect("fetch result is a JSON object");
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "markdown",
            "title",
            "canonical_url",
            "fetched_at",
            "content_hash",
            "renderer",
        ]),
        "the OF-444 result is closed at six fields"
    );
    assert_eq!(object.len(), 6, "no seventh field may reach the wire");
    for absent in [
        "links",
        "status",
        "html",
        "raw",
        "provider",
        "ingested",
        "entity_id",
    ] {
        assert!(
            !object.contains_key(absent),
            "unexpected field {absent} on the fetch result"
        );
    }

    for (kind, token) in [
        (RendererKind::Readability, "readability"),
        (RendererKind::Headless, "headless"),
        (RendererKind::Firecrawl, "firecrawl"),
    ] {
        assert_eq!(kind.as_str(), token);
        assert_eq!(
            serde_json::to_value(kind).expect("serialize renderer kind"),
            Value::from(token),
            "renderer token is pinned"
        );
        assert_eq!(
            serde_json::from_value::<RendererKind>(Value::from(token))
                .expect("decode renderer kind"),
            kind
        );
    }

    let round_tripped: FetchResult = serde_json::from_value(value).expect("decode fetch result");
    assert_eq!(round_tripped, result);
}

const HASH_FIXTURE_MARKDOWN: &str = "# OF-444\n\nAcquisition body.\n";
/// lower_hex(BLAKE3(b"oneiron.web_fetch.content.v1\0" || HASH_FIXTURE_MARKDOWN)).
const HASH_FIXTURE_HEX: &str = "b6e7636db6a7953a1ed178035555d3d873c222d23517200062ab986348fe5da8";

#[test]
fn content_hash_is_domain_separated_markdown_bytes() {
    assert_eq!(
        WEB_FETCH_CONTENT_HASH_DOMAIN, b"oneiron.web_fetch.content.v1\0",
        "the hash domain is NUL terminated and carries no length prefix"
    );

    let hash = content_hash(HASH_FIXTURE_MARKDOWN);
    assert_eq!(hash, HASH_FIXTURE_HEX);
    assert_eq!(hash.len(), 64);
    assert!(
        hash.chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()),
        "content hash is lowercase hex"
    );

    let mut expected = blake3::Hasher::new();
    expected.update(b"oneiron.web_fetch.content.v1\0");
    expected.update(HASH_FIXTURE_MARKDOWN.as_bytes());
    assert_eq!(hash, expected.finalize().to_hex().to_string());

    // The domain prefix is load bearing: the bare Markdown hash is different.
    assert_ne!(
        hash,
        blake3::hash(HASH_FIXTURE_MARKDOWN.as_bytes())
            .to_hex()
            .to_string()
    );

    // One Markdown byte changes the identity.
    assert_ne!(hash, content_hash("# OF-444\n\nAcquisition body!\n"));

    // Title, canonical URL, timestamp, and renderer are not hashed, and two
    // different rungs emitting identical Markdown hash identically.
    let log = call_log();
    let first = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Ok(RenderedPage {
            markdown: HASH_FIXTURE_MARKDOWN.to_string(),
            title: "First Title".to_string(),
            canonical_url: "https://first.test/canonical".to_string(),
            final_url: "https://first.test/page".to_string(),
            discovered_links: Vec::new(),
        }),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://first.test/page", 11)
    .expect("first fetch");

    let second = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Err(RendererError::transport("forced escalation")),
    )))
    .expect("readability slot")
    .with_firecrawl(rung(&scripted(
        &log,
        RendererKind::Firecrawl,
        Ok(RenderedPage {
            markdown: HASH_FIXTURE_MARKDOWN.to_string(),
            title: "Second Title".to_string(),
            canonical_url: "https://second.test/canonical".to_string(),
            final_url: "https://second.test/page".to_string(),
            discovered_links: Vec::new(),
        }),
    )))
    .expect("firecrawl slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://second.test/page", 999)
    .expect("second fetch");

    assert_ne!(first.title, second.title);
    assert_ne!(first.canonical_url, second.canonical_url);
    assert_ne!(first.fetched_at, second.fetched_at);
    assert_ne!(first.renderer, second.renderer);
    assert_eq!(first.content_hash, HASH_FIXTURE_HEX);
    assert_eq!(
        first.content_hash, second.content_hash,
        "identical Markdown from two rungs is one identity"
    );
}

// ---------------------------------------------------------------------------
// The fixed ladder
// ---------------------------------------------------------------------------

#[test]
fn readability_success_stops_the_ladder() {
    let log = call_log();
    let first = scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );
    let second = scripted(
        &log,
        RendererKind::Headless,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );
    let third = scripted(
        &log,
        RendererKind::Firecrawl,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );

    let fetcher = WebFetcher::new(rung(&first))
        .expect("readability slot")
        .with_headless(rung(&second))
        .expect("headless slot")
        .with_firecrawl(rung(&third))
        .expect("firecrawl slot")
        .with_minimum_content(ladder_minimum());

    let result = fetcher
        .fetch("https://example.test/page", 7)
        .expect("readability rung wins");

    assert_eq!(result.renderer, RendererKind::Readability);
    assert_eq!(first.calls(), 1);
    assert_eq!(second.calls(), 0, "a lower rung must not run after a win");
    assert_eq!(third.calls(), 0, "a lower rung must not run after a win");
    assert_eq!(
        *log.lock().expect("call log"),
        vec![RendererKind::Readability]
    );
}

#[test]
fn ladder_escalates_only_on_error_or_empty_extraction() {
    // Rung 1 error promotes to rung 2 and stops there.
    let log = call_log();
    let first = scripted(
        &log,
        RendererKind::Readability,
        Err(RendererError::transport("connection reset")),
    );
    let second = scripted(
        &log,
        RendererKind::Headless,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );
    let third = scripted(
        &log,
        RendererKind::Firecrawl,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );
    let result = WebFetcher::new(rung(&first))
        .expect("readability slot")
        .with_headless(rung(&second))
        .expect("headless slot")
        .with_firecrawl(rung(&third))
        .expect("firecrawl slot")
        .with_minimum_content(ladder_minimum())
        .fetch("https://example.test/page", 1)
        .expect("headless rung wins");
    assert_eq!(result.renderer, RendererKind::Headless);
    assert_eq!(third.calls(), 0);
    assert_eq!(
        *log.lock().expect("call log"),
        vec![RendererKind::Readability, RendererKind::Headless],
        "rung 2 runs only after rung 1 returned"
    );

    // Rung 1 below threshold promotes to rung 2.
    let log = call_log();
    let thin = "  \n  tiny  \n ";
    let first = scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page(thin, "https://example.test/page")),
    );
    let second = scripted(
        &log,
        RendererKind::Headless,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );
    let result = WebFetcher::new(rung(&first))
        .expect("readability slot")
        .with_headless(rung(&second))
        .expect("headless slot")
        .with_minimum_content(ladder_minimum())
        .fetch("https://example.test/page", 1)
        .expect("headless rung wins after empty extraction");
    assert_eq!(result.renderer, RendererKind::Headless);

    // The recorded empty-extraction byte count is exactly the compared value.
    let log = call_log();
    let error = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page(thin, "https://example.test/page")),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://example.test/page", 1)
    .expect_err("no rung produced content");
    let WebFetchError::AllRenderersFailed { attempts, .. } = error else {
        panic!("expected the aggregate ladder failure");
    };
    assert_eq!(
        attempts[0],
        RendererAttemptFailure::EmptyExtraction {
            renderer: RendererKind::Readability,
            extracted_bytes: thin.trim().len(),
            minimum_bytes: 16,
        }
    );

    // Rung 2 failure promotes to rung 3.
    let log = call_log();
    let first = scripted(
        &log,
        RendererKind::Readability,
        Err(RendererError::extraction("no article found")),
    );
    let second = scripted(
        &log,
        RendererKind::Headless,
        Err(RendererError::transport("browser navigation failed")),
    );
    let third = scripted(
        &log,
        RendererKind::Firecrawl,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );
    let result = WebFetcher::new(rung(&first))
        .expect("readability slot")
        .with_headless(rung(&second))
        .expect("headless slot")
        .with_firecrawl(rung(&third))
        .expect("firecrawl slot")
        .with_minimum_content(ladder_minimum())
        .fetch("https://example.test/page", 1)
        .expect("firecrawl rung wins");
    assert_eq!(result.renderer, RendererKind::Firecrawl);
    assert_eq!(
        *log.lock().expect("call log"),
        vec![
            RendererKind::Readability,
            RendererKind::Headless,
            RendererKind::Firecrawl,
        ],
        "the ladder is strictly sequential"
    );
}

#[test]
fn all_renderers_failed_preserves_ordered_attempts() {
    let log = call_log();
    let error = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Err(RendererError::transport("readability transport")),
    )))
    .expect("readability slot")
    .with_headless(rung(&scripted(
        &log,
        RendererKind::Headless,
        Err(RendererError::extraction("headless extraction")),
    )))
    .expect("headless slot")
    .with_firecrawl(rung(&scripted(
        &log,
        RendererKind::Firecrawl,
        Err(RendererError::invalid_response("firecrawl envelope")),
    )))
    .expect("firecrawl slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://example.test/page", 3)
    .expect_err("every rung failed");

    let WebFetchError::AllRenderersFailed { url, attempts } = error else {
        panic!("the ladder failure must not be flattened into the last transport error");
    };
    assert_eq!(url, "https://example.test/page");
    assert_eq!(
        attempts,
        vec![
            RendererAttemptFailure::Error {
                renderer: RendererKind::Readability,
                error: RendererError::transport("readability transport"),
            },
            RendererAttemptFailure::Error {
                renderer: RendererKind::Headless,
                error: RendererError::extraction("headless extraction"),
            },
            RendererAttemptFailure::Error {
                renderer: RendererKind::Firecrawl,
                error: RendererError::invalid_response("firecrawl envelope"),
            },
        ]
    );

    // Absent optional rungs are recorded, never silently omitted, and an empty
    // extraction never counts as a win.
    let log = call_log();
    let error = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page("   ", "https://example.test/page")),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://example.test/page", 3)
    .expect_err("no rung produced content");
    let WebFetchError::AllRenderersFailed { attempts, .. } = error else {
        panic!("expected the aggregate ladder failure");
    };
    assert_eq!(
        attempts,
        vec![
            RendererAttemptFailure::EmptyExtraction {
                renderer: RendererKind::Readability,
                extracted_bytes: 0,
                minimum_bytes: 16,
            },
            RendererAttemptFailure::Unavailable {
                renderer: RendererKind::Headless,
            },
            RendererAttemptFailure::Unavailable {
                renderer: RendererKind::Firecrawl,
            },
        ]
    );

    // Slots are typed: a renderer cannot be installed on the wrong rung.
    let log = call_log();
    let misplaced = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Headless,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    )));
    assert!(matches!(
        misplaced,
        Err(WebFetchError::InvalidRendererSlot {
            expected: RendererKind::Readability,
            actual: RendererKind::Headless,
        })
    ));
}

// ---------------------------------------------------------------------------
// Native extraction and adapters
// ---------------------------------------------------------------------------

#[test]
fn native_readability_extracts_markdown_title_canonical_and_links() {
    let final_url = fixture_url("https://fixture.test/articles/one");
    let page = extract_readable_page(&article_html(), &final_url).expect("extract article");

    assert_eq!(page.title, "Fixture Article Title");
    assert_eq!(
        page.canonical_url, "https://canonical.fixture.test/article",
        "JSON-LD metadata supplies the canonical identity"
    );
    assert_eq!(
        page.final_url, "https://fixture.test/articles/one",
        "the response-final URL is kept separately from metadata canonical"
    );

    assert!(
        page.markdown.contains("acquisition primitive"),
        "markdown body: {}",
        page.markdown
    );
    assert!(
        page.markdown.contains("**Containment**"),
        "TextMode::Markdown must emit Markdown, not raw text: {}",
        page.markdown
    );

    assert_eq!(
        page.discovered_links,
        vec![
            "https://absolute.fixture.test/page".to_string(),
            "https://cdn.fixture.test/assets/".to_string(),
            "https://cdn.fixture.test/assets/nav-target".to_string(),
            "https://cdn.fixture.test/assets/relative-page".to_string(),
        ],
        "links resolve against <base>, drop fragments and non-HTTP(S) schemes, \
         and arrive sorted and deduplicated"
    );

    // A document with nothing to grab is an extraction failure, not a win.
    let barren = extract_readable_page("<html><head><title>t</title></head></html>", &final_url)
        .expect_err("nothing to extract");
    assert_eq!(barren.kind, RendererErrorKind::Extraction);

    // A metadata canonical that is not an HTTP(S) URL falls back to the final URL.
    let hostile = format!(
        r##"<!DOCTYPE html><html><head><title>Hostile</title>
        <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"Article","name":"Hostile","url":"mailto:someone@fixture.test"}}
        </script></head><body><article><h1>Hostile</h1>{ARTICLE_BODY}</article></body></html>"##
    );
    let hostile_page = extract_readable_page(&hostile, &final_url).expect("extract hostile");
    assert_eq!(
        hostile_page.canonical_url,
        "https://fixture.test/articles/one"
    );
}

#[test]
fn headless_reuses_native_readability_extraction() {
    let headless_source: Arc<dyn HeadlessRenderer> = Arc::new(FakeHeadless {
        html: article_html(),
        final_url: "https://fixture.test/articles/one".to_string(),
    });
    let headless: Arc<dyn Renderer> = Arc::new(NativeHeadlessRenderer::new(headless_source));

    let log = call_log();
    let result = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Err(RendererError::extraction("client-rendered shell")),
    )))
    .expect("readability slot")
    .with_headless(headless)
    .expect("headless slot")
    .fetch("https://fixture.test/articles/one", 55)
    .expect("headless rung wins");

    assert_eq!(result.renderer, RendererKind::Headless);
    let direct = extract_readable_page(
        &article_html(),
        &fixture_url("https://fixture.test/articles/one"),
    )
    .expect("direct extraction");
    assert_eq!(
        result.markdown, direct.markdown,
        "headless is a rendering rung, not a second extraction algorithm"
    );
    assert_eq!(result.title, direct.title);
    assert_eq!(result.canonical_url, direct.canonical_url);
    assert_eq!(result.content_hash, content_hash(&direct.markdown));

    // A browser-final URL that is not absolute HTTP(S) is an invalid response.
    let bad = NativeHeadlessRenderer::new(Arc::new(BadHeadless));
    let error = bad
        .render("https://fixture.test/articles/one")
        .expect_err("about:blank is not a web transport");
    assert_eq!(error.kind, RendererErrorKind::InvalidResponse);
}

#[test]
fn native_http_get_maps_status_and_final_url() {
    let html = served_article_html();
    let base = spawn_fixture_server(move |request| match request_path(request).as_str() {
        "/redirect" => http_redirect("/final"),
        "/final" => http_response("200 OK", "text/html; charset=utf-8", &html),
        "/boom" => http_response("500 Internal Server Error", "text/plain", "boom"),
        _ => http_response("404 Not Found", "text/plain", "missing"),
    });

    let renderer = NativeReadabilityRenderer::new(reqwest::blocking::Client::new());

    let page = renderer
        .render(&format!("{base}/redirect"))
        .expect("301 then 200 chain");
    assert_eq!(
        page.final_url,
        format!("{base}/final"),
        "the redirect-final URL is what gets recorded"
    );
    assert_eq!(
        page.canonical_url,
        format!("{base}/canonical-target"),
        "canonical metadata resolves against the redirect-final URL"
    );
    assert_eq!(
        page.discovered_links,
        vec![format!("{base}/next")],
        "links resolve against the redirect-final URL"
    );
    assert_eq!(page.title, "Served Article Title");
    assert!(page.markdown.contains("acquisition primitive"));

    let status_error = renderer
        .render(&format!("{base}/boom"))
        .expect_err("500 is a transport failure");
    assert_eq!(status_error.kind, RendererErrorKind::Transport);

    let refused = renderer
        .render("http://127.0.0.1:1/unreachable")
        .expect_err("a refused connection is a transport failure");
    assert_eq!(refused.kind, RendererErrorKind::Transport);
}

#[test]
fn firecrawl_adapter_maps_the_pinned_self_hosted_envelope() {
    let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let base = spawn_fixture_server(move |request| {
        sink.lock()
            .expect("recorded requests")
            .push(request.to_string());
        match request_path(request).as_str() {
            "/v1/scrape" => http_response(
                "200 OK",
                "application/json",
                r##"{"success":true,"data":{"markdown":"# Firecrawl page\n\nBody text that clears the floor.","links":["https://example.test/next","https://example.test/next","mailto:x@example.test","/relative"],"metadata":{"title":"  Example  ","sourceURL":"https://example.test/page#frag"}}}"##,
            ),
            "/not-success" => http_response("200 OK", "application/json", r#"{"success":false}"#),
            "/no-data" => http_response("200 OK", "application/json", r#"{"success":true}"#),
            "/no-markdown" => http_response(
                "200 OK",
                "application/json",
                r#"{"success":true,"data":{"metadata":{"sourceURL":"https://example.test/page"}}}"#,
            ),
            "/no-source" => http_response(
                "200 OK",
                "application/json",
                r#"{"success":true,"data":{"markdown":"body","metadata":{}}}"#,
            ),
            "/bad-source" => http_response(
                "200 OK",
                "application/json",
                r#"{"success":true,"data":{"markdown":"body","metadata":{"sourceURL":"mailto:x@example.test"}}}"#,
            ),
            "/boom" => http_response("502 Bad Gateway", "text/plain", "upstream"),
            _ => http_response("404 Not Found", "text/plain", "missing"),
        }
    });

    let client = reqwest::blocking::Client::new();
    let renderer = FirecrawlRenderer::new(client.clone(), &format!("{base}/v1/scrape"))
        .expect("self-hosted scrape endpoint");

    let page = renderer
        .render("https://example.test/page")
        .expect("firecrawl envelope");

    let requests = recorded.lock().expect("recorded requests").clone();
    assert_eq!(request_method(&requests[0]), "POST");
    assert_eq!(request_path(&requests[0]), "/v1/scrape");
    let sent: Value =
        serde_json::from_str(&request_body(&requests[0])).expect("decode scrape request");
    assert_eq!(
        sent,
        json!({
            "url": "https://example.test/page",
            "formats": ["markdown", "links"],
            "onlyMainContent": true,
        })
    );

    assert_eq!(
        page.markdown,
        "# Firecrawl page\n\nBody text that clears the floor."
    );
    assert_eq!(page.title, "Example");
    assert_eq!(
        page.final_url, "https://example.test/page",
        "sourceURL is normalized and supplies the final URL"
    );
    assert_eq!(page.canonical_url, "https://example.test/page");
    assert_eq!(
        page.discovered_links,
        vec![
            "https://example.test/next".to_string(),
            "https://example.test/relative".to_string(),
        ],
        "links are normalized, filtered to HTTP(S), sorted and deduplicated"
    );

    for path in [
        "/not-success",
        "/no-data",
        "/no-markdown",
        "/no-source",
        "/bad-source",
    ] {
        let broken = FirecrawlRenderer::new(client.clone(), &format!("{base}{path}"))
            .expect("endpoint")
            .render("https://example.test/page")
            .expect_err("a malformed 2xx envelope is an invalid response");
        assert_eq!(
            broken.kind,
            RendererErrorKind::InvalidResponse,
            "unexpected mapping for {path}"
        );
    }

    let status_error = FirecrawlRenderer::new(client.clone(), &format!("{base}/boom"))
        .expect("endpoint")
        .render("https://example.test/page")
        .expect_err("a non-2xx status is a transport failure");
    assert_eq!(status_error.kind, RendererErrorKind::Transport);

    let refused = FirecrawlRenderer::new(client.clone(), REFUSED_ENDPOINT)
        .expect("endpoint")
        .render("https://example.test/page")
        .expect_err("a refused connection is a transport failure");
    assert_eq!(refused.kind, RendererErrorKind::Transport);

    assert!(matches!(
        FirecrawlRenderer::new(client, "not a url"),
        Err(WebFetchError::InvalidUrl { .. })
    ));

    // The winning rung token is `firecrawl`.
    let log = call_log();
    let firecrawl: Arc<dyn Renderer> = Arc::new(
        FirecrawlRenderer::new(
            reqwest::blocking::Client::new(),
            &format!("{base}/v1/scrape"),
        )
        .expect("endpoint"),
    );
    let result = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Err(RendererError::transport("blocked")),
    )))
    .expect("readability slot")
    .with_firecrawl(firecrawl)
    .expect("firecrawl slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://example.test/page", 4)
    .expect("firecrawl rung wins");
    assert_eq!(result.renderer, RendererKind::Firecrawl);
}

// ---------------------------------------------------------------------------
// Caller-supplied time and explicit limits
// ---------------------------------------------------------------------------

#[test]
fn caller_supplies_fetch_time() {
    let log = call_log();
    let fetcher = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum());

    let result = fetcher
        .fetch("https://example.test/page", 1_712_345_678)
        .expect("fetch");
    assert_eq!(result.fetched_at, 1_712_345_678);

    let (_site, crawler) = fixture_site(&[
        page_entry(
            "https://time.test/",
            "https://time.test/",
            &["https://time.test/a"],
        ),
        page_entry("https://time.test/a", "https://time.test/a", &[]),
    ]);
    let crawled = crawler
        .crawl(CrawlRequest::same_site(
            "https://time.test/",
            1_600_000_000,
            budget(4),
        ))
        .expect("crawl");
    assert_eq!(crawled.pages.len(), 2);
    for page in &crawled.pages {
        assert_eq!(
            page.fetched_at, 1_600_000_000,
            "one crawl records one acquisition timestamp"
        );
    }

    // Grep guard: the module reads no host clock.
    let source = include_str!("../web_fetch.rs");
    for needle in ["SystemTime", "UNIX_EPOCH", "unix_seconds_now"] {
        assert!(
            !source.contains(needle),
            "web_fetch.rs must not reference {needle}"
        );
    }
}

#[test]
fn zero_limits_are_rejected_at_construction_and_decode() {
    assert!(matches!(
        CrawlPageBudget::new(0),
        Err(WebFetchError::InvalidPageBudget)
    ));
    assert!(matches!(
        MinExtractedContentBytes::new(0),
        Err(WebFetchError::InvalidMinimumContentBytes)
    ));
    assert_eq!(budget(7).get(), 7);
    assert_eq!(
        MinExtractedContentBytes::default().get(),
        DEFAULT_MIN_EXTRACTED_CONTENT_BYTES
    );

    assert!(
        serde_json::from_str::<CrawlPageBudget>("0").is_err(),
        "a zero budget cannot be smuggled in through the wire"
    );
    assert_eq!(
        serde_json::to_string(&budget(7)).expect("serialize budget"),
        "7",
        "the budget serializes as a bare integer"
    );
    assert_eq!(
        serde_json::from_str::<CrawlPageBudget>("7").expect("decode budget"),
        budget(7)
    );

    let request: CrawlRequest = serde_json::from_str(
        r#"{"seed_url":"https://example.test/","fetched_at":9,"page_budget":3}"#,
    )
    .expect("decode crawl request");
    assert_eq!(
        request.scope,
        CrawlScope::SameSite,
        "same site is the default"
    );
    assert_eq!(request.page_budget.get(), 3);
    assert_eq!(
        request.clone().with_scope(CrawlScope::CrossSite).scope,
        CrawlScope::CrossSite
    );
    assert_eq!(
        CrawlRequest::same_site("https://example.test/", 9, budget(3)),
        request
    );

    assert!(
        serde_json::from_str::<CrawlRequest>(
            r#"{"seed_url":"https://example.test/","fetched_at":9,"page_budget":0}"#
        )
        .is_err(),
        "a zero page budget is rejected inside a request too"
    );
    assert!(
        serde_json::from_str::<CrawlRequest>(
            r#"{"seed_url":"https://example.test/","fetched_at":9}"#
        )
        .is_err(),
        "there is no implicit default page budget"
    );
}

// ---------------------------------------------------------------------------
// Crawl
// ---------------------------------------------------------------------------

fn same_site_fixture() -> Vec<(String, RenderedPage)> {
    vec![
        page_entry_with_canonical(
            "https://site.test/",
            "https://site.test/start",
            "https://other.test/canonical",
            &[
                "https://blog.site.test/x",
                "https://other.test/z",
                "https://site.test/a",
                "https://site.test/a#section",
                "https://site.test/b",
            ],
        ),
        page_entry(
            "https://site.test/a",
            "https://site.test/a",
            &["https://site.test/c", "https://site.test/d"],
        ),
        // /b redirects onto /d, which is still queued behind /c.
        page_entry(
            "https://site.test/b",
            "https://site.test/d",
            &["https://site.test/c"],
        ),
        page_entry("https://site.test/c", "https://site.test/c", &[]),
        page_entry("https://site.test/d", "https://site.test/d", &[]),
    ]
}

#[test]
fn crawl_is_same_site_and_budgeted() {
    let pages = same_site_fixture();
    let (site, fetcher) = fixture_site(&pages);

    let result = fetcher
        .crawl(CrawlRequest::same_site("https://site.test/", 42, budget(6)))
        .expect("same-site crawl");

    let attempts = site.attempts();
    assert_eq!(
        attempts,
        vec![
            "https://site.test/".to_string(),
            "https://site.test/a".to_string(),
            "https://site.test/b".to_string(),
            "https://site.test/c".to_string(),
        ],
        "deterministic breadth-first attempt order"
    );
    assert!(attempts.len() <= 6, "the explicit budget is never exceeded");

    assert_eq!(result.completion, CrawlCompletion::Complete);
    assert!(result.failed.is_empty());
    assert_eq!(
        canonical_urls(&result),
        vec![
            "https://other.test/canonical".to_string(),
            "https://site.test/a".to_string(),
            "https://site.test/b".to_string(),
            "https://site.test/c".to_string(),
        ],
        "a cross-host canonical changes only what the seed page reports"
    );

    // Containment is pinned to the seed's response-final host, so a sibling
    // subdomain and a foreign host are both out of scope.
    assert!(!attempts.iter().any(|url| url.contains("blog.site.test")));
    assert!(!attempts.iter().any(|url| url.contains("other.test")));

    // A diamond fetches the shared child exactly once.
    assert_eq!(
        attempts
            .iter()
            .filter(|url| *url == "https://site.test/c")
            .count(),
        1
    );

    // /b redirected onto the still-queued /d, so /d is skipped at dequeue with
    // no budget charge and no duplicate page.
    assert!(
        !attempts.iter().any(|url| url == "https://site.test/d"),
        "a queue entry already visited through a redirect is never fetched"
    );
    assert_eq!(result.pages.len(), 4);

    // A tighter budget stops the same walk early and surfaces the frontier.
    let (site, fetcher) = fixture_site(&pages);
    let tight = fetcher
        .crawl(CrawlRequest::same_site("https://site.test/", 42, budget(2)))
        .expect("budgeted crawl");
    assert_eq!(site.attempts().len(), 2);
    assert_eq!(
        tight.completion,
        CrawlCompletion::BudgetExhausted {
            unvisited_urls: vec![
                "https://site.test/b".to_string(),
                "https://site.test/c".to_string(),
                "https://site.test/d".to_string(),
            ],
        }
    );
}

#[test]
fn cross_site_crawl_requires_explicit_scope() {
    let pages = vec![
        page_entry(
            "https://a.test/",
            "https://a.test/",
            &[
                "ftp://a.test/file",
                "https://a.test/hop",
                "https://b.test/page",
            ],
        ),
        // A same-host link that redirects onto a foreign host.
        page_entry(
            "https://a.test/hop",
            "https://b.test/redirected",
            &["https://b.test/deep"],
        ),
        page_entry("https://b.test/page", "https://b.test/page", &[]),
        page_entry("https://b.test/deep", "https://b.test/deep", &[]),
    ];

    let (site, fetcher) = fixture_site(&pages);
    let same_site = fetcher
        .crawl(CrawlRequest::same_site("https://a.test/", 8, budget(6)))
        .expect("same-site crawl");

    assert_eq!(
        site.attempts(),
        vec![
            "https://a.test/".to_string(),
            "https://a.test/hop".to_string()
        ]
    );
    assert_eq!(
        canonical_urls(&same_site),
        vec!["https://a.test/".to_string()],
        "the cross-host redirect target is excluded from pages"
    );
    assert_eq!(
        same_site.failed,
        vec![CrawlPageFailure {
            url: "https://a.test/hop".to_string(),
            reason: "cross_site_redirect".to_string(),
        }],
        "the reason literal is exact"
    );
    assert_eq!(same_site.completion, CrawlCompletion::Complete);
    assert!(
        !site.attempts().iter().any(|url| url.contains("b.test")),
        "a foreign host admits none of its links"
    );

    let (site, fetcher) = fixture_site(&pages);
    let cross_site = fetcher
        .crawl(
            CrawlRequest::same_site("https://a.test/", 8, budget(6))
                .with_scope(CrawlScope::CrossSite),
        )
        .expect("cross-site crawl");

    assert_eq!(
        site.attempts(),
        vec![
            "https://a.test/".to_string(),
            "https://a.test/hop".to_string(),
            "https://b.test/page".to_string(),
            "https://b.test/deep".to_string(),
        ],
        "cross-site walking is followed only when explicitly requested"
    );
    assert_eq!(
        canonical_urls(&cross_site),
        vec![
            "https://a.test/".to_string(),
            "https://a.test/hop".to_string(),
            "https://b.test/page".to_string(),
            "https://b.test/deep".to_string(),
        ]
    );
    assert!(cross_site.failed.is_empty());
    assert!(
        !site.attempts().iter().any(|url| url.starts_with("ftp:")),
        "non-HTTP(S) links are not a web-fetch transport in either scope"
    );
}

#[test]
fn crawl_absorbs_mid_walk_page_failure() {
    let pages = vec![
        page_entry(
            "https://walk.test/",
            "https://walk.test/",
            &[
                "https://walk.test/a",
                "https://walk.test/b",
                "https://walk.test/c",
            ],
        ),
        page_entry("https://walk.test/a", "https://walk.test/a", &[]),
        // https://walk.test/b is deliberately absent: 404 on every rung.
        page_entry("https://walk.test/c", "https://walk.test/c", &[]),
    ];

    let (site, fetcher) = fixture_site(&pages);
    let result = fetcher
        .crawl(CrawlRequest::same_site("https://walk.test/", 21, budget(5)))
        .expect("the walk survives a mid-walk failure");

    assert_eq!(
        site.attempts(),
        vec![
            "https://walk.test/".to_string(),
            "https://walk.test/a".to_string(),
            "https://walk.test/b".to_string(),
            "https://walk.test/c".to_string(),
        ],
        "later frontier pages are still visited"
    );
    assert!(site.attempts().len() <= 5);
    assert_eq!(
        canonical_urls(&result),
        vec![
            "https://walk.test/".to_string(),
            "https://walk.test/a".to_string(),
            "https://walk.test/c".to_string(),
        ]
    );
    assert_eq!(result.completion, CrawlCompletion::Complete);

    assert_eq!(result.failed.len(), 1);
    assert_eq!(result.failed[0].url, "https://walk.test/b");
    assert_eq!(
        result.failed[0].reason,
        "all web fetch renderers failed: \
         readability: Transport: fixture readability 404 for https://walk.test/b; \
         headless: Transport: fixture headless 404 for https://walk.test/b; \
         firecrawl: Transport: fixture firecrawl 404 for https://walk.test/b",
        "the ordered ladder trace is preserved rather than flattened"
    );
    assert!(result.failed[0].reason.contains("404"));

    // A seed failure stays a typed top-level error: there is no final URL from
    // which to pin the walk.
    let (_site, fetcher) = fixture_site(&[page_entry(
        "https://walk.test/a",
        "https://walk.test/a",
        &[],
    )]);
    let error = fetcher
        .crawl(CrawlRequest::same_site("https://walk.test/", 21, budget(5)))
        .expect_err("seed failure propagates");
    assert!(matches!(
        error,
        WebFetchError::AllRenderersFailed { ref url, .. } if url == "https://walk.test/"
    ));

    // An unusable seed never reaches a renderer at all.
    let (site, fetcher) = fixture_site(&pages);
    assert!(matches!(
        fetcher.crawl(CrawlRequest::same_site("ftp://walk.test/", 21, budget(5))),
        Err(WebFetchError::UnsupportedScheme { .. })
    ));
    assert!(matches!(
        fetcher.crawl(CrawlRequest::same_site("not a url", 21, budget(5))),
        Err(WebFetchError::InvalidUrl { .. })
    ));
    assert!(site.attempts().is_empty());
}

#[test]
fn crawl_budget_surfaces_the_unvisited_frontier() {
    let pages = vec![
        page_entry(
            "https://grid.test/",
            "https://grid.test/",
            &[
                "https://grid.test/a",
                "https://grid.test/b",
                "https://grid.test/c",
            ],
        ),
        // https://grid.test/a is absent: its failure still consumes budget.
        page_entry("https://grid.test/b", "https://grid.test/b", &[]),
        page_entry("https://grid.test/c", "https://grid.test/c", &[]),
    ];

    let (site, fetcher) = fixture_site(&pages);
    let result = fetcher
        .crawl(CrawlRequest::same_site("https://grid.test/", 5, budget(3)))
        .expect("budgeted crawl is a successful partial result");

    assert_eq!(
        site.attempts(),
        vec![
            "https://grid.test/".to_string(),
            "https://grid.test/a".to_string(),
            "https://grid.test/b".to_string(),
        ],
        "successes and failures consume the same budget"
    );
    assert_eq!(site.attempts().len(), 3);
    assert_eq!(result.pages.len(), 2);
    assert_eq!(result.failed.len(), 1);
    assert_eq!(result.failed[0].url, "https://grid.test/a");
    assert_eq!(
        result.completion,
        CrawlCompletion::BudgetExhausted {
            unvisited_urls: vec!["https://grid.test/c".to_string()],
        },
        "the remaining frontier is surfaced rather than silently truncated"
    );
}

// ---------------------------------------------------------------------------
// Colocated non-claims oracle: acquisition writes nothing
// ---------------------------------------------------------------------------

#[test]
fn fetch_and_crawl_write_zero_vault_rows() -> crate::Result<()> {
    let source = include_str!("../web_fetch.rs");
    for needle in [
        "Vault",
        "Store",
        "heed",
        "ingest",
        "claim",
        "receipt",
        "write_envelope",
        "WriteEnvelope",
    ] {
        assert!(
            !source.contains(needle),
            "web_fetch.rs must carry no {needle} import or reference"
        );
    }
    for needle in [
        "oss_safeguard",
        "crate::gate",
        "gate::",
        "GateDecision",
        "evaluate_gate",
        "dispatch_outbound_intent",
        "outbound_chokepoint",
        "schedule_outbound",
    ] {
        assert!(
            !source.contains(needle),
            "web_fetch.rs must carry no {needle} integration"
        );
    }
    for word in source.split(|character: char| !character.is_ascii_alphanumeric()) {
        assert!(
            !word.eq_ignore_ascii_case("exa"),
            "hosted search services stay outside the ladder"
        );
    }

    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;

    let counts_before = {
        let rtxn = vault.store.env.read_txn()?;
        (
            vault.store.entities.len(&rtxn)?,
            vault.store.vault_meta.len(&rtxn)?,
        )
    };

    let log = call_log();
    let fetched = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page(LADDER_MARKDOWN, "https://silent.test/page")),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://silent.test/page", 77)
    .expect("fetch");
    assert_eq!(fetched.renderer, RendererKind::Readability);

    let (_site, crawler) = fixture_site(&[
        page_entry(
            "https://silent.test/",
            "https://silent.test/",
            &["https://silent.test/a"],
        ),
        page_entry("https://silent.test/a", "https://silent.test/a", &[]),
    ]);
    let crawled = crawler
        .crawl(CrawlRequest::same_site(
            "https://silent.test/",
            77,
            budget(4),
        ))
        .expect("crawl");
    assert_eq!(crawled.pages.len(), 2);

    let counts_after = {
        let rtxn = vault.store.env.read_txn()?;
        (
            vault.store.entities.len(&rtxn)?,
            vault.store.vault_meta.len(&rtxn)?,
        )
    };
    assert_eq!(
        counts_before, counts_after,
        "acquisition is read only: it writes no row"
    );
    Ok(())
}
