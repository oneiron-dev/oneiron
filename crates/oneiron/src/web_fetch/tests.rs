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
    spawn_byte_fixture_server(move |request| handler(request).into_bytes())
}

/// The byte-level form of [`spawn_fixture_server`], for a fixture whose body is
/// deliberately not UTF-8 — a declared legacy charset, or a BOM.
fn spawn_byte_fixture_server<H>(handler: H) -> String
where
    H: Fn(&str) -> Vec<u8> + Send + 'static,
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
            let _ = stream.write_all(&response);
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
    String::from_utf8(http_response_bytes(status, content_type, body.as_bytes()))
        .expect("a text fixture response is UTF-8")
}

/// The one response builder, in bytes, so a non-UTF-8 body reaches the wire
/// exactly as written instead of through a lossy `String`.
fn http_response_bytes(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
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
            // `sourceURL` deliberately echoes a *different* request URL than the
            // navigation-final `url`, so the mapping proves it reads the final
            // identity from the response contract rather than the request echo.
            "/v1/scrape" => http_response(
                "200 OK",
                "application/json",
                r##"{"success":true,"data":{"markdown":"# Firecrawl page\n\nBody text that clears the floor.","links":["https://example.test/next","https://example.test/next","mailto:x@example.test","/relative"],"metadata":{"title":"  Example  ","sourceURL":"https://redirect.test/requested","url":"https://example.test/page#frag","statusCode":200}}}"##,
            ),
            "/not-success" => http_response("200 OK", "application/json", r#"{"success":false}"#),
            "/no-data" => http_response("200 OK", "application/json", r#"{"success":true}"#),
            "/no-markdown" => http_response(
                "200 OK",
                "application/json",
                r#"{"success":true,"data":{"metadata":{"url":"https://example.test/page"}}}"#,
            ),
            // A request echo alone is not a navigation-final identity.
            "/no-final" => http_response(
                "200 OK",
                "application/json",
                r#"{"success":true,"data":{"markdown":"body","metadata":{"sourceURL":"https://example.test/page"}}}"#,
            ),
            "/bad-final" => http_response(
                "200 OK",
                "application/json",
                r#"{"success":true,"data":{"markdown":"body","metadata":{"url":"mailto:x@example.test"}}}"#,
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
        "the navigation-final `url` is normalized and supplies the final URL"
    );
    assert_ne!(
        page.final_url, "https://redirect.test/requested",
        "the request-echoing sourceURL never supplies the final URL"
    );
    assert_eq!(page.canonical_url, "https://example.test/page");
    assert_eq!(
        page.discovered_links,
        vec![
            "https://example.test/next".to_string(),
            "https://example.test/relative".to_string(),
        ],
        "links are normalized, filtered to HTTP(S), sorted and deduplicated, and \
         a relative link resolves against the navigation-final `url` host rather \
         than the sourceURL host"
    );

    for path in [
        "/not-success",
        "/no-data",
        "/no-markdown",
        "/no-final",
        "/bad-final",
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

#[test]
fn crawl_suppresses_a_duplicate_of_a_completed_navigation_final_identity() {
    let pages = vec![
        page_entry(
            "https://dup.test/",
            "https://dup.test/",
            &["https://dup.test/a", "https://dup.test/b"],
        ),
        page_entry(
            "https://dup.test/a",
            "https://dup.test/a",
            &["https://dup.test/c"],
        ),
        // /b is a later alias for the already completed /a: the same
        // navigation-final URL, the same document, and one link nothing else
        // reaches.
        page_entry_with_canonical(
            "https://dup.test/b",
            "https://dup.test/a",
            "https://dup.test/a",
            &["https://dup.test/d"],
        ),
        page_entry("https://dup.test/c", "https://dup.test/c", &[]),
        page_entry("https://dup.test/d", "https://dup.test/d", &[]),
    ];

    let (site, fetcher) = fixture_site(&pages);
    let result = fetcher
        .crawl(CrawlRequest::same_site("https://dup.test/", 13, budget(6)))
        .expect("crawl over an alias of a completed page");

    let attempts = site.attempts();
    assert_eq!(
        attempts,
        vec![
            "https://dup.test/".to_string(),
            "https://dup.test/a".to_string(),
            "https://dup.test/b".to_string(),
            "https://dup.test/c".to_string(),
        ],
        "the later alias still spends its own page attempt"
    );
    assert_eq!(
        canonical_urls(&result),
        vec![
            "https://dup.test/".to_string(),
            "https://dup.test/a".to_string(),
            "https://dup.test/c".to_string(),
        ],
        "a navigation-final identity already completed is not admitted twice"
    );
    assert_eq!(
        canonical_urls(&result)
            .iter()
            .filter(|url| *url == "https://dup.test/a")
            .count(),
        1,
        "the alias returns the same page and adds no second result"
    );
    assert!(
        !attempts.iter().any(|url| url == "https://dup.test/d"),
        "the suppressed duplicate enqueues none of its links"
    );
    assert!(result.failed.is_empty(), "a duplicate is not a failure");
    assert_eq!(result.completion, CrawlCompletion::Complete);

    // The alias is charged as an attempt: three units cover the seed, the
    // destination, and the alias, leaving the destination's own child queued.
    let (site, fetcher) = fixture_site(&pages);
    let charged = fetcher
        .crawl(CrawlRequest::same_site("https://dup.test/", 13, budget(3)))
        .expect("budgeted crawl over an alias of a completed page");
    assert_eq!(
        site.attempts(),
        vec![
            "https://dup.test/".to_string(),
            "https://dup.test/a".to_string(),
            "https://dup.test/b".to_string(),
        ],
        "both the destination and its later alias consume a budget unit"
    );
    assert_eq!(charged.pages.len(), 2);
    assert_eq!(
        charged.completion,
        CrawlCompletion::BudgetExhausted {
            unvisited_urls: vec!["https://dup.test/c".to_string()],
        },
        "the suppressed duplicate contributes nothing to the reported frontier"
    );
}

#[test]
fn crawl_skips_a_queued_destination_reached_by_an_earlier_redirect() {
    let pages = vec![
        page_entry(
            "https://hop.test/",
            "https://hop.test/",
            &["https://hop.test/a", "https://hop.test/b"],
        ),
        // /a redirects onto /b while /b is still queued behind it.
        page_entry_with_canonical(
            "https://hop.test/a",
            "https://hop.test/b",
            "https://hop.test/b",
            &["https://hop.test/c"],
        ),
        page_entry("https://hop.test/b", "https://hop.test/b", &[]),
        page_entry("https://hop.test/c", "https://hop.test/c", &[]),
    ];

    // Exactly three units: the seed, the alias, and the tail page. Charging the
    // skipped destination a unit would starve the tail page.
    let (site, fetcher) = fixture_site(&pages);
    let result = fetcher
        .crawl(CrawlRequest::same_site("https://hop.test/", 17, budget(3)))
        .expect("crawl over an alias of a queued page");

    assert_eq!(
        site.attempts(),
        vec![
            "https://hop.test/".to_string(),
            "https://hop.test/a".to_string(),
            "https://hop.test/c".to_string(),
        ],
        "a queue entry already reached by a redirect is never fetched"
    );
    assert_eq!(
        canonical_urls(&result),
        vec![
            "https://hop.test/".to_string(),
            "https://hop.test/b".to_string(),
            "https://hop.test/c".to_string(),
        ],
        "the redirecting alias is the first completion of that identity"
    );
    assert_eq!(
        result.completion,
        CrawlCompletion::Complete,
        "the dequeue-time skip charges no budget unit"
    );
    assert!(result.failed.is_empty());
}

#[test]
fn crawl_admits_a_page_whose_final_url_is_its_requested_url() {
    let pages = vec![
        page_entry(
            "https://own.test/",
            "https://own.test/",
            &["https://own.test/a", "https://own.test/b"],
        ),
        page_entry("https://own.test/a", "https://own.test/a", &[]),
        page_entry("https://own.test/b", "https://own.test/b", &[]),
    ];

    let (site, fetcher) = fixture_site(&pages);
    let result = fetcher
        .crawl(CrawlRequest::same_site("https://own.test/", 23, budget(4)))
        .expect("crawl without a redirect");

    assert_eq!(
        site.attempts(),
        vec![
            "https://own.test/".to_string(),
            "https://own.test/a".to_string(),
            "https://own.test/b".to_string(),
        ],
        "every ordinary page is fetched"
    );
    assert_eq!(
        canonical_urls(&result),
        vec![
            "https://own.test/".to_string(),
            "https://own.test/a".to_string(),
            "https://own.test/b".to_string(),
        ],
        "a page whose final URL is its own requested URL is its first completion, \
         not a duplicate of the requested URL recorded before the fetch"
    );
    assert!(result.failed.is_empty());
    assert_eq!(result.completion, CrawlCompletion::Complete);
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

// ---------------------------------------------------------------------------
// ONE-1932 review regressions: the required-rung invariant, the featureless
// acceptance gates, the credential boundary, bounded bodies, central canonical
// validation, response-contract identity, the pinned root surface, and closed
// decoding.
// ---------------------------------------------------------------------------

#[test]
fn an_absent_required_rung_fails_closed_and_absent_optional_rungs_do_not() {
    let log = call_log();
    let headless = scripted(
        &log,
        RendererKind::Headless,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );
    let firecrawl = scripted(
        &log,
        RendererKind::Firecrawl,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    );
    let mut fetcher = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    )))
    .expect("readability slot")
    .with_headless(rung(&headless))
    .expect("headless slot")
    .with_firecrawl(rung(&firecrawl))
    .expect("firecrawl slot")
    .with_minimum_content(ladder_minimum());

    // Emptying the required slot is exactly the state the driver must refuse.
    fetcher.readability = None;

    let error = fetcher
        .fetch("https://example.test/page", 9)
        .expect_err("a missing required rung is not a ladder outcome");
    assert!(
        matches!(
            &error,
            WebFetchError::MissingRequiredRenderer {
                renderer: RendererKind::Readability
            }
        ),
        "unexpected error for an empty required slot: {error}"
    );
    assert!(
        !error.to_string().contains("renderer unavailable"),
        "a required rung is never reported as an optional unavailable attempt"
    );
    assert_eq!(
        headless.calls(),
        0,
        "a skipped required rung must not silently promote the request downward"
    );
    assert_eq!(firecrawl.calls(), 0);

    // A crawl seed cannot route around the same invariant.
    let seed_error = fetcher
        .crawl(CrawlRequest::same_site(
            "https://example.test/page",
            9,
            budget(2),
        ))
        .expect_err("the seed inherits the fail-closed rung error");
    assert!(matches!(
        seed_error,
        WebFetchError::MissingRequiredRenderer { .. }
    ));

    // A genuinely optional absent rung keeps its typed record and its place.
    let optional_absent = WebFetcher::new(rung(&scripted(
        &call_log(),
        RendererKind::Readability,
        Err(RendererError::transport("blocked")),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://example.test/page", 9)
    .expect_err("no rung produced content");
    let WebFetchError::AllRenderersFailed { attempts, .. } = optional_absent else {
        panic!("an absent optional rung still yields the ordered ladder trace");
    };
    assert_eq!(
        attempts,
        vec![
            RendererAttemptFailure::Error {
                renderer: RendererKind::Readability,
                error: RendererError::transport("blocked"),
            },
            RendererAttemptFailure::Unavailable {
                renderer: RendererKind::Headless
            },
            RendererAttemptFailure::Unavailable {
                renderer: RendererKind::Firecrawl
            },
        ],
        "Unavailable, Error, and ladder order all survive"
    );
}

/// Reads a repo-root file at test time.
///
/// Read rather than `include_str!`d because these files live outside the crate
/// directory: a compile-time include would bind the packaged crate to paths the
/// package does not carry, while a test-time read keeps the coupling where it
/// belongs — in the workspace this gate actually runs in.
fn read_repo_file(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {} must succeed: {error}", path.display()))
}

#[test]
fn verify_script_runs_both_featureless_gates_alongside_the_all_features_gates() {
    let script = read_repo_file("scripts/verify.sh");
    for wiring in ["run_stage clippy-featureless", "run_stage test-featureless"] {
        assert!(
            script.contains(wiring),
            "scripts/verify.sh must wire the featureless stage `{wiring}`"
        );
    }
    for required in [
        "cargo test -p oneiron --lib --no-default-features",
        "cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings",
    ] {
        assert!(
            script.contains(required),
            "scripts/verify.sh must run the featureless acceptance gate `{required}`"
        );
    }
    for retained in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets --all-features -- -D warnings",
        "cargo nextest run --workspace --all-features --profile full",
        "cargo test --doc --workspace --exclude oneiron-bench --all-features",
    ] {
        assert!(
            script.contains(retained),
            "the featureless gates are added to, never instead of, `{retained}`"
        );
    }
}

#[test]
fn every_web_fetch_root_export_is_pinned_exactly_once() {
    let lib = include_str!("../lib.rs");
    let pin = read_repo_file("scripts/ratchet/root-surface.txt");

    let group = lib
        .split_once("pub use crate::web_fetch::{")
        .expect("lib.rs re-exports the web_fetch surface")
        .1
        .split_once("};")
        .expect("the web_fetch re-export group is terminated")
        .0;
    let exported: Vec<&str> = group
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    assert!(
        exported.len() > 20,
        "the web_fetch export group did not parse: {exported:?}"
    );

    for name in exported {
        let pinned = pin.lines().filter(|line| line.trim() == name).count();
        assert_eq!(
            pinned, 1,
            "crate-root export {name} must appear exactly once in \
             scripts/ratchet/root-surface.txt"
        );
    }
}

#[test]
fn fetch_result_decoding_rejects_an_unknown_field() {
    let result = FetchResult {
        markdown: "# Heading\n\nBody.".to_string(),
        title: "Title".to_string(),
        canonical_url: "https://example.test/page".to_string(),
        fetched_at: 1_700_000_000,
        content_hash: content_hash("# Heading\n\nBody."),
        renderer: RendererKind::Readability,
    };
    let encoded = serde_json::to_value(&result).expect("serialize fetch result");
    let object = encoded
        .as_object()
        .expect("fetch result is a JSON object")
        .clone();
    assert_eq!(object.len(), 6, "serialization stays closed at six keys");

    let exact: FetchResult =
        serde_json::from_value(Value::Object(object.clone())).expect("the six keys decode");
    assert_eq!(exact, result);

    let mut extended = object.clone();
    extended.insert("provider_debug".to_string(), json!("firecrawl-internal"));
    let rejected = serde_json::from_value::<FetchResult>(Value::Object(extended))
        .expect_err("a seventh field must not be silently dropped");
    assert!(
        rejected.to_string().contains("provider_debug"),
        "the rejection names the unknown field: {rejected}"
    );

    let mut truncated = object;
    truncated.remove("content_hash");
    assert!(
        serde_json::from_value::<FetchResult>(Value::Object(truncated)).is_err(),
        "a missing field is a decode failure, never a default"
    );
}

/// A URL whose userinfo must never appear in a request, a payload, or a
/// diagnostic. The password is a distinctive literal so a leak is unambiguous.
const CREDENTIALED_URL: &str = "https://agent:s3cr3t@example.test/page";

fn assert_no_credential(haystack: &str, context: &str) {
    for secret in ["s3cr3t", "agent:", "agent@"] {
        assert!(
            !haystack.contains(secret),
            "{context} leaked `{secret}`: {haystack}"
        );
    }
}

#[test]
fn userinfo_credentials_are_refused_and_never_reach_a_diagnostic() {
    assert_eq!(
        redact_url_credentials(CREDENTIALED_URL),
        "https://REDACTED@example.test/page"
    );
    assert_eq!(
        redact_url_credentials("https://example.test/page"),
        "https://example.test/page",
        "a credential-free URL is reported verbatim"
    );
    assert_eq!(
        redact_url_credentials("https://a:b@c:d@host.test"),
        "https://REDACTED@host.test/",
        "the last authority `@` wins, so a password containing `@` is still covered; \
         the reported spelling is the parser's own serialization"
    );
    assert_eq!(
        redact_url_credentials("not a url"),
        "not a url",
        "an unparseable string is still reportable"
    );

    let log = call_log();
    let fetcher = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum());

    let error = fetcher
        .fetch(CREDENTIALED_URL, 3)
        .expect_err("embedded credentials are refused at the caller boundary");
    assert!(
        matches!(&error, WebFetchError::CredentialsInUrl { .. }),
        "unexpected error: {error}"
    );
    assert_no_credential(&error.to_string(), "the fetch error");
    assert!(
        log.lock().expect("call log").is_empty(),
        "no rung runs for a refused URL"
    );

    let seed_error = fetcher
        .crawl(CrawlRequest::same_site(CREDENTIALED_URL, 3, budget(2)))
        .expect_err("a credentialed seed is refused");
    assert_no_credential(&seed_error.to_string(), "the crawl seed error");

    // `FirecrawlRenderer` is deliberately not `Debug` (it holds a client), so
    // the error is taken by pattern rather than by `expect_err`.
    let Err(endpoint_error) = FirecrawlRenderer::new(
        reqwest::blocking::Client::new(),
        "https://agent:s3cr3t@scrape.test/v1/scrape",
    ) else {
        panic!("a credentialed scrape endpoint is refused");
    };
    assert!(matches!(&endpoint_error, WebFetchError::InvalidUrl { .. }));
    assert_no_credential(&endpoint_error.to_string(), "the endpoint error");

    // The provider never sees the request at all.
    let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let base = spawn_fixture_server(move |request| {
        sink.lock()
            .expect("recorded requests")
            .push(request.to_string());
        http_response("200 OK", "application/json", r#"{"success":false}"#)
    });
    let refused = FirecrawlRenderer::new(
        reqwest::blocking::Client::new(),
        &format!("{base}/v1/scrape"),
    )
    .expect("endpoint")
    .render(CREDENTIALED_URL)
    .expect_err("a credentialed target is refused before transport");
    assert_eq!(refused.kind, RendererErrorKind::Transport);
    assert_no_credential(&refused.message, "the firecrawl refusal");
    assert!(
        recorded.lock().expect("recorded requests").is_empty(),
        "the credentialed URL never reached the provider"
    );

    let native = NativeReadabilityRenderer::new(reqwest::blocking::Client::new())
        .render(CREDENTIALED_URL)
        .expect_err("a credentialed target is refused before the GET");
    assert_eq!(native.kind, RendererErrorKind::Transport);
    assert_no_credential(&native.message, "the native refusal");

    // A renderer that *reports* a credentialed identity is refused as well, and
    // the trace redacts rather than drops it.
    let reported = WebFetcher::new(rung(&scripted(
        &call_log(),
        RendererKind::Readability,
        Ok(RenderedPage {
            markdown: LADDER_MARKDOWN.to_string(),
            title: "Credentialed".to_string(),
            canonical_url: "https://example.test/page".to_string(),
            final_url: CREDENTIALED_URL.to_string(),
            discovered_links: Vec::new(),
        }),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://example.test/page", 3)
    .expect_err("a credentialed final URL is not a usable identity");
    let WebFetchError::AllRenderersFailed { attempts, .. } = reported else {
        panic!("expected the ordered ladder trace");
    };
    let rendered = attempts
        .iter()
        .map(RendererAttemptFailure::render_reason)
        .collect::<Vec<String>>()
        .join("; ");
    assert_no_credential(&rendered, "the rendered ladder trace");
    assert!(
        rendered.contains("REDACTED"),
        "the credential is redacted, not dropped: {rendered}"
    );

    // A credentialed link never enters a frontier.
    assert!(
        normalize_link_list([CREDENTIALED_URL], &fixture_url("https://example.test/")).is_empty(),
        "a credentialed link is not walkable"
    );
}

#[test]
fn response_bodies_are_read_under_an_explicit_byte_ceiling() {
    let html = served_article_html();
    let oversized_html = "x".repeat(8 * 1024);
    let oversized_envelope = format!(
        r#"{{"success":true,"data":{{"markdown":"{}","metadata":{{"url":"https://example.test/page","statusCode":200}}}}}}"#,
        "y".repeat(8 * 1024)
    );
    let base = spawn_fixture_server(move |request| match request_path(request).as_str() {
        "/small" => http_response("200 OK", "text/html; charset=utf-8", &html),
        "/huge" => http_response("200 OK", "text/html; charset=utf-8", &oversized_html),
        "/v1/scrape" => http_response("200 OK", "application/json", &oversized_envelope),
        _ => http_response("404 Not Found", "text/plain", "missing"),
    });

    let tight = NonZeroUsize::new(1024).expect("non-zero ceiling");
    let roomy = NonZeroUsize::new(1024 * 1024).expect("non-zero ceiling");
    let native = NativeReadabilityRenderer::new(reqwest::blocking::Client::new());

    let capped = native
        .clone()
        .with_max_response_bytes(tight)
        .render(&format!("{base}/huge"))
        .expect_err("an oversized body is refused instead of buffered");
    assert_eq!(capped.kind, RendererErrorKind::InvalidResponse);
    assert!(
        capped.message.contains("1024") && capped.message.contains("ceiling"),
        "the refusal names the ceiling it enforced: {}",
        capped.message
    );

    let admitted = native
        .with_max_response_bytes(roomy)
        .render(&format!("{base}/small"))
        .expect("a body under the ceiling still extracts");
    assert_eq!(admitted.title, "Served Article Title");

    let firecrawl_capped = FirecrawlRenderer::new(
        reqwest::blocking::Client::new(),
        &format!("{base}/v1/scrape"),
    )
    .expect("endpoint")
    .with_max_response_bytes(tight)
    .render("https://example.test/page")
    .expect_err("an oversized envelope is refused instead of buffered");
    assert_eq!(firecrawl_capped.kind, RendererErrorKind::InvalidResponse);
    assert!(firecrawl_capped.message.contains("ceiling"));

    let firecrawl_admitted = FirecrawlRenderer::new(
        reqwest::blocking::Client::new(),
        &format!("{base}/v1/scrape"),
    )
    .expect("endpoint")
    .with_max_response_bytes(roomy)
    .render("https://example.test/page")
    .expect("an envelope under the ceiling decodes");
    assert_eq!(firecrawl_admitted.final_url, "https://example.test/page");
}

#[test]
fn a_custom_rung_canonical_url_passes_the_same_central_validation() {
    let page_with = |canonical: &str| RenderedPage {
        markdown: LADDER_MARKDOWN.to_string(),
        title: "Custom".to_string(),
        canonical_url: canonical.to_string(),
        final_url: "https://example.test/final".to_string(),
        discovered_links: Vec::new(),
    };

    for rejected in [
        "javascript:alert(1)",
        "not a url",
        "mailto:x@example.test",
        "/relative-only",
        CREDENTIALED_URL,
        "",
    ] {
        let error = WebFetcher::new(rung(&scripted(
            &call_log(),
            RendererKind::Readability,
            Ok(page_with(rejected)),
        )))
        .expect("readability slot")
        .with_minimum_content(ladder_minimum())
        .fetch("https://example.test/page", 5)
        .expect_err("an unvalidated canonical URL cannot reach the closed result");
        let WebFetchError::AllRenderersFailed { attempts, .. } = error else {
            panic!("expected the ordered ladder trace");
        };
        assert_eq!(
            attempts.len(),
            3,
            "the ordered trace is preserved for {rejected}"
        );
        assert!(
            matches!(
                &attempts[0],
                RendererAttemptFailure::Error {
                    renderer: RendererKind::Readability,
                    error,
                } if error.kind == RendererErrorKind::InvalidResponse
                    && error.message.contains("canonical URL")
            ),
            "unexpected first attempt for {rejected}: {:?}",
            attempts[0]
        );
    }

    // A valid canonical is normalized exactly like every other accepted URL.
    let result = WebFetcher::new(rung(&scripted(
        &call_log(),
        RendererKind::Readability,
        Ok(page_with("https://example.test/canonical#fragment")),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum())
    .fetch("https://example.test/page", 5)
    .expect("a valid canonical is accepted");
    assert_eq!(
        result.canonical_url, "https://example.test/canonical",
        "the canonical identity is normalized, fragment dropped"
    );
}

#[test]
fn firecrawl_target_status_is_read_from_the_envelope_before_transport_status() {
    let base = spawn_fixture_server(|request| match request_path(request).as_str() {
        // A failed target arrives inside a well-formed 2xx envelope, carrying an
        // error page whose body would otherwise clear the extraction floor.
        "/target-404" => http_response(
            "200 OK",
            "application/json",
            r##"{"success":true,"data":{"markdown":"# Not Found\n\nThe page is gone, and this body is long enough to clear any floor.","metadata":{"url":"https://example.test/gone","statusCode":404}}}"##,
        ),
        "/target-500" => http_response(
            "200 OK",
            "application/json",
            r##"{"success":true,"data":{"markdown":"# Server Error\n\nAn upstream failure page that would otherwise be indexed as content.","metadata":{"url":"https://example.test/boom","statusCode":500}}}"##,
        ),
        // A non-2xx transport whose body still carries the scrape verdict.
        "/error-envelope" => http_response(
            "500 Internal Server Error",
            "application/json",
            r#"{"success":false}"#,
        ),
        // A non-2xx transport with no decodable envelope at all.
        "/opaque" => http_response("502 Bad Gateway", "text/html", "<html>gateway</html>"),
        "/target-ok" => http_response(
            "200 OK",
            "application/json",
            r##"{"success":true,"data":{"markdown":"# Fine\n\nA target that really did answer, with a body past the floor.","metadata":{"url":"https://example.test/fine","statusCode":200}}}"##,
        ),
        "/target-unreported" => http_response(
            "200 OK",
            "application/json",
            r##"{"success":true,"data":{"markdown":"# Fine\n\nA target whose status the envelope never mentions at all.","metadata":{"url":"https://example.test/quiet"}}}"##,
        ),
        _ => http_response("404 Not Found", "text/plain", "missing"),
    });

    let client = reqwest::blocking::Client::new();
    let render = |path: &str| {
        FirecrawlRenderer::new(client.clone(), &format!("{base}{path}"))
            .expect("endpoint")
            .render("https://example.test/page")
    };

    for (path, status) in [("/target-404", "404"), ("/target-500", "500")] {
        let error = render(path).expect_err("a failed target is not content");
        assert_eq!(
            error.kind,
            RendererErrorKind::Transport,
            "unexpected mapping for {path}"
        );
        assert!(
            error.message.contains(status),
            "the target status is reported for {path}: {}",
            error.message
        );
    }

    // The structured envelope verdict is not masked by the transport status.
    let envelope_wins = render("/error-envelope").expect_err("a scrape error envelope is honored");
    assert_eq!(
        envelope_wins.kind,
        RendererErrorKind::InvalidResponse,
        "the envelope verdict survives a non-2xx transport status"
    );
    assert!(envelope_wins.message.contains("did not report success"));

    // With no decodable envelope, the transport status is the only truth left.
    let opaque = render("/opaque").expect_err("an opaque non-2xx body is a transport failure");
    assert_eq!(opaque.kind, RendererErrorKind::Transport);
    assert!(
        opaque.message.contains("502"),
        "the transport status is reported: {}",
        opaque.message
    );

    // A 2xx target maps, whether or not the envelope reported its status.
    assert_eq!(
        render("/target-ok").expect("a 2xx target maps").final_url,
        "https://example.test/fine"
    );
    assert_eq!(
        render("/target-unreported")
            .expect("an unreported status is not a failure")
            .final_url,
        "https://example.test/quiet"
    );
}

// ---------------------------------------------------------------------------
// Non-canonical credential spellings
// ---------------------------------------------------------------------------

/// The same `agent:s3cr3t` credential in the spellings WHATWG parsing still
/// reads as userinfo, each paired with the only diagnostic it may produce.
///
/// None of them contains the `://` a textual redactor keys on: one carries no
/// slash at all, one carries a single slash, one carries backslashes, and one
/// hides ASCII tab and newline inside the credential itself. Every one of them
/// parses to an HTTP(S) URL with username `agent` and password `s3cr3t`.
const NONCANONICAL_CREDENTIALED_URLS: [(&str, &str); 4] = [
    (
        "http:agent:s3cr3t@example.test/page",
        "http://REDACTED@example.test/page",
    ),
    (
        "http:/agent:s3cr3t@example.test/page",
        "http://REDACTED@example.test/page",
    ),
    (
        "http:\\\\agent:s3cr3t@example.test/page",
        "http://REDACTED@example.test/page",
    ),
    (
        "https://age\tnt:s3c\nr3t@example.test/page",
        "https://REDACTED@example.test/page",
    ),
];

/// The credential in every fragment it could leak as. The tab/newline spelling
/// splits both halves across the stripped character, so the halves are named
/// here too — a redactor that echoed that spelling raw would pass a check for
/// the joined literal alone.
fn assert_no_userinfo(haystack: &str, context: &str) {
    for fragment in ["s3cr3t", "s3c", "r3t", "agent"] {
        assert!(
            !haystack.contains(fragment),
            "{context} leaked `{fragment}`: {haystack:?}"
        );
    }
}

/// A host browser that must never be reached: the URL is refused first.
struct UnreachableHeadless;

impl HeadlessRenderer for UnreachableHeadless {
    fn render_html(&self, url: &str) -> RendererResult<HeadlessDocument> {
        panic!("the browser boundary was reached with {url:?}");
    }
}

#[test]
fn noncanonical_userinfo_spellings_are_sanitized_in_every_public_diagnostic() {
    // One parse-aware sanitizer answers every spelling with the parser's own
    // canonical serialization.
    for (raw, sanitized) in NONCANONICAL_CREDENTIALED_URLS {
        let reported = redact_url_credentials(raw);
        assert_eq!(
            reported, sanitized,
            "the parsed userinfo is replaced whatever the spelling: {raw:?}"
        );
        assert_no_userinfo(&reported, "the sanitizer");
    }

    // Input the parser rejects outright still loses its userinfo instead of
    // being echoed raw.
    for unparseable in [
        "http:agent:s3cr3t@",
        "https://agent:s3cr3t@",
        "http:\\\\agent:s3cr3t@",
    ] {
        assert!(
            Url::parse(unparseable).is_err(),
            "{unparseable:?} is meant to exercise the parse-failure leg"
        );
        assert_no_userinfo(
            &redact_url_credentials(unparseable),
            "the parse-failure fallback",
        );
    }

    let log = call_log();
    let fetcher = WebFetcher::new(rung(&scripted(
        &log,
        RendererKind::Readability,
        Ok(ladder_page(LADDER_MARKDOWN, "https://example.test/page")),
    )))
    .expect("readability slot")
    .with_minimum_content(ladder_minimum());

    for (raw, _) in NONCANONICAL_CREDENTIALED_URLS {
        let error = fetcher
            .fetch(raw, 3)
            .expect_err("embedded credentials are refused whatever the spelling");
        assert!(
            matches!(&error, WebFetchError::CredentialsInUrl { .. }),
            "unexpected error for {raw:?}: {error}"
        );
        assert_no_userinfo(&error.to_string(), "the fetch error");

        let seed_error = fetcher
            .crawl(CrawlRequest::same_site(raw, 3, budget(2)))
            .expect_err("a credentialed seed is refused whatever the spelling");
        assert_no_userinfo(&seed_error.to_string(), "the crawl seed error");
    }
    assert!(
        log.lock().expect("call log").is_empty(),
        "no rung runs for a refused URL"
    );

    // Every network boundary refuses the URL before it is spoken aloud.
    let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let base = spawn_fixture_server(move |request| {
        sink.lock()
            .expect("recorded requests")
            .push(request.to_string());
        http_response("200 OK", "application/json", r#"{"success":false}"#)
    });
    let firecrawl = FirecrawlRenderer::new(
        reqwest::blocking::Client::new(),
        &format!("{base}/v1/scrape"),
    )
    .expect("endpoint");

    for (raw, _) in NONCANONICAL_CREDENTIALED_URLS {
        let native = NativeReadabilityRenderer::new(reqwest::blocking::Client::new())
            .render(raw)
            .expect_err("a credentialed target is refused before the GET");
        assert_eq!(native.kind, RendererErrorKind::Transport);
        assert_no_userinfo(&native.message, "the native refusal");

        let headless = NativeHeadlessRenderer::new(Arc::new(UnreachableHeadless))
            .render(raw)
            .expect_err("a credentialed target is refused before the browser");
        assert_eq!(headless.kind, RendererErrorKind::Transport);
        assert_no_userinfo(&headless.message, "the headless refusal");

        let refused = firecrawl
            .render(raw)
            .expect_err("a credentialed target is refused before the payload");
        assert_eq!(refused.kind, RendererErrorKind::Transport);
        assert_no_userinfo(&refused.message, "the firecrawl refusal");
    }
    assert!(
        recorded.lock().expect("recorded requests").is_empty(),
        "no spelling of the credential reached the provider"
    );

    // A custom renderer that *reports* a credentialed identity, in either
    // field, is refused with a redacted trace rather than a dropped one.
    for (raw, sanitized) in NONCANONICAL_CREDENTIALED_URLS {
        for (field, page) in [
            (
                "final URL",
                RenderedPage {
                    markdown: LADDER_MARKDOWN.to_string(),
                    title: "Credentialed final".to_string(),
                    canonical_url: "https://example.test/page".to_string(),
                    final_url: raw.to_string(),
                    discovered_links: Vec::new(),
                },
            ),
            (
                "canonical URL",
                RenderedPage {
                    markdown: LADDER_MARKDOWN.to_string(),
                    title: "Credentialed canonical".to_string(),
                    canonical_url: raw.to_string(),
                    final_url: "https://example.test/page".to_string(),
                    discovered_links: Vec::new(),
                },
            ),
        ] {
            let error = WebFetcher::new(rung(&scripted(
                &call_log(),
                RendererKind::Readability,
                Ok(page),
            )))
            .expect("readability slot")
            .with_minimum_content(ladder_minimum())
            .fetch("https://example.test/page", 5)
            .expect_err("a credentialed renderer identity is not usable");
            let WebFetchError::AllRenderersFailed { attempts, .. } = error else {
                panic!("expected the ordered ladder trace");
            };
            let rendered = attempts
                .iter()
                .map(RendererAttemptFailure::render_reason)
                .collect::<Vec<String>>()
                .join("; ");
            assert_no_userinfo(&rendered, "the rendered ladder trace");
            assert!(
                rendered.contains(field) && rendered.contains(sanitized),
                "the {field} is redacted, not dropped, for {raw:?}: {rendered}"
            );
        }
    }
}

#[test]
fn a_credentialed_provider_identity_and_crawl_reason_stay_sanitized() {
    // JSON carries no raw tab or newline, so the no-slash spelling is the one a
    // hostile envelope actually reaches this boundary with.
    let base = spawn_fixture_server(|_request| {
        http_response(
            "200 OK",
            "application/json",
            r##"{"success":true,"data":{"markdown":"# Envelope\n\nA body comfortably past any configured extraction floor.","metadata":{"url":"http:agent:s3cr3t@example.test/page","statusCode":200}}}"##,
        )
    });
    let error = FirecrawlRenderer::new(
        reqwest::blocking::Client::new(),
        &format!("{base}/v1/scrape"),
    )
    .expect("endpoint")
    .render("https://example.test/page")
    .expect_err("a credentialed provider final URL is not a usable identity");
    assert_eq!(error.kind, RendererErrorKind::InvalidResponse);
    assert_no_userinfo(&error.message, "the firecrawl final URL rejection");
    assert!(
        error.message.contains("http://REDACTED@example.test/page"),
        "the provider identity is redacted, not dropped: {}",
        error.message
    );

    // A stored crawl reason is a public string too.
    let pages = vec![
        (
            "https://reason.test/".to_string(),
            RenderedPage {
                markdown: "markdown body for the seed page".to_string(),
                title: "seed".to_string(),
                canonical_url: "https://reason.test/".to_string(),
                final_url: "https://reason.test/".to_string(),
                discovered_links: vec!["https://reason.test/leaky".to_string()],
            },
        ),
        (
            "https://reason.test/leaky".to_string(),
            RenderedPage {
                markdown: "markdown body for the leaky page".to_string(),
                title: "leaky".to_string(),
                canonical_url: "https://reason.test/leaky".to_string(),
                final_url: "http:agent:s3cr3t@reason.test/page".to_string(),
                discovered_links: Vec::new(),
            },
        ),
    ];
    let (_site, fetcher) = fixture_site(&pages);
    let result = fetcher
        .crawl(CrawlRequest::same_site(
            "https://reason.test/",
            4,
            budget(4),
        ))
        .expect("the walk survives a page whose identity is unusable");

    assert_eq!(result.failed.len(), 1);
    assert_eq!(result.failed[0].url, "https://reason.test/leaky");
    assert_no_userinfo(&result.failed[0].reason, "the stored crawl reason");
    assert!(
        result.failed[0]
            .reason
            .contains("http://REDACTED@reason.test/page"),
        "the crawl reason redacts rather than drops: {}",
        result.failed[0].reason
    );
}

// ---------------------------------------------------------------------------
// Bounded decoding
// ---------------------------------------------------------------------------

/// The served article with a caller-chosen title and marker word, so one
/// decoded byte is observable in both the extracted title and the Markdown.
fn charset_article_html(title: &str, marker: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <title>{title}</title>
</head>
<body>
  <article>
    <h1>{title}</h1>
    <p>The marker word is {marker}, and it has to survive decoding intact.</p>
    {ARTICLE_BODY}
  </article>
</body>
</html>"##
    )
}

/// Encodes ASCII plus U+00A0..U+00FF as one byte each. windows-1252 agrees with
/// ISO-8859-1 over exactly that range, so this is a real windows-1252 fixture
/// rather than a second codec table living in the tests.
fn windows_1252_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|character| {
            let code = u32::from(character);
            assert!(
                character.is_ascii() || (0xA0..=0xFF).contains(&code),
                "fixture character {character:?} is not one windows-1252 byte"
            );
            u8::try_from(code).expect("the encodable range is asserted above")
        })
        .collect()
}

#[test]
fn a_bounded_native_read_honors_declared_charset_and_bom_and_fails_closed() {
    let html = charset_article_html("Café Fixture", "café");
    let declared_latin = windows_1252_bytes(&html);
    let malformed = windows_1252_bytes(&html);
    let utf8 = html.as_bytes().to_vec();
    let utf8_with_bom = {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(html.as_bytes());
        bytes
    };

    let base = spawn_byte_fixture_server(move |request| match request_path(request).as_str() {
        "/windows-1252" => {
            http_response_bytes("200 OK", "text/html; charset=windows-1252", &declared_latin)
        }
        // UTF-8 bytes behind a BOM, under a header that says otherwise.
        "/bom" => http_response_bytes("200 OK", "text/html; charset=windows-1252", &utf8_with_bom),
        "/undeclared" => http_response_bytes("200 OK", "text/html", &utf8),
        // A standards-valid header whose quoted `note` value contains both a
        // `;` and a decoy `charset=windows-1252`. The only real parameter is
        // the top-level `charset=utf-8` that follows it.
        "/quoted-decoy" => http_response_bytes(
            "200 OK",
            r#"text/html; note="x;charset=windows-1252"; charset=utf-8"#,
            &utf8,
        ),
        "/unknown" => http_response_bytes("200 OK", "text/html; charset=no-such-charset", &utf8),
        // windows-1252 bytes wearing a UTF-8 label: not decodable, not lossy.
        "/malformed" => http_response_bytes("200 OK", "text/html; charset=utf-8", &malformed),
        _ => http_response_bytes("404 Not Found", "text/plain", b"missing"),
    });

    let renderer = NativeReadabilityRenderer::new(reqwest::blocking::Client::new());

    let latin = renderer
        .render(&format!("{base}/windows-1252"))
        .expect("a declared legacy charset decodes");
    assert!(
        latin.title.contains("Café"),
        "the declared charset drives decoding, not UTF-8 with replacement: {:?}",
        latin.title
    );
    assert!(latin.markdown.contains("café"));
    assert!(
        !latin.markdown.contains('\u{FFFD}') && !latin.title.contains('\u{FFFD}'),
        "no replacement character stands in for a byte the peer really sent"
    );

    let bom = renderer
        .render(&format!("{base}/bom"))
        .expect("a BOM decodes");
    assert!(
        bom.title.contains("Café"),
        "the BOM outranks the header's charset: {:?}",
        bom.title
    );
    assert!(
        !bom.markdown.contains("Ã©") && !bom.markdown.contains('\u{FEFF}'),
        "the declared charset did not win over the BOM, and the BOM is consumed"
    );

    let undeclared = renderer
        .render(&format!("{base}/undeclared"))
        .expect("an undeclared charset defaults to UTF-8");
    assert!(undeclared.title.contains("Café"));

    let unknown = renderer
        .render(&format!("{base}/unknown"))
        .expect_err("an unsupported declared charset fails the rung closed");
    assert_eq!(unknown.kind, RendererErrorKind::InvalidResponse);
    assert!(
        unknown.message.contains("no-such-charset"),
        "the refusal names the label it could not honor: {}",
        unknown.message
    );

    let broken = renderer
        .render(&format!("{base}/malformed"))
        .expect_err("a malformed byte sequence fails the rung closed");
    assert_eq!(broken.kind, RendererErrorKind::InvalidResponse);
    assert!(
        broken.message.contains("UTF-8"),
        "the refusal names the encoding it applied: {}",
        broken.message
    );

    // A `;` inside a quoted parameter value is not a parameter boundary, so
    // the decoy `charset=windows-1252` inside `note` never becomes the
    // declared charset. windows-1252 accepts every byte, so honoring the decoy
    // would silently mojibake the UTF-8 bytes instead of failing closed.
    let decoy = renderer
        .render(&format!("{base}/quoted-decoy"))
        .expect("the real top-level charset parameter decodes");
    assert!(
        decoy.title.contains("Café") && decoy.markdown.contains("café"),
        "the top-level charset=utf-8 drives decoding, not the quoted decoy: {:?}",
        decoy.title
    );
    assert!(
        !decoy.title.contains("CafÃ©") && !decoy.markdown.contains("Ã©"),
        "the decoy charset inside the quoted value was honored and corrupted the text"
    );

    // The streaming ceiling still runs first, and still fails closed.
    let capped = renderer
        .with_max_response_bytes(NonZeroUsize::new(64).expect("non-zero ceiling"))
        .render(&format!("{base}/windows-1252"))
        .expect_err("the byte ceiling is enforced before anything is decoded");
    assert_eq!(capped.kind, RendererErrorKind::InvalidResponse);
    assert!(
        capped.message.contains("64") && capped.message.contains("ceiling"),
        "the refusal names the ceiling it enforced: {}",
        capped.message
    );
}

// ---------------------------------------------------------------------------
// Custom renderer link normalization
// ---------------------------------------------------------------------------

/// One custom rung's link set: unsorted, duplicated, relative and absolute,
/// fragmented, non-HTTP(S), credentialed, and off-site.
const CUSTOM_RUNG_RAW_LINKS: [&str; 10] = [
    "https://links.test/gamma",
    "/gamma",
    "beta",
    "https://links.test/beta#section",
    "../alpha",
    "/alpha",
    "mailto:someone@links.test",
    "javascript:void(0)",
    CREDENTIALED_URL,
    "https://other.test/z",
];

fn custom_rung_links() -> Vec<String> {
    CUSTOM_RUNG_RAW_LINKS
        .iter()
        .copied()
        .map(String::from)
        .collect()
}

#[test]
fn a_custom_rung_link_set_is_normalized_sorted_and_order_independent() {
    // The successful-rung boundary itself: a public custom `Renderer` gets the
    // same central normalization the built-in rungs get.
    let renderer = scripted(
        &call_log(),
        RendererKind::Readability,
        Ok(RenderedPage {
            markdown: LADDER_MARKDOWN.to_string(),
            title: "Custom".to_string(),
            canonical_url: "https://links.test/".to_string(),
            final_url: "https://links.test/".to_string(),
            discovered_links: custom_rung_links(),
        }),
    );
    let fetcher = WebFetcher::new(rung(&renderer))
        .expect("readability slot")
        .with_minimum_content(ladder_minimum());
    let (_page, links, final_url) = fetcher
        .try_rung(
            RendererKind::Readability,
            renderer.as_ref(),
            "https://links.test/",
            7,
        )
        .expect("the custom rung succeeds");
    assert_eq!(
        links,
        vec![
            "https://links.test/alpha".to_string(),
            "https://links.test/beta".to_string(),
            "https://links.test/gamma".to_string(),
            "https://other.test/z".to_string(),
        ],
        "relative links resolve against the final URL, and the set is \
         HTTP(S)-only, fragment-free, sorted and deduplicated"
    );
    assert_eq!(final_url.as_str(), "https://links.test/");

    // Renderer order therefore carries no budget semantics: the same link set
    // in any order walks the same pages and leaves the same frontier.
    let mut observed: Vec<(Vec<String>, CrawlCompletion)> = Vec::new();
    for permute in [0_usize, 1, 2] {
        let mut permuted = custom_rung_links();
        match permute {
            0 => {}
            1 => permuted.reverse(),
            _ => permuted.rotate_left(3),
        }
        let pages = vec![
            (
                "https://links.test/".to_string(),
                RenderedPage {
                    markdown: "markdown body for the seed page".to_string(),
                    title: "seed".to_string(),
                    canonical_url: "https://links.test/".to_string(),
                    final_url: "https://links.test/".to_string(),
                    discovered_links: permuted,
                },
            ),
            page_entry("https://links.test/alpha", "https://links.test/alpha", &[]),
        ];
        let (site, fetcher) = fixture_site(&pages);
        let result = fetcher
            .crawl(CrawlRequest::same_site(
                "https://links.test/",
                31,
                budget(2),
            ))
            .expect("a budgeted walk over a custom rung's links");
        observed.push((site.attempts(), result.completion));
    }

    assert_eq!(
        observed[0].0,
        vec![
            "https://links.test/".to_string(),
            "https://links.test/alpha".to_string(),
        ],
        "the frontier is walked in normalized bytewise order, not renderer order"
    );
    assert_eq!(
        observed[0].1,
        CrawlCompletion::BudgetExhausted {
            unvisited_urls: vec![
                "https://links.test/beta".to_string(),
                "https://links.test/gamma".to_string(),
            ],
        },
        "the whole remaining frontier is reported, relative spellings included"
    );
    for permuted in &observed[1..] {
        assert_eq!(
            *permuted, observed[0],
            "a permutation of the same link set cannot change the walk"
        );
    }
}
