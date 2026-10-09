use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use serde_json::{Value, json};

use super::render::normalize_link_list;
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

impl ScriptedRenderer {}

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
        final_url: Some(final_url.to_string()),
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
            final_url: Some(final_url.to_string()),
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

fn fixture_url(raw: &str) -> Url {
    Url::parse(raw).expect("fixture URL")
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
    assert_eq!(round_tripped.markdown(), "# Heading\n\nBody.");
    assert_eq!(round_tripped.title(), "Title");
    assert_eq!(round_tripped.canonical_url(), "https://example.test/page");
    assert_eq!(round_tripped.fetched_at(), 1_700_000_000);
    assert_eq!(
        round_tripped.content_hash(),
        content_hash("# Heading\n\nBody.")
    );
    assert_eq!(round_tripped.renderer(), RendererKind::Readability);
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
            final_url: Some("https://first.test/page".to_string()),
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
            final_url: Some("https://second.test/page".to_string()),
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
// Native extraction and adapters
// ---------------------------------------------------------------------------

#[test]
fn firecrawl_adapter_maps_the_pinned_self_hosted_envelope() {
    let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let base = spawn_fixture_server(move |request| {
        sink.lock()
            .expect("recorded requests")
            .push(request.to_string());
        match request_path(request).as_str() {
            // A sourceURL-only deployment remains valid for single-page
            // acquisition, but that request/canonical echo is not final-URL
            // evidence for containment-sensitive crawling.
            "/v1/scrape" => http_response(
                "200 OK",
                "application/json",
                r##"{"success":true,"data":{"markdown":"# Firecrawl page\n\nBody text that clears the floor.","links":["https://example.test/next","https://example.test/next","mailto:x@example.test","/relative"],"metadata":{"title":"  Example  ","sourceURL":"https://example.test/page#frag","statusCode":200}}}"##,
            ),
            "/with-final" => http_response(
                "200 OK",
                "application/json",
                r##"{"success":true,"data":{"markdown":"# Landed page\n\nBody text that clears the floor.","links":["/relative"],"metadata":{"title":"Landed","sourceURL":"https://canonical.example/page#fragment","url":"https://landing.example/final#fragment","statusCode":200}}}"##,
            ),
            "/not-success" => http_response("200 OK", "application/json", r#"{"success":false}"#),
            "/no-data" => http_response("200 OK", "application/json", r#"{"success":true}"#),
            "/no-markdown" => http_response(
                "200 OK",
                "application/json",
                r#"{"success":true,"data":{"metadata":{"sourceURL":"https://example.test/page"}}}"#,
            ),
            "/no-final" => http_response(
                "200 OK",
                "application/json",
                r#"{"success":true,"data":{"markdown":"body","metadata":{"title":"No URL"}}}"#,
            ),
            "/bad-final" => http_response(
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
        page.final_url, None,
        "sourceURL is canonical identity, not redirect-final evidence"
    );
    assert_eq!(page.canonical_url, "https://example.test/page");
    assert_eq!(
        page.discovered_links,
        vec![
            "https://example.test/next".to_string(),
            "https://example.test/relative".to_string(),
        ],
        "links are normalized, filtered to HTTP(S), sorted and deduplicated, and \
         a relative link resolves against sourceURL"
    );

    let witnessed = FirecrawlRenderer::new(client.clone(), &format!("{base}/with-final"))
        .expect("endpoint")
        .render("https://request.example/page")
        .expect("envelope with distinct canonical and final identities");
    assert_eq!(
        witnessed.canonical_url, "https://canonical.example/page",
        "sourceURL remains Firecrawl's canonical field"
    );
    assert_eq!(
        witnessed.final_url,
        Some("https://landing.example/final".to_string()),
        "only the separate url field supplies navigation-final evidence"
    );
    assert_eq!(
        witnessed.discovered_links,
        vec!["https://landing.example/relative".to_string()],
        "relative links resolve against the independently reported landing"
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

    let crawl_error = WebFetcher::new(rung(&scripted(
        &call_log(),
        RendererKind::Readability,
        Err(RendererError::transport("blocked")),
    )))
    .expect("readability slot")
    .with_firecrawl(Arc::new(
        FirecrawlRenderer::new(
            reqwest::blocking::Client::new(),
            &format!("{base}/v1/scrape"),
        )
        .expect("endpoint"),
    ))
    .expect("firecrawl slot")
    .with_minimum_content(ladder_minimum())
    .crawl(CrawlRequest::same_site(
        "https://example.test/page",
        4,
        budget(1),
    ))
    .expect_err("a crawl cannot use a sourceURL request echo as final evidence");
    let WebFetchError::AllRenderersFailed { attempts, .. } = crawl_error else {
        panic!("unexpected crawl error: {crawl_error}");
    };
    assert!(
        attempts.iter().any(|attempt| matches!(
            attempt,
            RendererAttemptFailure::Error { error, .. }
                if error.message.contains("no independently witnessed navigation-final URL")
        )),
        "the Firecrawl rung fails explicitly: {attempts:?}"
    );
}

// ---------------------------------------------------------------------------
// Crawl
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ONE-1932 review regressions: the required-rung invariant, the featureless
// acceptance gates, the credential boundary, bounded bodies, central canonical
// validation, response-contract identity, the pinned root surface, and closed
// decoding.
// ---------------------------------------------------------------------------

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
            final_url: Some(CREDENTIALED_URL.to_string()),
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
        normalize_link_list([CREDENTIALED_URL], &fixture_url("https://example.test/"))
            .expect("one bounded link normalizes")
            .is_empty(),
        "a credentialed link is not walkable"
    );
}

#[test]
fn a_custom_rung_canonical_url_passes_the_same_central_validation() {
    let page_with = |canonical: &str| RenderedPage {
        markdown: LADDER_MARKDOWN.to_string(),
        title: "Custom".to_string(),
        canonical_url: canonical.to_string(),
        final_url: Some("https://example.test/final".to_string()),
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
                    final_url: Some(raw.to_string()),
                    discovered_links: Vec::new(),
                },
            ),
            (
                "canonical URL",
                RenderedPage {
                    markdown: LADDER_MARKDOWN.to_string(),
                    title: "Credentialed canonical".to_string(),
                    canonical_url: raw.to_string(),
                    final_url: Some("https://example.test/page".to_string()),
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
            r##"{"success":true,"data":{"markdown":"# Envelope\n\nA body comfortably past any configured extraction floor.","metadata":{"sourceURL":"http:agent:s3cr3t@example.test/page","statusCode":200}}}"##,
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
                final_url: Some("https://reason.test/".to_string()),
                discovered_links: vec!["https://reason.test/leaky".to_string()],
            },
        ),
        (
            "https://reason.test/leaky".to_string(),
            RenderedPage {
                markdown: "markdown body for the leaky page".to_string(),
                title: "leaky".to_string(),
                canonical_url: "https://reason.test/leaky".to_string(),
                final_url: Some("http:agent:s3cr3t@reason.test/page".to_string()),
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
// Redirect-introduced userinfo
// ---------------------------------------------------------------------------

/// The credential a hostile `Location` introduces *after* the requested URL has
/// already passed the pre-transport check, so no boundary in this module ever
/// admitted it. Both halves are distinctive literals, and neither is a substring
/// of any fixture path, so a leak into a diagnostic is unambiguous.
const REDIRECT_USERINFO_USERNAME: &str = "smuggleduser";
const REDIRECT_USERINFO_PASSWORD: &str = "smuggledpass";

fn assert_no_redirect_credential(haystack: &str, context: &str) {
    for fragment in [REDIRECT_USERINFO_USERNAME, REDIRECT_USERINFO_PASSWORD] {
        assert!(
            !haystack.contains(fragment),
            "{context} leaked `{fragment}`: {haystack:?}"
        );
    }
}

/// A seed page whose only link is the redirecting page, so a walk reaches that
/// redirect as an ordinary non-seed frontier page.
fn redirect_seed_html() -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Redirect Seed</title>
</head>
<body>
  <article>
    <h1>Redirect Seed</h1>
    {ARTICLE_BODY}
    <p><a href="hostile-redirect">the redirecting page</a></p>
  </article>
</body>
</html>"##
    )
}

#[test]
fn a_redirect_location_carrying_userinfo_never_reaches_a_public_diagnostic() {
    // The destination server exists only to be redirected *to*. It records what
    // it received — which is how this test knows the redirect was really
    // followed rather than never taken — and answers 500, so the `reqwest`
    // error is produced after redirect processing rather than before it.
    let reached: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&reached);
    let destination = spawn_fixture_server(move |request| {
        sink.lock()
            .expect("the redirect destination log")
            .push(request.to_string());
        http_response("500 Internal Server Error", "text/plain", "blocked")
    });
    let reached_count = || reached.lock().expect("the redirect destination log").len();
    let authority = destination
        .strip_prefix("http://")
        .expect("the fixture base is an http origin")
        .to_string();

    // The peer's own `Location`, carrying credentials no caller supplied.
    let credentialed_location = format!(
        "http://{REDIRECT_USERINFO_USERNAME}:{REDIRECT_USERINFO_PASSWORD}@{authority}/blocked"
    );
    let redacted_location = format!("http://{REDACTED_USERINFO}@{authority}/blocked");
    // A second `Location`, at a loopback port nothing is listening on, so the
    // *send* boundary fails after the redirect instead of the status boundary.
    let refused_location = format!(
        "http://{REDIRECT_USERINFO_USERNAME}:{REDIRECT_USERINFO_PASSWORD}@127.0.0.1:1/blocked"
    );

    let seed_html = redirect_seed_html();
    let origin = spawn_fixture_server(move |request| match request_path(request).as_str() {
        "/seed" => http_response("200 OK", "text/html; charset=utf-8", &seed_html),
        "/hostile-redirect" => http_redirect(&credentialed_location),
        "/refused-redirect" => http_redirect(&refused_location),
        _ => http_response("404 Not Found", "text/plain", "missing"),
    });
    let redirect_url = format!("{origin}/hostile-redirect");

    // 1. The direct native rung. The post-redirect status failure is still a
    //    transport failure, the smuggled credential is absent, and the
    //    destination is still reported — redacted rather than dropped.
    let renderer = NativeReadabilityRenderer::new(reqwest::blocking::Client::new());
    let status_error = renderer
        .render(&redirect_url)
        .expect_err("the redirected request fails at the destination");
    assert_eq!(status_error.kind, RendererErrorKind::Transport);
    assert_no_redirect_credential(&status_error.message, "the native GET status error");
    assert!(
        status_error.message.contains(&redacted_location),
        "the post-redirect destination is redacted, not dropped: {}",
        status_error.message
    );
    assert_eq!(
        reached_count(),
        1,
        "the redirect really was followed to the credentialed destination"
    );

    // 2. The send boundary, reached by redirecting onto a refused loopback port
    //    so the error is produced while connecting rather than after a status.
    let send_error = renderer
        .render(&format!("{origin}/refused-redirect"))
        .expect_err("the redirected request cannot connect");
    assert_eq!(send_error.kind, RendererErrorKind::Transport);
    assert_no_redirect_credential(&send_error.message, "the native GET send error");
    assert!(
        send_error.message.starts_with("web fetch GET failed: "),
        "the send failure is reported, not swallowed: {}",
        send_error.message
    );

    // 3. The same failure through the real ladder, with renderer identity and
    //    ladder order unchanged and the rendered attempt trace credential-safe.
    let native = NativeReadabilityRenderer::new(reqwest::blocking::Client::new());
    let rung: Arc<dyn Renderer> = Arc::new(native);
    let ladder_error = WebFetcher::new(Arc::clone(&rung))
        .expect("readability slot")
        .with_minimum_content(ladder_minimum())
        .fetch(&redirect_url, 17)
        .expect_err("no rung produced content");
    let WebFetchError::AllRenderersFailed { url, attempts } = ladder_error else {
        panic!("expected the ordered ladder trace");
    };
    // The aggregate failure names the checked request URL, never the peer's.
    assert_eq!(url, redirect_url);
    assert_no_redirect_credential(&url, "the aggregate failure URL");
    assert_eq!(
        attempts.len(),
        3,
        "the ladder still records every rung in its fixed order"
    );
    assert!(
        matches!(
            &attempts[0],
            RendererAttemptFailure::Error {
                renderer: RendererKind::Readability,
                error,
            } if error.kind == RendererErrorKind::Transport
        ),
        "rung 1 stays a typed readability transport failure: {:?}",
        attempts[0]
    );
    assert_eq!(
        attempts[1],
        RendererAttemptFailure::Unavailable {
            renderer: RendererKind::Headless
        }
    );
    assert_eq!(
        attempts[2],
        RendererAttemptFailure::Unavailable {
            renderer: RendererKind::Firecrawl
        }
    );
    let rendered = attempts
        .iter()
        .map(RendererAttemptFailure::render_reason)
        .collect::<Vec<String>>()
        .join("; ");
    assert_no_redirect_credential(&rendered, "the rendered ladder trace");
    assert!(
        rendered.starts_with("readability: Transport: "),
        "the trace keeps the typed rung failure: {rendered}"
    );
    assert!(
        rendered.contains(&redacted_location),
        "the trace keeps a redacted destination: {rendered}"
    );
    assert_eq!(
        reached_count(),
        2,
        "the ladder leg followed the same redirect route"
    );

    // 4. A non-seed crawl page driven through the same redirect. Its reason is
    //    a stored public string, so it is credential-safe as well.
    let crawled = WebFetcher::new(Arc::clone(&rung))
        .expect("readability slot")
        .with_minimum_content(ladder_minimum())
        .crawl(CrawlRequest::same_site(
            format!("{origin}/seed"),
            23,
            budget(4),
        ))
        .expect("the walk survives a page whose redirect fails");
    assert_eq!(
        canonical_urls(&crawled),
        vec![format!("{origin}/seed")],
        "the seed is the only page admitted"
    );
    assert_eq!(crawled.completion, CrawlCompletion::Complete);
    assert_eq!(crawled.failed.len(), 1);
    // The stored failure is the non-seed redirecting page, by requested identity.
    assert_eq!(crawled.failed[0].url, redirect_url);
    let reason = &crawled.failed[0].reason;
    assert_no_redirect_credential(reason, "the stored crawl reason");
    let stored_prefix = "all web fetch renderers failed: readability: Transport: ";
    assert!(
        reason.starts_with(stored_prefix),
        "the stored reason keeps the ordered ladder trace: {reason}"
    );
    assert!(
        reason.contains(&redacted_location),
        "the stored reason keeps a redacted destination: {reason}"
    );
    assert_eq!(
        reached_count(),
        3,
        "the crawl leg followed the same redirect route"
    );

    // Every leg traversed the redirect route itself: the destination server saw
    // the redirected request each time, so nothing passed by stopping short of
    // transport.
    let received = reached
        .lock()
        .expect("the redirect destination log")
        .clone();
    assert_eq!(received.len(), 3);
    for request in &received {
        assert_eq!(
            request_path(request),
            "/blocked",
            "the recorded request is the redirect destination"
        );
    }
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
// Decode-time content identity
// ---------------------------------------------------------------------------

fn is_lowercase_hex64(hex: &str) -> bool {
    let is_lower_hex = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    hex.len() == 64 && hex.bytes().all(is_lower_hex)
}

/// The genuine six-key encoding of one writer-produced result, checked to
/// round-trip unchanged before any test mutates a copy of it.
fn encoded_fetch_result() -> serde_json::Map<String, Value> {
    let log = call_log();
    let page = ladder_page(LADDER_MARKDOWN, "https://identity.test/page");
    let renderer = scripted(&log, RendererKind::Readability, Ok(page));
    let written = WebFetcher::new(rung(&renderer))
        .expect("readability slot")
        .with_minimum_content(ladder_minimum())
        .fetch("https://identity.test/page", 1_700_000_042)
        .expect("writer output");

    let encoded = serde_json::to_value(&written).expect("serialize writer output");
    let object = encoded.as_object().expect("a fetch result is an object");
    assert_eq!(object.len(), 6, "the writer still emits exactly six keys");
    let decoded = serde_json::from_value::<FetchResult>(encoded.clone());
    assert_eq!(
        decoded.expect("genuine writer output decodes"),
        written,
        "a genuinely produced result round-trips unchanged"
    );
    object.clone()
}

#[test]
fn fetch_result_decoding_rejects_a_stale_or_foreign_content_hash() {
    let object = encoded_fetch_result();

    // Each foreign identity is well shaped but covers different Markdown.
    for foreign in [
        content_hash("# Heading\n\nBody."),
        content_hash(HASH_FIXTURE_MARKDOWN),
        content_hash(&format!("{LADDER_MARKDOWN} ")),
    ] {
        assert!(
            is_lowercase_hex64(&foreign),
            "the stale fixture is itself well shaped: {foreign}",
        );
        let mut stale = object.clone();
        stale.insert("content_hash".to_string(), json!(foreign));
        let rejected = serde_json::from_value::<FetchResult>(Value::Object(stale));
        assert!(rejected.is_err(), "a stale identity must not rematerialize",);
    }
}

#[test]
fn fetch_result_decoding_rejects_a_malformed_content_hash() {
    let object = encoded_fetch_result();
    let written = object.get("content_hash").and_then(Value::as_str);
    let genuine = written
        .expect("the writer wrote a content hash")
        .to_string();
    assert_ne!(
        genuine.to_ascii_uppercase(),
        genuine,
        "the fixture identity carries at least one hex letter to re-case"
    );

    for candidate in [
        String::new(),
        "not-a-hash".to_string(),
        genuine.to_ascii_uppercase(),
        genuine[..63].to_string(),
        format!("{genuine}0"),
        format!("g{}", &genuine[1..]),
        format!("A{}", &genuine[1..]),
    ] {
        let mut payload = object.clone();
        payload.insert("content_hash".to_string(), json!(candidate));
        let decoded = serde_json::from_value::<FetchResult>(Value::Object(payload));
        assert!(
            decoded.is_err(),
            "a malformed content_hash must not decode: {candidate:?}"
        );
    }
}

#[test]
fn fetch_result_decoding_validates_and_normalizes_canonical_url() {
    let object = encoded_fetch_result();

    for invalid in [
        "/relative",
        "file:///tmp/page",
        "https://agent:s3cr3t@example.test/page",
    ] {
        let mut payload = object.clone();
        payload.insert("canonical_url".to_string(), json!(invalid));
        let reported = serde_json::from_value::<FetchResult>(Value::Object(payload))
            .expect_err("an identity the writer cannot produce must not rematerialize");
        let detail = reported.to_string();
        assert!(
            !detail.contains("agent") && !detail.contains("s3cr3t"),
            "decode diagnostics never repeat embedded credentials: {detail}",
        );
    }

    let mut normalized = object;
    normalized.insert(
        "canonical_url".to_string(),
        json!("HTTPS://EXAMPLE.TEST:443/a/../page#fragment"),
    );
    let decoded = serde_json::from_value::<FetchResult>(Value::Object(normalized))
        .expect("a valid web identity decodes");
    assert_eq!(decoded.canonical_url(), "https://example.test/page");
}

#[test]
fn fetch_result_decoding_keeps_the_field_doors_closed() {
    let object = encoded_fetch_result();

    let mut extended = object.clone();
    extended.insert("provider_debug".to_string(), json!("firecrawl-internal"));
    let decoded = serde_json::from_value::<FetchResult>(Value::Object(extended));
    assert!(
        decoded.is_err(),
        "the wire form still denies unknown fields"
    );

    for field in [
        "markdown",
        "title",
        "canonical_url",
        "fetched_at",
        "content_hash",
        "renderer",
    ] {
        let mut truncated = object.clone();
        truncated.remove(field);
        let decoded = serde_json::from_value::<FetchResult>(Value::Object(truncated));
        assert!(
            decoded.is_err(),
            "a missing {field} is a decode failure, never a default",
        );
    }

    // Recomputation refuses; it never substitutes. Rewriting the Markdown under
    // a genuine identity is a decode failure, not a quiet re-identification.
    let mut swapped = object;
    swapped.insert("markdown".to_string(), json!("rewritten body"));
    let decoded = serde_json::from_value::<FetchResult>(Value::Object(swapped));
    assert!(
        decoded.is_err(),
        "markdown rewritten under a genuine hash is refused, not re-hashed",
    );
}

// ---------------------------------------------------------------------------
// Peer-controlled link cardinality
// ---------------------------------------------------------------------------

#[test]
fn a_long_chain_is_bounded_by_live_frontier_not_historical_enqueues() {
    let frontier_ceiling = super::ladder::MAX_CRAWL_FRONTIER_URLS;
    let seed = fixture_url("https://chain.test/p/0");
    let mut walk = super::ladder::CrawlWalk::new(seed, frontier_ceiling + 2);
    let markdown = "markdown body for a one-link chain";
    let hash = content_hash(markdown);

    // Cross the old historical-enqueue ceiling while the live queue remains one
    // URL wide. Clearing admitted pages keeps this a frontier-state regression,
    // not a 65k-result allocation test.
    for index in 0..=frontier_ceiling {
        let current = walk
            .pop_frontier()
            .expect("the previous page left exactly one live successor");
        let requested = current.to_string();
        walk.visited.insert(requested.clone());
        let next = format!("https://chain.test/p/{}", index + 1);
        walk.absorb_success(
            requested.clone(),
            FetchResult {
                markdown: markdown.to_string(),
                title: String::new(),
                canonical_url: requested,
                fetched_at: 1_700_000_042,
                content_hash: hash.clone(),
                renderer: RendererKind::Readability,
            },
            &[next],
            &current,
            CrawlScope::SameSite,
        );
        assert!(
            walk.failed.is_empty(),
            "historical enqueue count cannot reject chain page {index}"
        );
        assert_eq!(
            walk.frontier.len(),
            1,
            "the live frontier remains exactly one URL wide at page {index}"
        );
        walk.pages.clear();
    }
}
