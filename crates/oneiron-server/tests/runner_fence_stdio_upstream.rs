//! A stdio connector's upstream door (row L8-27, B2; RULING
//! L8-27-B2-STDIO = A): an `mcp_stdio` connector that names an `upstream`
//! API calls it through this server's loopback door. The child's
//! environment holds the door's URL and a reference to the door, never the
//! credential; the door adds the header its call presents, for that call's
//! span alone, and clears the presented value from what the upstream
//! answers. A request with another reference, under another connector's
//! name, outside a call or after the child stopped is refused; a request
//! whose call ends before its body is read is aborted and never sent; an
//! answer still in a content coding is refused, and the codings the child
//! asks for never pass; a call that presents nothing reaches the upstream
//! with no credential; a connector that names an upstream is not started
//! without a door origin; the upstream is part of the connector's endpoint,
//! and only a bare origin is taken.
//!
//! The child is a Python stand-in that calls its upstream with urllib, or
//! with a raw socket for a request it finishes in a later call. The
//! upstream is a stand-in HTTP server on loopback that records each request
//! and then answers it with the `Authorization` it got, in its body and in
//! `x-echo` (under `/encoded`, in a coding no client decodes). The door is
//! served on loopback by the API's own router. Run the tests with
//! `--test-threads=1`.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use oneiron::secret_custody::SentValue;
use oneiron_server::config::ConnectorHostConfig;
use oneiron_server::connector_call_host::stdio::upstream::{
    UPSTREAM_DOOR_PATH, UPSTREAM_REFERENCE_PREFIX, UpstreamHeld, upstream_door_routes,
};
use oneiron_server::connector_call_host::stdio::{
    ConnectorStdioRegistry, StdioDelivery, StdioToolCall,
};
use oneiron_server::runtime::runner_fence::HostRunnerFence;
use reqwest::header::HeaderValue;
use serde_json::{Value, json};

/// The revision the tests pin.
const REVISION: &str = "2025-11-25";

/// The credential the call presents: only the upstream may see it.
const SECRET: &str = "owen-issues-token-v1";

/// The text each copy of it becomes in what the child is given.
const CLEARED: &str = "[issues token]";

/// An MCP stdio server: `tools/call fetch` sends `GET` to its upstream's
/// base URL plus `path`, with `Authorization: Bearer` and its key (or
/// `token`, when the call names one) and `Accept-Encoding: accept` when the
/// call names one, and says the status, the body and `x-echo` it got back,
/// and its whole environment. With `slow: "begin"` it sends a `POST`'s head
/// and half its body and keeps the rest; with `slow: "end"`, in a later
/// call, it says what the door answered, sending the rest of the body first
/// only when the door had said nothing within 3 s.
const STAND_IN: &str = r#"import json, os, socket, sys, time, urllib.error, urllib.parse, urllib.request

slow = None

def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()

def read():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    return json.loads(line)

def fetch(arguments):
    url = os.environ.get("PROBE_API_URL", "") + arguments["path"]
    token = arguments.get("token", os.environ.get("PROBE_API_TOKEN", ""))
    headers = {"Authorization": "Bearer " + token}
    if "accept" in arguments:
        headers["Accept-Encoding"] = arguments["accept"]
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=20) as answer:
            status, body, echo = answer.status, answer.read().decode(), answer.headers.get("x-echo", "")
    except urllib.error.HTTPError as error:
        status, body, echo = error.code, error.read().decode(), error.headers.get("x-echo", "")
    except Exception as error:
        status, body, echo = 0, repr(error), ""
    return {"status": status, "body": body, "echo": echo, "env": dict(os.environ)}

def begin_slow(arguments):
    global slow
    base = urllib.parse.urlsplit(os.environ.get("PROBE_API_URL", ""))
    slow = socket.create_connection((base.hostname, base.port), timeout=20)
    head = ("POST " + base.path + arguments["path"] + " HTTP/1.1\r\nHost: " + base.netloc
            + "\r\nAuthorization: Bearer " + os.environ.get("PROBE_API_TOKEN", "")
            + "\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhalf.")
    slow.sendall(head.encode())
    time.sleep(1)
    return {"begun": True}

def end_slow():
    slow.settimeout(3)
    try:
        answer = slow.recv(65536)
    except socket.timeout:
        slow.sendall(b"rest.")
        slow.settimeout(20)
        answer = slow.recv(65536)
    return {"answer": answer.decode(errors="replace")}

while True:
    message = read()
    method = message.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": message["id"], "result": {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "issues", "version": "1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": message["id"], "result": {
            "tools": [{"name": "fetch", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        arguments = message["params"].get("arguments", {})
        if arguments.get("slow") == "begin":
            said = begin_slow(arguments)
        elif arguments.get("slow") == "end":
            said = end_slow()
        else:
            said = fetch(arguments)
        send({"jsonrpc": "2.0", "id": message["id"], "result": {
            "content": [{"type": "text", "text": "fetched"}],
            "structuredContent": said}})
"#;

/// A vault directory and the key custody directory beside it (what the
/// fence is built for), and beside them the stand-in.
struct Layout {
    _root: tempfile::TempDir,
    vault: PathBuf,
    stand_in: PathBuf,
}

fn layout() -> Layout {
    let root = tempfile::tempdir().expect("temp root");
    let vault = root.path().join("vault");
    let custody = oneiron::store::custody_container_path(&vault).expect("custody path");
    let beside = root.path().join("beside");
    for dir in [&vault, &custody, &beside] {
        fs::create_dir_all(dir).expect("layout directory");
    }
    let stand_in = beside.join("issues_server.py");
    fs::write(&stand_in, STAND_IN).expect("stand-in");
    Layout {
        _root: root,
        vault,
        stand_in,
    }
}

/// The `[connectors.issues]` section that starts the stand-in, calling the
/// upstream at `origin` when one is named.
fn section(stand_in: &Path, origin: Option<&str>) -> ConnectorHostConfig {
    let mut text = format!(
        "transport = \"mcp_stdio\"\ncommand = [\"python3\", {:?}]\n",
        stand_in.display().to_string(),
    );
    if let Some(origin) = origin {
        text.push_str(&format!(
            "upstream = {{ origin = {origin:?}, base_url_env = \"PROBE_API_URL\", token_env = \
             \"PROBE_API_TOKEN\" }}\n"
        ));
    }
    let connector: ConnectorHostConfig = toml::from_str(&text).expect("the section parses");
    connector.validate("issues").expect("the section is valid");
    connector
}

/// One request the upstream stand-in got.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    authorization: Option<String>,
    api_key: Option<String>,
    accept_encoding: Option<String>,
}

/// The upstream stand-in on loopback: its origin, and the requests it got.
fn upstream() -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("upstream listener");
    let origin = format!(
        "http://{}",
        listener.local_addr().expect("upstream address")
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let _ = answer(stream, &kept);
        }
    });
    (origin, seen)
}

/// Reads one request, records it in `seen`, and only then answers it 200,
/// so a test that reads `seen` once the child has its answer finds it: the
/// `Authorization` it got in a JSON body and in `x-echo`, the body reversed
/// and named `Content-Encoding: x-reversed` under `/encoded`.
fn answer(mut stream: TcpStream, seen: &Mutex<Vec<Seen>>) -> Option<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut words = line.split_whitespace();
    let method = words.next()?.to_owned();
    let target = words.next()?.to_owned();
    let (mut authorization, mut api_key, mut accept_encoding, mut length) =
        (None, None, None, 0_usize);
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        let value = value.trim().to_owned();
        match name.to_ascii_lowercase().as_str() {
            "authorization" => authorization = Some(value),
            "x-api-key" => api_key = Some(value),
            "accept-encoding" => accept_encoding = Some(value),
            "content-length" => length = value.parse().ok()?,
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    let echo = authorization.clone().unwrap_or_default();
    let mut reply = json!({ "authorization": echo, "target": target }).to_string();
    let mut coding = String::new();
    if target.starts_with("/encoded") {
        reply = reply.chars().rev().collect();
        coding.push_str("Content-Encoding: x-reversed\r\n");
    }
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Seen {
            method,
            target,
            authorization,
            api_key,
            accept_encoding,
        });
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{coding}X-Echo: {echo}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    )
    .ok()?;
    stream.flush().ok()
}

/// The upstream doors of `registry`, served on loopback by the API's own
/// door router: their origin, and the runtime that serves them.
fn door(registry: &ConnectorStdioRegistry) -> (String, tokio::runtime::Runtime) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("door runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("door listener");
    let origin = format!("http://{}", listener.local_addr().expect("door address"));
    let app = upstream_door_routes::<()>(Arc::clone(registry.upstream_doors()));
    runtime.spawn(async move {
        let served = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        );
        drop(served.await);
    });
    (origin, runtime)
}

/// What the call presents: the header built from [`SECRET`], and the value
/// to clear.
fn held() -> UpstreamHeld {
    let mut auth = HeaderValue::from_str(&format!("Bearer {SECRET}")).expect("a header value");
    auth.set_sensitive(true);
    UpstreamHeld::new(
        Some(auth),
        Some(SentValue::new(SECRET.as_bytes(), CLEARED).keep()),
        None,
    )
}

/// One `tools/call fetch` through `registry`: what the stand-in said, or
/// `None` when no child took the call.
fn fetch(
    registry: &ConnectorStdioRegistry,
    connector: &ConnectorHostConfig,
    fence: &HostRunnerFence,
    door_origin: Option<&str>,
    held: UpstreamHeld,
    arguments: Value,
) -> Option<Value> {
    let outcome = registry.call_tool(StdioToolCall {
        name: "issues",
        connector,
        fence: Some(fence),
        revision: REVISION,
        tool: "fetch",
        arguments,
        door_origin,
        held,
    });
    match outcome.delivery {
        StdioDelivery::Answered { message, .. } => {
            Some(message["result"]["structuredContent"].clone())
        }
        StdioDelivery::NotSent => None,
        StdioDelivery::NoAnswer => panic!("the stand-in gave no answer"),
        StdioDelivery::Held { reason } => panic!("the call was held: {reason}"),
    }
}

/// A client of the door from this device, as another local process is.
fn local_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .expect("a local client")
}

#[test]
fn a_stdio_childs_upstream_request_carries_the_held_credential_which_the_child_never_holds() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    eprintln!(
        "runner_fence_stdio_upstream: mechanism {:?}",
        fence.outcome().mechanism
    );
    let (upstream_origin, seen) = upstream();
    let registry = ConnectorStdioRegistry::default();
    let (door_origin, _runtime) = door(&registry);
    let connector = section(&layout.stand_in, Some(&upstream_origin));
    let said = fetch(
        &registry,
        &connector,
        &fence,
        Some(&door_origin),
        held(),
        json!({ "path": "/repos/owen/notes?state=open" }),
    )
    .expect("the call was sent (is python3 on PATH?)");
    eprintln!("runner_fence_stdio_upstream: the stand-in said: {said}");
    assert_eq!(said["status"], 200, "{said}");
    // The upstream got the held credential once, on the child's method,
    // path and query, and no reference.
    let seen = seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].target, "/repos/owen/notes?state=open");
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Bearer {SECRET}").as_str())
    );
    assert_eq!(seen[0].api_key, None);
    // What came back to the child is cleared of it: the body, and the
    // header that echoed it.
    for part in ["body", "echo"] {
        let text = said[part].as_str().expect("a text part");
        assert!(
            !text.contains(SECRET) && text.contains(CLEARED),
            "{part} is not cleared: {text}"
        );
    }
    // The child's environment holds its door and a reference to it, never
    // the credential.
    let env = said["env"].as_object().expect("the child's environment");
    assert_eq!(
        env["PROBE_API_URL"],
        format!("{door_origin}{UPSTREAM_DOOR_PATH}/issues")
    );
    assert!(
        env["PROBE_API_TOKEN"]
            .as_str()
            .is_some_and(|reference| reference.starts_with(UPSTREAM_REFERENCE_PREFIX)),
        "{env:?}"
    );
    for (name, value) in env {
        assert!(
            !value.as_str().unwrap_or_default().contains(SECRET),
            "{name} holds the credential"
        );
    }
    registry.stop();
}

#[test]
fn a_door_request_with_another_reference_or_outside_a_call_is_refused() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let (upstream_origin, seen) = upstream();
    let registry = ConnectorStdioRegistry::default();
    let (door_origin, _runtime) = door(&registry);
    let connector = section(&layout.stand_in, Some(&upstream_origin));
    let other = format!("{UPSTREAM_REFERENCE_PREFIX}{}", "0".repeat(64));
    let said = fetch(
        &registry,
        &connector,
        &fence,
        Some(&door_origin),
        held(),
        json!({ "path": "/repos/owen/notes", "token": other }),
    )
    .expect("the call was sent (is python3 on PATH?)");
    assert_eq!(said["status"], 401, "{said}");
    let reference = said["env"]["PROBE_API_TOKEN"]
        .as_str()
        .expect("the child's reference")
        .to_owned();
    let client = local_client();
    let url = format!("{door_origin}{UPSTREAM_DOOR_PATH}/issues/repos/owen/notes");
    let status = |url: &str| {
        client
            .get(url)
            .bearer_auth(&reference)
            .send()
            .expect("the door answers")
            .status()
            .as_u16()
    };
    // Between calls the child's door holds nothing.
    assert_eq!(status(&url), 409);
    // Under another connector's name the reference opens nothing.
    assert_eq!(
        status(&format!("{door_origin}{UPSTREAM_DOOR_PATH}/notes/repos")),
        401
    );
    // Once the child is stopped, its reference opens nothing.
    registry.stop();
    assert_eq!(status(&url), 401);
    assert!(
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty(),
        "a refused request reached the upstream"
    );
}

#[test]
fn a_door_request_whose_call_ends_before_its_body_is_read_is_aborted_and_never_sent() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let (upstream_origin, seen) = upstream();
    let registry = ConnectorStdioRegistry::default();
    let (door_origin, _runtime) = door(&registry);
    let connector = section(&layout.stand_in, Some(&upstream_origin));
    // The child begins a request inside one call, and holds back half its
    // body until the next.
    let begun = fetch(
        &registry,
        &connector,
        &fence,
        Some(&door_origin),
        held(),
        json!({ "slow": "begin", "path": "/repos/owen/notes" }),
    )
    .expect("the call was sent (is python3 on PATH?)");
    assert_eq!(begun["begun"], true, "{begun}");
    let ended = fetch(
        &registry,
        &connector,
        &fence,
        Some(&door_origin),
        held(),
        json!({ "slow": "end" }),
    )
    .expect("the second call was sent");
    let answer = ended["answer"].as_str().expect("the door's answer");
    eprintln!("runner_fence_stdio_upstream: the door answered the late request: {answer:?}");
    // The first call's end aborted the request: the door refused it before
    // the rest of its body came, and it never reached the upstream.
    assert!(answer.starts_with("HTTP/1.1 409"), "{answer}");
    assert!(
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty(),
        "a request whose call had ended reached the upstream"
    );
    registry.stop();
}

#[test]
fn an_upstream_answer_still_in_a_content_coding_is_refused_and_the_childs_codings_never_pass() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let (upstream_origin, seen) = upstream();
    let registry = ConnectorStdioRegistry::default();
    let (door_origin, _runtime) = door(&registry);
    let connector = section(&layout.stand_in, Some(&upstream_origin));
    let said = fetch(
        &registry,
        &connector,
        &fence,
        Some(&door_origin),
        held(),
        json!({ "path": "/encoded/notes", "accept": "x-reversed" }),
    )
    .expect("the call was sent (is python3 on PATH?)");
    // The reversed body holds the credential where no clearing reads it:
    // the door gives none of it back.
    assert_eq!(said["status"], 502, "{said}");
    let body = said["body"].as_str().expect("a text body");
    let reversed: String = SECRET.chars().rev().collect();
    assert!(!body.contains(&reversed), "{body}");
    let seen = seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_ne!(
        seen[0].accept_encoding.as_deref(),
        Some("x-reversed"),
        "the child's codings reached the upstream"
    );
    registry.stop();
}

#[test]
fn a_call_that_presents_nothing_reaches_the_upstream_with_no_credential() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let (upstream_origin, seen) = upstream();
    let registry = ConnectorStdioRegistry::default();
    let (door_origin, _runtime) = door(&registry);
    let connector = section(&layout.stand_in, Some(&upstream_origin));
    let said = fetch(
        &registry,
        &connector,
        &fence,
        Some(&door_origin),
        UpstreamHeld::default(),
        json!({ "path": "/public" }),
    )
    .expect("the call was sent (is python3 on PATH?)");
    assert_eq!(said["status"], 200, "{said}");
    let seen = seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].target, "/public");
    assert_eq!(seen[0].authorization, None, "the door sent a credential");
    registry.stop();
}

#[test]
fn a_stdio_connector_that_names_an_upstream_is_not_started_without_a_door_origin() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let registry = ConnectorStdioRegistry::default();
    let connector = section(&layout.stand_in, Some("http://127.0.0.1:9"));
    let said = fetch(
        &registry,
        &connector,
        &fence,
        None,
        held(),
        json!({ "path": "/" }),
    );
    assert!(said.is_none(), "a child with no door was started: {said:?}");
    registry.stop();
}

#[test]
fn a_stdio_connectors_upstream_is_part_of_its_endpoint_and_only_a_bare_origin_is_taken() {
    let parse = |extra: &str| -> ConnectorHostConfig {
        toml::from_str(&format!(
            "transport = \"mcp_stdio\"\ncommand = [\"issues-mcp\"]\n{extra}"
        ))
        .expect("the section parses")
    };
    let upstream = |origin: &str, base_url_env: &str, token_env: &str| {
        format!(
            "upstream = {{ origin = {origin:?}, base_url_env = {base_url_env:?}, token_env = \
             {token_env:?} }}\n"
        )
    };
    let named = |origin: &str| upstream(origin, "ISSUES_API_URL", "ISSUES_TOKEN");
    let bare = parse("");
    let first = parse(&named("https://api.example.com"));
    let moved = parse(&named("https://api.example.org"));
    for connector in [&bare, &first, &moved] {
        connector.validate("issues").expect("the section is valid");
    }
    let endpoints: BTreeSet<String> = [&bare, &first, &moved]
        .iter()
        .map(|connector| connector.installed_endpoint("issues"))
        .collect();
    assert_eq!(endpoints.len(), 3, "an upstream is part of the endpoint");
    for (extra, why) in [
        (named("https://api.example.com/v3"), "a path"),
        (named("https://api.example.com/?state=open"), "a query"),
        (named("http://api.example.com"), "http off loopback"),
        (named("https://owen:pw@api.example.com"), "credentials"),
        (
            upstream("https://api.example.com", "ISSUES", "ISSUES"),
            "one variable for both",
        ),
        (
            upstream("https://api.example.com", "PATH", "ISSUES_TOKEN"),
            "an inherited variable",
        ),
        (
            upstream("https://api.example.com", "ISSUES URL", "ISSUES_TOKEN"),
            "a variable name that cannot be set",
        ),
        (
            format!(
                "env = {{ ISSUES_API_URL = \"x\" }}\n{}",
                named("https://api.example.com")
            ),
            "a variable env sets",
        ),
    ] {
        assert!(
            parse(&extra).validate("issues").is_err(),
            "an upstream with {why} was taken"
        );
    }
    let http: ConnectorHostConfig = toml::from_str(&format!(
        "transport = \"mcp_http\"\nendpoint = \"https://mcp.example.com/mcp\"\n{}",
        named("https://api.example.com")
    ))
    .expect("the section parses");
    assert!(
        http.validate("issues").is_err(),
        "an mcp_http connector names no upstream"
    );
}
