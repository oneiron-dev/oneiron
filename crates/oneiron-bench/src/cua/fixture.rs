//! PRIVATE S1 lifecycle. This module never supplies the missing engine transport.
use super::{
    Result,
    config::Config,
    served::{Process, isolated},
    taskgen::{Cell, Plan},
    write_json,
};
use rand::RngCore;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    time::Instant,
};

pub(super) fn transport_ready(_config: &Config) -> Result<()> {
    // BrowserConfig::guest currently constructs fixture: None. A file fixture
    // is not S1's dynamic API. FIX 8061 belongs to the engine lane.
    Err("fixture_transport_unavailable".into())
}
pub(super) struct Fixture {
    process: Process,
    client: reqwest::Client,
    token: String,
    pub events: PathBuf,
}
impl Fixture {
    pub(crate) async fn start(plan: &Plan, dir: &Path, deadline: Instant) -> Result<Self> {
        // These binds are readiness checks, not a retry/start-another-server loop.
        for port in [8765, 8766] {
            let addr = if port == 8765 {
                "172.30.91.1"
            } else {
                "127.0.0.1"
            };
            std::net::TcpListener::bind((addr, port))
                .map_err(|e| format!("fixture_listener_unavailable:{port}:{e}"))?;
        }
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let token_path = dir.join("private-token");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        options
            .open(&token_path)
            .map_err(|e| e.to_string())?
            .write_all(token.as_bytes())
            .map_err(|e| e.to_string())?;
        let events = dir.join("events.jsonl");
        let mut command = isolated(Path::new("python3"));
        command
            .arg("-I")
            .arg(plan.fixture_root.join("state_server.py"))
            .args(["--public-host", "172.30.91.1", "--event-log"])
            .arg(&events)
            .arg("--token-file")
            .arg(&token_path)
            .stdout(Stdio::piped())
            .stderr(fs::File::create(dir.join("fixture.stderr")).map_err(|e| e.to_string())?);
        let mut process = Process::spawn(command)?;
        let mut lines = BufReader::new(
            process
                .child()
                .stdout
                .take()
                .ok_or("fixture_stdout_missing")?,
        )
        .lines();
        let banner = tokio::time::timeout_at(deadline, lines.next_line())
            .await
            .map_err(|_| "fixture_startup_timeout")?
            .map_err(|e| e.to_string())?
            .ok_or("fixture_startup_eof")?;
        let startup: Value = serde_json::from_str(&banner).map_err(|e| e.to_string())?;
        if startup["private"] != json!(["127.0.0.1", 8766])
            || startup["public"] != json!(["172.30.91.1", 8765])
        {
            return Err("fixture_listener_identity_mismatch".into());
        }
        write_json(&dir.join("fixture-startup.json"), &startup)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        let fixture = Self {
            process,
            client,
            token,
            events,
        };
        let health = fixture.request("/health", None, deadline).await?;
        if health["ok"] != true {
            return Err("fixture_health_failed".into());
        }
        Ok(fixture)
    }
    async fn request(
        &self,
        path: &str,
        payload: Option<Value>,
        deadline: Instant,
    ) -> Result<Value> {
        let url = format!("http://127.0.0.1:8766{path}");
        let request = match payload {
            Some(body) => self.client.post(url).json(&body),
            None => self.client.get(url),
        };
        tokio::time::timeout_at(deadline, async {
            request
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|e| e.to_string())?
                .error_for_status()
                .map_err(|e| e.to_string())?
                .json()
                .await
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|_| "fixture_private_timeout".to_owned())?
    }
    pub(crate) async fn reset(&self, cell: &Cell, deadline: Instant) -> Result<Value> {
        self.request(
            "/reset",
            Some(json!({"fixture":cell.fixture,"version":cell.version,"seed":cell.seed})),
            deadline,
        )
        .await
    }
    pub(crate) async fn snapshot(&self, cell: &Cell, deadline: Instant) -> Result<Value> {
        self.request(&format!("/state/{}", cell.fixture), None, deadline)
            .await
    }
    pub(crate) async fn settle(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
    pub(crate) async fn stop(&mut self) -> Result<()> {
        self.process.stop().await
    }
}
