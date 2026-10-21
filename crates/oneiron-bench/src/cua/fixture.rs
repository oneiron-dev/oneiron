//! PRIVATE S1 lifecycle and the frozen PUBLIC-only served forward.
use std::{fs, path::{Path, PathBuf}, process::Stdio, time::Duration};
use rand::RngCore;
use serde_json::{Value, json};
use tokio::{io::{AsyncBufReadExt, BufReader}, time::Instant};
use super::{Result, served::{Process, isolated}, taskgen::{Cell, Plan}, write_json};

/// The frozen PUBLIC bind is also the only permitted forward target.
pub(super) fn forward_target(plan: &Plan, browser: &Value) -> Result<std::net::SocketAddrV4> {
    let unavailable = |piece: &str| format!("fixture_transport_unavailable:{piece}");
    let target = plan.fixture_public_bind.ok_or_else(|| unavailable("plan.fixture_public_bind_missing"))?;
    oneiron::code_sandbox::egress::FixtureForward::new(target)
        .map_err(|e| unavailable(&format!("plan.fixture_public_bind_invalid:{e}")))?;
    if target.port() == 8766 { return Err(unavailable("public_private_port_collision")) }
    let pin = browser["bench_fixture_forward"].as_str()
        .ok_or_else(|| unavailable("pins.browser.bench_fixture_forward_missing"))?;
    if pin.parse::<std::net::SocketAddrV4>().ok() != Some(target) {
        return Err(unavailable("pins_forward_public_bind_mismatch"));
    }
    Ok(target)
}
pub(super) fn transport_ready(plan: &Plan, browser: &Value, config: &Path) -> Result<()> {
    let target = forward_target(plan, browser)?;
    let text = fs::read_to_string(config)
        .map_err(|e| format!("fixture_transport_unavailable:served_config_missing:{e}"))?;
    // The writer emits a single scalar-only browser table. Check the written
    // table, not a caller's readiness assertion or the source pin alone.
    let mut in_browser = false;
    let mut forwards = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') { in_browser = line == "[browser]"; }
        if in_browser && let Some((key, value)) = line.split_once('=')
            && key.trim() == "bench_fixture_forward" {
            forwards.push(value.trim().to_owned());
        }
    }
    if forwards != [format!("\"{target}\"")] {
        return Err("fixture_transport_unavailable:served_config_forward_missing_or_mismatched".into());
    }
    Ok(())
}
pub(super) fn entry_url(reset: &Value) -> Result<String> {
    let entry = reset["entry"].as_str().ok_or("reset_entry_missing")?;
    if !entry.starts_with('/') || entry.starts_with("//") || entry.contains("..")
        || entry.contains(['\\', '?', '#', '%']) || entry.chars().any(char::is_control) {
        return Err("reset_entry_not_relative".into());
    }
    Ok(format!("http://127.0.0.1:8080{entry}"))
}
pub(super) fn task_packet(cell: &Cell, reset: &Value) -> Result<String> {
    Ok(cell.public_task.replace("{entry_url}", &entry_url(reset)?))
}
pub(super) struct Fixture {
    process: Process, client: reqwest::Client, token: String, pub(crate) events: PathBuf,
}
impl Fixture {
    pub(crate) async fn start(plan: &Plan, dir: &Path, deadline: Instant) -> Result<Self> {
        // These binds are readiness checks, not a retry/start-another-server loop.
        let public = plan.fixture_public_bind.ok_or("fixture_transport_unavailable:plan.fixture_public_bind_missing")?;
        oneiron::code_sandbox::egress::FixtureForward::new(public).map_err(|e| e.to_string())?;
        for address in [public, "127.0.0.1:8766".parse().map_err(|e| format!("private_bind_invalid:{e}"))?] {
            std::net::TcpListener::bind(address).map_err(|e| format!("fixture_listener_unavailable:{address}:{e}"))?;
        }
        let mut random = [0u8;32]; rand::rngs::OsRng.fill_bytes(&mut random);
        let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let token_path = dir.join("private-token");
        let mut options = fs::OpenOptions::new(); options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        use std::io::Write;
        options.open(&token_path).map_err(|e| e.to_string())?.write_all(token.as_bytes()).map_err(|e| e.to_string())?;
        let events = dir.join("events.jsonl");
        let mut command = isolated(Path::new("python3"));
        command.arg("-I").arg(plan.fixture_root.join("state_server.py"))
            .arg("--public-host").arg(public.ip().to_string()).arg("--public-port").arg(public.port().to_string())
            .arg("--event-log").arg(&events).arg("--token-file").arg(&token_path)
            .stdout(Stdio::piped()).stderr(fs::File::create(dir.join("fixture.stderr")).map_err(|e| e.to_string())?);
        let mut process = Process::spawn(command)?;
        let mut lines = BufReader::new(process.child().stdout.take().ok_or("fixture_stdout_missing")?).lines();
        let banner = tokio::time::timeout_at(deadline,lines.next_line()).await.map_err(|_| "fixture_startup_timeout")?
            .map_err(|e| e.to_string())?.ok_or("fixture_startup_eof")?;
        let startup: Value = serde_json::from_str(&banner).map_err(|e| e.to_string())?;
        if startup["private"] != json!(["127.0.0.1",8766]) || startup["public"] != json!([public.ip().to_string(),public.port()]) {
            return Err("fixture_listener_identity_mismatch".into());
        }
        write_json(&dir.join("fixture-startup.json"), &startup)?;
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())?;
        let fixture = Self {process,client,token,events};
        let health = fixture.request("/health", None, deadline).await?;
        if health["ok"] != true { return Err("fixture_health_failed".into()) }
        Ok(fixture)
    }
    async fn request(&self, path: &str, payload: Option<Value>, deadline: Instant) -> Result<Value> {
        let url = format!("http://127.0.0.1:8766{path}");
        let request = match payload { Some(body) => self.client.post(url).json(&body), None => self.client.get(url) };
        tokio::time::timeout_at(deadline,async {
            request.bearer_auth(&self.token).send().await.map_err(|e| e.to_string())?
                .error_for_status().map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())
        }).await.map_err(|_| "fixture_private_timeout".to_owned())?
    }
    pub(crate) async fn reset(&self, cell: &Cell, deadline: Instant) -> Result<Value> {
        self.request("/reset",Some(json!({"fixture":cell.fixture,"version":cell.version,"seed":cell.seed})),deadline).await
    }
    pub(crate) async fn snapshot(&self, cell: &Cell, deadline: Instant) -> Result<Value> {
        self.request(&format!("/state/{}",cell.fixture),None,deadline).await
    }
    pub(crate) async fn settle(&self, duration: Duration) { tokio::time::sleep(duration).await; }
    pub(crate) async fn stop(&mut self) -> Result<()> { self.process.stop().await }
}
