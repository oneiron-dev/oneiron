//! Shipped binary lifecycle and official MCP stdio. No second engine client.
use super::{Result, browser_setup, config::Arm, fixture, rows, taskgen::Plan, write_json};
use rand::RngCore;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::Instant,
};

pub(super) struct Process {
    child: Child,
    group: u32,
}
impl Process {
    pub(crate) fn spawn(mut command: Command) -> Result<Self> {
        command.kill_on_drop(true);
        let child = command.spawn().map_err(|e| e.to_string())?;
        let group = child.id().ok_or("child_pid_missing")?;
        Ok(Self { child, group })
    }
    pub(crate) fn child(&mut self) -> &mut Child {
        &mut self.child
    }
    pub(crate) async fn stop(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let status = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", self.group)])
                .status()
                .await
                .map_err(|e| e.to_string())?;
            if !status.success() && self.child.try_wait().map_err(|e| e.to_string())?.is_none() {
                return Err("owned_process_group_stop_failed".into());
            }
        }
        let _ = self.child.start_kill();
        self.child.wait().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", self.group)])
                .status();
        }
        let _ = self.child.start_kill();
    }
}
pub(super) fn isolated(binary: &Path) -> Command {
    let mut command = Command::new("setsid");
    command.arg(binary).stdin(Stdio::null());
    for (key, _) in std::env::vars().filter(|(k, _)| k.starts_with("ONEIRON_")) {
        command.env_remove(key);
    }
    if let Some(fence) = fence_launcher(binary) {
        command.env(FENCE_LAUNCHER_ENV, fence);
    }
    command.env("NO_COLOR", "1");
    command
}

const FENCE_LAUNCHER_ENV: &str = "ONEIRON_FENCE_LAUNCHER";

/// The host's fence launcher survives the `ONEIRON_*` strip: the browser guest
/// cannot start without it, and it names a host binary, not engine config. The
/// caller's absolute path wins; else the `oneiron-fence` built beside `binary`.
fn fence_launcher(binary: &Path) -> Option<PathBuf> {
    let given = std::env::var_os(FENCE_LAUNCHER_ENV).map(PathBuf::from);
    if let Some(path) = given.filter(|path| path.is_absolute()) {
        return Some(path);
    }
    fs::canonicalize(binary.with_file_name("oneiron-fence"))
        .ok()
        .filter(|path| path.is_file())
}

pub(super) async fn once(mut command: Command, deadline: Instant, log: &Path) -> Result<()> {
    command
        .stdout(fs::File::create(log).map_err(|e| e.to_string())?)
        .stderr(fs::File::create(log.with_extension("stderr")).map_err(|e| e.to_string())?);
    let mut process = Process::spawn(command)?;
    let status = tokio::time::timeout_at(deadline, process.child.wait())
        .await
        .map_err(|_| "timeout")?
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("child_command_failed:{status}"));
    }
    Ok(())
}
pub(super) struct Served {
    server: Process,
    bridge: Process,
    input: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    id: u64,
    versions: std::collections::BTreeMap<String, String>,
    evidence: PathBuf,
}
impl Served {
    pub(crate) async fn fresh(
        binary: &Path,
        dir: &Path,
        arm: &Arm,
        browser: &Value,
        plan: &Plan,
        startup: Duration,
        poll: Duration,
    ) -> Result<Self> {
        let deadline = Instant::now() + startup;
        let absolute_dir = dir.canonicalize().map_err(|e| e.to_string())?;
        let dir = absolute_dir.as_path();
        let target = fixture::forward_target(plan, browser)?;
        let egress = dir.join("egress.json");
        fs::write(&egress, b"{\"allowed_domains\": []}\n").map_err(|e| e.to_string())?;
        let config = dir.join("oneiron.toml");
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let issuer: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let mut init = isolated(binary);
        init.arg("init")
            .arg(dir.join("vault"))
            .args(["--embedder", "none", "--config"])
            .arg(&config)
            .env("ONEIRON_AUTH_SECRET", &issuer);
        once(init, deadline, &dir.join("init.stdout")).await?;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&config)
            .map_err(|e| e.to_string())?;
        use std::io::Write;
        file.write_all(arm.server_models()?.as_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(b"\n[browser]\n")
            .map_err(|e| e.to_string())?;
        for (key, value) in browser.as_object().ok_or("browser_config_malformed")? {
            if !value.is_string() && !value.is_number() {
                return Err("browser_scalar_required".into());
            }
            writeln!(file, "{key} = {value}").map_err(|e| e.to_string())?;
        }
        file.sync_all().map_err(|e| e.to_string())?;
        fixture::transport_ready(plan, browser, &config)?;
        write_json(
            &dir.join("transport.json"),
            &json!({
                "browser.bench_fixture_forward":target.to_string(), "fixture_public_bind":plan.fixture_public_bind,
                "config":config, "config_digest":super::digest(&fs::read(&config).map_err(|e| e.to_string())?),
                "ONEIRON_EGRESS_CONFIG":egress, "egress":super::read::<Value>(&egress)?,
                "virtual_origin":"http://127.0.0.1:8080"
            }),
        )?;
        let credential = dir.join("candidate.cred");
        let mut mint = isolated(binary);
        mint.args([
            "token",
            "agent",
            "--name",
            "cua-candidate",
            "--tier",
            "full-access",
            "--comm",
            "parent",
            "--out",
        ])
        .arg(&credential)
        .arg("--config")
        .arg(&config)
        .env("ONEIRON_AUTH_SECRET", &issuer);
        once(mint, deadline, &dir.join("mint.stdout")).await?;
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| e.to_string())?
            .local_addr()
            .map_err(|e| e.to_string())?
            .port();
        let origin = format!("http://127.0.0.1:{port}");
        browser_setup::bootstrap(binary, &config, &issuer, &origin, dir, browser, deadline).await?;
        let mut serve = isolated(binary);
        serve
            .args([
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--config",
            ])
            .arg(&config)
            .env("ONEIRON_AUTH_SECRET", &issuer)
            .env("ONEIRON_EGRESS_CONFIG", &egress)
            .env("RUST_LOG", "warn,oneiron::run_receipt=info")
            .stdout(fs::File::create(dir.join("server.stdout")).map_err(|e| e.to_string())?)
            .stderr(fs::File::create(dir.join("server.stderr")).map_err(|e| e.to_string())?);
        let mut server = Process::spawn(serve)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        loop {
            if server
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            {
                return Err("server_exited_during_startup".into());
            }
            if let Ok(Ok(response)) =
                tokio::time::timeout_at(deadline, client.get(format!("{origin}/api/health")).send())
                    .await
            {
                if response.status().is_success() {
                    let health: Value = tokio::time::timeout_at(deadline, response.json())
                        .await
                        .map_err(|_| "timeout")?
                        .map_err(|e| e.to_string())?;
                    write_json(&dir.join("health.json"), &health)?;
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("server_startup_timeout".into());
            }
            tokio::time::sleep_until((Instant::now() + poll).min(deadline)).await;
        }
        browser_setup::install(binary, &client, &origin, dir, deadline).await?;
        let mut bridge_cmd = isolated(binary);
        bridge_cmd
            .args([
                "mcp",
                "--surface",
                "tool-first",
                "--url",
                &origin,
                "--credential-file",
            ])
            .arg(&credential)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(dir.join("mcp.stderr")).map_err(|e| e.to_string())?);
        let mut bridge = Process::spawn(bridge_cmd)?;
        let input = bridge.child.stdin.take().ok_or("bridge_stdin_missing")?;
        let lines =
            BufReader::new(bridge.child.stdout.take().ok_or("bridge_stdout_missing")?).lines();
        let mut served = Self {
            server,
            bridge,
            input,
            lines,
            id: 0,
            versions: Default::default(),
            evidence: dir.join("mcp.jsonl"),
        };
        served.rpc("initialize", json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cua-bench","version":"1"}}), deadline).await?;
        served
            .send(
                &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                deadline,
            )
            .await?;
        let listed = served.rpc("tools/list", json!({}), deadline).await?;
        for tool in listed["result"]["tools"]
            .as_array()
            .ok_or("tools_list_malformed")?
        {
            if let (Some(name), Some(version)) = (
                tool["name"].as_str(),
                tool["inputSchema"]["properties"]["schema_version"]["const"].as_str(),
            ) {
                served.versions.insert(name.into(), version.into());
            }
        }
        if !served.versions.contains_key("execute_code") {
            return Err("execute_code_unavailable".into());
        }
        Ok(served)
    }
    async fn send(&mut self, value: &Value, deadline: Instant) -> Result<()> {
        let text = format!("{value}\n");
        tokio::time::timeout_at(deadline, async {
            self.input.write_all(text.as_bytes()).await?;
            self.input.flush().await
        })
        .await
        .map_err(|_| "timeout")?
        .map_err(|e| e.to_string())
    }
    async fn rpc(&mut self, method: &str, params: Value, deadline: Instant) -> Result<Value> {
        self.id += 1;
        self.send(
            &json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":params}),
            deadline,
        )
        .await?;
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.next_line())
                .await
                .map_err(|_| "timeout")?
                .map_err(|e| e.to_string())?
                .ok_or("mcp_bridge_eof")?;
            let value: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            rows::append(&self.evidence, &value)?;
            if value.get("id").is_none() {
                continue;
            }
            if value["id"] != self.id {
                return Err("mcp_response_id_mismatch".into());
            }
            if value.get("error").is_some() || value["result"]["isError"] == true {
                return Err(format!("mcp_terminal_error:{value}"));
            }
            return Ok(value);
        }
    }
    async fn tool(&mut self, name: &str, mut args: Value, deadline: Instant) -> Result<Value> {
        args["schema_version"] = json!(self.versions.get(name).ok_or("tool_schema_unavailable")?);
        args["consent"] =
            json!({"policy_ref":"policy:agent-session","purpose":"synthetic CUA fixture"});
        let reply = self
            .rpc(
                "tools/call",
                json!({"name":name,"arguments":args}),
                deadline,
            )
            .await?;
        let content = &reply["result"]["structuredContent"];
        if !content.is_object() {
            return Err("structured_content_missing".into());
        }
        Ok(content.clone())
    }
    pub(crate) async fn execute(
        &mut self,
        run_ref: &str,
        task: &str,
        deadline: Instant,
    ) -> Result<Value> {
        self.tool(
            "execute_code",
            json!({"run_ref":run_ref,"task":task}),
            deadline,
        )
        .await
    }
    pub(crate) async fn finish(
        &mut self,
        run_ref: &str,
        task: &str,
        deadline: Instant,
        poll: Duration,
    ) -> Result<Value> {
        loop {
            let result = self.execute(run_ref, task, deadline).await?;
            match result["result"]["status"]
                .as_str()
                .ok_or("executor_status_missing")?
            {
                "complete" => return Ok(result),
                "yielded" | "window_full" => {
                    if Instant::now() >= deadline {
                        return Err("timeout".into());
                    }
                    tokio::time::sleep_until((Instant::now() + poll).min(deadline)).await;
                }
                "waiting" => return Err("needs_you_no_send_approval".into()),
                other => return Err(format!("executor_terminal_status:{other}")),
            }
        }
    }
    pub(crate) async fn gate_receipts(&mut self, deadline: Instant) -> Result<Value> {
        self.tool(
            "vault.receipts",
            json!({"arguments":{"spec":{"limit":100,"kinds":["gate"]}}}),
            deadline,
        )
        .await
    }
    pub(crate) async fn artifacts(
        &mut self,
        run_ref: &str,
        last: &Value,
        deadline: Instant,
    ) -> Result<Value> {
        let cards = last["results"].as_array().ok_or("artifact_cards_missing")?;
        if last["resultsCount"].as_u64() != Some(cards.len() as u64) {
            return Err("artifact_card_coverage_unavailable".into());
        }
        let mut files = serde_json::Map::new();
        for name in ["exhibitors.json", "profiles.json", "ranked.tsv"] {
            if !cards.iter().any(|card| card["name"] == name) {
                return Err(format!("artifact_missing:{name}"));
            }
            let mut selection = json!({"bytes":[0]});
            let mut text = String::new();
            let mut end = 0;
            loop {
                let read = self
                    .tool(
                        "read_result",
                        json!({"run_ref":run_ref,"ref":name,"facet":"slice","input":selection}),
                        deadline,
                    )
                    .await?;
                let output = &read["result"]["output"];
                if output["start"].as_u64() != Some(end) || output["lossy"] == true {
                    return Err("artifact_slice_incomplete".into());
                }
                text.push_str(output["text"].as_str().ok_or("artifact_text_unavailable")?);
                let next_end = output["end"].as_u64().ok_or("artifact_slice_end_missing")?;
                if output["done"] == true {
                    break;
                }
                if next_end <= end || !output["next"].is_object() {
                    return Err("artifact_paging_no_progress".into());
                }
                end = next_end;
                selection = output["next"].clone();
            }
            let value = if name.ends_with(".json") {
                serde_json::from_str(&text).map_err(|e| e.to_string())?
            } else {
                json!(text)
            };
            files.insert(name.into(), value);
        }
        Ok(Value::Object(files))
    }
    pub(crate) async fn stop(&mut self) -> Result<()> {
        let bridge = self.bridge.stop().await;
        let server = self.server.stop().await;
        bridge.and(server)
    }
}
