//! Closed-loop authenticated fleet traffic against one real loopback server and vault.
use futures_util::{StreamExt, TryStreamExt, stream};
use oneiron::{TimeRange, Vault};
use oneiron_server::{config::SyncServerConfig, server::SyncServer};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{
    Result,
    configuration::Plan,
    optimization::{self, AT, id},
    report::Metric,
    wire::Agent,
};

fn progress(phase: &str, completed: usize, total: usize) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "fleet-progress phase={phase} completed={completed}/{total}"
    );
}

pub(super) struct Observation {
    pub metrics: BTreeMap<String, Metric>,
    pub held_sockets: usize,
    pub verified_writes: usize,
    pub verified_recalls: usize,
    pub hold_observed_ms: f64,
}

struct ServerTask(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn seed_actors(vault: &Vault, agents: usize) -> Result<()> {
    for start in (0..agents).step_by(1000) {
        let mut batch = vault.batch();
        for i in start..(start + 1000).min(agents) {
            batch = batch.put(
                &id(0x31, i)?,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: AT, end: AT },
                AT,
                b"fleet principal",
            );
        }
        batch.commit()?;
    }
    Ok(())
}

pub(super) async fn measure(plan: &Plan) -> Result<Observation> {
    let directory = tempfile::tempdir_in(&plan.scratch)?;
    let vault = Arc::new(Vault::open(directory.path(), optimization::config(plan))?);
    seed_actors(&vault, plan.agents)?;
    progress("seeded", plan.agents, plan.agents);
    let secret = oneiron::EntityId::now().to_hex();
    let server = Arc::new(SyncServer::new(
        vault.clone(),
        SyncServerConfig {
            auth_secret: Some(secret.clone()),
            ..Default::default()
        },
    )?);
    // One SyncServer/vault, with several listener ports so a loopback fleet
    // does not require changing the host's ephemeral-port range.
    let app = oneiron_server::build_app(server);
    let mut addresses = Vec::with_capacity(plan.listeners);
    let mut _server_tasks = Vec::with_capacity(plan.listeners);
    for _ in 0..plan.listeners {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        addresses.push(listener.local_addr()?);
        let router = app.clone();
        _server_tasks.push(ServerTask(tokio::spawn(async move {
            axum::serve(listener, router).await
        })));
    }
    let timeout = Duration::from_secs(plan.timeout_secs);
    let http = reqwest::Client::builder()
        .timeout(timeout)
        .no_proxy()
        .pool_max_idle_per_host(plan.concurrency)
        .build()?;
    let urls = addresses
        .iter()
        .map(|address| format!("ws://{address}/ws"))
        .collect::<Vec<_>>();
    let endpoint = format!("http://{}/v1/core/facade/witness", addresses[0]);
    let client_sockets = super::wire::client_sockets(plan.agents, plan.listeners)?;
    let start = Instant::now();
    let mut opened = 0;
    let connected: Vec<_> = stream::iter(client_sockets.into_iter().enumerate())
        .map(|(index, tcp)| {
            let url = &urls[index % urls.len()];
            let address = addresses[index % addresses.len()];
            let secret = &secret;
            async move {
                let token = super::wire::token(secret, &id(0x31, index)?.to_hex());
                let start = Instant::now();
                let agent =
                    Agent::connect(index, url, address, tcp, secret, token, timeout).await?;
                Ok::<_, super::Error>((agent, start.elapsed().as_secs_f64() * 1000.0))
            }
        })
        .buffer_unordered(plan.concurrency)
        .map_ok(|row| {
            opened += 1;
            if opened % 1000 == 0 || opened == plan.agents {
                progress("socket_open", opened, plan.agents);
            }
            row
        })
        .try_collect()
        .await?;
    let open_elapsed = start.elapsed().as_secs_f64();
    let (mut agents, open_ms): (Vec<_>, Vec<_>) = connected.into_iter().unzip();
    let mut metrics = BTreeMap::new();
    metrics.insert("socket_open".into(), Metric::new(open_ms, open_elapsed)?);
    // All N sockets exist simultaneously before any measured write or recall.
    ping_phase(&mut agents, plan, 0, "socket_probe_before", &mut metrics).await?;
    let held_start = Instant::now();
    let mut verified_writes = 0;
    let mut verified_recalls = 0;
    for round in 0..plan.rounds {
        write_phase(&mut agents, plan, &http, &endpoint, round, &mut metrics).await?;
        verify_writes(&vault, plan, round)?;
        verified_writes += plan.agents;
        progress(
            "writes_verified",
            verified_writes,
            plan.agents * plan.rounds,
        );
        recall_phase(&mut agents, plan, round, &mut metrics).await?;
        verified_recalls += plan.agents;
        progress(
            "recalls_verified",
            verified_recalls,
            plan.agents * plan.rounds,
        );
    }
    tokio::time::sleep(Duration::from_millis(plan.hold_ms)).await;
    ping_phase(&mut agents, plan, 1, "socket_probe_after", &mut metrics).await?;
    let hold_observed_ms = held_start.elapsed().as_secs_f64() * 1000.0;
    Ok(Observation {
        metrics,
        held_sockets: agents.len(),
        verified_writes,
        verified_recalls,
        hold_observed_ms,
    })
}

// Alphabetic unique tokens avoid numeric-token normalization changing the query set.
fn needle(index: usize, round: usize) -> String {
    let mut number = index * 100 + round;
    let mut token = String::from("fleetneedle");
    for _ in 0..8 {
        token.push((b'a' + (number % 26) as u8) as char);
        number /= 26;
    }
    token
}

async fn write_phase(
    agents: &mut [Agent],
    plan: &Plan,
    http: &reqwest::Client,
    endpoint: &str,
    round: usize,
    metrics: &mut BTreeMap<String, Metric>,
) -> Result<()> {
    let phase = Instant::now();
    let samples = stream::iter(agents.iter_mut()).map(|agent| async move {
        let start = Instant::now();
        let message_id = id(0x33, agent.index * 100 + round)?.to_hex();
        let body = json!({"conversation_ref":id(0x32, agent.index)?.to_hex(),
            "turn_ref":id(0x34, agent.index * 100 + round)?.to_hex(),
            "occurred_at":AT + round as u64,
            "messages":[{"id":message_id,"author":"companion","message_type":"dialogue",
                "content":needle(agent.index, round),"metadata":null,"is_visible":true,"order":0}]});
        let response = http.post(endpoint).bearer_auth(&agent.token).json(&body).send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(format!("witness for agent {} returned {}: {}", agent.index,
                status, String::from_utf8_lossy(&bytes)).into());
        }
        let receipt: oneiron::memory::WitnessReceipt = serde_json::from_slice(&bytes)?;
        if receipt.message_short_ids.len() != 1 || !receipt.receipt_ref.starts_with("witness:") {
            return Err("witness returned incomplete receipt".into());
        }
        agent.expected_message = receipt.message_short_ids[0].clone();
        Ok::<_, super::Error>(start.elapsed().as_secs_f64() * 1000.0)
    }).buffer_unordered(plan.concurrency).try_collect().await?;
    metrics.insert(
        format!("write_{round}"),
        Metric::new(samples, phase.elapsed().as_secs_f64())?,
    );
    Ok(())
}

fn verify_writes(vault: &Vault, plan: &Plan, round: usize) -> Result<()> {
    for i in 0..plan.agents {
        let bytes = vault
            .get(&id(0x33, i * 100 + round)?)?
            .ok_or("witness acknowledged an absent message")?;
        let body: serde_json::Value = rmp_serde::from_slice(&bytes)?;
        if body["content"].as_str() != Some(needle(i, round).as_str()) {
            return Err("stored witness content differs from submitted bytes".into());
        }
    }
    Ok(())
}

async fn recall_phase(
    agents: &mut [Agent],
    plan: &Plan,
    round: usize,
    metrics: &mut BTreeMap<String, Metric>,
) -> Result<()> {
    let phase = Instant::now();
    let samples = stream::iter(agents.iter_mut())
        .map(|agent| async move {
            let start = Instant::now();
            agent.recall(round, &needle(agent.index, round)).await?;
            Ok::<_, super::Error>(start.elapsed().as_secs_f64() * 1000.0)
        })
        .buffer_unordered(plan.concurrency)
        .try_collect()
        .await?;
    metrics.insert(
        format!("recall_{round}"),
        Metric::new(samples, phase.elapsed().as_secs_f64())?,
    );
    Ok(())
}

async fn ping_phase(
    agents: &mut [Agent],
    plan: &Plan,
    phase_id: u8,
    name: &str,
    metrics: &mut BTreeMap<String, Metric>,
) -> Result<()> {
    let phase = Instant::now();
    let samples = stream::iter(agents.iter_mut())
        .map(|agent| async move {
            let start = Instant::now();
            agent.ping(phase_id).await?;
            Ok::<_, super::Error>(start.elapsed().as_secs_f64() * 1000.0)
        })
        .buffer_unordered(plan.concurrency)
        .try_collect()
        .await?;
    metrics.insert(
        name.into(),
        Metric::new(samples, phase.elapsed().as_secs_f64())?,
    );
    Ok(())
}
