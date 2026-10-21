//! Pass-through only: exact wire identities and durable campaign cash reservations.
use std::{path::{Path, PathBuf}, sync::{Arc, Mutex}};
use axum::{Router, body::{Body, Bytes}, extract::{Request, State}, http::{HeaderMap, StatusCode, Uri}, response::{IntoResponse, Response}, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use super::{Result, rows};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stop {
    ModelIdMismatch, ModelIdUnattested, RequestedModelMismatch,
    CashBoundUnavailable, CashCapReached, ProviderFailure, ProviderTimeout,
    UnsupportedProviderProtocol, GateEvidenceFailure, ProviderResponseBoundExceeded,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tariff {
    pub version: String,
    pub input_microusd_per_million: u64,
    pub output_microusd_per_million: u64,
    pub cache_read_microusd_per_million: u64,
    pub cache_write_microusd_per_million: u64,
    pub image_microusd_each: u64,
    pub highest_context_tier: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Route {
    pub provider: String, pub engine_model: String,
    pub requested_model: String, pub returned_model: String,
    pub upstream: String, pub listen_port: u16, pub protocol: String,
    pub cash: bool, pub tariff: Option<Tariff>,
    pub max_context_tokens: u64, pub input_overhead_tokens: u64, pub max_output_tokens: u64,
    pub max_request_bytes: usize, pub max_response_bytes: usize, pub max_images: u64, pub timeout_seconds: u64,
    pub weight_digest: Option<String>, pub tokenizer_digest: Option<String>,
    pub deployment_identity: Option<String>,
    pub attestation: Option<super::config::Evidence>,
}
impl Route {
    pub(crate) fn local_url(&self) -> String { format!("http://127.0.0.1:{}", self.listen_port) }
    pub(crate) fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.upstream).map_err(|e| e.to_string())?;
        if (url.scheme() != "https" && !(url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))))
            || url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() || url.password().is_some()
            || self.listen_port == 0 || self.requested_model.is_empty() || self.returned_model.is_empty()
            || self.max_context_tokens == 0 || self.input_overhead_tokens == 0 || self.max_output_tokens == 0 || self.max_request_bytes == 0
            || self.max_response_bytes == 0 || self.timeout_seconds == 0 || !matches!(self.protocol.as_str(), "chat" | "messages" | "native" | "native_chat" | "system_one") {
            return Err("invalid_provider_route".into());
        }
        if matches!(self.protocol.as_str(), "native" | "native_chat") || self.weight_digest.is_some() {
            let evidence = self.attestation.as_ref().ok_or("model_id_unattested")?.load()?;
            for (field, pin) in [("weight_digest", &self.weight_digest), ("tokenizer_digest", &self.tokenizer_digest), ("deployment_identity", &self.deployment_identity)] {
                if pin.as_ref().is_none_or(|p| p.is_empty() || evidence[field] != *p) {
                    return Err("model_id_unattested".into());
                }
            }
            if evidence["requested_model"] != self.requested_model || evidence["returned_model"] != self.returned_model {
                return Err("model_id_mismatch".into());
            }
        }
        if !self.cash && !self.requested_model.ends_with("-sub") && self.weight_digest.is_none() {
            return Err("noncash_route_not_subscription_or_owned".into());
        }
        if self.upstream.trim_end_matches('/') == self.local_url() { return Err("provider_gate_self_forward".into()) }
        if self.cash { self.reservation().map_err(|e| format!("{e:?}"))?; }
        Ok(())
    }
    fn reservation(&self) -> std::result::Result<u64, Stop> {
        let t = self.tariff.as_ref().ok_or(Stop::CashBoundUnavailable)?;
        if !t.highest_context_tier || t.version.is_empty() || t.input_microusd_per_million == 0 || t.output_microusd_per_million == 0 {
            return Err(Stop::CashBoundUnavailable);
        }
        // Reserve the full declared context at all input/cache charges. This
        // intentionally overestimates; no usage/billing reply releases it.
        let input_rate = u128::from(t.input_microusd_per_million) + u128::from(t.cache_read_microusd_per_million) + u128::from(t.cache_write_microusd_per_million);
        let amount = (u128::from(self.max_context_tokens) * input_rate
            + u128::from(self.max_output_tokens) * u128::from(t.output_microusd_per_million)).div_ceil(1_000_000)
            + u128::from(self.max_images) * u128::from(t.image_microusd_each);
        u64::try_from(amount).map_err(|_| Stop::CashBoundUnavailable)
    }
}

pub(super) struct Ledger {
    path: PathBuf, pins: String, reserved: u64, sequence: u64,
    pub stop: Option<Stop>,
}
impl Ledger {
    pub(crate) fn open(path: &Path, pins: &str) -> Result<Self> {
        let mut ledger = Self {path:path.into(), pins:pins.into(), reserved:0, sequence:0, stop:None};
        for row in rows::load_values(path)? {
            if row["pins"] != pins { return Err("cash_ledger_pin_mismatch".into()) }
            ledger.sequence += 1;
            if row["id"].as_u64() != Some(ledger.sequence) { return Err("cash_ledger_sequence_mismatch".into()) }
            ledger.reserved = ledger.reserved.checked_add(row["reserved_microusd"].as_u64().ok_or("cash_ledger_malformed")?).ok_or("cash_ledger_overflow")?;
        }
        if ledger.reserved > 5_000_000 { return Err("cash_ledger_over_ceiling".into()) }
        for row in rows::load_values(&path.with_extension("stops.jsonl"))? {
            if row["pins"] != pins { return Err("gate_stop_pin_mismatch".into()) }
            ledger.stop = Some(serde_json::from_value(row["cause"].clone()).map_err(|e| e.to_string())?);
        }
        Ok(ledger)
    }
    pub(crate) fn blocked(&self, cash: bool) -> Option<Stop> {
        self.stop.as_ref().filter(|stop| cash || !matches!(stop, Stop::CashCapReached)).cloned()
    }
    fn stop_with(&mut self, stop: Stop) {
        if self.stop.is_none() || (matches!(self.stop, Some(Stop::CashCapReached)) && !matches!(stop, Stop::CashCapReached)) {
            let record = json!({"pins":self.pins,"cause":stop});
            self.stop = Some(if rows::append(&self.path.with_extension("stops.jsonl"),&record).is_ok() {
                stop
            } else { Stop::GateEvidenceFailure });
        }
    }
    fn reserve(&mut self, route: &Route, cell: &str, path: &str, body: &[u8], inference: bool) -> std::result::Result<u64, Stop> {
        if let Some(stop) = self.blocked(route.cash) { return Err(stop) }
        let amount = if route.cash && inference { route.reservation()? } else { 0 };
        if self.reserved.checked_add(amount).is_none_or(|sum| sum > 5_000_000) { return Err(Stop::CashCapReached) }
        self.sequence += 1;
        let entry = json!({"id":self.sequence,"pins":self.pins,"cell":cell,"provider":route.provider,
            "requested_model":route.requested_model,"engine_model":route.engine_model,
            "path":path,"inference":inference,"request_digest":super::digest(body),"reserved_microusd":amount,
            "accounting":"conservative_reservation_retained_including_lost_responses","tariff":route.tariff});
        rows::append(&self.path, &entry).map_err(|_| Stop::GateEvidenceFailure)?;
        self.reserved += amount;
        Ok(self.sequence)
    }
    pub(crate) fn reserved(&self) -> u64 { self.reserved }
}
pub(super) type SharedLedger = Arc<Mutex<Ledger>>;
#[derive(Clone)]
struct Proxy {
    route: Route, cell: String, ledger: SharedLedger, evidence: PathBuf, client: reqwest::Client,
    cancelled: tokio::sync::watch::Receiver<bool>,
}
pub(super) struct Gate { tasks: Vec<tokio::task::JoinHandle<()>>, ledger: SharedLedger, cancel: tokio::sync::watch::Sender<bool> }
impl Drop for Gate { fn drop(&mut self) { self.stop(); } }
impl Gate {
    pub(crate) fn stop(&mut self) {
        let _ = self.cancel.send(true);
        for task in self.tasks.drain(..) { task.abort(); }
    }
    pub(crate) async fn start(routes: &[Route], ledger: SharedLedger, cell: &str, evidence: &Path) -> Result<Self> {
        if let Ok(l) = ledger.lock() {
            if let Some(stop) = l.blocked(routes.iter().any(|r| r.cash)) {
                return Err(format!("provider_gate_terminal:{}",serde_json::to_string(&stop).map_err(|e| e.to_string())?));
            }
        }
        let (cancel, cancelled) = tokio::sync::watch::channel(false);
        let mut gate = Self {tasks:Vec::new(), ledger, cancel};
        for route in routes {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, route.listen_port)).await.map_err(|e| format!("gate_bind_failed:{e}"))?;
            let proxy = Proxy { route:route.clone(), cell:cell.into(), ledger:gate.ledger.clone(), evidence:evidence.into(), cancelled:cancelled.clone(),
                client:reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())? };
            let app = Router::new().route("/{*path}", post(forward).get(native_read)).with_state(proxy);
            gate.tasks.push(tokio::spawn(async move { let _ = axum::serve(listener, app).await; }));
        }
        Ok(gate)
    }
}
fn refuse(proxy: &Proxy, stop: Stop) -> Response {
    if !*proxy.cancelled.borrow() {
        if let Ok(mut ledger) = proxy.ledger.lock() { ledger.stop_with(stop.clone()); }
    }
    let value = json!({"error":{"cause":stop}});
    let _ = rows::append(&proxy.evidence, &json!({"cell":proxy.cell,"terminal_stop":value}));
    (StatusCode::BAD_GATEWAY, axum::Json(value)).into_response()
}
async fn native_read(State(proxy): State<Proxy>, uri: Uri, headers: HeaderMap) -> Response {
    // Native tokenizer probes are physical HTTP calls, but not inference.
    if !matches!(proxy.route.protocol.as_str(), "native" | "native_chat") || uri.path() != "/health" { return refuse(&proxy, Stop::UnsupportedProviderProtocol) }
    exchange(proxy, uri, headers, Bytes::new(), false).await
}
async fn forward(State(proxy): State<Proxy>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, proxy.route.max_request_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => return refuse(&proxy, Stop::CashBoundUnavailable),
    };
    exchange(proxy, parts.uri, parts.headers, bytes, true).await
}
async fn exchange(proxy: Proxy, uri: Uri, headers: HeaderMap, body: Bytes, post_method: bool) -> Response {
    if proxy.ledger.lock().map_or(true, |l| l.blocked(proxy.route.cash).is_some()) { return refuse(&proxy, Stop::ProviderFailure) }
    let request: Value = if post_method { match serde_json::from_slice(&body) {
        Ok(v) => v, Err(_) => return refuse(&proxy, Stop::UnsupportedProviderProtocol)
    }} else { json!({}) };
    let path = uri.path();
    let native = matches!(proxy.route.protocol.as_str(), "native" | "native_chat");
    let native_probe = native && matches!(path, "/tokenize" | "/health");
    let native_completion = native && path == "/completion";
    let expected_path = match proxy.route.protocol.as_str() { "chat" | "native_chat" => "/v1/chat/completions", "messages" => "/v1/messages", "system_one" => "/v1/systemone", _ => "/completion" };
    if uri.query().is_some() || (!native_probe && !native_completion && path != expected_path) || request["stream"] == true {
        return refuse(&proxy, Stop::UnsupportedProviderProtocol);
    }
    if !native_probe && !native_completion && request["model"] != proxy.route.requested_model {
        return refuse(&proxy, Stop::RequestedModelMismatch);
    }
    if native && request.get("model").is_some_and(|m| m != &json!(proxy.route.requested_model)) {
        return refuse(&proxy, Stop::RequestedModelMismatch);
    }
    if !native_probe {
        let limit = ["max_tokens", "max_completion_tokens", "n_predict"].iter().find_map(|k| request[*k].as_u64());
        // Byte bound is stricter than a token bound for text. Image bytes are
        // bounded too; all declared images are additionally cash-reserved.
        if (proxy.route.protocol != "system_one" && limit.is_none_or(|n| n == 0 || n > proxy.route.max_output_tokens))
            || body.len() > proxy.route.max_request_bytes || (body.len() as u64).checked_add(proxy.route.input_overhead_tokens).is_none_or(|n| n > proxy.route.max_context_tokens)
            || ["n", "best_of"].iter().any(|k| request.get(*k).is_some_and(|n| n.as_u64() != Some(1)))
            || (proxy.route.protocol == "system_one" && proxy.route.cash) {
            return refuse(&proxy, Stop::CashBoundUnavailable);
        }
        if proxy.route.cash && (proxy.route.max_images != 0 || body.windows(5).any(|b| b == b"image")) {
            // Image pricing needs a validated decoder bound, not a prompt assertion.
            return refuse(&proxy, Stop::CashBoundUnavailable);
        }
    }
    let id = {
        let Ok(mut ledger) = proxy.ledger.lock() else { return refuse(&proxy, Stop::GateEvidenceFailure) };
        match ledger.reserve(&proxy.route, &proxy.cell, path, &body, !native_probe) {
            Ok(id) => id,
            Err(stop) => { drop(ledger); return refuse(&proxy, stop) }
        }
    };
    let url = format!("{}{}", proxy.route.upstream.trim_end_matches('/'), path);
    let mut outgoing = if post_method { proxy.client.post(url).body(body.to_vec()) } else { proxy.client.get(url) };
    for name in ["authorization", "x-api-key", "anthropic-version", "anthropic-beta", "content-type", "typesafe-danger-zone-images"] {
        if let Some(value) = headers.get(name) { outgoing = outgoing.header(name, value); }
    }
    let mut cancelled = proxy.cancelled.clone();
    if *cancelled.borrow() { return refuse(&proxy, Stop::ProviderFailure) }
    let flight = async {
        let mut response = outgoing.send().await.map_err(|_| Stop::ProviderFailure)?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Stop::ProviderFailure)? {
            if bytes.len().saturating_add(chunk.len()) > proxy.route.max_response_bytes {
                return Err(Stop::ProviderResponseBoundExceeded);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok::<_, Stop>((status, bytes))
    };
    let returned = tokio::select! {
        result = tokio::time::timeout(std::time::Duration::from_secs(proxy.route.timeout_seconds), flight) => result,
        _ = cancelled.changed() => return refuse(&proxy, Stop::ProviderFailure),
    };
    let (status, bytes) = match returned { Ok(Ok(v)) => v, Ok(Err(e)) => return refuse(&proxy, e), Err(_) => return refuse(&proxy, Stop::ProviderTimeout) };
    let value: Value = match serde_json::from_slice(&bytes) { Ok(v) => v, Err(_) => return refuse(&proxy, Stop::ModelIdUnattested) };
    let reported = value["model"].as_str();
    let recorded = json!({"id":id,"cell":proxy.cell,"status":status.as_u16(),"requested_model":proxy.route.requested_model,
        "returned_model":reported,"deployment_identity":proxy.route.deployment_identity,"usage":value["usage"],
        "inference":!native_probe,"response_digest":super::digest(&bytes),"stage":null,"stage_unavailable":"no_public_physical_stage_join",
        "billing_actual":null});
    if rows::append(&proxy.evidence, &recorded).is_err() { return refuse(&proxy, Stop::GateEvidenceFailure) }
    if !status.is_success() { return refuse(&proxy, Stop::ProviderFailure) }
    if !native_probe {
        if value.get("model").is_some_and(|m| !m.is_string()) { return refuse(&proxy, Stop::ModelIdUnattested) }
        if let Some(model) = reported {
            if model != proxy.route.returned_model { return refuse(&proxy, Stop::ModelIdMismatch) }
        } else if !native_completion || proxy.route.deployment_identity.is_none() {
            return refuse(&proxy, Stop::ModelIdUnattested);
        }
    }
    if *proxy.cancelled.borrow() { return refuse(&proxy, Stop::ProviderFailure) }
    Response::builder().status(status.as_u16()).header("content-type", "application/json")
        .body(Body::from(bytes)).unwrap_or_else(|_| refuse(&proxy, Stop::ProviderFailure))
}
