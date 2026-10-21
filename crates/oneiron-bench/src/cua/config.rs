//! Deployment supplies exact pins; no marketing-name or backend substitution.
use super::{Result, digest, provider_gate::Route, read};
use oneiron::llm::manifest::ModelRole;
use oneiron_server::config::{BrowserConfig, ModelsConfig};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    pub path: PathBuf,
    pub digest: String,
}
impl Evidence {
    pub(crate) fn load(&self) -> Result<serde_json::Value> {
        let bytes = fs::read(&self.path).map_err(|e| e.to_string())?;
        if digest(&bytes) != self.digest {
            return Err("deployment_evidence_digest_mismatch".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Arm {
    pub models_body: PathBuf,
    pub models_digest: String,
    pub routes: Vec<Route>,
    pub role: String,
    pub thinking_evidence: Evidence,
    pub decision_recipe_digest: Option<String>,
    pub deployment_evidence: Option<Evidence>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub schema: u32,
    pub allowed: Vec<String>,
    pub background_tier_enabled: bool,
    pub engine: String,
    pub engine_binary_digest: String,
    pub engine_head: String,
    pub driver_digest: String,
    pub guest_image_digest: String,
    pub prompt_package_digest: String,
    pub browser: serde_json::Value,
    pub navigation_evidence: Option<Evidence>,
    pub arms: BTreeMap<String, Arm>,
    pub startup_seconds: u64,
    pub continuation_poll_ms: u64,
    pub settle_seconds: u64,
    pub action_policy: String,
    pub cash_cap_microusd: u64,
    pub campaign_id: String,
    pub cash_ledger: PathBuf,
    pub clock_tolerance_ms: u64,
}
impl Config {
    pub(crate) fn load(path: &Path, server: &Path) -> Result<Self> {
        let config: Self = read(path)?;
        if config.schema != 1
            || config.cash_cap_microusd != 5_000_000
            || !config.cash_ledger.is_absolute()
            || config.clock_tolerance_ms == 0
        {
            return Err("invalid_schema_or_cash_ceiling".into());
        }
        if !matches!(config.engine.as_str(), "chromium" | "lightpanda")
            || config.startup_seconds == 0
            || config.continuation_poll_ms == 0
            || config.settle_seconds == 0
            || !matches!(
                config.action_policy.as_str(),
                "observe_overshoot" | "require_hard_cap"
            )
        {
            return Err("invalid_runtime_limits".into());
        }
        if digest(&fs::read(server).map_err(|e| e.to_string())?) != config.engine_binary_digest {
            return Err("engine_binary_pin_mismatch".into());
        }
        let browser: BrowserConfig =
            serde_json::from_value(config.browser.clone()).map_err(|e| e.to_string())?;
        if serde_json::to_value(browser.engine).map_err(|e| e.to_string())? != config.engine
            || !browser.image.ends_with(&config.guest_image_digest)
        {
            return Err("browser_pin_mismatch".into());
        }
        for pin in [
            &config.engine_head,
            &config.driver_digest,
            &config.guest_image_digest,
            &config.prompt_package_digest,
            &config.campaign_id,
        ] {
            if pin.trim().is_empty() {
                return Err("deployment_pin_missing".into());
            }
        }
        let pins = crate::interface_bench::parse_pinned_model_config(
            &serde_json::json!({
            "allowed":config.allowed,"background_tier_enabled":config.background_tier_enabled})
            .to_string(),
        )
        .map_err(|e| e.to_string())?;
        if config.background_tier_enabled {
            return Err("background_models_forbidden".into());
        }
        let keys: BTreeSet<_> = config.arms.keys().map(String::as_str).collect();
        if keys != BTreeSet::from(["B", "C", "C+", "D"]) {
            return Err("arm_coverage_missing".into());
        }
        for (id, arm) in &config.arms {
            if arm.role != "generative_reasoner" {
                return Err("unavailable_e5_browser_planner".into());
            }
            let thinking = arm.thinking_evidence.load()?;
            if thinking["attested"] != true || (id == "D" && thinking["effort"] != "medium") {
                return Err(format!("thinking_unattested:{id}"));
            }
            if let Some(evidence) = &arm.deployment_evidence {
                let deployed = evidence.load()?;
                if deployed["models_digest"] != arm.models_digest {
                    return Err("deployment_models_mismatch".into());
                }
            }
            if !arm.models_body.is_absolute() {
                return Err("models_path_not_absolute".into());
            }
            let body = arm.body()?;
            let models = ModelsConfig::from_toml(&body, arm.models_body.parent())
                .map_err(|e| e.to_string())?;
            if models.dreamer.enabled || models.workflows.enabled {
                return Err("background_models_forbidden".into());
            }
            let ladder = models
                .ladder(ModelRole::GenerativeReasoner)
                .ok_or("planner_model_unbound")?;
            if ladder.len() != 1 {
                return Err("diagnostic_planner_fallback_forbidden".into());
            }
            let planner = &ladder[0].model;
            let planner_route = arm
                .routes
                .iter()
                .find(|r| r.provider == planner.provider && r.requested_model == planner.model)
                .ok_or("planner_gate_missing")?;
            if thinking["requested_model"] != planner_route.requested_model
                || (id == "D" && !planner_route.cash)
            {
                return Err("planner_thinking_or_cash_unattested".into());
            }
            if let Some(read) = &models.decision_read {
                if arm.decision_recipe_digest.as_deref() != Some(read.recipe.fingerprint()) {
                    return Err("decision_recipe_mismatch".into());
                }
                let local = models
                    .ladder(ModelRole::LocalReasoner)
                    .ok_or("local_rung_missing")?;
                if !arm.routes.iter().any(|r| {
                    r.provider == local[0].model.provider
                        && matches!(r.protocol.as_str(), "native" | "native_chat")
                }) {
                    return Err("native_gate_unavailable".into());
                }
            }
            if models
                .code_mode
                .prompt_package
                .as_ref()
                .is_none_or(|p| !p.is_absolute())
            {
                return Err("absolute_prompt_package_required".into());
            }
            let mut covered = BTreeSet::new();
            for rungs in models.roles.values() {
                for rung in rungs {
                    let provider = models
                        .providers
                        .get(&rung.model.provider)
                        .ok_or("provider_missing")?;
                    if matches!(provider.revision.as_str(), "live" | "latest") {
                        return Err("floating_provider_revision".into());
                    }
                    let engine_id = rung
                        .model
                        .engine_id(&provider.revision)
                        .map_err(|e| e.to_string())?;
                    let covered_pin =
                        crate::interface_bench::pinned_model_for_wire_id(&pins, engine_id.as_str())
                            .map_err(|e| e.to_string())?;
                    let route = arm
                        .routes
                        .iter()
                        .find(|r| {
                            r.provider == rung.model.provider
                                && r.requested_model == rung.model.model
                        })
                        .ok_or("provider_gate_coverage_missing")?;
                    if route.engine_model != covered_pin.as_str()
                        || provider.base_url.trim_end_matches('/') != route.local_url()
                        || provider.responses_socket.is_some()
                        || provider.request_compression.is_some()
                    {
                        return Err("provider_gate_bypass_or_pin_mismatch".into());
                    }
                    if id == "B" && !route.requested_model.ends_with("-sub") {
                        return Err("subscription_slug_required".into());
                    }
                    covered.insert(route.engine_model.clone());
                }
            }
            if let Some(seat) = &models.decisions.system_one {
                let wire = format!("{}-{}", seat.model, seat.version);
                let route = arm
                    .routes
                    .iter()
                    .find(|r| r.protocol == "system_one" && r.requested_model == wire)
                    .ok_or("system_one_gate_unavailable")?;
                if seat.endpoint != format!("{}/v1/systemone", route.local_url()) {
                    return Err("system_one_gate_bypass".into());
                }
                crate::interface_bench::pinned_model_for_wire_id(&pins, &route.engine_model)
                    .map_err(|e| e.to_string())?;
                covered.insert(route.engine_model.clone());
            }
            let mut ports = BTreeSet::new();
            let mut providers = BTreeSet::new();
            for route in &arm.routes {
                if !ports.insert(route.listen_port)
                    || !providers.insert(&route.provider)
                    || matches!(route.listen_port, 8765 | 8766)
                {
                    return Err("provider_gate_listener_collision".into());
                }
                route.validate()?;
                if !covered.contains(&route.engine_model) {
                    return Err("unbound_gate_route".into());
                }
            }
            if arm.routes.is_empty() {
                return Err("model_identity_unattested".into());
            }
        }
        if let Some(evidence) = &config.navigation_evidence {
            let observed = evidence.load()?;
            if observed["engine"] != config.engine
                || observed["engine_binary_digest"] != config.engine_binary_digest
                || observed["driver_digest"] != config.driver_digest
                || observed["guest_image_digest"] != config.guest_image_digest
                || observed["public_success"] != true
                || observed["private_refused"] != true
                || observed["external_refused"] != true
            {
                return Err("browser_navigation_unavailable".into());
            }
        }
        Ok(config)
    }
}
impl Arm {
    pub(crate) fn body(&self) -> Result<String> {
        let body = fs::read_to_string(&self.models_body).map_err(|e| e.to_string())?;
        if digest(body.as_bytes()) != self.models_digest {
            return Err("models_config_pin_mismatch".into());
        }
        // Prompt text belongs in pinned prompt files, not multiline TOML literals.
        if body.contains("\"\"\"") || body.contains("'''") {
            return Err("models_multiline_literal_unsupported".into());
        }
        Ok(body)
    }
    pub(crate) fn server_models(&self) -> Result<String> {
        let body = self.body()?;
        let mut output = String::from("\n[models]\n");
        for line in body.lines() {
            let trimmed = line.trim_start();
            if let Some(table) = trimmed.strip_prefix("[[") {
                output.push_str(&format!("[[models.{table}\n"));
            } else if let Some(table) = trimmed.strip_prefix('[') {
                output.push_str(&format!("[models.{table}\n"));
            } else {
                output.push_str(line);
                output.push('\n');
            }
        }
        Ok(output)
    }
}
