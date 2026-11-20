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
    pub(crate) path: PathBuf,
    pub(crate) digest: String,
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
    pub(crate) models_body: PathBuf,
    pub(crate) models_digest: String,
    pub(crate) routes: Vec<Route>,
    pub(crate) role: String,
    pub(crate) thinking_evidence: Evidence,
    pub(crate) decision_recipe_digest: Option<String>,
    pub(crate) deployment_evidence: Option<Evidence>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub(crate) schema: u32,
    pub(crate) allowed: Vec<String>,
    pub(crate) background_tier_enabled: bool,
    pub(crate) engine: String,
    pub(crate) engine_binary_digest: String,
    pub(crate) engine_head: String,
    pub(crate) driver_digest: String,
    pub(crate) guest_image_digest: String,
    pub(crate) prompt_package_digest: String,
    pub(crate) browser: serde_json::Value,
    pub(crate) navigation_evidence: Option<Evidence>,
    pub(crate) arms: BTreeMap<String, Arm>,
    pub(crate) startup_seconds: u64,
    pub(crate) continuation_poll_ms: u64,
    pub(crate) settle_seconds: u64,
    pub(crate) action_policy: String,
    pub(crate) cash_cap_microusd: u64,
    pub(crate) campaign_id: String,
    pub(crate) cash_ledger: PathBuf,
    pub(crate) clock_tolerance_ms: u64,
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
            if arm.role != "browser_planner" {
                return Err("browser_planner_role_required".into());
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
                .ladder(ModelRole::BrowserPlanner)
                .ok_or("planner_model_unbound")?;
            if ladder.len() != 1 {
                return Err("planner_single_pin_required".into());
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
            // The head's seat and the precision band's both speak the System
            // One wire, so each goes through its own `system_one` gate route.
            for (table, seat) in [
                ("system_one", &models.decisions.system_one),
                ("precision", &models.decisions.precision),
            ] {
                let Some(seat) = seat else { continue };
                let wire = format!("{}-{}", seat.model, seat.version);
                let route = system_one_seat_route(&arm.routes, table, &wire, &seat.endpoint)?;
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
/// The `system_one` gate route the seat of `table` goes through: the route
/// for its wire model whose local endpoint is the seat's endpoint. The head's
/// seat and the precision band's may name one wire model behind two gates;
/// each then goes through its own route.
fn system_one_seat_route<'r>(
    routes: &'r [Route],
    table: &str,
    wire: &str,
    endpoint: &str,
) -> Result<&'r Route> {
    let mut wired = routes
        .iter()
        .filter(|r| r.protocol == "system_one" && r.requested_model == wire)
        .peekable();
    if wired.peek().is_none() {
        return Err(format!("{table}_gate_unavailable"));
    }
    wired
        .find(|r| endpoint == format!("{}/v1/systemone", r.local_url()))
        .ok_or_else(|| format!("{table}_gate_bypass"))
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

#[cfg(test)]
mod tests {
    use super::{Route, system_one_seat_route};

    fn system_one_route(provider: &str, listen_port: u16) -> Route {
        serde_json::from_value(serde_json::json!({
            "provider": provider,
            "engine_model": "d3/flash@r1",
            "requested_model": "d3-flash-r1",
            "returned_model": "d3-flash-r1",
            "upstream": "https://systemone.invalid",
            "listen_port": listen_port,
            "protocol": "system_one",
            "cash": false,
            "max_context_tokens": 8192,
            "input_overhead_tokens": 0,
            "max_output_tokens": 256,
            "max_request_bytes": 65536,
            "max_response_bytes": 65536,
            "max_images": 0,
            "timeout_seconds": 30,
        }))
        .expect("a system_one gate route")
    }

    #[test]
    fn two_seats_on_one_wire_model_each_take_their_own_gate_route() {
        let routes = [
            system_one_route("head-gate", 9101),
            system_one_route("precision-gate", 9102),
        ];
        let head = system_one_seat_route(
            &routes,
            "system_one",
            "d3-flash-r1",
            "http://127.0.0.1:9101/v1/systemone",
        )
        .expect("the head's route");
        let precision = system_one_seat_route(
            &routes,
            "precision",
            "d3-flash-r1",
            "http://127.0.0.1:9102/v1/systemone",
        )
        .expect("the precision seat's route");
        assert_eq!(head.listen_port, 9101);
        assert_eq!(precision.listen_port, 9102);
    }

    #[test]
    fn a_seat_past_every_gate_of_its_wire_model_is_a_bypass() {
        let routes = [system_one_route("head-gate", 9101)];
        assert_eq!(
            system_one_seat_route(
                &routes,
                "precision",
                "d3-flash-r1",
                "http://127.0.0.1:9199/v1/systemone",
            )
            .err(),
            Some("precision_gate_bypass".to_owned())
        );
        assert_eq!(
            system_one_seat_route(
                &routes,
                "precision",
                "d3-other-r1",
                "http://127.0.0.1:9101/v1/systemone",
            )
            .err(),
            Some("precision_gate_unavailable".to_owned())
        );
    }
}
