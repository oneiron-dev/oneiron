//! The Dreamer's tuning config, recorded as a versioned vault artifact so the
//! nightly harness self-audit (ARCH-0026 harness-maintenance) can see a
//! backbone or dial change. Recording never retunes anything: the audit only
//! files a retune proposal for the owner.

use std::collections::BTreeMap;

use oneiron::Vault;
use oneiron::dreamer_runner::maintenance::DreamerTuningConfig;

use super::dreamer::role_routes;
use crate::config::models::{DreamerSettings, role_key};
use crate::models::{ModelRuntime, Seat};

/// Records this host's Dreamer config. The backbone is each Dreamer role's
/// routed model; the prompt is named by hash, never stored; the thresholds
/// are the host's pass dials. The same config as the head writes nothing.
pub(super) fn record_tuning_config(
    vault: &Vault,
    runtime: &ModelRuntime,
    seat: &Seat,
    settings: &DreamerSettings,
    now: u64,
) -> anyhow::Result<()> {
    let routes = role_routes(runtime, vault, seat)
        .map_err(|(role, refusal)| anyhow::anyhow!("{}: {refusal:?}", role_key(role)))?;
    let backbone = routes
        .iter()
        .map(|(role, route)| format!("{}={}", role_key(*role), route.model))
        .collect::<Vec<_>>()
        .join(",");
    let task = settings
        .task_instruction
        .as_deref()
        .unwrap_or(oneiron::llm::decision::catalogue::TASK_REALIZE_INSTRUCTION);
    let prompts = settings
        .summary_instruction
        .iter()
        .map(|text| {
            format!(
                "summary_instruction:{}",
                blake3::hash(text.as_bytes()).to_hex()
            )
        })
        .chain(std::iter::once(format!(
            "task_instruction:{}",
            blake3::hash(task.as_bytes()).to_hex()
        )))
        .collect();
    // A sitting dial the host left unset is the vault's row, not this
    // host's: it is absent here (FIX 8600).
    #[allow(clippy::cast_precision_loss, reason = "dials far below 2^52")]
    let manifest_thresholds = [
        ("idle_floor_secs", settings.idle_floor_secs),
        ("session_ceiling_secs", settings.session_ceiling_secs),
        ("pass_budget_units", Some(settings.pass_budget_units)),
    ]
    .into_iter()
    .filter_map(|(name, value)| Some((name.to_owned(), value? as f64)))
    .collect::<BTreeMap<_, _>>();
    vault.record_dreamer_tuning_config(
        &DreamerTuningConfig {
            backbone,
            prompts,
            weights: BTreeMap::new(),
            manifest_thresholds,
        },
        now,
    )?;
    Ok(())
}
