//! Best-effort sizing from all sampled model rows; never a provider bound.
use oneiron::llm::manifest::ModelRole;
use serde_json::Value;

use super::Backend;

pub(super) struct FrameEstimate {
    windows: Vec<WindowEstimate>,
}

struct WindowEstimate {
    input_tokens: u64,
    tokens_per_o200k: f64,
    prompt: String,
}

impl FrameEstimate {
    pub(super) fn sample(backend: &Backend) -> Option<Self> {
        let role = ModelRole::GenerativeReasoner;
        let seat = backend.server.ai.seat(role)?;
        let mut models = seat.rung_models();
        models.extend(seat.fallback_rung_models());
        if models.is_empty() {
            return None;
        }
        let route = backend
            .server
            .ai
            .model_runtime()
            .route_role(&backend.server.vault, role, seat)
            .ok()?;
        // An off-seat manifest model may have a different prompt/ladder.
        // Without that inventory, do not call the known subset complete.
        if route.model != seat.model && !models.iter().any(|(model, _)| *model == route.model) {
            return None;
        }
        let mut windows = Vec::with_capacity(models.len());
        for (model, prompt) in models {
            let row = backend.server.vault.model_registry_row(&model).ok()??;
            if row.is_stale() {
                return None;
            }
            let tokens_per_o200k = row.tokens_per_o200k?;
            if !tokens_per_o200k.is_finite() || tokens_per_o200k <= 0.0 {
                return None;
            }
            let input_tokens = row
                .catalog
                .context_window_tokens
                .checked_sub(row.catalog.max_output_tokens?)?;
            if input_tokens == 0 {
                return None;
            }
            windows.push(WindowEstimate {
                input_tokens,
                tokens_per_o200k,
                prompt: prompt.unwrap_or_default(),
            });
        }
        Some(Self { windows })
    }

    pub(super) fn fits(&self, data: &Value, schema: &Value) -> bool {
        let data = data.to_string();
        let schema = schema.to_string();
        self.windows.iter().all(|window| {
            let framed = format!("{}\n{data}\n{schema}", window.prompt);
            let tokens = oneiron::count_context_pack_tokens(&framed) as f64;
            (tokens * window.tokens_per_o200k).ceil() <= window.input_tokens as f64
        })
    }
}
