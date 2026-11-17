//! Adapts crate routing to the same small JSON shape as the native red adapter.

use oneiron::Vault;
use oneiron_dreamer::extraction_routing::{Route, observe_and_route};
use oneiron_dreamer::extraction_selection::ExtractionSelectionConfig;
use oneiron_remote::OneironClient;
use serde_json::{Value, json};

/// Returns route choices without invoking a lender or writing any candidate.
pub(crate) fn routes(
    _vault: &Vault,
    client: &OneironClient,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
    config: &ExtractionSelectionConfig,
    policy_pin: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (_, plan) = observe_and_route(client, attempt, now_ms, operands, config, policy_pin)?;
    let mut attachment_heads = Vec::new();
    let mut own_claims = Vec::new();
    for candidate in &plan.routes {
        match &candidate.choice {
            Route::Attach { head } => attachment_heads.push(head.clone()),
            Route::New | Route::ObservedBeside { .. } => {
                own_claims.push(candidate.representative_index);
            }
            Route::Judge { .. } | Route::AlreadyRepresented { .. } => {}
        }
    }
    Ok(json!({
        "attachment_heads": attachment_heads,
        "own_claims": own_claims,
        "judge_sets": plan.judge_sets.iter().map(|set| json!({
            "candidate_indexes": set.candidate_indexes, "prior_heads": set.prior_heads,
        })).collect::<Vec<_>>(),
    }))
}
