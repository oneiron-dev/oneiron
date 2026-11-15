//! Adapts the unchanged native route to the same JSON shape as the crate adapter.

use oneiron::Vault;
use oneiron::test_doors::extraction_routing::native_routes;
use oneiron_dreamer::extraction_selection::ExtractionSelectionConfig;
use oneiron_remote::OneironClient;
use serde_json::{Value, json};

/// Returns native route choices without invoking a lender or writing any candidate.
pub(crate) fn routes(
    vault: &Vault,
    _client: &OneironClient,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
    _config: &ExtractionSelectionConfig,
    _policy_pin: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let native = native_routes(vault, attempt, now_ms, operands)?;
    let candidates = native["candidates"]
        .as_array()
        .ok_or("missing native candidates")?;
    let index_of = |claim: &Value| -> Result<usize, Box<dyn std::error::Error>> {
        let row = candidates
            .iter()
            .find(|row| row["claim"] == *claim)
            .ok_or("unknown native claim")?;
        Ok(usize::try_from(
            row["index"].as_u64().ok_or("missing native index")?,
        )?)
    };
    let mut attachment_heads = Vec::new();
    let mut own_claims = Vec::new();
    for choice in native["choices"]
        .as_array()
        .ok_or("missing native choices")?
    {
        match choice["kind"].as_str() {
            Some("attach") => attachment_heads.push(choice["head"].clone()),
            Some("new") => own_claims.push(index_of(&choice["claim"])?),
            Some("already_represented") => {}
            _ => return Err("unknown native choice".into()),
        }
    }
    let mut judge_sets = Vec::new();
    for set in native["judge_sets"]
        .as_array()
        .ok_or("missing native judge sets")?
    {
        let indexes: Vec<usize> = set["candidate_claims"]
            .as_array()
            .ok_or("missing native members")?
            .iter()
            .map(index_of)
            .collect::<Result<_, _>>()?;
        judge_sets.push(json!({"candidate_indexes": indexes, "prior_heads": set["prior_heads"]}));
    }
    Ok(
        json!({"attachment_heads": attachment_heads, "own_claims": own_claims,
        "judge_sets": judge_sets}),
    )
}
