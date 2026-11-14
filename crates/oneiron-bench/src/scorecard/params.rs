//! The `oneiron.retrieval_eval_params.v1` eval params file: blend weights for one run.
//!
//! `--params` omitted resolves to the learned table, the same digest an explicit
//! `"learned_table"` gives. The resolved file maps to the eval weight source.

use oneiron::pipeline::BlendWeightsSource;
use oneiron::store::RetrievalBlendWeights;

use super::ScorecardFailure;

/// The contract string every eval params file carries.
pub(crate) const PARAMS_CONTRACT: &str = "oneiron.retrieval_eval_params.v1";

/// The params of one run: the eval weight source and the digest over the resolved file.
pub(crate) struct ResolvedParams {
    /// Where the run's blend weights come from.
    pub(crate) source: BlendWeightsSource,
    /// The digest over the resolved params file.
    pub(crate) digest: String,
    /// The exact JSON object the digest is computed over.
    pub(crate) resolved: serde_json::Value,
}

/// The pinned object form of `blend_weights`: all five signals.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedWeights {
    recency: f64,
    salience: f64,
    confidence: f64,
    gravity: f64,
    relevance: f64,
}

impl PinnedWeights {
    /// Every weight, in `RetrievalBlendWeights::new` order, for the shared checks.
    fn all(&self) -> [(&str, f64); 5] {
        [
            ("recency", self.recency),
            ("salience", self.salience),
            ("confidence", self.confidence),
            ("gravity", self.gravity),
            ("relevance", self.relevance),
        ]
    }
}

/// Resolve `--params` (or its absence) into the eval weight source and the digest.
pub(crate) fn resolve(params: Option<&str>) -> Result<ResolvedParams, ScorecardFailure> {
    let Some(path) = params else {
        let resolved = serde_json::json!({
            "contract": PARAMS_CONTRACT,
            "blend_weights": "learned_table",
        });
        return Ok(ResolvedParams {
            source: BlendWeightsSource::LearnedTable,
            digest: params_digest(&resolved)?,
            resolved,
        });
    };
    let bytes = std::fs::read(path)
        .map_err(|error| ScorecardFailure::Input(format!("params read failed: {error}")))?;
    let file: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| ScorecardFailure::Input(format!("params parse failed: {error}")))?;
    let Some(object) = file.as_object() else {
        return Err(ScorecardFailure::Input(
            "params file must be a JSON object".to_owned(),
        ));
    };
    if object.contains_key("retrieval_params") {
        return Err(ScorecardFailure::Input(
            "retrieval_params arrives with L9-03; this file takes blend_weights only".to_owned(),
        ));
    }
    match object.get("contract").and_then(serde_json::Value::as_str) {
        Some(PARAMS_CONTRACT) => {}
        Some(found) => {
            return Err(ScorecardFailure::Input(format!("wrong contract: {found}")));
        }
        None => {
            return Err(ScorecardFailure::Input(
                "params file needs its contract".to_owned(),
            ));
        }
    }
    for key in object.keys() {
        if key != "contract" && key != "blend_weights" {
            return Err(ScorecardFailure::Input(format!(
                "unknown params field: {key}"
            )));
        }
    }
    let (source, blend) = match object.get("blend_weights") {
        None => (
            BlendWeightsSource::LearnedTable,
            serde_json::Value::from("learned_table"),
        ),
        Some(serde_json::Value::String(named)) if named == "learned_table" => (
            BlendWeightsSource::LearnedTable,
            serde_json::Value::from("learned_table"),
        ),
        Some(serde_json::Value::String(named)) => {
            return Err(ScorecardFailure::Input(format!(
                "unknown blend_weights: {named}"
            )));
        }
        Some(blend @ serde_json::Value::Object(_)) => {
            let pinned: PinnedWeights = serde_json::from_value(blend.clone())
                .map_err(|error| ScorecardFailure::Input(format!("bad blend_weights: {error}")))?;
            (pinned_source(&pinned)?, blend.clone())
        }
        Some(_) => {
            return Err(ScorecardFailure::Input(
                "blend_weights must be learned_table or an object".to_owned(),
            ));
        }
    };
    let resolved = serde_json::json!({
        "contract": PARAMS_CONTRACT,
        "blend_weights": blend,
    });
    Ok(ResolvedParams {
        source,
        digest: params_digest(&resolved)?,
        resolved,
    })
}

/// The pinned weights as the eval source, after the finite and range checks.
fn pinned_source(pinned: &PinnedWeights) -> Result<BlendWeightsSource, ScorecardFailure> {
    let mut narrow = [0.0f32; 5];
    for (slot, (name, value)) in narrow.iter_mut().zip(pinned.all()) {
        if !value.is_finite() || value < 0.0 {
            return Err(ScorecardFailure::Input(format!(
                "blend weight {name} must be finite and >= 0.0"
            )));
        }
        let cast = value as f32;
        if !cast.is_finite() {
            return Err(ScorecardFailure::Input(format!(
                "blend weight {name} does not fit an f32"
            )));
        }
        *slot = cast;
    }
    Ok(BlendWeightsSource::Pinned(RetrievalBlendWeights::new(
        narrow[0], narrow[1], narrow[2], narrow[3], narrow[4],
    )))
}

/// The params digest: sha256 over the canonical bytes of the resolved file.
fn params_digest(resolved: &serde_json::Value) -> Result<String, ScorecardFailure> {
    let canonical = serde_json_canonicalizer::to_vec(resolved)
        .map_err(|error| ScorecardFailure::Run(format!("params digest failed: {error}")))?;
    Ok(oneiron_ruler::pack::sha256_hex(&canonical))
}
