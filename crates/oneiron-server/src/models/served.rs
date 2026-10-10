//! Which model actually answered: the receipt field a ladder fills in, and
//! what an answered call is charged.
// The ladder stamps the engine's key, so the charge rule reads what it wrote.
use oneiron::llm::FAILED_RUNGS_KEY;
use oneiron::llm::{BudgetDenied, BudgetGuard, BudgetLease, BudgetSettlement, LlmUsage};
use serde_json::{Map, Value as JsonValue};

/// Key inside a provider usage object naming the model the reply reported.
pub(crate) const SERVED_MODEL_KEY: &str = "served_model";

/// Settles an answered call by the engine's one rule
/// ([`oneiron::llm::answered_units`]): its tokens, or `floor` when it reports
/// none, plus `floor` for each rung that failed before it. Chat turns,
/// workflow steps and code mode all charge an answer this way.
pub(crate) fn settle_answered(
    guard: &BudgetGuard,
    lease: &BudgetLease,
    usage: &LlmUsage,
    floor: u64,
) -> Result<BudgetSettlement, BudgetDenied> {
    guard.settle_usage(lease, oneiron::llm::answered_units(usage, floor))
}

/// Stamps the model a reply names into its usage object, which the adapters
/// carry through as `LlmUsage::raw_provider`. A usage object that is not a
/// JSON object is left as it came.
pub(super) fn record_served_model(usage: Option<&mut JsonValue>, served: Option<JsonValue>) {
    let (Some(JsonValue::Object(usage)), Some(served)) = (usage, served) else {
        return;
    };
    usage.insert(SERVED_MODEL_KEY.to_owned(), served);
}

/// The receipt a ladder leaves on every answer: which rung served it, how
/// many rungs were tried and failed before it, and what the provider called
/// the model, beside the provider's own usage.
pub(super) fn served_receipt(
    provider: &str,
    requested: &str,
    rung: usize,
    failed_rungs: usize,
    raw_provider: JsonValue,
) -> JsonValue {
    let reported = raw_provider.get(SERVED_MODEL_KEY).cloned();
    let mut receipt = Map::new();
    receipt.insert("provider".into(), provider.into());
    receipt.insert("requested_model".into(), requested.into());
    receipt.insert("rung".into(), rung.into());
    receipt.insert(FAILED_RUNGS_KEY.into(), failed_rungs.into());
    if let Some(reported) = reported {
        receipt.insert("reported_model".into(), reported);
    }
    receipt.insert("usage".into(), raw_provider);
    JsonValue::Object(receipt)
}
