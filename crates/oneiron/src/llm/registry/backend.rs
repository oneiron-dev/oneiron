//! Backend-specific serving identities and prices. Unknown serving details stay unknown.

#[doc(hidden)]
pub use oneiron_verb_wire::llm::registry::backend::{
    ModelBackendPin, ModelCostReceipt, PricedModelBackend, catalog_usage_cost,
};
