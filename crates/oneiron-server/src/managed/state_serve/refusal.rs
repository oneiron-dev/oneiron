//! The body a frozen engine's refusal is served with.

use super::REAP_PAUSE_REFUSAL;
use crate::managed::ManagedError;

/// [`writes_frozen_response`](super::ingress::writes_frozen_response)'s body.
pub(super) fn writes_frozen_body(error: &ManagedError) -> serde_json::Value {
    let refusal = REAP_PAUSE_REFUSAL;
    serde_json::json!({
        "error": refusal.error,
        "message": error.to_string(),
        "bound": refusal.bound,
        "temporary": refusal.temporary,
        "affected": ["effects", "non_safe_method_requests", "upgrades", "background_passes"],
        "resumes_on": refusal.resumes_on,
        "self_hosted": {
            "supported": refusal.self_hosted_supported,
            "condition": "no_service_reap_limit",
        },
    })
}
