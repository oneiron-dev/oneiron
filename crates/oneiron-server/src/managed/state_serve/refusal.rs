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

#[cfg(test)]
mod tests {
    use super::*;

    /// The managed HTTP body names the capacity bound and the self-host
    /// route, in the shape every other door serves (L9-61).
    #[test]
    fn the_managed_body_names_the_capacity_bound_and_the_self_host_route() {
        let body = writes_frozen_body(&ManagedError::WritesFrozen);
        assert_eq!(
            body["bound"],
            serde_json::json!({
                "kind": "capacity",
                "resource": "vault_lifecycle_allocation",
                "phase": "reap_prepare",
            })
        );
        assert_eq!(
            body["self_hosted"],
            serde_json::json!({"supported": true, "condition": "no_service_reap_limit"})
        );
        let message = body["message"].as_str().expect("message");
        assert!(message.contains("a capacity bound"), "{message}");
        assert!(message.contains("self-hosted vault"), "{message}");
    }
}
