//! The body a frozen engine's refusal is served with.

use oneiron_vault_contract::CtlBound;

use super::REAP_PAUSE_REFUSAL;
use crate::managed::ManagedError;

/// The bound a reap pause names and its self-host route (L9-61, DEC-0005
/// #will-sweep: "Each refusal names the law, the provider term or the
/// capacity limit, and the self-host route"). One shape on every door that
/// serves the pause: the managed HTTP body, the facade body, the MCP
/// gateway's `error.data` and the voice hello's `refused` line each carry
/// `bound` and `self_hosted` beside their own code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ReapPauseBound {
    /// The bound's kind, the resource it bounds and the phase it holds in.
    pub(crate) bound: CtlBound,
    /// Whether the same act works on a self-hosted vault, and why.
    pub(crate) self_hosted: SelfHostedRoute,
}

/// Whether the same act works on a self-hosted vault, and the condition
/// that makes it so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SelfHostedRoute {
    pub(crate) supported: bool,
    pub(crate) condition: &'static str,
}

/// [`REAP_PAUSE_REFUSAL`]'s bound and self-host route: a self-hosted vault
/// has no service reap limit.
pub(crate) const REAP_PAUSE_BOUND: ReapPauseBound = ReapPauseBound {
    bound: REAP_PAUSE_REFUSAL.bound,
    self_hosted: SelfHostedRoute {
        supported: REAP_PAUSE_REFUSAL.self_hosted_supported,
        condition: "no_service_reap_limit",
    },
};

/// [`writes_frozen_response`](super::ingress::writes_frozen_response)'s body.
pub(super) fn writes_frozen_body(error: &ManagedError) -> serde_json::Value {
    let refusal = REAP_PAUSE_REFUSAL;
    serde_json::json!({
        "error": refusal.error,
        "message": error.to_string(),
        "bound": REAP_PAUSE_BOUND.bound,
        "temporary": refusal.temporary,
        "affected": ["effects", "non_safe_method_requests", "upgrades", "background_passes"],
        "resumes_on": refusal.resumes_on,
        "self_hosted": REAP_PAUSE_BOUND.self_hosted,
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
