//! The typed refusals of the direct error vocabulary (FIX 6032). Each keeps
//! the 403 its route answered with as a generic `FORBIDDEN` and names its own
//! code, its bound (`requiredScope`) and its way out. Kept apart from
//! `error/mod.rs` so that file stays under the giant-file bar.

use super::{ApiError, ApiErrorDetails};

/// The wire code of a courtesy deletion whose signed body did not
/// authenticate (CALLS `COURTESY_DELETE_REFUSAL_CODE`).
pub(super) const COURTESY_DELETE_REFUSAL_CODE: &str = "COURTESY_DELETE_UNAUTHENTICATED";

/// The wire code of a control credential that does not grant the control
/// operation it asked for (CALLS `CONTROL_SCOPE_REFUSAL_CODE`).
pub(super) const CONTROL_SCOPE_REFUSAL_CODE: &str = "CONTROL_SCOPE_DENIED";

/// The support-grant refusal's guidance, the words the engine's own
/// `HOST_ACTION_REQUIRES_SUPPORT_GRANT` carries on the facade.
const SUPPORT_GRANT_SUGGESTION: &str = "Ask the customer for a support grant; the operator's own admin commands (status, backup, restore, repair, move) need none.";

impl ApiError {
    /// FIX 2222: a host credential where no host acts as a person, in the
    /// engine's words; its bound is the customer's support grant.
    pub(crate) fn host_action_requires_support_grant(message: impl Into<String>) -> Self {
        Self::new(
            message,
            ApiErrorDetails::HostActionRequiresSupportGrant {
                required_scope: Some("support_grant".to_owned()),
            },
            [SUPPORT_GRANT_SUGGESTION],
        )
    }

    /// The authority log's refusal of this actor the act, with the engine's
    /// own words and suggestions, bound to `required_scope`.
    pub(crate) fn owner_binding_required(
        message: impl Into<String>,
        required_scope: Option<&str>,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new(
            message,
            ApiErrorDetails::OwnerBindingRequired {
                required_scope: required_scope.map(str::to_owned),
            },
            suggestions,
        )
    }

    /// A courtesy deletion's signed body names no pact with its sender, or
    /// does not verify against the key that pact pinned. One refusal for
    /// both, so the sender learns neither.
    pub(crate) fn courtesy_delete_unauthenticated() -> Self {
        Self::new(
            "courtesy deletion is not authenticated: no pact with this sender, or the signed \
             body does not verify against the key it pinned",
            ApiErrorDetails::CourtesyDeleteUnauthenticated {
                required_scope: Some("signed_pact_proof".to_owned()),
            },
            ["Resend a valid signed request against the pact key."],
        )
    }

    /// A control credential whose scopes do not grant `operation`
    /// (`control:verify`, `control:rotate` or `control:revoke`).
    pub(crate) fn control_scope_denied(operation: &str) -> Self {
        Self::new(
            format!("control credential does not grant {operation}"),
            ApiErrorDetails::ControlScopeDenied {
                required_scope: Some(operation.to_owned()),
            },
            ["Use a control credential that grants this operation."],
        )
    }
}
