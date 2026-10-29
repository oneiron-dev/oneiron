//! The OpenAPI schemas of `POST /v1/owner/identity/asks/answer` (FIX 11611),
//! `POST /v1/owner/proactivity/action-mode`, the two
//! `POST /v1/owner/representation/*` writes, `POST /v1/owner/stewardship`,
//! `POST /v1/owner/self-heal/findings/label` (FIX 11611 part D) and
//! `POST /v1/owner/proactivity/digest/assemble` (FIX 11654).
//! [`super`] is already past the file-size bar, so their schema fns live
//! here, beside the route files' own.

use oneiron::dreamer_runner::maintenance::action_mode::ActionModePolicy;
use oneiron::dreamer_runner::maintenance::identity::IdentitySettled;
use oneiron::dreamer_runner::maintenance::stewardship::StewardshipRules;
use oneiron::self_heal::distillation::ReviewedFinding;

use super::{
    AnswerIdentityAsk, ApproveRepresentation, ApprovedView, DeclineRepresentation, DigestView,
    LabelFinding, SetActionMode, SetStewardship,
};

/// The OpenAPI schema of `POST /v1/owner/identity/asks/answer`'s body
/// (FIX 11611): [`AnswerIdentityAsk`].
pub(crate) fn answer_identity_ask_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AnswerIdentityAsk>()
}

/// The OpenAPI schema of `POST /v1/owner/identity/asks/answer`'s answer
/// (FIX 11611): [`IdentitySettled`].
pub(crate) fn identity_settled_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<IdentitySettled>()
}

/// The OpenAPI schema of `POST /v1/owner/proactivity/action-mode`'s body
/// (FIX 11611): [`SetActionMode`].
pub(crate) fn set_action_mode_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SetActionMode>()
}

/// The OpenAPI schema of `POST /v1/owner/proactivity/action-mode`'s answer
/// (FIX 11611): the policy, or `null` when none is set.
pub(crate) fn action_mode_policy_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Option<ActionModePolicy>>()
}

/// The OpenAPI schema of `POST /v1/owner/representation/approve`'s body
/// (FIX 11611): [`ApproveRepresentation`].
pub(crate) fn approve_representation_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ApproveRepresentation>()
}

/// The OpenAPI schema of `POST /v1/owner/representation/approve`'s answer
/// (FIX 11611): [`ApprovedView`].
pub(crate) fn representation_approved_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ApprovedView>()
}

/// The OpenAPI schema of `POST /v1/owner/representation/decline`'s body
/// (FIX 11611): [`DeclineRepresentation`].
pub(crate) fn decline_representation_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DeclineRepresentation>()
}

/// The OpenAPI schema of `POST /v1/owner/representation/decline`'s answer
/// (FIX 11611): `null`.
pub(crate) fn representation_declined_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<()>()
}

/// The OpenAPI schema of `POST /v1/owner/stewardship`'s body (FIX 11611):
/// [`SetStewardship`].
pub(crate) fn set_stewardship_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SetStewardship>()
}

/// The OpenAPI schema of `POST /v1/owner/stewardship`'s answer (FIX 11611):
/// [`StewardshipRules`].
pub(crate) fn stewardship_rules_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<StewardshipRules>()
}

/// The OpenAPI schema of `POST /v1/owner/self-heal/findings/label`'s body (FIX 11611):
/// [`LabelFinding`].
pub(crate) fn label_finding_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LabelFinding>()
}

/// The OpenAPI schema of `POST /v1/owner/self-heal/findings/label`'s answer (FIX 11611):
/// [`ReviewedFinding`].
pub(crate) fn reviewed_finding_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ReviewedFinding>()
}

/// The OpenAPI schema of `POST /v1/owner/proactivity/digest/assemble`'s
/// answer (FIX 11611): the digest, or `null` when nothing is due.
pub(crate) fn digest_assembled_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Option<DigestView>>()
}
