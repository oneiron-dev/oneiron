//! The OpenAPI schemas of `POST /v1/owner/identity/asks/answer` and
//! `POST /v1/owner/stewardship` (FIX 11611). [`super`] is already past the
//! file-size bar, so their schema fns live here, beside the route files' own.

use oneiron::dreamer_runner::maintenance::identity::IdentitySettled;
use oneiron::dreamer_runner::maintenance::stewardship::StewardshipRules;

use super::{AnswerIdentityAsk, SetStewardship};

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
