//! The OpenAPI schemas of `POST /v1/owner/identity/asks/answer` and `POST
//! /v1/owner/self-heal/findings/label` (FIX 11611). [`super`] is already
//! past the file-size bar, so their schema fns live here, beside the route
//! files' own.

use oneiron::dreamer_runner::maintenance::identity::IdentitySettled;
use oneiron::self_heal::distillation::ReviewedFinding;

use super::{AnswerIdentityAsk, LabelFinding};

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
