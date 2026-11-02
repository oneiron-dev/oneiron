//! The OpenAPI schemas of the connector admission writes (FIX 11611):
//! `POST /v1/owner/connectors/register`, `/slate/accept`, `/qualify`,
//! `/refresh` and `/enabled`. [`super`] is already past the file-size bar,
//! so their schema fns live here, beside the route files' own.

use super::{
    AcceptRequest, AttestRequest, EnabledRequest, KeyView, QualifyRequest, RefreshRequest,
    Refreshed, RegisterRequest, Registered, SlateView,
};

/// The OpenAPI schema of `POST /v1/owner/connectors/register`'s body (FIX 11611):
/// [`RegisterRequest`].
pub(crate) fn register_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RegisterRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/register`'s answer (FIX 11611):
/// [`Registered`].
pub(crate) fn registered_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Registered>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/slate/accept`'s body (FIX 11611):
/// [`AcceptRequest`].
pub(crate) fn accept_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AcceptRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/slate/accept`'s answer (FIX 11611):
/// [`SlateView`].
pub(crate) fn admitted_slate_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SlateView>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/qualify`'s body (FIX 11611):
/// [`QualifyRequest`].
pub(crate) fn qualify_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<QualifyRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/attest`'s body
/// (CONNECTOR-QUALIFY = A): [`AttestRequest`]. Its answer is [`KeyView`].
pub(crate) fn attest_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AttestRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/qualify`'s answer (FIX 11611),
/// shared with `POST /v1/owner/connectors/enabled`: [`KeyView`].
pub(crate) fn connector_key_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<KeyView>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/refresh`'s body (FIX 11611):
/// [`RefreshRequest`].
pub(crate) fn refresh_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RefreshRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/refresh`'s answer (FIX 11611):
/// [`Refreshed`].
pub(crate) fn refreshed_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Refreshed>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/enabled`'s body (FIX 11611):
/// [`EnabledRequest`].
pub(crate) fn enabled_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EnabledRequest>()
}
