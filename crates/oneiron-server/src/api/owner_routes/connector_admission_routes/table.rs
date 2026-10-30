//! The `/v1/owner` routes [`super`] serves, one row per method and path:
//! the router and the OpenAPI document read this one table (FIX 8931).

use axum::routing::{get, post};

use super::super::{OwnerRoute, OwnerTable, RestShape};
use super::schema::{
    accept_request_body_schema, admitted_slate_schema, attest_request_body_schema,
    connector_key_schema, enabled_request_body_schema, qualify_request_body_schema,
    refresh_request_body_schema, refreshed_schema, register_request_body_schema, registered_schema,
};
use super::{
    accept, attest, enabled, proxy, qualify, refresh, register, revoke_proxy_write, setup,
};

pub(in super::super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/register",
                summary: "Lists the connector's tools at its installed endpoint, screens and resolves them, drafts the grant slate and registers the key Pending at the negotiated revision.",
                row: None,
                shape: Some(RestShape::json(
                    register_request_body_schema,
                    registered_schema,
                )),
            },
            post(register),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/connectors/setup",
                summary: "The connector's key, its admission state and its grant slate, for a resumed setup.",
                row: None,
                shape: None,
            },
            get(setup),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/slate/accept",
                summary: "The owner's stamp on the connector's slate, at the revision reviewed.",
                row: None,
                shape: Some(RestShape::json(
                    accept_request_body_schema,
                    admitted_slate_schema,
                )),
            },
            post(accept),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/qualify",
                summary: "Runs the probe suite through the installed endpoint with the owner's kit, activates the key, and approves the exact manifest the suite ran on.",
                row: None,
                shape: Some(RestShape::json(
                    qualify_request_body_schema,
                    connector_key_schema,
                )),
            },
            post(qualify),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/attest",
                summary: "The owner attests a pending connector the probe suite cannot grade (CONNECTOR-QUALIFY = A): its tools must still match the stamped slate, and the key activates with an owner-attested receipt.",
                row: None,
                shape: Some(RestShape::json(
                    attest_request_body_schema,
                    connector_key_schema,
                )),
            },
            post(attest),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/refresh",
                summary: "Lists the connector's tools again, at its pinned revision while it still answers that one.",
                row: None,
                shape: Some(RestShape::json(
                    refresh_request_body_schema,
                    refreshed_schema,
                )),
            },
            post(refresh),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/enabled",
                summary: "The owner's on/off switch for an admitted connector.",
                row: None,
                shape: Some(RestShape::json(
                    enabled_request_body_schema,
                    connector_key_schema,
                )),
            },
            post(enabled),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/proxy",
                summary: "Admits the OpenAI proxy for one paired actor.",
                row: Some("vault.connectors.proxy.admit"),
                shape: None,
            },
            post(proxy),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/proxy/revoke-write",
                summary: "Revokes only the proxy remember grant at the reviewed key and slate revision, preserving read access and stored memory.",
                row: Some("vault.connectors.proxy.revoke_write"),
                shape: None,
            },
            post(revoke_proxy_write),
        ),
    ]
}
