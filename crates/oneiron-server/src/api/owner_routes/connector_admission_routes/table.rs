//! The `/v1/owner` routes [`super`] serves, one row per method and path:
//! the router and the OpenAPI document read this one table (FIX 8931).

use axum::routing::{get, post};

use super::super::{OwnerRoute, OwnerTable};
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
            },
            post(register),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/connectors/setup",
                summary: "The connector's key, its admission state and its grant slate, for a resumed setup.",
                row: None,
            },
            get(setup),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/slate/accept",
                summary: "The owner's stamp on the connector's slate, at the revision reviewed.",
                row: None,
            },
            post(accept),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/qualify",
                summary: "Runs the probe suite through the installed endpoint with the owner's kit, activates the key, and approves the exact manifest the suite ran on.",
                row: None,
            },
            post(qualify),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/attest",
                summary: "The owner attests a pending connector the probe suite cannot grade (CONNECTOR-QUALIFY = A): its tools must still match the stamped slate, and the key activates with an owner-attested receipt.",
                row: None,
            },
            post(attest),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/refresh",
                summary: "Lists the connector's tools again, at its pinned revision while it still answers that one.",
                row: None,
            },
            post(refresh),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/enabled",
                summary: "The owner's on/off switch for an admitted connector.",
                row: None,
            },
            post(enabled),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/proxy",
                summary: "Admits the OpenAI proxy for one paired actor.",
                row: Some("vault.connectors.proxy.admit"),
            },
            post(proxy),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/proxy/revoke-write",
                summary: "Revokes only the proxy remember grant at the reviewed key and slate revision, preserving read access and stored memory.",
                row: Some("vault.connectors.proxy.revoke_write"),
            },
            post(revoke_proxy_write),
        ),
    ]
}
