//! Security-scheme wiring and schema property-description helper.

use serde_json::Value;
use serde_json::json;

pub(crate) fn set_schema_property_description(
    spec: &mut Value,
    schema_name: &str,
    property_name: &str,
    description: &str,
) {
    if let Some(property) = spec
        .get_mut("components")
        .and_then(Value::as_object_mut)
        .and_then(|components| components.get_mut("schemas"))
        .and_then(Value::as_object_mut)
        .and_then(|schemas| schemas.get_mut(schema_name))
        .and_then(Value::as_object_mut)
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut(property_name))
        .and_then(Value::as_object_mut)
    {
        property.insert("description".to_owned(), Value::from(description));
    }
}

pub(crate) fn add_security_scheme(spec: &mut Value) {
    let Some(components) = spec.get_mut("components").and_then(Value::as_object_mut) else {
        return;
    };
    components
        .entry("securitySchemes")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("OpenAPI securitySchemes must be an object")
        .insert(
            "CoreBearer".to_owned(),
            json!({
                "type": "http",
                "scheme": "bearer",
                "description": "Bearer credential for protected routes: a logged `v2.slip.*` capability slip with its holder proof in `x-oneiron-binding`. The issuer secret and device lease never authorize requests. The grade each route requires is per-route. The protected legacy `/api/*` routes (all except the public `/api/health`) and `/v1/usage/*` require an owner-grade credential; a scoped token is refused there with the same `UNAUTHORIZED` as an absent one, however wide its scopes. The `/v1/owner/*` routes admit only the vault's owner (its live human owner on an unattenuated owner slip, a self-hosted root acting through a host action, or a managed vault's attested live owner) and refuse anyone else with 403. Scoped tokens are accepted on the scoped routes, subject to the scopes the token names: `/v1/core/*` (the facade verb routes included), `/v1/companion/*`, `POST /v1/ai/anonymous-chat` (an authenticated credential holding Read; the turn keeps no memory, but the caller is not anonymous to the server), and the memory proxy `POST /v1/chat/completions`. The proxy admits a paired connector credential holding Read and Propose (or Write), narrowed by no more than the connector's world and landing facet, whose connector binds `vault.recall` and `vault.remember` and holds a live `openai_proxy` registration with a stamped grant slate; a managed vault's attested live owner needs no registration."
            }),
        );

    // One scheme covers every protected route: all of them are presented as
    // `Authorization: Bearer`. The grade required is per-route, not per-plane:
    // the legacy `/api/*` routes listed below demand an owner-grade
    // credential, and so do the `/v1/usage/*` routes,
    // which authenticate through the same `check_api_auth`; the `/v1/owner/*`
    // door admits only the vault's live owner. Scoped tokens reach
    // `/v1/core/*`, the companion control-plane routes, the anonymous-chat
    // route and the memory proxy, which read a `CoreAuth` (or resolve the
    // connector caller) and enforce the scopes it names.
    //
    // `/api/health` is absent from this list by design, not by omission: it is
    // public (it takes no `CoreAuth` and calls no `check_api_auth`), so
    // attaching `CoreBearer` to it would document a gate that does not exist.
    // Anything added here must actually authenticate.
    for (path, method) in [
        ("/api/openapi.json", "get"),
        ("/api/skills/oneiron.skills.md", "get"),
        ("/api/core/discover", "get"),
        ("/api/search/vector", "get"),
        ("/api/search/semantic", "post"),
        ("/api/search/text", "get"),
        ("/api/entity/{id}", "get"),
        ("/api/edges/{id}", "get"),
        ("/v1/usage/events", "post"),
        ("/v1/usage/owners/{owner}/vaults/{vault_id}/rollup", "get"),
        ("/api/lease/revoke", "post"),
        ("/v1/companion/memory/reason", "post"),
        ("/v1/core/query", "post"),
        ("/v1/core/context-pack", "post"),
        ("/v1/core/hydrate", "post"),
        ("/v1/core/batch/shortId/hydrate", "post"),
        ("/v1/core/run-tree", "get"),
        ("/v1/core/run-tree/observe", "get"),
        ("/v1/core/run-tree/intervene", "post"),
        ("/v1/core/memory/{id}/timeline", "get"),
        ("/v1/core/memory/{id}/watch", "get"),
        ("/v1/core/memory/{id}/watch", "put"),
        ("/v1/core/memory/{id}/watch", "delete"),
        ("/v1/core/memory/verbs/{verb}", "post"),
        ("/v1/core/outbound/capabilities", "get"),
        ("/v1/core/outbound/capabilities/{connector}", "get"),
        (
            "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
            "get",
        ),
        ("/v1/core/conversations/{conversation_id}/records", "post"),
        ("/v1/core/messages/{message}/reactions", "post"),
        ("/v1/core/conversations/{conversation_id}/records", "get"),
        ("/v1/core/conversations/{conversation_id}/canonical", "get"),
        (
            "/v1/core/conversations/{conversation_id}/records/{record}/thread",
            "get",
        ),
        (
            "/v1/core/conversations/{conversation_id}/records/{record}/thread",
            "post",
        ),
        ("/v1/core/conversations/{conversation_id}/head", "post"),
        ("/v1/core/conversations/{conversation_id}/scope", "post"),
        (
            "/v1/core/conversations/{conversation_id}/migrate-dag",
            "post",
        ),
        ("/v1/core/turns/{turn_id}/sub-sessions", "post"),
        ("/v1/core/turns/{turn_id}/sub-sessions", "get"),
        ("/v1/core/conversations/{conversation_id}/summaries", "post"),
        ("/v1/core/summaries/{summary_id}/covers", "get"),
        ("/v1/core/claims/{claim_id}/drill", "get"),
        ("/v1/core/conversations", "get"),
        ("/v1/core/conversations", "post"),
        ("/v1/core/conversations/{conversation_id}/turns", "get"),
        ("/v1/core/conversations/{conversation_id}/transcript", "get"),
        ("/v1/core/messages/{message}/result", "post"),
        ("/v1/core/conversations/{conversation_id}/turns", "post"),
        ("/v1/core/turns/{turn_id}", "get"),
        ("/v1/core/batch", "post"),
        ("/v1/core/turns/annotate", "get"),
        ("/v1/core/turns/annotate", "post"),
        ("/v1/companion/access-grants", "post"),
        ("/v1/companion/access-grants/{grant_id}/revoke", "post"),
        ("/v1/companion/profiles", "get"),
        ("/v1/companion/profiles/access-requests", "get"),
        ("/v1/companion/profiles/{person_ref}", "get"),
        ("/v1/companion/profiles/{person_ref}", "post"),
        ("/v1/owner/courtesy-delete/send", "post"),
        ("/v1/owner/courtesy-delete/sent", "get"),
        ("/v1/owner/courtesy-delete/incoming", "get"),
        ("/v1/owner/courtesy-delete/answer", "post"),
    ] {
        if let Some(operation) = spec
            .get_mut("paths")
            .and_then(Value::as_object_mut)
            .and_then(|paths| paths.get_mut(path))
            .and_then(Value::as_object_mut)
            .and_then(|path_item| path_item.get_mut(method))
            .and_then(Value::as_object_mut)
        {
            operation.insert("security".to_owned(), json!([{ "CoreBearer": [] }]));
        }
    }
}
