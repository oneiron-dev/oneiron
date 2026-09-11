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
                "description": "Bearer credential for protected routes: the configured trust-root secret (owner-grade) or a minted `v2.<claims>.<mac>` scoped token. The protected legacy `/api/*` routes (all except the public `/api/health`), `/v1/consumer/*`, and `/v1/usage/*` all require an owner-grade credential; a scoped token is refused there with the same `UNAUTHORIZED` as an absent one, however wide its scopes. Scoped tokens are accepted only on the scoped `/v1/core/*` and `/v1/companion/*` routes, subject to the scopes the token names."
            }),
        );

    // One scheme covers every protected route: all of them are presented as
    // `Authorization: Bearer`. The grade required is per-route, not per-plane:
    // the legacy `/api/*` routes listed below demand an owner-grade
    // credential, and so do the `/v1/consumer/*` and `/v1/usage/*` routes,
    // which authenticate through the same `check_api_auth`. Scoped tokens
    // reach `/v1/core/*` and the companion control-plane routes, which read a
    // `CoreAuth` and enforce the scopes it names.
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
        ("/v1/consumer/usage", "get"),
        ("/v1/consumer/usage/details", "get"),
        ("/v1/consumer/top-up", "post"),
        ("/v1/usage/events", "post"),
        ("/v1/usage/tenants/{tenant_id}/rollup", "get"),
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
        ("/v1/core/memory/verbs/{verb}", "post"),
        ("/v1/core/outbound/capabilities", "get"),
        ("/v1/core/outbound/capabilities/{connector}", "get"),
        (
            "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
            "get",
        ),
        ("/v1/core/conversations", "get"),
        ("/v1/core/conversations", "post"),
        ("/v1/core/conversations/{conversation_id}/turns", "get"),
        ("/v1/core/conversations/{conversation_id}/turns", "post"),
        ("/v1/core/turns/{turn_id}", "get"),
        ("/v1/core/batch", "post"),
        ("/v1/core/turns/annotate", "get"),
        ("/v1/core/turns/annotate", "post"),
        ("/v1/companion/access-grants", "post"),
        ("/v1/companion/access-grants/{grant_id}/revoke", "post"),
        ("/v1/companion/profiles/{persona_ref}", "get"),
        ("/v1/companion/profiles/{persona_ref}", "post"),
        ("/v1/companion/register/records", "post"),
        ("/v1/companion/register/records/{record_id}", "get"),
        ("/v1/companion/register/records/{record_id}", "post"),
        ("/v1/companion/register/records/{record_id}/retire", "post"),
        (
            "/v1/companion/register/records/{record_id}/end-relationship",
            "post",
        ),
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
