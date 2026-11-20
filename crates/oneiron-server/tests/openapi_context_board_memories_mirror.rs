//! The served OpenAPI document's MEMORIES mirror (`ContextBoardMemories`)
//! names every key a served `oneiron::MemoriesSection` carries, with its
//! disclosure block and its cut counts set, and the mirrors those two refer
//! to name every key theirs carry (FIX
//! CONTEXT-BOARD-MEMORIES-SCHEMA-OMITS-DISCLOSURE-AND-CUT). A client built
//! from the document then sees both.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::Value;
use tower::ServiceExt;

/// The served section keys the engine skips when empty, with the component
/// each one's mirror refers to.
const OPTIONAL_KEYS: [(&str, &str); 2] = [
    ("disclosure", "CoreDisclosureAssembly"),
    ("cut", "ContextBoardMemoriesCut"),
];

fn app() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
    );
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server"),
    );
    // A hatch server answers only callers on this device: each request
    // comes from a loopback peer.
    let loopback = ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0)));
    (dir, build_app(server).layer(Extension(loopback)))
}

async fn served_spec(app: &Router) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .expect("OpenAPI request"),
        )
        .await
        .expect("serve OpenAPI");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("OpenAPI body");
    serde_json::from_slice(&body).expect("OpenAPI JSON")
}

/// A MEMORIES section as the engine serves it with every optional key it
/// can carry: a disclosure block naming its home vault, and a cut in each
/// slot.
fn full_section() -> Value {
    let mut section = oneiron::MemoriesSection::pins_only(Some(oneiron::DisclosureAssembly {
        emit_stamp: String::new(),
        mode: "absence_clamp".to_owned(),
        notice: None,
        interlocutors: Vec::new(),
        clamped_out: 1,
        home: Some("ab".repeat(32)),
    }));
    section.cut.claims = 1;
    section.cut.turns = 1;
    section.cut.summaries = 1;
    section.cut.facets = 1;
    section.cut.other = 1;
    serde_json::to_value(&section).expect("serialize the MEMORIES section")
}

fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("an object, got {value}"))
        .keys()
        .cloned()
        .collect()
}

fn schema<'a>(spec: &'a Value, name: &str) -> &'a Value {
    let schema = &spec["components"]["schemas"][name];
    assert!(
        schema.is_object(),
        "the served document has no {name} schema"
    );
    schema
}

/// The served keys `value` carries that the component `name` names no
/// property for.
fn unmirrored(spec: &Value, name: &str, value: &Value) -> Vec<String> {
    let properties = &schema(spec, name)["properties"];
    let mirrored = if properties.is_object() {
        keys(properties)
    } else {
        BTreeSet::new()
    };
    keys(value).difference(&mirrored).cloned().collect()
}

/// The component a property refers to, directly or through a nullable
/// `oneOf`.
fn referred_component(property: &Value) -> Option<String> {
    match property {
        Value::Object(fields) => fields
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|target| target.strip_prefix("#/components/schemas/"))
            .map(str::to_owned)
            .or_else(|| fields.values().find_map(referred_component)),
        Value::Array(items) => items.iter().find_map(referred_component),
        _ => None,
    }
}

#[tokio::test]
async fn the_memories_mirror_names_every_key_a_served_section_carries() {
    let (_dir, app) = app();
    let spec = served_spec(&app).await;
    let section = full_section();
    for (key, _) in OPTIONAL_KEYS {
        assert!(
            section.get(key).is_some(),
            "FIXTURE: the served section carries `{key}`"
        );
    }
    let missing = unmirrored(&spec, "ContextBoardMemories", &section);
    assert!(
        missing.is_empty(),
        "ContextBoardMemories names no property for the served keys {missing:?}"
    );
    let required = &schema(&spec, "ContextBoardMemories")["required"];
    for (key, _) in OPTIONAL_KEYS {
        assert!(
            !required
                .as_array()
                .is_some_and(|names| names.iter().any(|name| name == key)),
            "`{key}` is absent from a section that has none, so the mirror must not require it"
        );
    }
}

#[tokio::test]
async fn the_disclosure_and_cut_mirrors_name_every_key_theirs_carry() {
    let (_dir, app) = app();
    let spec = served_spec(&app).await;
    let section = full_section();
    for (key, component) in OPTIONAL_KEYS {
        let property = &schema(&spec, "ContextBoardMemories")["properties"][key];
        assert_eq!(
            referred_component(property).as_deref(),
            Some(component),
            "ContextBoardMemories.{key} refers to {component}: {property}"
        );
        let missing = unmirrored(&spec, component, &section[key]);
        assert!(
            missing.is_empty(),
            "{component} names no property for the served `{key}` keys {missing:?}"
        );
    }
}
