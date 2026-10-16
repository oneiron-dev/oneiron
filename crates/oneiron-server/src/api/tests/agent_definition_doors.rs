//! A `core:write` credential below owner grade turns no agent definition back
//! on: over `POST /v1/core/batch` or the `remember` verb it may not re-enable,
//! re-approve or reactivate a stored definition, nor bring a deleted one back
//! on. Turning a definition off stays open to it; an owner-grade credential
//! turns it back on.
use super::*;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;

const WRITER: &str = "scope=core:read,core:write";

fn running_definition() -> AgentDefinition {
    AgentDefinition::new(
        "custom.revocable",
        "Revocation fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(Vec::new()),
        None,
        true,
        None,
    )
}

/// The stored body as the JSON a core put carries.
fn json_of(value: &rmpv::Value) -> Value {
    match value {
        rmpv::Value::Nil => Value::Null,
        rmpv::Value::Boolean(flag) => Value::from(*flag),
        rmpv::Value::Integer(n) => n
            .as_i64()
            .map_or_else(|| Value::from(n.as_u64().expect("integer")), Value::from),
        rmpv::Value::F32(n) => Value::from(f64::from(*n)),
        rmpv::Value::F64(n) => Value::from(*n),
        rmpv::Value::String(text) => Value::from(text.as_str().expect("utf-8")),
        rmpv::Value::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        rmpv::Value::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("an AGENT_DEF body holds no {other:?}"),
    }
}

fn entity(id: &oneiron::EntityId, definition: &AgentDefinition) -> Value {
    let bytes = oneiron::agent_def::encode_agent_definition(definition).expect("encode");
    let body = rmpv::decode::read_value(&mut bytes.as_slice()).expect("decode");
    json!({ "id": id.to_hex(), "entity_type": ENTITY_TYPE_AGENT_DEF, "body": json_of(&body) })
}

async fn post(server: &Arc<SyncServer>, credential: &str, uri: &str, body: Value) -> StatusCode {
    let mut request = json_request("POST", uri, body);
    request
        .headers_mut()
        .insert(AUTHORIZATION, credential.parse().expect("header"));
    let (status, body) = route_json(server.clone(), request).await;
    if status == StatusCode::FORBIDDEN {
        assert_error_envelope(&body, "FORBIDDEN");
    }
    status
}

async fn batch(
    server: &Arc<SyncServer>,
    credential: &str,
    id: &oneiron::EntityId,
    definition: &AgentDefinition,
) -> StatusCode {
    let body = json!({ "entities": [entity(id, definition)] });
    post(server, credential, "/v1/core/batch", body).await
}

async fn remember(
    server: &Arc<SyncServer>,
    credential: &str,
    id: &oneiron::EntityId,
    definition: &AgentDefinition,
) -> StatusCode {
    let body = json!({ "entity": entity(id, definition) });
    post(server, credential, "/v1/core/memory/verbs/remember", body).await
}

fn stored(server: &SyncServer, id: &oneiron::EntityId) -> Option<AgentDefinition> {
    server.vault().get_agent_definition(id).expect("read")
}

fn next(
    definition: &AgentDefinition,
    version: &str,
    edit: impl FnOnce(&mut AgentDefinition),
) -> AgentDefinition {
    let mut next = definition.clone();
    next.version = version.to_owned();
    edit(&mut next);
    next
}

/// Each switch moved back on, from a definition turned off.
fn widenings() -> [(&'static str, fn(&mut AgentDefinition)); 4] {
    [
        ("enabled", |def| def.enabled = true),
        ("re-proposed", |def| {
            def.approval_status = ClaimApprovalStatus::Proposed;
        }),
        ("approved", |def| {
            def.approval_status = ClaimApprovalStatus::Approved;
        }),
        ("active", |def| {
            def.lifecycle_status = ClaimLifecycleStatus::Active;
        }),
    ]
}

#[derive(Debug, Clone, Copy)]
enum Door {
    Batch,
    Remember,
}

async fn put(
    door: Door,
    server: &Arc<SyncServer>,
    credential: &str,
    id: &oneiron::EntityId,
    definition: &AgentDefinition,
) -> StatusCode {
    match door {
        Door::Batch => batch(server, credential, id, definition).await,
        Door::Remember => remember(server, credential, id, definition).await,
    }
}

/// A fresh definition seeded running, then turned off by `writer`: every
/// restrictive move stays open below owner grade.
async fn revoked_definition(
    server: &Arc<SyncServer>,
    writer: &str,
) -> (oneiron::EntityId, AgentDefinition) {
    let id = oneiron::EntityId::now();
    let now = server.vault().now_recorded_at();
    let running = running_definition();
    server
        .vault()
        .put_agent_definition(
            &id,
            &running,
            oneiron::TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect("seed");
    let revoked = next(&running, "1.0.1", |def| {
        def.enabled = false;
        def.approval_status = ClaimApprovalStatus::Rejected;
        def.lifecycle_status = ClaimLifecycleStatus::Retracted;
    });
    assert_eq!(batch(server, writer, &id, &revoked).await, StatusCode::OK);
    assert_eq!(stored(server, &id), Some(revoked.clone()));
    (id, revoked)
}

#[tokio::test]
async fn below_owner_grade_no_core_put_turns_an_agent_definition_back_on() {
    let (_dir, server) = auth_test_server();
    let writer = test_bearer(WRITER);
    let mut let_through = Vec::new();
    for door in [Door::Batch, Door::Remember] {
        for (move_name, widen) in widenings() {
            let (id, revoked) = revoked_definition(&server, &writer).await;
            let status = put(door, &server, &writer, &id, &next(&revoked, "1.0.2", widen)).await;
            if status != StatusCode::FORBIDDEN || stored(&server, &id) != Some(revoked) {
                let_through.push(format!("{door:?} {move_name}: {status}"));
            }
        }
        // Deleted below owner grade, a definition does not come back on there.
        let (id, _) = revoked_definition(&server, &writer).await;
        let delete = json!({ "id": id.to_hex() });
        let deleted = post(&server, &writer, "/v1/core/memory/verbs/delete", delete).await;
        assert_eq!(deleted, StatusCode::OK);
        let recreated = next(&running_definition(), "1.0.4", |_| {});
        let status = put(door, &server, &writer, &id, &recreated).await;
        if status != StatusCode::FORBIDDEN
            || matches!(server.vault().get_agent_definition(&id), Ok(Some(_)))
        {
            let_through.push(format!("{door:?} recreated: {status}"));
        }
    }
    assert!(
        let_through.is_empty(),
        "below owner grade, these turned a definition back on: {let_through:#?}"
    );

    // The owner turns one back on.
    let (id, _) = revoked_definition(&server, &writer).await;
    let restored = next(&running_definition(), "1.0.3", |_| {});
    assert_eq!(
        batch(&server, &owner_bearer(), &id, &restored).await,
        StatusCode::OK
    );
    assert_eq!(stored(&server, &id), Some(restored));
}
