//! `POST /v1/core/context-pack` with `phonetic_vector`: the caller's vector
//! of a name searches the names the learned phonetic model embedded
//! (CROSS-ARCH-0013 `#ladder` rung 2), so a Latin-script name finds the
//! PERSON written in Han.

use super::*;
use oneiron::phonetic_learned::PhoneticEmbedder;

const MODEL: &str = "fixture-phonetic-v1";

/// The fixture model's vector of `name`: 小明 and Showming point nearly one
/// way, and every other name is orthogonal to both.
fn fixture_vector(name: &str) -> Vec<f32> {
    match name {
        "小明" => vec![1.0, 0.1, 0.0, 0.0],
        "Showming" => vec![1.0, 0.05, 0.05, 0.0],
        _ => vec![0.0, 0.0, 0.0, 1.0],
    }
}

struct FixtureModel;

impl PhoneticEmbedder for FixtureModel {
    fn model_id(&self) -> &str {
        MODEL
    }

    fn dimensions(&self) -> usize {
        4
    }

    fn locality(&self) -> oneiron::embed::EmbedderLocality {
        oneiron::embed::EmbedderLocality::OnDevice
    }

    fn embed_names(&self, names: &[&str]) -> oneiron::Result<Vec<Vec<f32>>> {
        Ok(names.iter().map(|name| fixture_vector(name)).collect())
    }
}

#[tokio::test]
async fn context_pack_phonetic_vector_reaches_the_learned_rung() {
    let (_dir, server) = auth_test_server();
    let person = |name: &str| {
        let id = oneiron::EntityId::now();
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
            )
            .expect("put the person");
        id
    };
    let xiao_ming = person("小明").to_hex();
    person("Distractor Person");
    let report = server
        .vault
        .reconcile_phonetic_embeddings(&FixtureModel, 64)
        .expect("reconcile");
    assert_eq!(report.embedded, 2, "{report:?}");

    let pack = |phonetic_vector: Value| {
        let server = server.clone();
        async move {
            route_json_auth(
                server,
                core_request_with_authz(
                    "POST",
                    "/v1/core/context-pack",
                    owner_bearer(),
                    Some(&serde_json::json!({
                        "limit": 5,
                        "phonetic_vector": phonetic_vector,
                    })),
                ),
            )
            .await
        }
    };

    let (status, body) = pack(serde_json::json!({
        "model_id": MODEL,
        "vector": fixture_vector("Showming"),
    }))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|hit| hit["id"].as_str())
        .collect();
    assert_eq!(ids.first().copied(), Some(xiao_ming.as_str()), "{body}");

    // A vector of another width than the model's rows is the caller's error.
    let (status, body) = pack(serde_json::json!({
        "model_id": MODEL,
        "vector": [1.0, 0.0],
    }))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
