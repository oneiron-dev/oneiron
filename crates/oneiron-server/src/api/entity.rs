use super::ViewQuery;
use super::check_api_auth;
use super::query_params;
use super::scoped_read_for_legacy_api;
use crate::error::ApiError;
use crate::projection;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::QueryRejection;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Json;
use axum::response::Response;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// Get entity by ID.
#[utoipa::path(
    get,
    path = "/api/entity/{id}",
    params(
        (
            "id" = String,
            Path,
            description = "Hex-encoded entity id to retrieve from the vault. Agents should pass ids exactly as returned by search results.",
            example = "0123456789abcdef0123456789abcdef"
        ),
        ViewQuery
    ),
    responses(
        (
            status = 200,
            description = "Raw entity payload bytes for the requested id when `view=standard` or omitted. `view=summary` and `view=full` return JSON projections.",
            content(
                (
                    String = "application/octet-stream",
                    example = "raw entity bytes"
                ),
                (
                    Object = "application/json",
                    examples(
                        (
                            "summary" = (
                                summary = "Summary projection",
                                value = json!({
                                    "id": "0123456789abcdef0123456789abcdef",
                                    "kind": "TASK",
                                    "label": "Ship OpenAPI projections",
                                    "updatedAt": 1782357635_u64
                                })
                            )
                        ),
                        (
                            "full" = (
                                summary = "Full projection",
                                value = json!({
                                    "id": "0123456789abcdef0123456789abcdef",
                                    "kind": "TASK",
                                    "type": 1,
                                    "label": "Ship OpenAPI projections",
                                    "updatedAt": 1782357635_u64,
                                    "title": "Ship OpenAPI projections",
                                    "body": "Document JSON entity projection responses."
                                })
                            )
                        )
                    )
                )
            )
        ),
        (
            status = 400,
            description = "Malformed entity id or invalid view query parameter.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "No entity exists for the supplied id.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Entity lookup or projection failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn get_entity(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    check_api_auth(&headers, &server)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Standard);

    let id = oneiron::EntityId::from_hex(&id_hex).map_err(|_| {
        ApiError::bad_request("entity id must be a 32-character hex entity id", Some("id"))
    })?;

    let scoped_read = scoped_read_for_legacy_api(&server)?;
    let read = scoped_read
        .get_entity_parts_with_receipt(&id, None)
        .inspect_err(|error| tracing::error!(%error,"get entity failed"))
        .map_err(|_| ApiError::internal_server_error("get entity failed"))?;
    let response = match read.value {
        None => ApiError::not_found("entity", Some(&id_hex)).into_response(),
        Some((_, _, data)) if view == View::Standard => {
            (StatusCode::OK, redacted_payload(data)?).into_response()
        }
        Some((entity_type, updated_at, data)) => (
            StatusCode::OK,
            Json(projection::project_entity_parts(
                &id,
                entity_type,
                updated_at,
                &data,
                view,
            )),
        )
            .into_response(),
    };
    attach_read_receipt(response, &read.receipt)
}

/// Preserve the legacy raw transport, but never return surviving credentials.
fn redacted_payload(bytes: Vec<u8>) -> Result<Vec<u8>, ApiError> {
    oneiron::batch::export::redacted_memory_payload(bytes)
        .map_err(|_| ApiError::internal_server_error("redaction serialization failed"))
}

fn attach_read_receipt(
    mut response: Response,
    receipt: &oneiron::claim::ScopedReadReceipt,
) -> Result<Response, ApiError> {
    let value = serde_json::to_string(receipt)
        .map_err(|_| ApiError::internal_server_error("read receipt serialization failed"))?;
    let value = axum::http::HeaderValue::from_str(&value)
        .map_err(|_| ApiError::internal_server_error("read receipt header failed"))?;
    response
        .headers_mut()
        .insert("x-oneiron-read-receipt", value);
    Ok(response)
}

#[cfg(test)]
mod credential_tests {
    use super::*;
    use serde_json::Value;
    #[test]
    fn raw_entity_transport_filters_credentials_and_preserves_safe_bytes() {
        assert_eq!(
            redacted_payload(b"safe opaque text".to_vec()).unwrap(),
            b"safe opaque text"
        );
        for json in [true, false] {
            let value = serde_json::json!({"safe":"kept","nested":{"password":"legacy-value"}});
            let encoded = if json {
                serde_json::to_vec(&value).unwrap()
            } else {
                rmp_serde::to_vec_named(&value).unwrap()
            };
            let bytes = redacted_payload(encoded).unwrap();
            let got: Value = if json {
                serde_json::from_slice(&bytes).unwrap()
            } else {
                rmp_serde::from_slice(&bytes).unwrap()
            };
            assert_eq!(got["safe"], "kept");
            assert_eq!(got["nested"]["password"], "[redacted]");
        }
    }
    #[tokio::test]
    async fn edge_transport_keeps_its_array_and_receipts_missing_and_live_sources() {
        let (_dir, server) = crate::api::tests::test_server();
        let id = oneiron::EntityId::from_bytes([0x31; 16]).unwrap();
        for present in [false, true] {
            if present {
                server
                    .vault
                    .put_entity(
                        &id,
                        oneiron::registry::ENTITY_TYPE_PERSON,
                        oneiron::TimeRange { start: 1, end: 1 },
                        1,
                        b"source",
                    )
                    .unwrap();
            }
            let response = get_edges(
                HeaderMap::new(),
                State(server.clone()),
                Path(id.to_hex()),
                Ok(Query(ViewQuery {
                    view: Some(View::Full),
                })),
            )
            .await
            .unwrap();
            assert_eq!(
                response.status(),
                if present {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            );
            let receipt: Value = serde_json::from_str(
                response.headers()["x-oneiron-read-receipt"]
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(receipt["suppressed_count"], 0);
            assert!(receipt["applied"].is_object());
            if present {
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<Value>(&body).unwrap(),
                    serde_json::json!([])
                );
            }
        }
    }
}

/// Get outbound edges for an entity.
#[utoipa::path(
    get,
    path = "/api/edges/{id}",
    params(
        (
            "id" = String,
            Path,
            description = "Hex-encoded source entity id whose outbound edge list should be returned.",
            example = "0123456789abcdef0123456789abcdef"
        ),
        ViewQuery
    ),
    responses(
        (
            status = 200,
            description = "Outbound graph edges from the requested entity, projected according to `view`.",
            headers(("x-oneiron-read-receipt" = String, description = "JSON requested scope, actor ceiling, intersection, narrowed axes and suppression count.")),
            body = Vec<Object>,
            content_type = "application/json",
            example = json!([{
                "kind": 1,
                "target": "fedcba9876543210fedcba9876543210"
            }])
        ),
        (
            status = 400,
            description = "Malformed entity id or invalid view query parameter.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Edge lookup failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn get_edges(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    check_api_auth(&headers, &server)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);

    let id = oneiron::EntityId::from_hex(&id_hex).map_err(|_| {
        ApiError::bad_request("entity id must be a 32-character hex entity id", Some("id"))
    })?;

    let scoped_read = scoped_read_for_legacy_api(&server)?;
    let read = scoped_read
        .edges_out(&id)
        .inspect_err(|e| {
            tracing::error!(error = %e, "get edges failed");
        })
        .map_err(|_| ApiError::internal_server_error("get edges failed"))?;
    let response = match read.value {
        None => ApiError::not_found("entity", Some(&id_hex)).into_response(),
        Some(edges) => Json(
            edges
                .into_iter()
                .map(|edge| projection::project_edge(&edge, view))
                .collect::<Vec<_>>(),
        )
        .into_response(),
    };
    attach_read_receipt(response, &read.receipt)
}

/// Outbound edge from one entity to another.
#[derive(Serialize, ToSchema)]
#[schema(example = json!({
    "kind": 1,
    "target": "fedcba9876543210fedcba9876543210",
    "weight": 1.0,
    "created_at": 1782357635_u64
}))]
pub(crate) struct EdgeResult {
    /// Numeric edge-kind discriminant used by the vault graph index.
    #[schema(example = 1)]
    kind: u8,
    /// Hex-encoded target entity id reached by this outbound edge.
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    target: String,
    /// Edge weight used by graph and context ranking.
    #[schema(example = 1.0)]
    weight: f32,
    /// Creation timestamp recorded for the edge, expressed as Unix seconds.
    #[schema(example = 1782357635_u64)]
    created_at: u64,
}
