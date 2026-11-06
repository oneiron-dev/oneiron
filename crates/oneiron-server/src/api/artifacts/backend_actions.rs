//! App-only Fetch calls through the native action and pairing doors.

use std::{io, sync::Arc};

use axum::{
    Extension,
    body::{Body, to_bytes},
    extract::{FromRequestParts, Request, State},
    http::{HeaderName, HeaderValue, Method, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use oneiron::artifact_hosting::ArtifactBackendSource;
use oneiron_container::{HttpRequest, HttpResponse};
use tower::ServiceExt;

use crate::{
    auth::CoreAuth,
    error::{ApiError, EnvelopedApiError},
    server::SyncServer,
};

pub(super) async fn fetch(
    server: Arc<SyncServer>,
    source: ArtifactBackendSource,
    request: HttpRequest,
) -> io::Result<HttpResponse> {
    let uri: Uri = request.url.parse().map_err(io::Error::other)?;
    let verb = uri.path().strip_prefix("/v1/core/actions/");
    if request.method != "POST"
        || uri.scheme().is_some()
        || uri.authority().is_some()
        || !(verb.is_some_and(|verb| !verb.is_empty() && !verb.contains('/'))
            || uri.path() == "/v1/core/pairing/redeem")
    {
        return Err(super::no_engine_egress());
    }
    let mut call = axum::http::Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(Body::from(request.body))
        .map_err(io::Error::other)?;
    for (name, value) in request.headers {
        call.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).map_err(io::Error::other)?,
            HeaderValue::from_str(&value).map_err(io::Error::other)?,
        );
    }
    // Keep the public API's outer layers in their original order. The
    // binding door consumes the holder proof once, before body decoding
    // and the staged identity check enter the unchanged action handler.
    let routes = crate::api::facade::action_routes::routes()
        .layer(middleware::from_fn_with_state(
            Arc::clone(&server),
            require_staged_app,
        ))
        .route(
            "/v1/core/pairing/redeem",
            post(crate::api::pairing::redeem_artifact_backend),
        )
        .layer(Extension(source))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&server),
            crate::wire_telemetry::observe_http,
        ))
        .layer(crate::api::request_floor::request_floor_layer(&server))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&server),
            crate::api::request_floor::name_request_floor,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&server),
            crate::api::body_codec::body_codec,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&server),
            crate::auth::admit_http_binding,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&server),
            crate::api::call_receipt::connection_receipt,
        ))
        .with_state(server);
    let response = match routes.oneshot(call).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, usize::MAX).await.map_err(io::Error::other)?;
    Ok(HttpResponse {
        url: request.url,
        status: parts.status.as_u16(),
        headers: parts
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
            .collect(),
        body,
    })
}

async fn require_staged_app(
    State(server): State<Arc<SyncServer>>,
    Extension(source): Extension<ArtifactBackendSource>,
    request: Request,
    next: Next,
) -> Response {
    let refused = || EnvelopedApiError::from(ApiError::unauthorized()).into_response();
    let (mut parts, body) = request.into_parts();
    let auth = match CoreAuth::from_request_parts(&mut parts, &server).await {
        Ok(auth) => auth,
        Err(refusal) => return refusal.into_response(),
    };
    if !auth
        .verified_slip()
        .is_some_and(|proof| proof.claims().actor_class.as_deref() == Some("agent"))
    {
        return refused();
    }
    let Some(principal) = auth
        .principal_ref()
        .and_then(|value| oneiron::EntityId::from_hex(value).ok())
    else {
        return refused();
    };
    let vault = server.vault().clone();
    let matches = tokio::task::spawn_blocking(move || {
        vault.artifact_backend_principal_matches(principal, &source)
    })
    .await;
    match matches {
        Ok(Ok(true)) => next.run(Request::from_parts(parts, body)).await,
        Ok(Ok(false)) => refused(),
        Ok(Err(error)) => {
            crate::api::core_engine_error("artifact backend binding failed", error).into_response()
        }
        Err(_) => EnvelopedApiError::from(ApiError::internal_server_error(
            "artifact backend binding failed",
        ))
        .into_response(),
    }
}
