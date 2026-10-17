//! Endpoint discovery and browser access for an external shared web client.
//! No UI assets, credentials or product configuration live on this surface.

use axum::{
    Json, Router,
    http::{HeaderValue, Method},
    routing::get,
};
use oneiron::HostingPrivacyPosture;
use serde::Serialize;
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer, ExposeHeaders};

/// The engine's position, independently of the host's privacy posture.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPosition {
    Embedded,
    LocalDaemon,
    Cloud,
}

/// Paths are relative to the endpoint the client selected, not an internal
/// bind address or a caller-supplied forwarding header. Pairing remains the
/// existing holder-bound ceremony; discovery grants no access.
#[derive(Clone, Debug, Serialize)]
pub struct EndpointDescriptor {
    pub version: u32,
    pub position: DeploymentPosition,
    pub mode: HostingPrivacyPosture,
    pub host_readable: bool,
    pub process_boundary: bool,
    pub owner_device_required: bool,
    pub api_base: Option<&'static str>,
    pub sync_path: Option<&'static str>,
    /// The `sync_path` subprotocol that carries MCP calls on one socket
    /// instead of one HTTP request each; an upgrade that names it gets the
    /// MCP carrier, not sync.
    pub mcp_subprotocol: Option<&'static str>,
    pub pairing_path: Option<&'static str>,
    pub relay_url: Option<String>,
    pub locker_base: Option<String>,
}

impl EndpointDescriptor {
    pub(crate) fn engine(position: DeploymentPosition, mode: HostingPrivacyPosture) -> Self {
        Self {
            version: 1,
            position,
            mode,
            host_readable: mode == HostingPrivacyPosture::Hosted,
            process_boundary: !matches!(position, DeploymentPosition::Embedded),
            owner_device_required: false,
            api_base: Some("/v1/core"),
            sync_path: Some("/ws"),
            mcp_subprotocol: Some(crate::handler::MCP_SUBPROTOCOL),
            pairing_path: Some("/.well-known/oneiron"),
            relay_url: None,
            locker_base: None,
        }
    }

    pub(crate) fn relay(relay_url: String, vault: &str) -> Self {
        Self {
            version: 1,
            position: DeploymentPosition::Cloud,
            mode: HostingPrivacyPosture::Relay,
            host_readable: false,
            process_boundary: true,
            owner_device_required: true,
            api_base: None,
            sync_path: None,
            mcp_subprotocol: None,
            pairing_path: None,
            relay_url: Some(relay_url),
            locker_base: Some(format!("/v1/relay/{vault}/locker")),
        }
    }
}

pub(crate) fn routes(descriptor: EndpointDescriptor) -> Router {
    Router::new().route(
        "/.well-known/oneiron/deployment",
        get(move || async move { Json(descriptor) }),
    )
}

/// Explicit origins only. The same policy works for the daemon, managed
/// guest and a host app serving an embedded router over its own transport.
/// Credentials stay in request headers, never cookies or discovery URLs.
pub fn cors_layer(origins: &[String]) -> anyhow::Result<CorsLayer> {
    Ok(cors_layer_for_origins(parse_allowed_origins(origins)?))
}

pub(crate) fn cors_layer_for_origins(origins: Vec<HeaderValue>) -> CorsLayer {
    if origins.is_empty() {
        return CorsLayer::new();
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        // Includes Authorization, Content-Type, the holder proof and the
        // headers introduced by individual API verbs without a second list.
        .allow_headers(AllowHeaders::mirror_request())
        .allow_private_network(true)
        .expose_headers(ExposeHeaders::list([
            axum::http::header::ETAG,
            axum::http::header::LOCATION,
            axum::http::header::RETRY_AFTER,
            axum::http::header::CONTENT_DISPOSITION,
        ]))
}

pub(crate) fn parse_allowed_origins(origins: &[String]) -> anyhow::Result<Vec<HeaderValue>> {
    origins
        .iter()
        .map(|origin| origin.trim())
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            let url = reqwest::Url::parse(origin)?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "invalid CORS origin {origin:?}"
            );
            Ok(url.origin().ascii_serialization().parse::<HeaderValue>()?)
        })
        .collect()
}
