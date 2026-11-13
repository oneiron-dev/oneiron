//! Every route the API listener registers either verifies a console
//! owner's attestation or is listed here with the reason it does not
//! (L10-29; DEC-0005 #owner-say-so-anywhere: no route answers "set it from
//! one of your machines"). An owner route the selection misses fails here by
//! name, the omission FIX 9292, 11370 and 11479 each found by hand.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::http::Method;

use self::Unattested::{OwnCredential, OwnerDevice, PublicProof, Refused, RootAdmin};
use super::{Surface, owner_attestable};
use crate::managed::attested_routes::staged_route;
use crate::server::SyncServer;

/// Why a registered route verifies no owner attestation.
#[derive(Clone, Copy)]
enum Unattested {
    /// A public door: its own capability, signature or provider proof
    /// stands alone (`attested_routes`' module doc).
    PublicProof,
    /// A root-admin door, never an owner act.
    RootAdmin,
    /// A door bound to the caller's own slip or step-up credential, of
    /// which an attestation carries none.
    OwnCredential,
    /// An act DEC-0005 keeps on the owner's own device: the console never
    /// receives the seed.
    OwnerDevice,
    /// A method or path the router refuses for every caller.
    Refused,
}

/// The registered routes no owner attestation is verified on, by method and
/// path pattern, each with its reason (the L10-29 route map at main
/// ae3d7c30ea3). A GET here stands for its HEAD too, as the router answers
/// that HEAD through the GET.
const UNATTESTED: &[(&str, &str, Unattested)] = &[
    // Discovery, health and the OAuth server's own doors.
    (
        "GET",
        "/.well-known/oauth-authorization-server",
        PublicProof,
    ),
    ("GET", "/.well-known/oauth-protected-resource", PublicProof),
    (
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
        PublicProof,
    ),
    ("GET", "/.well-known/oneiron", PublicProof),
    ("GET", "/.well-known/oneiron/deployment", PublicProof),
    ("GET", "/api/health", PublicProof),
    ("GET", "/oauth/authorize", PublicProof),
    ("GET", "/oauth/authorize/status", PublicProof),
    ("GET", "/oauth/client/native.json", PublicProof),
    ("GET", "/oauth/client/web.json", PublicProof),
    ("POST", "/oauth/register", PublicProof),
    ("POST", "/oauth/revoke", PublicProof),
    ("POST", "/oauth/token", PublicProof),
    // A booking page's guest doors, under the page's own token.
    ("GET", "/public/booking/{page_token}", PublicProof),
    (
        "POST",
        "/public/booking/{page_token}/availability",
        PublicProof,
    ),
    (
        "POST",
        "/public/booking/{page_token}/constraint-turn",
        PublicProof,
    ),
    (
        "POST",
        "/public/booking/{page_token}/verbs/{verb}",
        PublicProof,
    ),
    // The signing ceremony's signer doors.
    ("GET", "/sign", PublicProof),
    ("GET", "/sign/editor.js", PublicProof),
    ("GET", "/sign/field-renderer.js", PublicProof),
    ("POST", "/sign/geometry", PublicProof),
    ("POST", "/sign/image", PublicProof),
    ("POST", "/sign/layout", PublicProof),
    ("POST", "/sign/pdf", PublicProof),
    ("POST", "/sign/preview", PublicProof),
    ("POST", "/sign/signature", PublicProof),
    // Pairing redemption, federation, feedback and provider webhooks.
    ("POST", "/v1/core/pairing/oauth", PublicProof),
    ("POST", "/v1/core/pairing/pin", PublicProof),
    ("POST", "/v1/core/pairing/redeem", PublicProof),
    ("POST", "/v1/federation/courtesy-delete", PublicProof),
    ("POST", "/v1/federation/courtesy-delete/reply", PublicProof),
    (
        "POST",
        "/v1/federation/courtesy-delete/succession",
        PublicProof,
    ),
    ("GET", "/v1/feedback", PublicProof),
    ("POST", "/v1/feedback", PublicProof),
    ("POST", "/v1/hooks/line/webhook", PublicProof),
    ("POST", "/v1/hooks/linear", PublicProof),
    ("POST", "/v1/hooks/slack/events", PublicProof),
    ("GET", "/v1/hooks/slack/oauth", PublicProof),
    // Recovery pages, seat children and a left member's doors.
    ("POST", "/v1/recovery/custody/page", PublicProof),
    ("POST", "/v1/recovery/sealed-bundle/index", PublicProof),
    ("POST", "/v1/recovery/sealed-bundle/part", PublicProof),
    ("POST", "/v1/seat/credential-helper", PublicProof),
    (
        "POST",
        "/v1/seat/model/{slot}/v1/chat/completions",
        PublicProof,
    ),
    ("POST", "/v1/seat/model/{slot}/v1/messages", PublicProof),
    ("POST", "/v1/shared/left-notices", PublicProof),
    ("POST", "/v1/shared/removal-delivery", PublicProof),
    ("POST", "/v1/shared/removal-delivery/ack", PublicProof),
    ("POST", "/v1/shared/removal-export", PublicProof),
    (
        "POST",
        "/v1/shared/removal-export/{receipt_id}",
        PublicProof,
    ),
    // The operator's doors.
    ("GET", "/v1/operator/backups", RootAdmin),
    ("POST", "/v1/operator/backups", RootAdmin),
    ("POST", "/v1/operator/backups/rehearse", RootAdmin),
    ("POST", "/v1/operator/maintain", RootAdmin),
    ("GET", "/v1/operator/status", RootAdmin),
    // A phone line's arrivals and the caller's own step-up factors.
    (
        "POST",
        "/v1/core/phone-lines/{identity_ref}/arrivals",
        OwnCredential,
    ),
    ("POST", "/v1/core/step-up/challenge", OwnCredential),
    ("POST", "/v1/core/step-up/passkey", OwnCredential),
    ("GET", "/v1/core/step-up/passkeys", OwnCredential),
    ("POST", "/v1/core/step-up/passkeys", OwnCredential),
    ("POST", "/v1/core/step-up/passkeys/remove", OwnCredential),
    ("GET", "/v1/core/step-up/totp", OwnCredential),
    ("POST", "/v1/core/step-up/totp", OwnCredential),
    ("POST", "/v1/core/step-up/totp/confirm", OwnCredential),
    ("POST", "/v1/core/step-up/totp/enrollment", OwnCredential),
    ("POST", "/v1/core/step-up/totp/remove", OwnCredential),
    // The owner authority's recovery from a kit.
    ("POST", "/v1/recovery/owner-authority", OwnerDevice),
    // MCP's unsupported methods, the booking page's HEAD and a token path.
    ("DELETE", "/mcp", Refused),
    ("GET", "/mcp", Refused),
    ("DELETE", "/mcp/tool-first", Refused),
    ("GET", "/mcp/tool-first", Refused),
    ("HEAD", "/public/booking/{page_token}", Refused),
    ("GET", "/sign/{token}", Refused),
];

/// L10-29: every route the API listener registers either verifies a
/// console owner's attestation, held or staged, or is listed in
/// [`UNATTESTED`]; and every listed route is still registered and still
/// unattested. The feedback inbox is on, so its config-gated route is
/// registered too.
#[tokio::test]
async fn every_registered_api_route_is_owner_attested_or_classified()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(oneiron::Vault::open(
        dir.path(),
        oneiron::VaultConfig::server(),
    )?);
    let mut config = crate::config::SyncServerConfig::default();
    config.feedback_inbox.enabled = true;
    let server = Arc::new(SyncServer::new(vault, config)?);
    let routes = registered_routes(&crate::build_app(server));
    // The generated facade POSTs alone are over a thousand: fewer means the
    // router's form changed under this reading, not that routes went away.
    assert!(
        routes.len() > 1_000,
        "read {} routes from the router's form",
        routes.len()
    );

    let listed: BTreeMap<(&str, &str), Unattested> = UNATTESTED
        .iter()
        .map(|&(method, pattern, reason)| ((method, pattern), reason))
        .collect();
    assert_eq!(listed.len(), UNATTESTED.len(), "a route is listed twice");
    let mut unclassified = Vec::new();
    let mut attested_and_listed = Vec::new();
    for (method, pattern) in &routes {
        let attested = attests(method, pattern);
        let is_listed = listed.contains_key(&(method.as_str(), pattern.as_str()));
        if !attested && !is_listed {
            unclassified.push(format!("{method} {pattern}"));
        }
        if attested && is_listed {
            attested_and_listed.push(format!("{method} {pattern}"));
        }
    }
    let stale: Vec<String> = UNATTESTED
        .iter()
        .filter(|(method, pattern, _)| {
            !routes.contains(&((*method).to_owned(), (*pattern).to_owned()))
        })
        .map(|(method, pattern, _)| format!("{method} {pattern}"))
        .collect();
    assert!(
        unclassified.is_empty(),
        "registered routes that verify no owner attestation and are not \
         classified: {unclassified:#?}"
    );
    assert!(
        attested_and_listed.is_empty(),
        "attested routes listed as unattested: {attested_and_listed:#?}"
    );
    assert!(
        stale.is_empty(),
        "listed routes the router does not register: {stale:#?}"
    );
    Ok(())
}

/// Whether managed ingress verifies an owner attestation for `method` at a
/// path `pattern` matches, through either of its branches.
fn attests(method: &str, pattern: &str) -> bool {
    let method = Method::from_bytes(method.as_bytes()).expect("a registered method");
    let path = concrete_path(pattern);
    owner_attestable(Surface::Api, &method, &path) || staged_route(&method, &path).is_some()
}

/// A path `pattern` matches: each `{..}` one segment, each `{*..}` two.
fn concrete_path(pattern: &str) -> String {
    pattern
        .split('/')
        .map(|segment| {
            if segment.starts_with("{*") {
                "rest0/rest1"
            } else if segment.starts_with('{') {
                "segment0"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Each method and path pattern `router` registers, read from its `Debug`
/// form as axum 0.8 writes it: the path router's
/// `RouteId(n): MethodRouter(MethodRouter { get: .., head: .., .. })` for
/// each route, then `node: Node { paths: {RouteId(n): "/path", ..} }`. A
/// method whose endpoint reads `None` is not registered; a whole-service
/// route (`Route(Route)`) is read as method `ANY`. The fallback router
/// registers no route.
fn registered_routes(router: &axum::Router) -> BTreeSet<(String, String)> {
    let form = format!("{router:?}");
    let (path_router, _fallbacks) = form
        .split_once(", fallback_router: ")
        .expect("axum's Router form");
    let (endpoints, paths) = path_router
        .split_once("node: Node { paths: {")
        .expect("axum's PathRouter form");
    let paths: BTreeMap<u32, &str> = paths
        .split("RouteId(")
        .skip(1)
        .filter_map(|entry| {
            let (id, rest) = entry.split_once("): \"")?;
            let (path, _) = rest.split_once('"')?;
            Some((id.parse().ok()?, path))
        })
        .collect();
    let mut routes = BTreeSet::new();
    for entry in endpoints.split("RouteId(").skip(1) {
        let (id, endpoint) = entry.split_once("): ").expect("a route id");
        let id: u32 = id.parse().expect("a numeric route id");
        let path = (*paths.get(&id).expect("a path for each route id")).to_owned();
        if endpoint.starts_with("Route(") {
            routes.insert(("ANY".to_owned(), path));
            continue;
        }
        for method in [
            "get", "head", "delete", "options", "patch", "post", "put", "trace", "connect",
        ] {
            let Some((_, value)) = endpoint.split_once(&format!(" {method}: ")) else {
                continue;
            };
            if !value.starts_with("None") {
                routes.insert((method.to_ascii_uppercase(), path.clone()));
            }
        }
    }
    routes
}
