//! The signing ceremony. The public link carries the capability in its
//! fragment (`/sign#<token>`); after loading, the page scrubs it and trades
//! it once for a single-use exchange (`POST /sign/exchange`), which a
//! top-level form POST to `/sign/session` consumes to open a signing session
//! in a Secure, HttpOnly, SameSite=Strict cookie (ARCH-0064a [SGN-03],
//! `signing_session`). Each ceremony POST carries only that cookie; the vault
//! admits the link's capability it stands for before the body is read
//! (`ingress`, FIX 3808). A call that also presents a vault credential is
//! classed by it: an agent's Complete is an automated sign act, whoever's
//! link it holds.
use crate::server::SyncServer;
pub(crate) mod delivery_outbox;
mod editor_auth;
mod editor_budget;
pub(crate) mod hold_worker;
mod ingress;
pub(crate) mod notice_worker;
#[cfg(unix)]
pub(crate) mod page_inspector;
mod parse_lease;
mod presentation;
#[cfg(unix)]
pub(crate) mod seal_worker;
mod signing_session;
use crate::machine::MemoryRefusal;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ingress::SigningIngress;
use oneiron::blob_artifact::esign::{EsignSigningImageView, SigningCaller};
use signing_session::{SessionLifetimes, SigningSessions};
use std::sync::Arc;
use std::time::Instant;

/// The owner's field editor. Its shell mints an editor token into its page
/// (FIX 5618, `editor_auth`). A computation POST carrying one is admitted
/// from its head, waits for one of two slots and spools its raw body, which
/// no `DefaultBodyLimit` reads. A capability-free POST spools under the
/// same disk and memory floors; `EditorBudget`'s window still admits it
/// before its body is read (Engine call 2026-11-05 12:04, FIX 141/142).
pub(super) fn editor_routes() -> Router<Arc<SyncServer>> {
    let desk = editor_auth::EditorDesk::new();
    Router::new()
        .route("/sign/layout", post(presentation::layout))
        .route("/sign/geometry", post(presentation::upload_geometry))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&desk.budget),
            editor_budget::admit,
        ))
        .route("/sign/editor", get(presentation::editor))
        .route("/sign/field-renderer.js", get(presentation::field_script))
        .route("/sign/editor.js", get(presentation::editor_script))
        .layer(DefaultBodyLimit::disable())
        .layer(axum::Extension(desk))
        .layer(axum::middleware::from_fn(private_response))
}

/// Only the signing ceremony bypasses the hosted device-lease gate. Every
/// action and document read still checks the link's capability in the
/// vault, from its session and before its body. An admitted body has no size
/// refusal: it spools whole under the disk floor and its size is the
/// `[limits] esign_body_bytes` row, so no `DefaultBodyLimit` sits on these
/// routes. The sessions live in this router's own registry.
pub(super) fn public_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/sign", get(page))
        // A signing link is `/sign#<token>`: a capability in the request path
        // reaches server and proxy logs (F37), so a path token is refused,
        // never served.
        .route("/sign/{token}", get(path_token_refused))
        .route("/sign/exchange", post(exchange))
        .route("/sign/session", post(open_session))
        .route("/sign/action", post(action))
        .route("/sign/pdf", post(pdf))
        .route("/sign/image", post(image))
        .route("/sign/preview", post(presentation::preview))
        .route("/sign/signature", post(presentation::signature))
        .layer(axum::Extension(SigningSessions::default()))
        .layer(axum::middleware::from_fn(private_response))
}

/// `POST /sign/exchange`: the one door that reads a link's capability, from
/// the `x-oneiron-esign-capability` header. The vault admits it as every
/// ceremony door's session does; the answer is a single-use exchange that
/// lives `[limits] esign_exchange_seconds`, and replaces any exchange the
/// link had pending. The emailed link stays reusable.
async fn exchange(
    State(server): State<Arc<SyncServer>>,
    axum::Extension(sessions): axum::Extension<SigningSessions>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = ingress::link_capability(&headers) else {
        return refused();
    };
    if server.vault.admit_esign_ingress(&token).is_err() {
        return refused();
    }
    crate::http_listener::authenticated();
    let lifetimes = SessionLifetimes::from_limits(&server.config.limits);
    let exchange = sessions.mint_exchange(&token, lifetimes);
    Json(serde_json::json!({ "exchange": exchange })).into_response()
}

/// The most bytes `POST /sign/session`'s form may hold: its one field and a
/// 64-character exchange, with room to spare. It is a fixed form, not a
/// payload; a longer body is not an exchange.
const SESSION_FORM_BYTES: usize = 1024;

/// `POST /sign/session`: the page's top-level form POST, `exchange=<hex>`.
/// A live exchange is consumed here, at once, and opens its link's signing
/// session, replacing any session the link had open: the answer redirects to
/// the page and sets the session cookie, Secure, HttpOnly, SameSite=Strict
/// and scoped to `/sign`. An unknown, used or expired exchange, or a POST a
/// browser marks as sent from another site, opens nothing and sets no cookie.
async fn open_session(
    State(server): State<Arc<SyncServer>>,
    axum::Extension(sessions): axum::Extension<SigningSessions>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Another site may not open a session it minted in this browser.
    if headers
        .get("sec-fetch-site")
        .is_some_and(|site| site.as_bytes() != b"same-origin")
    {
        return session_refused();
    }
    let Ok(form) = axum::body::to_bytes(body, SESSION_FORM_BYTES).await else {
        return session_refused();
    };
    let presented = std::str::from_utf8(&form).ok().and_then(|form| {
        form.split('&').find_map(|pair| {
            pair.trim()
                .strip_prefix(signing_session::EXCHANGE_FIELD)
                .and_then(|rest| rest.strip_prefix('='))
        })
    });
    let lifetimes = SessionLifetimes::from_limits(&server.config.limits);
    let Some(id) = presented.and_then(|exchange| sessions.open_session(exchange, lifetimes)) else {
        return session_refused();
    };
    let Ok(cookie) = HeaderValue::from_str(&signing_session::session_set_cookie(&id)) else {
        return session_refused();
    };
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, HeaderValue::from_static("/sign")),
            (header::SET_COOKIE, cookie),
        ],
    )
        .into_response()
}

/// A refused session opening. The form POST is a page navigation, so its
/// answer is words for the signer, never a cookie.
fn session_refused() -> Response {
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "The signing request is unavailable. Reopen the invitation or contact its sender.",
    )
        .into_response()
}
async fn action(
    State(server): State<Arc<SyncServer>>,
    SigningIngress { token, admitted }: SigningIngress,
    parts: Parts,
    peer: NetworkPeer,
    local_peer: LocalPeer,
    body: Body,
) -> Response {
    let headers = &parts.headers;
    // Proxy forwarding headers are not an authenticated IP source. Do not
    // copy attacker-supplied X-Forwarded-For into the legal audit trail.
    // The user agent is kept whole, however long (Rule 5): the header's own
    // bound is the HTTP codec's.
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let Ok(ip) = signing_peer_ip(peer, local_peer) else {
        return unavailable();
    };
    let Ok((caller, verified_actor)) = signing_caller(&parts, &server) else {
        return refused();
    };
    let request: ingress::ActionBody =
        match ingress::payload(&server, admitted, headers, body).await {
            Ok(request) => request,
            Err(response) => return response,
        };
    // The act blocks, its writer and the inspection of the PDFs it lays
    // fields on (FIX 9609) alike, so it runs off the async runtime.
    let vault = Arc::clone(&server.vault);
    let acted = tokio::task::spawn_blocking(move || {
        vault.execute_signing_action_as(&token, &request.action, caller, verified_actor, ip, ua)
    })
    .await;
    match acted {
        Ok(Ok(outcome)) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::REFERRER_POLICY, "no-referrer"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            Json(outcome),
        )
            .into_response(),
        Ok(Err(_)) | Err(_) => refused(),
    }
}
/// Who the signing call shows itself to be. A browser signer sends no
/// credential (the page posts only its signing session's cookie), so the
/// capability stands alone; a call that presents one is classed by the
/// actor class its credential binds, and only `human` is a person. A
/// credential that does not verify is refused. On a managed vault a call its
/// supervisor attested for the vault's owner, with no credential of its own,
/// is that person while the vault records him as its live owner; otherwise
/// its capability stands alone, as a browser signer's does.
fn signing_caller(
    request: &Parts,
    server: &SyncServer,
) -> Result<(SigningCaller, Option<oneiron::EntityId>), ()> {
    let headers = &request.headers;
    if !headers.contains_key(header::AUTHORIZATION) {
        let auth = crate::auth::attested_owner(&request.extensions, server)
            .and_then(|holder| crate::auth::CoreAuth::for_attested_owner(holder, server).ok());
        return Ok(match auth {
            Some(auth) => (SigningCaller::Person, auth.principal_entity()),
            None => (SigningCaller::Bearer, None),
        });
    }
    let auth = crate::auth::CoreAuth::for_managed_request(
        headers,
        &request.extensions,
        crate::auth::request_path(request),
        server,
    )
    .unwrap_or_else(|| {
        crate::auth::CoreAuth::from_headers(headers, &server.config, server.vault().as_ref())
    })
    .map_err(|_| ())?;
    let caller = match auth.actor_class() {
        Some("human") => SigningCaller::Person,
        _ => SigningCaller::Agent,
    };
    Ok((caller, auth.principal_entity()))
}

type NetworkPeer = Result<
    axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::rejection::ExtensionRejection,
>;
type LocalPeer = Result<
    axum::extract::ConnectInfo<crate::managed::UnixPeer>,
    axum::extract::rejection::ExtensionRejection,
>;

fn signing_peer_ip(network: NetworkPeer, local: LocalPeer) -> Result<Option<String>, ()> {
    if let Ok(axum::extract::ConnectInfo(peer)) = network {
        return Ok(Some(peer.ip().to_string()));
    }
    if let Ok(axum::extract::ConnectInfo(peer)) = local
        && peer.verified()
    {
        // A kernel-verified Unix peer is the local supervisor, not a signer
        // address. Record no IP rather than inventing one or trusting XFF.
        return Ok(None);
    }
    Err(())
}

fn refused() -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Json(serde_json::json!({"error":{"code":"signing_unavailable"}})),
    )
        .into_response()
}

async fn pdf(
    State(server): State<Arc<SyncServer>>,
    SigningIngress { token, admitted }: SigningIngress,
    parts: Parts,
    peer: NetworkPeer,
    local_peer: LocalPeer,
    body: Body,
) -> Response {
    let headers = &parts.headers;
    let Ok(ip) = signing_peer_ip(peer, local_peer) else {
        return unavailable();
    };
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let Ok((caller, verified_actor)) = signing_caller(&parts, &server) else {
        return refused();
    };
    let request: ingress::ItemBody = match ingress::payload(&server, admitted, headers, body).await
    {
        Ok(request) => request,
        Err(response) => return response,
    };
    match server.vault.esign_pdf_for_capability_as(
        &token,
        request.item,
        caller,
        verified_actor,
        ip,
        ua,
    ) {
        Ok(bytes) => {
            let mut response = (
                [
                    (header::CONTENT_TYPE, "application/pdf"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=document.pdf",
                    ),
                    (header::CACHE_CONTROL, "no-store"),
                    (header::REFERRER_POLICY, "no-referrer"),
                    (
                        header::CONTENT_SECURITY_POLICY,
                        "sandbox; default-src 'none'",
                    ),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                ],
                bytes,
            )
                .into_response();
            if let Ok(name) = axum::http::HeaderValue::from_str(&format!(
                "attachment; filename=document-{}.pdf",
                request.item + 1
            )) {
                response
                    .headers_mut()
                    .insert(header::CONTENT_DISPOSITION, name);
            }
            response
        }
        Err(_) => refused(),
    }
}
/// How a signature image upload ended on its spool's worker.
enum ImageUpload {
    Stored(String),
    /// Its capability or turn, its format or visible pixels, or the
    /// decoder's bounds refused it.
    Refused,
    /// The machine memory reading and decoding it takes was not admitted.
    Memory(MemoryRefusal),
    /// It was not read back whole.
    Unread(ingress::WholeBody),
}

/// The signature image is the body itself, raw PNG or JPEG bytes: spooled
/// whole, then decoded and stored on the same worker. Only its capability and
/// turn, its format and visible pixels, and the decoder's bounds refuse it,
/// besides this machine's memory: the peak its read, decode and re-encode
/// hold is planned from its header and leased before the body is read into
/// memory, and held until the upload returns (FIX 7649).
async fn image(
    State(server): State<Arc<SyncServer>>,
    SigningIngress { token, admitted }: SigningIngress,
    parts: Parts,
    body: Body,
) -> Response {
    let headers = &parts.headers;
    let Ok((caller, verified_actor)) = signing_caller(&parts, &server) else {
        return refused();
    };
    let vault = Arc::clone(&server.vault);
    let memory = server.memory.clone();
    let uploaded = ingress::spooled(&server, admitted, &headers, body, move |file, bytes| {
        let mut spool = std::io::BufReader::new(file);
        let Ok(plan) = oneiron::blob_artifact::esign::plan_signature_image(&mut spool) else {
            return ImageUpload::Unread(ingress::WholeBody::Unread);
        };
        // A peak past u64 fits no machine: the lease refuses it at its floor.
        let peak = plan.peak_bytes(bytes).unwrap_or(u64::MAX);
        let deadline = Instant::now() + ingress::MEMORY_WAIT;
        let mut lease = match memory.lease(peak, deadline) {
            Ok(lease) => lease,
            Err(refusal) => return ImageUpload::Memory(refusal),
        };
        let image = match ingress::whole_body(spool.into_inner(), bytes, &lease) {
            Ok(image) => image,
            Err(unread) => return ImageUpload::Unread(unread),
        };
        // The read bytes are held now, so the live reading is not charged
        // them twice while the lease lives (FIX 9345). Only what was read
        // is named allocated; the peak's decode and re-encode room stays
        // pending on the lease until the upload returns.
        let read = u64::try_from(image.len()).unwrap_or(u64::MAX);
        lease.materialized(read, read);
        let mut memory_refusal = None;
        let uploaded = vault.upload_esign_signature_image_admitted_as(
            &token,
            &image,
            caller,
            verified_actor,
            &mut |plan, header_allocated| {
                if header_allocated != 0 {
                    lease.materialized(header_allocated, header_allocated);
                }
                let peak = plan.peak_bytes(read).unwrap_or(u64::MAX);
                let more = peak.saturating_sub(lease.bytes());
                if more == 0 {
                    return Ok(());
                }
                lease
                    .grow_pending(more, deadline, &|| false)
                    .inspect_err(|refusal| {
                        memory_refusal = Some(*refusal);
                    })
            },
        );
        if let Some(refusal) = memory_refusal {
            return ImageUpload::Memory(refusal);
        }
        match uploaded {
            Ok(image_ref) => ImageUpload::Stored(image_ref),
            Err(_) => ImageUpload::Refused,
        }
    })
    .await;
    match uploaded {
        Ok(ImageUpload::Stored(image_ref)) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            Json(EsignSigningImageView { image_ref }),
        )
            .into_response(),
        Ok(ImageUpload::Refused) => refused(),
        Ok(ImageUpload::Memory(refusal)) => ingress::memory_refused(refusal),
        Ok(ImageUpload::Unread(unread)) => ingress::whole_body_refused(unread),
        Err(response) => response,
    }
}
async fn path_token_refused() -> Response {
    (StatusCode::NOT_FOUND, "").into_response()
}

async fn page() -> Response {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let script = [
        include_str!("esign/field-renderer.js"),
        include_str!("esign/ceremony.js"),
    ]
    .join("\n");
    let digest =
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()));
    let csp = format!(
        "default-src 'none'; script-src 'sha256-{digest}'; connect-src 'self'; style-src 'unsafe-inline'; img-src blob:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer><title>Signing request</title><main><h1 id=title>Signing request</h1><p id=status></p><section id=fields></section><section id=preview></section><select id=item aria-label=Document></select><button id=download>Download PDF</button><label><input id=consent type=checkbox>I agree to sign this document.</label><button id=complete>Complete</button><button id=reject>Reject</button></main><script>{script}</script></html>"
    );
    (
        [
            (header::CONTENT_SECURITY_POLICY, csp),
            (header::CACHE_CONTROL, "no-store".into()),
            (header::REFERRER_POLICY, "no-referrer".into()),
        ],
        axum::response::Html(html),
    )
        .into_response()
}

async fn private_response(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error":{"code":"signing_transport_unavailable"}})),
    )
        .into_response()
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;
    #[tokio::test]
    async fn sessionless_page_and_refusals_never_cache_or_echo_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let server =
            Arc::new(SyncServer::new(vault, crate::config::SyncServerConfig::default()).unwrap());
        let app = public_routes().with_state(server);
        let page = app
            .clone()
            .oneshot(Request::builder().uri("/sign").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(page.headers()[header::REFERRER_POLICY], "no-referrer");
        assert!(page.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        assert!(!page.headers().contains_key(header::SET_COOKIE));
        for (path, body, status) in [
            (
                "/sign/action",
                serde_json::json!({"token":"11".repeat(32),"action":{"action":"load"}}).to_string(),
                StatusCode::FORBIDDEN,
            ),
            (
                "/sign/pdf",
                serde_json::json!({"token":"11".repeat(32),"item":0}).to_string(),
                StatusCode::FORBIDDEN,
            ),
            (
                "/sign/image",
                serde_json::json!({"token":"11".repeat(32),"png_or_jpeg_base64":"invalid"})
                    .to_string(),
                StatusCode::FORBIDDEN,
            ),
            // f549ba91f84 (#3269, FIX L12-B): a request with no capability is
            // refused 403 before its body is read, so the malformed body is never parsed.
            ("/sign/action", "{".to_owned(), StatusCode::FORBIDDEN),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .extension(axum::extract::ConnectInfo(
                            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(&"11".repeat(32)));
        }
    }
    /// A sent signing request with an admitted recipient capability.
    fn signing_transport_fixture() -> (tempfile::TempDir, Arc<SyncServer>, String) {
        use oneiron::blob_artifact::esign::{
            DocumentKind, EsignAuditActor, EsignDocument, EsignField, EsignItem,
            EsignOutboundCommand, EsignOutboundVerb, EsignRecipient, FieldGeometry, FieldMeta,
            RecipientRole,
        };
        use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
        use oneiron::federation::{Scope, ScopeAxis};
        use oneiron::outbound::{
            OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
            OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft, OutboundIntentSource,
            OutboundIntentTrigger,
        };
        use oneiron::{EdgeActorClass, EntityId, TimeRange, WriteActor};

        let dir = tempfile::tempdir().expect("create signing fixture directory");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device())
                .expect("open signing fixture vault"),
        );
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("create embedded owner actor");
        let artifact = EntityId::now();
        let when = TimeRange { start: 1, end: 1 };
        vault
            .put_blob_artifact(
                &artifact,
                &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
                when,
                1,
            )
            .expect("store signing PDF artifact");
        vault
            .append_blob_artifact_version(
                &artifact,
                include_bytes!("../../../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"),
                &BlobVersionProvenance::UserUpload,
                WriteActor::new(owner, EdgeActorClass::Human),
                when,
                1,
            )
            .expect("append signing PDF version");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("read system time after Unix epoch")
            .as_secs();
        let recipient = EntityId::now().to_hex();
        let field = EntityId::now().to_hex();
        let document = EsignDocument {
            schema_version: 1,
            kind: DocumentKind::Document,
            title: "Agreement".into(),
            sequential: true,
            expires_at: now + 3600,
            items: vec![EsignItem {
                artifact_ref: artifact.to_hex(),
                original_version: 1,
            }],
            recipients: vec![EsignRecipient {
                id: recipient.clone(),
                email: "signer@example.test".into(),
                name: "Signer".into(),
                role: RecipientRole::Signer,
                order: 0,
                expires_at: now + 3600,
                principal_ref: None,
                automated: false,
                natural_person: None,
            }],
            fields: vec![EsignField {
                id: field,
                item: 0,
                recipient,
                required: true,
                geometry: FieldGeometry {
                    page: 1,
                    x_percent: 10.0,
                    y_percent: 10.0,
                    width_percent: 50.0,
                    height_percent: 20.0,
                },
                meta: FieldMeta::Text { max_bytes: 50 },
            }],
            full_trail_appendix: false,
            lifecycle: None,
            token_expires_at: None,
            project: None,
            commitments: Vec::new(),
        };
        vault
            .create_esign_document(
                artifact,
                &document,
                EsignAuditActor {
                    actor: owner.to_hex(),
                    ip: None,
                    user_agent: None,
                },
                now,
            )
            .expect("create signing document");
        let mut effect = Scope::top();
        effect.verbs = ScopeAxis::Some(["effect".to_owned()].into());
        oneiron::conversation_dag::test_support::put_test_policy_manifest(
            &vault,
            WriteActor::new(owner, EdgeActorClass::Human),
            EntityId::now(),
            &serde_json::json!({
                "schema_version":"1.2", "pack_id":"esign-http-test", "pack_version":"v1",
                "min_engine_version":"0.0.0",
                "defaults":{"criticality":"normal","sensitivity":"normal"},
                "rules":[],
                "actor_ceilings":[{"actor_class":"human","actor_ref":owner.to_hex(),"ceiling":"auto"}],
                "scoped_grants":[{"actor_ref":owner.to_hex(),"effector":"external:send_for_signature",
                    "scope":effect,"selectors":{"channel":"esign"}}]
            }),
        )
        .expect("install signing policy manifest");
        let authenticated = vault
            .authenticate_owner(
                owner,
                &owner.to_hex(),
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .expect("authenticate signing owner");
        let token = vault
            .issue_esign_capabilities(&authenticated, artifact)
            .expect("issue signer capability")
            .remove(0)
            .1
            .expose_for_delivery()
            .to_owned();
        let verb = EsignOutboundVerb::SendForSignature;
        let command = EsignOutboundCommand {
            document: artifact.to_hex(),
            recipient_count: 1,
            verb,
            reason: None,
        };
        let request = OutboundDispatchRequest::new(
            "receipt:public-sign",
            "public-sign",
            OutboundIntent::from_trigger(
                OutboundIntentDraft {
                    actor: owner.to_hex(),
                    on_behalf_of: None,
                    verb: verb.as_str().into(),
                    channel: "esign".into(),
                    target: artifact.to_hex(),
                    content_ref: None,
                    idempotency_key: Some("public-sign".into()),
                    dedupe_key: Some("public-sign".into()),
                    mention: None,
                },
                OutboundIntentTrigger {
                    source: OutboundIntentSource::AgentImmediate,
                    trigger_ref: "public-sign".into(),
                    job_ref: None,
                },
            ),
            OutboundDispatchActor {
                actor_class: "human".into(),
                actor_ref: Some(owner.to_hex()),
                actor_entity_ref: Some(owner),
            },
            OutboundDispatchGate::allow_when_policy_grants(),
            now,
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        vault
            .dispatch_esign(request, &command, None, None)
            .expect("dispatch signing request");
        let server = Arc::new(
            SyncServer::new(vault, crate::config::SyncServerConfig::default())
                .expect("create signing sync server"),
        );
        (dir, server, token)
    }

    /// Opens a signing session for `token` the way the page does: the
    /// exchange door, then the session form. Answers the `Cookie` value.
    async fn signing_session(app: &Router, token: &str) -> String {
        let exchange = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sign/exchange")
                    .header("x-oneiron-esign-capability", token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exchange.status(), StatusCode::OK);
        let exchange: serde_json::Value =
            serde_json::from_slice(&to_bytes(exchange.into_body(), 4096).await.unwrap()).unwrap();
        let opened = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sign/session")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "exchange={}",
                        exchange["exchange"].as_str().unwrap()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(opened.status(), StatusCode::SEE_OTHER);
        let cookie = opened.headers()[header::SET_COOKIE].to_str().unwrap();
        cookie.split(';').next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn forwarded_headers_cannot_replace_the_signing_transport_peer() {
        let (_dir, server, token) = signing_transport_fixture();
        let app = public_routes().with_state(server);
        let cookie = signing_session(&app, &token).await;
        for path in ["/sign/action", "/sign/pdf", "/sign/preview"] {
            let body = if path == "/sign/action" {
                serde_json::json!({"action":{"action":"load"}})
            } else {
                serde_json::json!({"item":0})
            };
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, cookie.as_str())
                        .header("x-forwarded-for", "192.0.2.7")
                        .header("forwarded", "for=192.0.2.7")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert_eq!(
                body,
                serde_json::json!({"error":{"code":"signing_transport_unavailable"}})
            );
        }
    }

    #[tokio::test]
    async fn geometry_upload_accepts_the_full_renderer_input_budget() {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let server =
            Arc::new(SyncServer::new(vault, crate::config::SyncServerConfig::default()).unwrap());
        let app = editor_routes().with_state(server);
        let mut pdf = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (index, body) in [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>",
            "<< /Length 0 >>\nstream\nendstream",
        ]
        .into_iter()
        .enumerate()
        {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", index + 1, body).as_bytes());
        }
        offsets.push(pdf.len());
        pdf.extend_from_slice(b"5 0 obj\n(");
        pdf.extend(std::iter::repeat_n(b'x', 4 * 1024 * 1024));
        pdf.extend_from_slice(b")\nendobj\n");
        let xref = pdf.len();
        pdf.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sign/geometry")
                    .header(header::CONTENT_TYPE, "application/pdf")
                    .body(Body::from(pdf))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["pages"].as_array().unwrap().len(), 1);
        assert_eq!(
            body["pages"][0]["crop"],
            serde_json::json!([0.0, 0.0, 100.0, 100.0])
        );
    }
}
