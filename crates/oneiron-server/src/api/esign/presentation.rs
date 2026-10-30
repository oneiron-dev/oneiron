//! Stateless field editor and capability-scoped ceremony presentation adapters.
use super::editor_auth::{EditorDesk, EditorIngress};
use super::parse_lease::ParseLease;
use super::*;
use axum::extract::{FromRequest, Request};
use oneiron::blob_artifact::esign::render::{self, PageGeometry};
use oneiron::blob_artifact::esign::{EsignField, FieldValue};
use oneiron::limit_ask::EngineLimit;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::BufReader;
use tokio::sync::OwnedSemaphorePermit;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LayoutRequest {
    fields: Vec<EsignField>,
    values: BTreeMap<String, FieldValue>,
    pages: Vec<PageGeometry>,
}
/// Pure editor layout over caller data: it reads and writes no vault rows.
/// Every field of every page is laid out, however many (Rule 5). The
/// ceremony's preview calls it directly, never the editor's HTTP door.
fn laid_out(request: LayoutRequest) -> Response {
    let layouts: Result<Vec<_>, _> = request
        .fields
        .iter()
        .map(|field| {
            let page = request
                .pages
                .get(field.geometry.page.saturating_sub(1) as usize)
                .ok_or(render::PdfPreparationError::InvalidGeometry)?;
            render::layout_field(field, request.values.get(&field.id), *page)
        })
        .collect();
    match layouts {
        Ok(layouts) => {
            Json(serde_json::json!({"pages":request.pages,"fields":layouts})).into_response()
        }
        Err(_) => refused(),
    }
}

/// `POST /sign/layout`. With no editor header it is the door it was: JSON
/// under the router's 3 MiB body limit and `EditorBudget`'s window. An
/// admitted editor's body (FIX 5618) spools whole and parses on the worker
/// that holds its slot; its size is the `[limits] esign_body_bytes` row,
/// which asks the vault owner past it and never refuses the body.
pub(super) async fn layout(
    State(server): State<Arc<SyncServer>>,
    ingress: EditorIngress,
    request: Request,
) -> Response {
    let slot = match ingress {
        EditorIngress::Anonymous => {
            return match Json::<LayoutRequest>::from_request(request, &server).await {
                Ok(Json(request)) => laid_out(request),
                Err(rejection) => rejection.into_response(),
            };
        }
        EditorIngress::Admitted(slot) => slot,
    };
    let (parts, body) = request.into_parts();
    super::ingress::editor_spooled(
        &server,
        EngineLimit::EsignBodyBytes,
        &parts.headers,
        body,
        move |file, _| {
            let _slot = slot;
            match serde_json::from_reader::<_, LayoutRequest>(BufReader::new(file)) {
                Ok(request) => laid_out(request),
                Err(_) => super::ingress::malformed(),
            }
        },
    )
    .await
    .unwrap_or_else(|refusal| refusal)
}

pub(super) async fn preview(
    State(server): State<Arc<SyncServer>>,
    SigningIngress { token, admitted }: SigningIngress,
    headers: HeaderMap,
    peer: NetworkPeer,
    local_peer: LocalPeer,
    body: Body,
) -> Response {
    let Ok(ip) = signing_peer_ip(peer, local_peer) else {
        return unavailable();
    };
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let request: super::ingress::ItemBody =
        match super::ingress::payload(&server, admitted, &headers, body).await {
            Ok(request) => request,
            Err(response) => return response,
        };
    let Ok((page, bytes)) = server
        .vault
        .esign_preview_for_capability(&token, request.item, ip, ua)
    else {
        return refused();
    };
    let Ok(pages) =
        render::inspect_pdf_pages_within(&bytes, server.vault.esign_stream_decode_bytes())
    else {
        return refused();
    };
    laid_out(LayoutRequest {
        fields: page
            .fields
            .into_iter()
            .filter(|f| f.item as usize == request.item)
            .collect(),
        values: page.values.into_iter().map(|(k, v)| (k, v.value)).collect(),
        pages,
    })
}

/// The owner's editor shell is not a public signing capability: loading it
/// needs an owner-grade caller, as before. It mints that caller an
/// editor-computation token (FIX 5618, `editor_auth`) into the no-store
/// page; the page's script reads it, removes it from the document and sends
/// it only in the `x-oneiron-esign-editor` header of its computation POSTs.
pub(super) async fn editor(
    auth: crate::auth::CoreAuth,
    axum::Extension(desk): axum::Extension<Arc<EditorDesk>>,
) -> Response {
    if !auth.is_owner_grade() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let token = desk.mint(auth);
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer><meta id=editor-capability name=oneiron-esign-editor content=\"{token}\"><title>Field geography editor</title><main><h1>Field geography editor</h1><p>Load a PDF and a field geography pack. Positions are percentages of the visible page after rotation.</p><label>PDF <input id=pdf-file type=file accept=application/pdf></label><label>Pack JSON <input id=pack-file type=file accept=application/json></label><label>Item <input id=current-item type=number min=0 value=0></label><label>Recipient reference <input id=recipient></label><label>Field type <select id=field-kind><option>signature</option><option>initials</option><option>name</option><option>email</option><option>date</option><option>text</option><option>checkbox</option><option>select</option></select></label><label>Select options (one per line)<textarea id=select-options></textarea></label><button id=add>Add field</button><section id=fields></section><section id=preview></section><button id=save>Export geography pack</button><p id=status></p></main><script src=/sign/field-renderer.js></script><script src=/sign/editor.js></script></html>"
    );
    ([ (header::CONTENT_SECURITY_POLICY,"default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src blob:; base-uri 'none'; frame-ancestors 'none'"), (header::CACHE_CONTROL,"no-store") ],axum::response::Html(html)).into_response()
}
pub(super) async fn field_script() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("field-renderer.js"),
    )
        .into_response()
}
pub(super) async fn editor_script() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("editor.js"),
    )
        .into_response()
}
/// `POST /sign/geometry`: byte-only inspection, no template parse, blob
/// write, or outbound effects. With no editor header it is the door it was:
/// the PDF under the route's 16 MiB body limit and `EditorBudget`'s window.
/// An admitted editor's PDF (FIX 5618) spools whole and is inspected on the
/// worker that holds its slot; its size is the `[limits]
/// esign_geometry_body_bytes` row, which asks the vault owner past it and
/// never refuses the PDF. The PDF's bytes are leased from this machine's
/// memory before it is read into memory (FIX 7649), and the lease grows for
/// its parse's own memory as the parse proceeds (FIX 8065, `parse_lease`).
pub(super) async fn upload_geometry(
    State(server): State<Arc<SyncServer>>,
    ingress: EditorIngress,
    request: Request,
) -> Response {
    // Each stream decodes within the vault's own row (FIX 6287).
    let stream_decode_bytes = server.vault.esign_stream_decode_bytes();
    let memory = server.memory.clone();
    let slot = match ingress {
        EditorIngress::Anonymous => {
            let permit = request
                .extensions()
                .get::<Arc<OwnedSemaphorePermit>>()
                .cloned();
            let body = match axum::body::Bytes::from_request(request, &server).await {
                Ok(body) => body,
                Err(rejection) => return rejection.into_response(),
            };
            return match tokio::task::spawn_blocking(move || {
                let _permit = permit;
                render::inspect_pdf_pages_within(&body, stream_decode_bytes)
            })
            .await
            {
                Ok(Ok(pages)) => Json(serde_json::json!({"pages":pages})).into_response(),
                _ => refused(),
            };
        }
        EditorIngress::Admitted(slot) => slot,
    };
    let (parts, body) = request.into_parts();
    super::ingress::editor_spooled(
        &server,
        EngineLimit::EsignGeometryBodyBytes,
        &parts.headers,
        body,
        move |file, bytes| {
            let _slot = slot;
            let deadline = std::time::Instant::now() + super::ingress::MEMORY_WAIT;
            let lease = match memory.lease(bytes, deadline) {
                Ok(lease) => lease,
                Err(refusal) => return super::ingress::memory_refused(refusal),
            };
            let pdf = match super::ingress::whole_body(file, bytes, &lease) {
                Ok(pdf) => pdf,
                Err(unread) => return super::ingress::whole_body_refused(unread),
            };
            let parse = Arc::new(ParseLease::new(lease, deadline));
            match render::inspect_pdf_pages_admitted(&pdf, stream_decode_bytes, parse.clone()) {
                Ok(pages) => Json(serde_json::json!({"pages":pages})).into_response(),
                Err(_) => match parse.refused() {
                    Some(refusal) => super::ingress::memory_refused(refusal),
                    None => refused(),
                },
            }
        },
    )
    .await
    .unwrap_or_else(|refusal| refusal)
}

pub(super) async fn signature(
    State(server): State<Arc<SyncServer>>,
    SigningIngress { token, admitted }: SigningIngress,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let request: super::ingress::SignatureBody =
        match super::ingress::payload(&server, admitted, &headers, body).await {
            Ok(request) => request,
            Err(response) => return response,
        };
    match server
        .vault
        .esign_signature_image_for_capability(&token, &request.image_ref)
    {
        Ok(bytes) => ([(header::CONTENT_TYPE, "image/png")], bytes).into_response(),
        Err(_) => refused(),
    }
}
