//! Stateless field editor and capability-scoped ceremony presentation adapters.
use super::*;
use oneiron::blob_artifact::esign::render::{self, PageGeometry};
use oneiron::blob_artifact::esign::{EsignField, FieldValue};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LayoutRequest {
    fields: Vec<EsignField>,
    values: BTreeMap<String, FieldValue>,
    pages: Vec<PageGeometry>,
}
/// Pure editor layout. Caller data only; this door reads/writes no vault rows.
pub(super) async fn layout(Json(request): Json<LayoutRequest>) -> Response {
    if request.fields.len() > 10000 || request.pages.len() > 1000 || request.values.len() > 10000 {
        return refused();
    }
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

pub(super) async fn preview(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    peer: Result<
        axum::extract::ConnectInfo<std::net::SocketAddr>,
        axum::extract::rejection::ExtensionRejection,
    >,
    Json(request): Json<PdfRequest>,
) -> Response {
    let Ok(token) = EsignCapability::parse(&request.token) else {
        return refused();
    };
    let Ok(axum::extract::ConnectInfo(peer)) = peer else {
        return unavailable();
    };
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 1024)
        .map(str::to_owned);
    let Ok((page, bytes)) = server.vault.esign_preview_for_capability(
        &token,
        request.item,
        Some(peer.ip().to_string()),
        ua,
    ) else {
        return refused();
    };
    let Ok(pages) = render::inspect_pdf_pages(&bytes) else {
        return refused();
    };
    layout(Json(LayoutRequest {
        fields: page
            .fields
            .into_iter()
            .filter(|f| f.item as usize == request.item)
            .collect(),
        values: page.values.into_iter().map(|(k, v)| (k, v.value)).collect(),
        pages,
    }))
    .await
}

pub(super) async fn editor() -> Response {
    let html = "<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer><title>Field geography editor</title><main><h1>Field geography editor</h1><p>Load a PDF and a field geography pack. Positions are percentages of the visible page after rotation.</p><label>PDF <input id=pdf-file type=file accept=application/pdf></label><label>Pack JSON <input id=pack-file type=file accept=application/json></label><label>Item <input id=current-item type=number min=0 value=0></label><label>Recipient reference <input id=recipient></label><label>Field type <select id=field-kind><option>signature</option><option>initials</option><option>name</option><option>email</option><option>date</option><option>text</option><option>checkbox</option><option>select</option></select></label><label>Select options (one per line)<textarea id=select-options></textarea></label><button id=add>Add field</button><section id=fields></section><section id=preview></section><button id=save>Export geography pack</button><p id=status></p></main><script src=/sign/field-renderer.js></script><script src=/sign/editor.js></script></html>";
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
pub(super) async fn upload_geometry(
    axum::Extension(permit): axum::Extension<Arc<tokio::sync::OwnedSemaphorePermit>>,
    body: axum::body::Bytes,
) -> Response {
    // Byte-only inspection, no template parse, blob write, or outbound effects.
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        render::inspect_pdf_pages(&body)
    })
    .await
    {
        Ok(Ok(pages)) => Json(serde_json::json!({"pages":pages})).into_response(),
        _ => refused(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignatureRead {
    token: String,
    image_ref: String,
}
pub(super) async fn signature(
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<SignatureRead>,
) -> Response {
    let Ok(token) = EsignCapability::parse(&request.token) else {
        return refused();
    };
    match server
        .vault
        .esign_signature_image_for_capability(&token, &request.image_ref)
    {
        Ok(bytes) => ([(header::CONTENT_TYPE, "image/png")], bytes).into_response(),
        Err(_) => refused(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use oneiron::blob_artifact::esign::{FieldGeometry, FieldMeta};
    #[tokio::test]
    async fn editor_and_ceremony_adapter_return_the_export_drawing_program() {
        let field = EsignField {
            id: oneiron::EntityId::now().to_hex(),
            item: 0,
            recipient: oneiron::EntityId::now().to_hex(),
            required: true,
            geometry: FieldGeometry {
                page: 1,
                x_percent: 10.,
                y_percent: 20.,
                width_percent: 30.,
                height_percent: 10.,
            },
            meta: FieldMeta::Text { max_bytes: 80 },
        };
        let page = PageGeometry {
            crop: [0., 0., 600., 800.],
            rotation: 0,
            user_unit: 1.,
        };
        let value = FieldValue::Text("Accepted".into());
        let expected = render::layout_field(&field, Some(&value), page).unwrap();
        let response = layout(Json(LayoutRequest {
            values: BTreeMap::from([(field.id.clone(), value)]),
            fields: vec![field.clone()],
            pages: vec![page],
        }))
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let wire: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(wire["fields"][0], serde_json::to_value(expected).unwrap());
        let response = layout(Json(LayoutRequest {
            values: BTreeMap::new(),
            fields: vec![field],
            pages: vec![],
        }))
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
