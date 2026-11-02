//! The open feedback inbox (ARCH-0056 #open-inbox): anyone may leave this
//! vault a note, with no key and no moderation. A GET link carries the text
//! in its query (`/v1/feedback?text=…`); a POST carries it as a plain-text,
//! form or JSON (`{"text": …}`) body, or carries the v1 bundle a vault's
//! `collector` send delivers, or the content-free issue signature a vault's
//! Coach delivers (`oneiron.issue_signature.v1`, read back typed, FIX 7684).
//! Mounted only while `[feedback.inbox]` is on.
//!
//! The flood cap is the one refusal, asked before anything of a request is
//! read; besides it, only the machine's floors (the `[limits]` body row and
//! the disk reserve) and an empty or unreadable note are refused, or a body
//! that declares the issue signature schema and does not read back as one.
//! The reply says only that the note landed, so nothing of the vault is
//! reachable from here; the notes are read back through the owner's routes.

mod flood;

pub(crate) use flood::FloodCap;

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequest, Query, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Form, Json, Router};
use oneiron::feedback::{
    FeedbackCategory, FeedbackEncoding, FeedbackInboxVia, declares_issue_signature,
    decode_feedback_bundle_as, reads_as_issue_signature,
};
use serde::Deserialize;

use crate::auth::ClientAddress;
use crate::error::{ApiError, ApiErrorDetails};
use crate::server::SyncServer;

/// The inbox's route, or none while `[feedback.inbox]` is off.
pub(super) fn routes(server: &SyncServer) -> Router<Arc<SyncServer>> {
    if !server.config.feedback_inbox.enabled {
        return Router::new();
    }
    Router::new()
        .route("/v1/feedback", get(take_link).post(take_post))
        .layer(DefaultBodyLimit::max(body_row(server)))
}

/// What a link's query, a form or a JSON body may name. Other fields are
/// ignored, and so is a category the bundle contract does not name.
#[derive(Deserialize)]
struct NoteFields {
    text: Option<String>,
    category: Option<String>,
}

enum Note {
    Text {
        via: FeedbackInboxVia,
        text: String,
        category: Option<FeedbackCategory>,
    },
    Bundle(FeedbackEncoding, Bytes),
    /// A JSON body that declares the issue signature schema, as sent.
    Signature(String),
}

/// A request that lands nothing before the flood cap is asked.
#[derive(Debug, Clone, Copy)]
enum Unlanded {
    NoText,
    Unreadable,
    NotABundle,
    /// A body that declares the issue signature schema and does not read
    /// back as one: its sender never records it delivered.
    NotASignature,
    /// Past the `[limits]` row.
    TooLarge,
}

impl Unlanded {
    fn response(self) -> Response {
        match self {
            Self::NoText => {
                ApiError::bad_request("the note has no text", Some("text")).into_response()
            }
            Self::Unreadable => {
                ApiError::bad_request("the note is not readable text", Some("text")).into_response()
            }
            Self::NotABundle => {
                ApiError::bad_request("the body is not a v1 feedback bundle", None).into_response()
            }
            Self::NotASignature => ApiError::bad_request(
                "the body is not an oneiron.issue_signature.v1 signature",
                None,
            )
            .into_response(),
            Self::TooLarge => refusal(
                StatusCode::PAYLOAD_TOO_LARGE,
                "feedback_inbox_too_large",
                "the note is too long",
                None,
            ),
        }
    }

    /// An extractor's refusal: past the row, or else not readable.
    fn rejected(status: StatusCode) -> Self {
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            Self::TooLarge
        } else {
            Self::Unreadable
        }
    }
}

async fn take_link(
    State(server): State<Arc<SyncServer>>,
    ClientAddress(sender): ClientAddress,
    method: Method,
    uri: Uri,
) -> Response {
    // A link checker's HEAD lands nothing; the GET it is checking does.
    if method == Method::HEAD {
        return StatusCode::NO_CONTENT.into_response();
    }
    if let Some(shed) = shed(&server, sender) {
        return shed;
    }
    // The query as sent is bounded before any of it is decoded.
    if uri.query().map_or(0, str::len) > body_row(&server) {
        return Unlanded::TooLarge.response();
    }
    let note = Query::<NoteFields>::try_from_uri(&uri)
        .map_err(|_| Unlanded::Unreadable)
        .and_then(|Query(fields)| fields_note(FeedbackInboxVia::Link, fields));
    land(server, note).await
}

async fn take_post(
    State(server): State<Arc<SyncServer>>,
    ClientAddress(sender): ClientAddress,
    request: Request,
) -> Response {
    if let Some(shed) = shed(&server, sender) {
        return shed;
    }
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    // The sender names the bundle's encoding beside the bytes; an unlabelled
    // bundle is v1, and a token this engine cannot read lands nothing.
    let encoding = match request.headers().get("x-oneiron-bundle-encoding") {
        None => Ok(FeedbackEncoding::V1),
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|token| FeedbackEncoding::from_token(token.trim()).ok())
            .ok_or(Unlanded::NotABundle),
    };
    let note = match content_type.as_str() {
        "application/msgpack" => match encoding {
            Ok(encoding) => Bytes::from_request(request, &server)
                .await
                .map(|bytes| Note::Bundle(encoding, bytes))
                .map_err(|rejection| Unlanded::rejected(rejection.status())),
            Err(unlanded) => Err(unlanded),
        },
        // A body that declares the issue signature schema lands only as one;
        // every other JSON body is a note's fields, as it always was.
        "application/json" => match Bytes::from_request(request, &server).await {
            Ok(bytes) if declares_issue_signature(&bytes) => String::from_utf8(bytes.to_vec())
                .map(Note::Signature)
                .map_err(|_| Unlanded::NotASignature),
            Ok(bytes) => serde_json::from_slice::<NoteFields>(&bytes)
                .map_err(|_| Unlanded::Unreadable)
                .and_then(|fields| fields_note(FeedbackInboxVia::Post, fields)),
            Err(rejection) => Err(Unlanded::rejected(rejection.status())),
        },
        "application/x-www-form-urlencoded" => Form::<NoteFields>::from_request(request, &server)
            .await
            .map_err(|rejection| Unlanded::rejected(rejection.status()))
            .and_then(|Form(fields)| fields_note(FeedbackInboxVia::Post, fields)),
        _ => match Bytes::from_request(request, &server).await {
            Ok(bytes) => String::from_utf8(bytes.to_vec())
                .map_err(|_| Unlanded::Unreadable)
                .and_then(|text| text_note(FeedbackInboxVia::Post, text, None)),
            Err(rejection) => Err(Unlanded::rejected(rejection.status())),
        },
    };
    land(server, note).await
}

/// The flood cap, asked before anything of a request is read: every
/// attempt it lets through counts, an empty or unreadable one too, and a
/// shed sender costs no decoding.
fn shed(server: &SyncServer, sender: Option<std::net::IpAddr>) -> Option<Response> {
    let shed = server.feedback_flood.admit(sender, Instant::now()).err()?;
    Some(refusal(
        StatusCode::TOO_MANY_REQUESTS,
        "feedback_inbox_flood",
        "the inbox takes no more notes from this sender this hour",
        Some(shed.retry_after.as_secs()),
    ))
}

fn fields_note(via: FeedbackInboxVia, fields: NoteFields) -> Result<Note, Unlanded> {
    let category = fields.category.and_then(|named| {
        FeedbackCategory::ALL
            .into_iter()
            .find(|category| category.as_str() == named)
    });
    text_note(via, fields.text.unwrap_or_default(), category)
}

fn text_note(
    via: FeedbackInboxVia,
    text: String,
    category: Option<FeedbackCategory>,
) -> Result<Note, Unlanded> {
    if text.trim().is_empty() {
        return Err(Unlanded::NoText);
    }
    Ok(Note::Text {
        via,
        text,
        category,
    })
}

async fn land(server: Arc<SyncServer>, note: Result<Note, Unlanded>) -> Response {
    let note = match note {
        Ok(note) => note,
        Err(unlanded) => return unlanded.response(),
    };
    let size = match &note {
        Note::Text { text, .. } => text.len(),
        Note::Bundle(encoding, bytes) => {
            if decode_feedback_bundle_as(*encoding, bytes).is_err() {
                return Unlanded::NotABundle.response();
            }
            bytes.len()
        }
        Note::Signature(body) => {
            if !reads_as_issue_signature(body) {
                return Unlanded::NotASignature.response();
            }
            body.len()
        }
    };
    // A POST body past the row was already refused by its extractor; a
    // link's query is bounded here.
    if size > body_row(&server) {
        return Unlanded::TooLarge.response();
    }
    // Room for the stored row (the note, a bundle's second copy of its
    // note, the row's framing), held until the write commits.
    let claim = server.transfers.disk.claim();
    let room = (size as u64).saturating_mul(2).saturating_add(4_096);
    if !server.transfers.disk.hold(&claim, room) {
        return refusal(
            StatusCode::INSUFFICIENT_STORAGE,
            "feedback_inbox_disk_floor",
            "this server's disk is at its floor",
            None,
        );
    }
    let stored = tokio::task::spawn_blocking(move || {
        let _held = claim;
        match note {
            Note::Text {
                via,
                text,
                category,
            } => server.vault().take_feedback_note(via, text, category),
            Note::Bundle(encoding, bytes) => {
                server.vault().take_feedback_bundle_as(encoding, &bytes)
            }
            Note::Signature(body) => server.vault().take_feedback_signature(&body),
        }
    })
    .await;
    match stored {
        Ok(Ok(_)) => {
            let mut response = (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"received": true})),
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "the feedback inbox could not store a note");
            ApiError::internal_server_error("the note could not be stored").into_response()
        }
        Err(_) => ApiError::internal_server_error("the note could not be stored").into_response(),
    }
}

/// The `[limits]` row bounding one note, as a length.
fn body_row(server: &SyncServer) -> usize {
    usize::try_from(server.config.limits.feedback_inbox_bytes).unwrap_or(usize::MAX)
}

/// A typed refusal: the usual error body under `status`, with `retry-after`
/// when the sender may come back.
fn refusal(
    status: StatusCode,
    state: &str,
    message: &str,
    retry_after_secs: Option<u64>,
) -> Response {
    let body = ApiError::new(
        message,
        ApiErrorDetails::InvalidState {
            state: Some(state.to_owned()),
        },
        Vec::<String>::new(),
    );
    let mut response = (status, Json(body)).into_response();
    if let Some(secs) = retry_after_secs {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
