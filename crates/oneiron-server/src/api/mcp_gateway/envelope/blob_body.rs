//! A tool-first `tools/call`'s `arguments.spec.content_base64`, spooled and
//! decoded into a file before the call (FIX 22074; Engine rulings E1 = C,
//! E2 = A, E5 = A, E7 PR 4). A POST to `/mcp/tool-first` that declares its
//! length within the request bound, from a caller the gateway resolves
//! outside an anonymous session, is read onto an anonymous file the vault
//! stages, and the content of a `vault.artifacts.create`, `.append` or
//! `.propose_output` call is decoded into a file of its own as the spool is
//! read, never one string or one buffer in memory. The endpoint parses the
//! rest of the body with that string empty; the call's verb reads the
//! bytes from the file, or its pre chain puts the string back before any
//! hook reads the args. Every identity the call states is the one of the
//! body as it arrived: the connection receipt's body digest, the call
//! receipt's params digest, the invocation claim with the exact
//! `params.arguments` text streamed from the spool, and the page argument
//! digest admission and paging bind.
//!
//! A body this reader does not take as one JSON-RPC object with one
//! standard base64 content string at that path, longer than an entity ref,
//! for one of those tools, is read whole from the spool, exactly as the
//! endpoint read every body before. Any other POST is read as the route's
//! `Bytes` extractor read it.

use super::*;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::extract::FromRequest;
use axum::http::StatusCode;
use axum::http::request::Parts;

use crate::api::body_spool::{
    self, Base64FileSink, BodySpool, BulkMember, HeadFail, SinkRefusal, SpoolFailed, SpoolPolicy,
    SpooledField, TextFileSink, Unspooled,
};
use crate::mcp::{McpHeldContent, McpVerbToolArgs};

/// The member whose string is decoded into a file.
const CONTENT_MEMBER: &str = "content_base64";

/// The objects the content sits in, from the JSON-RPC request down:
/// `params`, its `arguments` (the tool call's), their `arguments` (the
/// verb's) and its `spec`.
const CONTENT_PATH: [&str; 4] = ["params", "arguments", "arguments", "spec"];

/// The content's path from `params`.
const PARAMS_CONTENT_PATH: [&str; 4] = ["arguments", "arguments", "spec", CONTENT_MEMBER];

/// The most decoded bytes whose base64 is no longer than an entity ref's 32
/// hex digits. The receipt captures the version of every entity a request
/// names by such a string (`oneiron::receipt::json_entity_refs`), so content
/// this short keeps its string.
const ENTITY_REF_DECODED_BYTES: u64 = 24;

/// What the tool-first endpoint read of a POST's body.
pub(crate) struct McpArrived {
    /// The bytes the endpoint parses: the body as it arrived, or, for held
    /// content, the body with that content's string empty.
    pub(super) bytes: Bytes,
    /// The held content and the body's identities, when it held one.
    pub(super) held: Option<McpHeld>,
}

impl McpArrived {
    /// A body read whole.
    pub(crate) fn whole(bytes: Bytes) -> Self {
        Self { bytes, held: None }
    }
}

/// A body whose content is held as a file: what its identities read of the
/// body as it arrived, and the content.
pub(crate) struct McpHeld {
    body_digest: String,
    params_digest: String,
    /// The body as it arrived, for the exact `params.arguments` text.
    spool: File,
    /// Where `params.arguments` sits in the spool.
    arguments: (u64, u64),
    tool: String,
    content: SpooledField,
}

impl McpHeld {
    /// BLAKE3 of the body as it arrived, as a connection receipt digests it.
    pub(super) fn body_digest(&self) -> &str {
        &self.body_digest
    }

    /// The canonical digest of the request's `params` as they arrived, as
    /// the call receipt and the invocation claim digest them.
    pub(super) fn params_digest(&self) -> &str {
        &self.params_digest
    }

    /// The invocation claim's identity: `parts`, then the exact original
    /// `params.arguments` text as its last part, streamed from the spool.
    ///
    /// # Errors
    ///
    /// The spool's read errors.
    pub(super) fn invocation_body(
        &self,
        locality: CallerLocality,
        parts: &[&[u8]],
    ) -> io::Result<[u8; 32]> {
        let (start, end) = self.arguments;
        let mut spool = &self.spool;
        spool.seek(SeekFrom::Start(start))?;
        facade::invocation_body_with_reader(
            None,
            locality,
            parts,
            end.saturating_sub(start),
            &mut spool,
        )
    }

    /// The content for `call` when it is the call of the tool it arrived
    /// for, with that call's page argument digest; `None` for another.
    ///
    /// # Errors
    ///
    /// The content file's read errors.
    pub(super) fn content_for(self, call: &McpVerbToolArgs) -> io::Result<Option<McpHeldContent>> {
        if call.tool.name != self.tool {
            return Ok(None);
        }
        let content = &self.content;
        let page = crate::mcp::mcp_page_argument_digest_held(
            &call.payload,
            content.base64_json_len(),
            |hasher| content.write_base64_json(hasher),
        )?;
        Ok(Some(McpHeldContent::new(
            &self.tool,
            self.content.into_file(),
            page,
        )))
    }
}

/// Reads a tool-first POST's body: onto a spool, an artifact write's
/// content into a file, when it declares its length within the request
/// bound and its caller resolves outside an anonymous session; else as the
/// route's `Bytes` extractor read it, with the same refusals.
///
/// # Errors
///
/// The extractor's refusal; a spool the vault had no room or memory for,
/// as the endpoint's JSON-RPC refusal.
pub(crate) async fn read_tool_first(
    server: &Arc<SyncServer>,
    parts: &Parts,
    locality: CallerLocality,
    body: Body,
) -> Result<McpArrived, Response> {
    let limit = u64::try_from(crate::api::request_floor::request_floor(server)).unwrap_or(u64::MAX);
    let declared = body_spool::declared_length(&parts.headers).filter(|len| *len <= limit);
    tracing::debug!(target: "oneiron::run_start", stage = "tool_first_read_start", declared = ?declared, "run start");
    if declared.is_none() || !spool_admitted(server, parts, locality).await {
        return whole_body(parts, body).await.map(McpArrived::whole);
    }
    let over = Arc::new(AtomicBool::new(false));
    let body = body_spool::capped(body, limit, Arc::clone(&over));
    tracing::debug!(target: "oneiron::run_start", stage = "spool_admitted_returned", "run start");
    let vault = Arc::clone(&server.vault);
    let read = body_spool::spool_then(
        server,
        declared,
        body,
        SpoolPolicy::default(),
        move |spool| read_spool(&vault, spool),
    )
    .await;
    tracing::debug!(target: "oneiron::run_start", stage = "spool_then_returned", "run start");
    match read {
        Ok(_) if over.load(Ordering::Relaxed) => Err(not_buffered()),
        Ok(Ok(arrived)) => Ok(arrived),
        // The whole body arrived; its spool did not read.
        Ok(Err(failed)) => Err(spool_refused(
            server,
            &parts.headers,
            failed.unspooled,
            failed.body_digest.as_deref(),
        )),
        Err(Unspooled::Failed) => Err(not_buffered()),
        Err(unspooled) => Err(spool_refused(server, &parts.headers, unspooled, None)),
    }
}

/// Whether a POST's body may go on the vault's disk: its `Origin` and
/// protocol header pass, and its caller resolves outside an anonymous
/// off-record session. The caller is resolved again, in full, by its call.
async fn spool_admitted(server: &Arc<SyncServer>, parts: &Parts, locality: CallerLocality) -> bool {
    if !super::http::origin_admitted(server, &parts.headers)
        || super::http::mcp_protocol_header_refusal(&parts.headers).is_some()
    {
        return false;
    }
    let Ok(caller) = crate::api::mcp_gateway::owner_call::resolve_mcp_caller(
        McpSurfaceMode::ToolFirst,
        "",
        &parts.headers,
        &parts.extensions,
        locality,
        server,
    )
    .await
    else {
        return false;
    };
    tracing::debug!(target: "oneiron::run_start", stage = "spool_admitted_caller_resolved", "run start");
    let principal =
        crate::api::call_receipt::mcp_session_principal(caller.auth.as_ref(), caller.actor_ref);
    !crate::api::call_receipt::in_anonymous_session(server, &parts.headers, principal)
}

/// The body as the route's `Bytes` extractor reads it: under the request
/// bound its layer set, with its refusals.
async fn whole_body(parts: &Parts, body: Body) -> Result<Bytes, Response> {
    let mut request = axum::extract::Request::new(body);
    *request.headers_mut() = parts.headers.clone();
    *request.extensions_mut() = parts.extensions.clone();
    Bytes::from_request(request, &())
        .await
        .map_err(IntoResponse::into_response)
}

/// A body that did not arrive whole, as the `Bytes` extractor answers it.
fn not_buffered() -> Response {
    (StatusCode::BAD_REQUEST, "Failed to buffer the request body").into_response()
}

/// A body the vault had no room or memory to spool, or whose spool did not
/// read, as the endpoint's connection refusal: no call ran. A body that
/// arrived whole states its digest (`body_digest`); one that did not, none.
fn spool_refused(
    server: &SyncServer,
    headers: &HeaderMap,
    unspooled: Unspooled,
    body_digest: Option<&str>,
) -> Response {
    let (kind, message) = match unspooled {
        Unspooled::NoRoom => (
            crate::owner::backup::write_budget::CAPACITY_STATE,
            unspooled.refusal().message().to_owned(),
        ),
        Unspooled::Failed => (
            "engine_error",
            "the request body's spool did not read".to_owned(),
        ),
        unspooled => ("engine_error", unspooled.refusal().message().to_owned()),
    };
    let arrival = match body_digest {
        Some(digest) => super::http::Arrival::spooled(digest),
        None => super::http::Arrival::of(&[]),
    };
    super::http::mcp_connection_refusal(
        server,
        headers,
        "mcp",
        arrival,
        Value::Null,
        McpGatewayError::new(-32603, kind, message),
    )
}

/// What [`read_spool_in`] read of the spool.
enum Scanned {
    /// The body whole.
    Whole(Bytes),
    /// The rest of the body, its content empty, and what the held content
    /// keeps but the spool itself.
    Held {
        projected: Vec<u8>,
        params_digest: String,
        arguments: (u64, u64),
        tool: String,
        content: SpooledField,
    },
}

/// Reads the spool ([`read_spool_in`]), keeping it for the identities of a
/// held body; a failure names the body's digest.
fn read_spool(vault: &oneiron::Vault, mut spool: BodySpool) -> Result<McpArrived, SpoolFailed> {
    let scanned = read_spool_in(vault, &mut spool).map_err(|unspooled| spool.failed(unspooled))?;
    let (projected, params_digest, arguments, tool, content) = match scanned {
        Scanned::Whole(bytes) => return Ok(McpArrived::whole(bytes)),
        Scanned::Held {
            projected,
            params_digest,
            arguments,
            tool,
            content,
        } => (projected, params_digest, arguments, tool, content),
    };
    let body_digest = spool
        .digest()
        .map_err(|_| spool.failed(Unspooled::Failed))?;
    Ok(McpArrived {
        bytes: Bytes::from(projected),
        held: Some(McpHeld {
            body_digest,
            params_digest,
            spool: spool.into_file(),
            arguments,
            tool,
            content,
        }),
    })
}

/// Reads the spool: the content to its file and the rest of the body as
/// JSON, when the body is one tool-first call of an artifact write with one
/// base64 content string longer than an entity ref; else the body whole.
fn read_spool_in(vault: &oneiron::Vault, spool: &mut BodySpool) -> Result<Scanned, Unspooled> {
    let file = vault
        .archive_spool_file()
        .map_err(body_spool::create_failed)?;
    let head_file = vault
        .archive_spool_file()
        .map_err(body_spool::create_failed)?;
    let (scanned, head, content) = {
        let mut memory = spool
            .admit_sealed_decode_buffers()
            .map_err(Unspooled::MemoryRefused)?;
        let mut content = Base64FileSink::new_admitted(file, &mut memory);
        let mut head = TextFileSink::new_admitted(head_file, &mut memory);
        let scanned = spool.member_path_head_admitted(
            &CONTENT_PATH,
            &mut BulkMember::required(CONTENT_MEMBER, &mut content),
            &mut head,
            &mut memory,
        );
        (scanned, head.into_field(), content.into_field())
    };
    // No working buffer or lease survives into the next read.
    let (spans, content) = match (scanned, content) {
        (Err(HeadFail::Failed), _) | (Ok(_), Err(SinkRefusal::Failed)) => {
            return Err(Unspooled::Failed);
        }
        (Ok(_), Err(SinkRefusal::NoRoom)) => return Err(Unspooled::NoRoom),
        (Ok(spans), Ok(content)) if content.file().1 > ENTITY_REF_DECODED_BYTES => (spans, content),
        _ => return read_whole(spool),
    };
    let projected = read_field(&head?).map_err(|_| Unspooled::Failed)?;
    let Ok(request) = serde_json::from_slice::<Value>(&projected) else {
        return read_whole(spool);
    };
    let tool = request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .filter(|_| request.get("method").and_then(Value::as_str) == Some("tools/call"))
        .filter(|tool| oneiron::task_verb::sdk::takes_blob_input(tool));
    let (Some(tool), Some(params), Some(&arguments)) = (tool, request.get("params"), spans.get(1))
    else {
        return read_whole(spool);
    };
    let params_digest = oneiron::receipt::call_json_digest_with_member_path(
        params,
        &PARAMS_CONTENT_PATH,
        |hasher| content.write_base64_json(hasher),
    )
    .map_err(|_| Unspooled::Failed)?;
    let tool = tool.to_owned();
    Ok(Scanned::Held {
        projected,
        params_digest,
        arguments,
        tool,
        content,
    })
}

/// A spooled field's bytes whole: the rest of a body, its content empty.
fn read_field(field: &SpooledField) -> io::Result<Vec<u8>> {
    let (mut file, len) = field.file();
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or_default());
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The spooled body whole, as the endpoint read every body before.
fn read_whole(spool: &mut BodySpool) -> Result<Scanned, Unspooled> {
    let len = spool.byte_len().map_err(|_| Unspooled::Failed)?;
    let mut memory = spool.admit_reader().map_err(Unspooled::MemoryRefused)?;
    let bytes = spool
        .with_reader_admitted(&mut memory, |reader| -> io::Result<Vec<u8>> {
            reader.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or_default());
            reader.read_to_end(&mut bytes)?;
            Ok(bytes)
        })
        .map_err(|_| Unspooled::Failed)?;
    Ok(Scanned::Whole(Bytes::from(bytes)))
}
