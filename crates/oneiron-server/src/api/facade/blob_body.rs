//! A facade artifact write's `content_base64`, spooled and decoded into a
//! file before the call (FIX 22074; Engine rulings E1 = C, E2 = A, E5 = A).
//! `vault.artifacts.create`, `.append` and `.propose_output` POSTed as JSON
//! read their body onto an anonymous file the vault stages, and the content
//! member is decoded into a file of its own as the spool is read, never one
//! string or one buffer in memory. The call runs on the rest of the body
//! with that member empty, and its row reads the bytes from the file
//! (`oneiron::task_verb::sdk::invoke_blob_input`), or gets the string back
//! before a hook reads its args. The receipt, the invocation claim and
//! admission state the digest of the body as it arrived.
//!
//! A body this reader does not take as one object with one standard base64
//! content string (malformed, a duplicate or a missing member, content that
//! is not base64 or no longer than an entity ref) is read whole from the
//! spool, as the facade read every body before: its JSON value, its
//! refusals and what its hooks read stay as they were. A body past the
//! facade's bound, or one that did not arrive whole, reaches the route
//! empty, as before.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::{Body, Bytes};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use serde_json::{Map, Value};

use super::FacadeApiError;
use crate::api::body_spool::{
    self, Base64FileSink, BodySpool, BulkMember, HeadFail, SinkRefusal, SpoolFailed, SpoolPolicy,
    SpooledField, TextFileSink, Unspooled,
};
use crate::server::SyncServer;

/// The member whose string is decoded into a file.
const CONTENT_MEMBER: &str = "content_base64";

/// The most decoded bytes whose base64 is no longer than an entity ref's 32
/// hex digits. The receipt captures the version of every entity a request
/// names by such a string (`oneiron::receipt::json_entity_refs`), so content
/// this short keeps its string.
const ENTITY_REF_DECODED_BYTES: u64 = 24;

/// What the receipt layer read of a facade call's body.
pub(super) struct ReceiptBody {
    /// The bytes the route reads: the body as it arrived, or, for content
    /// held as a file, the rest of the body with that member empty.
    pub(super) bytes: Bytes,
    /// The body as JSON, when it is: for held content, the rest of it.
    pub(super) request: Option<Value>,
    /// The digest of the body as it arrived.
    pub(super) digest: String,
    /// The refusal of a body the vault had no room or memory to read:
    /// answered without running the call.
    pub(super) refused: Option<FacadeApiError>,
}

/// A held content's file, on the request's extensions and then on its
/// call ([`super::FacadeCall`]) for the one row it arrived for. A clone
/// shares the file, which goes once the last clone drops.
#[derive(Clone)]
pub(super) struct FacadeBlobBody(Arc<HeldContent>);

struct HeldContent {
    verb: String,
    digest: String,
    content: HeldFile,
}

/// Where a held content's file came from.
enum HeldFile {
    /// This reader's own spool.
    Spooled(SpooledField),
    /// The action whose row this call is (FIX 22096).
    Action(oneiron::code_run::actions::ActionBlobInput),
}

/// An action's input whose content its action holds as a file (FIX 22096):
/// on the extensions of the action's call while its driver runs, then on
/// those of its row's request, which carries the input with that member
/// empty. Never on a request a caller sent.
#[derive(Clone)]
pub(super) struct HeldActionInput(pub(super) oneiron::code_run::actions::ActionBlobInput);

impl FacadeBlobBody {
    /// The verb whose call the content arrived for.
    pub(super) fn verb(&self) -> &str {
        &self.0.verb
    }

    /// The digest of the body as it arrived.
    pub(super) fn digest(&self) -> &str {
        &self.0.digest
    }

    /// The decoded content's file.
    pub(super) fn file(&self) -> &File {
        match &self.0.content {
            HeldFile::Spooled(content) => content.file().0,
            HeldFile::Action(held) => held.file(),
        }
    }
}

/// Reads the body of a facade call of `verb` for its receipt: a held verb's
/// JSON POST onto a spool, its content into a file whose
/// [`FacadeBlobBody`] goes on `parts`' extensions; any other call's as
/// `secret_body::read_middleware_body` reads it. A call in an anonymous
/// off-record session is read in memory, as before: its content is never
/// put on the vault's disk here.
pub(super) async fn read_receipt_body(
    server: &SyncServer,
    parts: &mut Parts,
    verb: &str,
    body: Body,
    anonymous: bool,
) -> ReceiptBody {
    if let Some(HeldActionInput(held)) = parts.extensions.remove::<HeldActionInput>() {
        return action_held_body(server, parts, verb, body, held).await;
    }
    let held = oneiron::task_verb::sdk::takes_blob_input(verb)
        && !anonymous
        && parts.method == Method::POST
        && crate::api::has_json_content_type(&parts.headers);
    if !held {
        let (bytes, request) = super::secret_body::read_middleware_body(
            body,
            verb,
            &mut parts.extensions,
            crate::api::request_floor::request_floor(server),
        )
        .await;
        return whole(bytes, request);
    }
    match spool(server, &parts.headers, body).await {
        Ok(Spooled::Whole(bytes)) => {
            let request = serde_json::from_slice(&bytes).ok();
            whole(bytes, request)
        }
        Ok(Spooled::Held {
            mut head,
            digest,
            content,
        }) => {
            head.insert(CONTENT_MEMBER.to_owned(), Value::String(String::new()));
            let head = Value::Object(head);
            parts
                .extensions
                .insert(FacadeBlobBody(Arc::new(HeldContent {
                    verb: verb.to_owned(),
                    digest: digest.clone(),
                    content: HeldFile::Spooled(content),
                })));
            ReceiptBody {
                bytes: Bytes::from(serde_json::to_vec(&head).unwrap_or_default()),
                request: Some(head),
                digest,
                refused: None,
            }
        }
        Err((refused, body_digest)) => ReceiptBody {
            bytes: Bytes::new(),
            request: None,
            digest: body_digest.unwrap_or_else(|| oneiron::receipt::call_bytes_digest(&[])),
            refused: Some(refused),
        },
    }
}

/// A body read whole, digested as the receipt digested it before.
fn whole(bytes: Bytes, request: Option<Value>) -> ReceiptBody {
    let digest = match &request {
        Some(value) => oneiron::receipt::call_json_digest(value),
        None => oneiron::receipt::call_bytes_digest(&bytes),
    };
    ReceiptBody {
        bytes,
        request,
        digest,
        refused: None,
    }
}

/// A spooled body, read.
enum Spooled {
    /// The body whole, as it arrived; empty when it was past the bound or
    /// did not arrive whole.
    Whole(Bytes),
    /// Every member but the content, the whole body's digest, and the
    /// content's decoded bytes.
    Held {
        head: Map<String, Value>,
        digest: String,
        content: SpooledField,
    },
}

/// Spools `body`, at most the facade's request bound of it, counted as it
/// arrives, and reads it on the spool's worker. A refusal after the whole
/// body arrived names the body's digest.
async fn spool(
    server: &SyncServer,
    headers: &HeaderMap,
    body: Body,
) -> Result<Spooled, (FacadeApiError, Option<String>)> {
    let limit = u64::try_from(crate::api::request_floor::request_floor(server)).unwrap_or(u64::MAX);
    let declared = body_spool::declared_length(headers);
    if declared.is_some_and(|declared| declared > limit) {
        return Ok(Spooled::Whole(Bytes::new()));
    }
    let over = Arc::new(AtomicBool::new(false));
    let body = body_spool::capped(body, limit, Arc::clone(&over));
    let vault = Arc::clone(&server.vault);
    let read = body_spool::spool_then(
        server,
        declared,
        body,
        SpoolPolicy::default(),
        move |spool| read_spool(&vault, spool),
    )
    .await;
    if over.load(Ordering::Relaxed) {
        return Ok(Spooled::Whole(Bytes::new()));
    }
    match read {
        Ok(Ok(spooled)) => Ok(spooled),
        Ok(Err(failed)) => Err((
            FacadeApiError::from(read_refusal(failed.unspooled)),
            failed.body_digest,
        )),
        // A body that did not arrive whole reaches the route empty, as before.
        Err(Unspooled::Failed) => Ok(Spooled::Whole(Bytes::new())),
        Err(unspooled) => Err((FacadeApiError::from(unspooled.refusal()), None)),
    }
}

/// The body of an action's row whose action holds its content as `held`
/// (FIX 22096): the row's input with that member empty, read as any small
/// body is. The content's file goes on the call as the spool's would, and
/// the receipt states the digest of the whole input. A body that is not
/// `held`'s input is refused: the row never runs without its content.
async fn action_held_body(
    server: &SyncServer,
    parts: &mut Parts,
    verb: &str,
    body: Body,
    held: oneiron::code_run::actions::ActionBlobInput,
) -> ReceiptBody {
    let (bytes, request) = super::secret_body::read_middleware_body(
        body,
        verb,
        &mut parts.extensions,
        crate::api::request_floor::request_floor(server),
    )
    .await;
    let digest = held.receipt_digest().to_owned();
    if held.verb().as_str() != verb || request.as_ref() != Some(held.head()) {
        return ReceiptBody {
            bytes: Bytes::new(),
            request: None,
            digest,
            refused: Some(FacadeApiError::from(
                crate::error::ApiError::internal_server_error(
                    "an action's held input does not match its row",
                ),
            )),
        };
    }
    parts
        .extensions
        .insert(FacadeBlobBody(Arc::new(HeldContent {
            verb: verb.to_owned(),
            digest: digest.clone(),
            content: HeldFile::Action(held),
        })));
    ReceiptBody {
        bytes,
        request,
        digest,
        refused: None,
    }
}

/// The refusal of a whole body whose spool did not read: the room or memory
/// it lacked, or the spool's own failure.
fn read_refusal(unspooled: Unspooled) -> crate::error::ApiError {
    match unspooled {
        Unspooled::Failed => {
            crate::error::ApiError::internal_server_error("the request body's spool did not read")
        }
        unspooled => unspooled.refusal(),
    }
}

/// Reads the spool ([`read_spool_in`]); a failure names the body's digest.
fn read_spool(vault: &oneiron::Vault, mut spool: BodySpool) -> Result<Spooled, SpoolFailed> {
    read_spool_in(vault, &mut spool).map_err(|unspooled| spool.failed(unspooled))
}

/// Reads the spool: the content to its file and the rest as JSON when the
/// body is one object with one base64 content string longer than an entity
/// ref; else the body whole.
fn read_spool_in(vault: &oneiron::Vault, spool: &mut BodySpool) -> Result<Spooled, Unspooled> {
    let file = vault
        .archive_spool_file()
        .map_err(body_spool::create_failed)?;
    let head_file = vault
        .archive_spool_file()
        .map_err(body_spool::create_failed)?;
    let (syntax, head, content) = {
        let mut memory = spool
            .admit_sealed_decode_buffers()
            .map_err(Unspooled::MemoryRefused)?;
        let mut content = Base64FileSink::new_admitted(file, &mut memory);
        let mut head = TextFileSink::new_admitted(head_file, &mut memory);
        let syntax = spool.object_head_admitted(
            &mut [BulkMember::required(CONTENT_MEMBER, &mut content)],
            &mut head,
            &mut memory,
        );
        (syntax, head.into_field(), content.into_field())
    };
    // No working buffer or lease survives into the next admission.
    let content = match (syntax, content) {
        (Err(HeadFail::Failed), _) | (Ok(()), Err(SinkRefusal::Failed)) => {
            return Err(Unspooled::Failed);
        }
        (Ok(()), Err(SinkRefusal::NoRoom)) => return Err(Unspooled::NoRoom),
        (Ok(()), Ok(content)) if content.file().1 > ENTITY_REF_DECODED_BYTES => Some(content),
        _ => None,
    };
    if let Some(content) = content {
        let head = head?;
        let parsed = {
            let mut memory = spool.admit_reader().map_err(Unspooled::MemoryRefused)?;
            head.json_admitted::<Map<String, Value>>(&mut memory)
        };
        match parsed {
            Ok(head) => {
                let digest = arrival_digest(&head, &content).map_err(|_| Unspooled::Failed)?;
                return Ok(Spooled::Held {
                    head,
                    digest,
                    content,
                });
            }
            Err(error) if error.is_io() => return Err(Unspooled::Failed),
            // The rest is not one JSON object: the body is read whole.
            Err(_) => {}
        }
    }
    read_whole(spool)
}

/// The digest of the body as it arrived: its members' canonical JSON with
/// the content's string, its decoded bytes encoded again as standard base64,
/// which is the string the caller sent, the only spelling standard base64
/// decodes to those bytes.
fn arrival_digest(head: &Map<String, Value>, content: &SpooledField) -> io::Result<String> {
    oneiron::receipt::call_json_digest_with_member(head, CONTENT_MEMBER, |hasher| {
        content.write_base64_json(hasher)
    })
}

/// The spooled body whole, as the facade read every body before.
fn read_whole(spool: &mut BodySpool) -> Result<Spooled, Unspooled> {
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
    Ok(Spooled::Whole(Bytes::from(bytes)))
}
