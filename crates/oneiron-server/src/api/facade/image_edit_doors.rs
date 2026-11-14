//! `vault.artifacts.image.edit` (L4-15; the Engine's rulings of 13 Nov 09:34
//! and 09:53): crops and resizes of one image artifact, run by the host's
//! image organ through [`oneiron_organ_host::image::edit_image`].
//!
//! The caller is the owner, or a person or agent on a slip bound to it
//! ([`image_editor`], the row's `host_door_proof`). Its own lane reads the
//! artifact before any organ runs, and its proposal is made by it; anyone
//! but the owner also has the proposal's sources admitted through their own
//! read as it lands (FIX 9310). The whole edit is one `image.render` call
//! that runs where a node can (this host, then the owner's other nodes): its
//! PNG lands as one proposal for Keep, or, when no node can run it now, the
//! edit is held beside the artifact with its reason until a redrive runs it
//! (IO-HOLD C). The door mints nothing: the call receipt the proposal names
//! is the host's attestation.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult,
};
use oneiron::secret_custody::SecretSight;
use oneiron::task_verb::sdk::{
    ImageEditAnswer, ImageEditOp, ImageEditRequest, ImageExportFormat, ImageResizeFilter,
};
use oneiron::{EdgeActorClass, EntityId};
use oneiron_organ_host::image::{
    ImageEdit, ImageEditRefusal, ImageEdited, ImageOp, ResizeFilter, edit_image,
};
use oneiron_organ_host::{AskHandlers, CallClass, HostError, Submitted};

use super::host_doors::support::{Listed, credential_listing, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.artifacts.image.edit";
/// Each organ call's deadline.
const CALL_DEADLINE: Duration = Duration::from_secs(60);
/// The door's own refusal codes: `image_` and the adapter's code.
const CODE_PREFIX: &str = "image_";

/// The principal an image edit binds its proposal to: the owner, or a person
/// or agent on its own slip.
pub(in crate::api::facade) fn image_editor(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    super::owner_binding::facade_caller_or(server, auth, || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "an image edit binds its proposal to an authenticated principal",
            &["Present the owner's credential, or a slip bound to a person or agent."],
        )
    })
}

/// `vault.artifacts.image.edit`: the caller's edit of one image artifact it
/// reads, its PNG waiting for Keep or held for a node. The organ calls run
/// on a blocking thread. Beside the answer, the rows its reads listed and the
/// artifact it read.
pub(crate) async fn vault_artifacts_image_edit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ImageEditRequest,
) -> Listed<ImageEditAnswer> {
    let caller = match image_editor(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    // Built on the runtime, so a call this host cannot run may reach one of
    // the owner's other nodes.
    let router = crate::handler::mesh::organ_router(server);
    let sight = source_sight(auth);
    let source = EntityId::from_hex(&input.artifact_ref).ok();
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let ImageExportFormat::Png = input.format;
            let (artifact, actor) =
                memory.artifacts_edit_admission(&input.artifact_ref, &input.run_ref)?;
            // The owner's own edit keeps the host's receipt as built.
            let submitter = (!memory.is_vault_owner()?).then_some(caller.0);
            let edit = ImageEdit {
                artifact,
                version: input.version,
                ops: input.ops.iter().copied().map(image_op).collect(),
                run_ref: input.run_ref,
                trigger: None,
                submitter,
                sight,
                grant: VERB.to_owned(),
                class: CallClass::Interactive,
                deadline: CALL_DEADLINE,
            };
            edit_image(&router, server.vault(), &edit, actor, &AskHandlers::none())
                .map(edit_answer)
                .map_err(refusal_error)
        })
        .await;
    if answer.is_ok() {
        listed.extend(source);
    }
    (answer, listed)
}

/// How the source is read for the organ, as the export door reads a file:
/// the owner's own person in full, any other caller masked (OF-560).
fn source_sight(auth: &CoreAuth) -> SecretSight {
    if auth.is_owner_grade() && auth.actor_class() != Some("agent") {
        SecretSight::Owner
    } else {
        SecretSight::Masked
    }
}

fn image_op(op: ImageEditOp) -> ImageOp {
    match op {
        ImageEditOp::Crop { x, y, w, h } => ImageOp::Crop { x, y, w, h },
        ImageEditOp::Resize { w, h, filter } => ImageOp::Resize {
            w,
            h,
            filter: match filter {
                ImageResizeFilter::Nearest => ResizeFilter::Nearest,
                ImageResizeFilter::Bilinear => ResizeFilter::Bilinear,
            },
        },
    }
}

fn edit_answer(edited: ImageEdited) -> ImageEditAnswer {
    let (proposals, held) = match edited.submitted {
        Submitted::Landed { proposals, .. } => (proposals, None),
        Submitted::Waiting(wait) => (Vec::new(), Some(wait)),
    };
    ImageEditAnswer {
        artifact_ref: edited.artifact.to_hex(),
        born: edited.born,
        proposals,
        held,
    }
}

/// The facade's error for an edit that did not run: an absent artifact or
/// version is `NOT_FOUND`; the vault's own refusal (a ref already waiting, a
/// source the submitter cannot read) keeps its code; a host failure is
/// `INTERNAL_SERVER_ERROR`, its detail logged; every other refusal takes
/// its own code, `image_` and the adapter's ([`image_edit_refusal_status`]).
fn refusal_error(refusal: ImageEditRefusal) -> MemoryError {
    match refusal {
        ImageEditRefusal::NotFound => MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "the artifact or its version is not in this vault",
            &[],
        ),
        ImageEditRefusal::Host(HostError::Engine(error)) => MemoryError::from(error),
        ImageEditRefusal::Host(error) => {
            tracing::warn!(%error, verb = VERB, "the image organ host failed");
            MemoryError::new(MEMORY_CODE_INTERNAL, "the image organ host failed", &[])
        }
        other => MemoryError::new(
            &format!("{CODE_PREFIX}{}", other.code()),
            other.to_string(),
            &[],
        ),
    }
}

/// The HTTP status of each of the door's own refusal codes: the caller's
/// request for an edit no organ takes, or a node that cannot run it now.
pub(crate) fn image_edit_refusal_status(code: &str) -> Option<StatusCode> {
    let code = code.strip_prefix(CODE_PREFIX)?;
    Some(match code {
        "not_an_image" | "no_ops" | "too_many_ops" | "bad_request" | "unknown_verb"
        | "schema_mismatch" => StatusCode::BAD_REQUEST,
        "unsupported" => StatusCode::UNPROCESSABLE_ENTITY,
        "too_large" => StatusCode::PAYLOAD_TOO_LARGE,
        "stale_base" => StatusCode::CONFLICT,
        "no_node" | "budget" | "cancelled" | "revoked" | "deadline_exceeded" => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        "internal" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => return None,
    })
}
