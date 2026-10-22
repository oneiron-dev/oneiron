//! The owner's artifact review, ask, admit and deck preview doors, and his audit and mesh reads.
//! The `vault_artifacts_*` doors, `vault_authority_audit` and `vault_mesh_path_receipts`.
//! The engine's artifact and authority records (`oneiron`) are forwarded here unchanged.

use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::ActAnswer;
use oneiron::{EdgeActorClass, EntityId};

use super::support::{
    Listed, artifact_asker, credential_listing, internal, naming, owner_proof, read_beside, refused,
    rendered, slide_reviewer,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.artifacts.review_slides`: reviews an artifact's head through the
/// host's decide() ladder as the bound actor, from the host's starting dial
/// and bands, and holds the proposal for Keep or Discard. A unit with no
/// image is rendered by the host's LibreOffice renderer when it has one. The
/// ladder and the render run on a blocking thread, one call per unit.
/// Beside it, the rows its reads listed, the head version it reviews and
/// renders from (FIX 5455) and every stored image a unit names. A caller off
/// this device whose reply names or lists a row that stays here hears only
/// that the review ran ([`crate::device_local::act_answer`]).
pub(crate) async fn vault_artifacts_review_slides(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::blob_artifact::SlideReviewSubmit,
) -> Listed<ActAnswer<oneiron::blob_artifact::SlideReviewOutcome>> {
    const VERB: &str = "vault.artifacts.review_slides";
    let caller = match slide_reviewer(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let beside = read_beside(
        std::iter::once(input.artifact_ref.as_str()).chain(
            input
                .units
                .iter()
                .filter_map(|unit| unit.review_image_ref.as_deref()),
        ),
    );
    // A caller who leaves stops the render its worker runs (FIX 7653).
    let (_stop, stop) = crate::slide_render::StopOnDrop::new();
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let host = server.decision_host();
            // Its render takes a turn in the renderer line as it starts, at
            // the caller's fair place, and gives it back before the ladder
            // reads the units (FIX 7653).
            let renderer =
                crate::slide_render::AdmittedRenderer::at_render(server, Some(caller.0), stop);
            memory.artifacts_review_slides_through(
                &input,
                &crate::decision_artifact::HostUnitDecider::new(server, caller.1, VERB),
                host.dial(oneiron::llm::decision::DecisionRung::Big),
                &host.bands(),
                renderer
                    .as_ref()
                    .map(crate::slide_render::AdmittedRenderer::slides),
            )
        })
        .await;
    listed.extend(beside);
    crate::device_local::act_answer(server.vault(), &auth.destination(), (answer, listed))
}

/// `vault.artifacts.ask`: asks one typed question over an artifact's units
/// (sheet rows, paragraphs or folder items) through the host's decide()
/// ladder as the bound actor, from the host's starting dial and bands, and
/// holds the answers as one proposal for Keep or Discard. The ladder runs on
/// a blocking thread, one call per unit, as `vault.artifacts.review_slides`.
/// Beside it, the rows its reads listed, the artifact it asks over and each
/// version its reads picked (FIX 5455): the artifact's head and every folder
/// file's. A caller off this device whose reply names or lists a row that
/// stays here hears only that the ask ran ([`crate::device_local::act_answer`]).
pub(crate) async fn vault_artifacts_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::blob_artifact::ArtifactAskSubmit,
) -> Listed<ActAnswer<oneiron::blob_artifact::ArtifactAskOutcome>> {
    const VERB: &str = "vault.artifacts.ask";
    let caller = match artifact_asker(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let beside = read_beside([input.artifact_ref.as_str()]);
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let host = server.decision_host();
            memory.artifacts_ask_through(
                &input,
                &crate::decision_artifact::HostUnitDecider::new(server, caller.1, VERB),
                host.dial(oneiron::llm::decision::DecisionRung::Big),
                &host.bands(),
            )
        })
        .await;
    listed.extend(beside);
    crate::device_local::act_answer(server.vault(), &auth.destination(), (answer, listed))
}

/// `vault.artifacts.admit`: the caller's own provider measurements for an
/// artifact ask's units, admitted as the bound actor in place of the host
/// ladder's, under the host's starting dial and bands, and held as one
/// proposal for Keep or Discard. The engine validates each submitted
/// decision — its provider-bound paired and person readings included —
/// before the proposal is held, so an invalid measurement mints nothing.
/// It runs on a blocking thread, one call per unit, as
/// `vault.artifacts.ask` does. Beside it, the rows its reads listed and
/// the artifact it asks over.
pub(crate) async fn vault_artifacts_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::blob_artifact::ArtifactAdmitSubmit,
) -> Listed<oneiron::blob_artifact::ArtifactAskOutcome> {
    const VERB: &str = "vault.artifacts.admit";
    let caller = match artifact_asker(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let beside = read_beside([input.ask.artifact_ref.as_str()]);
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let host = server.decision_host();
            memory.artifacts_admit_through(
                &input,
                host.dial(oneiron::llm::decision::DecisionRung::Big),
                &host.bands(),
            )
        })
        .await;
    listed.extend(beside);
    (answer, listed)
}

/// `vault.artifacts.body.deck.preview`: the asked slides of a deck's head,
/// drawn by this host's review renderer on a blocking thread, for a
/// credential that reads the artifact. Beside it, the rows its reads listed
/// (the package version it projects over and each live-born picture's
/// asset, a held drawing's too, FIX 5455) and the head it draws from. The
/// preview takes its turn in the renderer line before any of its work and
/// keeps it, with the memory it leased, until its answer is encoded
/// (FIX 7653); a refusal at the render's deadline or a machine floor is
/// typed.
pub(crate) async fn vault_artifacts_body_deck_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::office_body::DeckPreviewRequest,
) -> Listed<crate::slide_render::RenderedPreview> {
    const VERB: &str = "vault.artifacts.body.deck.preview";
    let admitted = || -> MemoryResult<(EntityId, EdgeActorClass)> {
        let caller = crate::api::facade::owner_binding::facade_caller_or(server, auth, || {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a deck preview reads as the credential's own principal",
                &["Present a slip paired with a principal ref and an actor class."],
            )
        })?;
        if let Ok(artifact) = EntityId::from_hex(&input.artifact_ref)
            && !auth.can_read_entity(&server.vault, &artifact)?
        {
            return Err(oneiron::Error::EntityNotFound.into());
        }
        Ok(caller)
    };
    let caller = match admitted() {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let beside =
        read_beside(std::iter::once(input.artifact_ref.as_str()).chain(input.fork_ref.as_deref()));
    // The caller's fair turn in the renderer line comes before any of the
    // preview's work, a kept drawing's included (FIX 7653); its worker keeps
    // it until it ends, and a caller who leaves stops it.
    let Ok(turn) = server.renderer_turns.admit(caller.0).await else {
        return refused(crate::slide_render::RenderRefusal::Deadline.memory_error());
    };
    let (_stop, stop) = crate::slide_render::StopOnDrop::new();
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let renderer = crate::slide_render::AdmittedRenderer::held(server, turn, stop)?;
            let preview = memory.artifacts_body_deck_preview(
                &input,
                renderer
                    .as_ref()
                    .map(crate::slide_render::AdmittedRenderer::slides),
            );
            crate::slide_render::rendered(preview, renderer)
        })
        .await;
    listed.extend(beside);
    (answer, listed)
}

/// `vault.authority.audit`: one page of the dated AUTHORITY_LOG audit, the
/// owner's view under the proof `/v1/owner` takes from the request.
pub(super) async fn vault_authority_audit_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::receipt::AuthorityAuditQuery,
) -> MemoryResult<oneiron::receipt::AuthorityAuditPage> {
    let owner = owner_proof(auth, server, "vault.authority.audit")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        server
            .vault()
            .authority_audit(&owner, &input)
            .map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal("vault.authority.audit"))?
}

/// [`vault_authority_audit_answer`], listing no row: the authority log holds none
/// (`host_door_lists`).
pub(crate) async fn vault_authority_audit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::receipt::AuthorityAuditQuery,
) -> Listed<oneiron::receipt::AuthorityAuditPage> {
    naming(
        vault_authority_audit_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

/// `vault.mesh.path_receipts`: the newest path receipts this machine's
/// paired-machine mesh left, newest first and bounded, the owner's view
/// under the proof `/v1/owner` takes from the request.
pub(super) async fn vault_mesh_path_receipts_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::MeshPathReceiptsRequest,
) -> MemoryResult<Vec<oneiron::sync::mesh_path::MeshPathReceipt>> {
    let _owner = owner_proof(auth, server, "vault.mesh.path_receipts")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        server
            .vault()
            .mesh_path_receipts(input.bound())
            .map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal("vault.mesh.path_receipts"))?
}

/// [`vault_mesh_path_receipts_answer`], listing no row: path receipts live in a side table
/// (`host_door_lists`).
pub(crate) async fn vault_mesh_path_receipts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::MeshPathReceiptsRequest,
) -> Listed<Vec<oneiron::sync::mesh_path::MeshPathReceipt>> {
    naming(
        vault_mesh_path_receipts_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}
