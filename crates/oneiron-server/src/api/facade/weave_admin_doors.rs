//! The weave Admin's host adapters (OF-499 A3, FIX 9431): an Admin's live
//! report, its lens, its saved digest and its wrong labels, each over the
//! engine's Admin readers under one current Admin proof.
//!
//! The proof binds the exact verified slip the request was admitted on, the
//! one Admin membership grant the request names, and the step-up witness
//! (`AdminStepUp`) the person's MFA step-up left (MFA-1 A: an Admin cannot
//! skip it). These adapters only take that opaque witness; none mints one,
//! reads a caller's claim that a step-up happened, or stands an Owner proof
//! in for it. The engine revalidates the proof in each read's own
//! transaction. No trusted step-up verifier exists yet, so no route, verb or
//! MCP tool calls these: the served Admin route is bound when that verifier
//! can hand one its witness (FIX-LIST). Every Owner, person and agent weave
//! door stays as it is, and never asks for this proof.

use std::sync::Arc;

use oneiron::authority::{AdminStepUp, AuthenticatedWeaveAdmin};
use oneiron::claim::{
    WeaveDigestRequest, WeaveDigestView, WeaveItemCorrectionView, WeaveLinkCorrectionView,
    WeaveReportRequest, WeaveReportView, WeaveWrongItemRequest, WeaveWrongLinkRequest,
};
use oneiron::lens::{GeneratedUiSurfaceCapabilities, LensFrameCard, WeaveLensRequest};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::hold_weave_digest;
use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// What each adapter names itself as when its worker does not finish.
const ADMIN_REPORT: &str = "the weave admin report";
const ADMIN_DIGEST: &str = "the weave admin digest";
const ADMIN_LINK_WRONG: &str = "the weave admin link label";
const ADMIN_ITEM_WRONG: &str = "the weave admin item label";

/// One person's current Admin proof for the weave, with the person it
/// stands for: the holder of the verified slip it was built from. Built
/// only by [`bind_weave_admin`]; never from caller JSON.
pub(crate) struct BoundWeaveAdmin {
    proof: AuthenticatedWeaveAdmin,
    person: EntityId,
}

impl BoundWeaveAdmin {
    /// The handle an Admin read runs on: its own person's, as a human.
    const fn caller(&self) -> (EntityId, EdgeActorClass) {
        (self.person, EdgeActorClass::Human)
    }
}

fn not_admin(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("a weave admin reads {why}"),
        &["Present your own verified human credential, and step up on it."],
    )
}

/// The Admin proof for `auth`'s request: the exact slip it was verified on,
/// held by its own holder, under the Admin membership grant
/// `membership_grant`, with `step_up`, the witness the trusted step-up
/// ingress left for that holder over that slip
/// (`Vault::authenticate_weave_admin`). A hosted operator's root is refused
/// first, typed, as at every facade door.
///
/// # Errors
/// `FORBIDDEN` for a request with no verified slip; the engine's
/// `WEAVE_ADMIN_NOT_CURRENT` when the proof does not hold.
pub(crate) fn bind_weave_admin(
    server: &SyncServer,
    auth: &CoreAuth,
    membership_grant: EntityId,
    step_up: &AdminStepUp,
) -> MemoryResult<BoundWeaveAdmin> {
    super::owner_binding::host_preflight(server, auth)?;
    let request = auth
        .verified_slip()
        .ok_or_else(|| not_admin("on the verified slip its request was admitted on"))?;
    let person = EntityId::from_hex(&request.claims().holder_ref)
        .map_err(|_| not_admin("as the person who holds its slip"))?;
    let proof = server
        .vault()
        .authenticate_weave_admin(request, membership_grant, step_up)?;
    Ok(BoundWeaveAdmin { proof, person })
}

/// The Admin's live weave report: a vault-global shape inside its Scope.
pub(crate) async fn weave_admin_report(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    admin: BoundWeaveAdmin,
    input: WeaveReportRequest,
) -> Listed<WeaveReportView> {
    let caller = admin.caller();
    credential_listing(server, auth, caller, ADMIN_REPORT, move |_, _, memory| {
        memory.weave_admin_report(&admin.proof, &input)
    })
    .await
}

/// The Admin's live report rendered into its lens on this server's Dreamer
/// narrative route, as `vault.weave.lens` renders a credential's own, its
/// card lowered for the surface the call names, else for the whole atom
/// kit, and its frame held for `auth`'s events on it.
pub(crate) async fn weave_admin_lens(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    admin: BoundWeaveAdmin,
    client_surface: Option<GeneratedUiSurfaceCapabilities>,
    input: WeaveLensRequest,
) -> Listed<LensFrameCard> {
    let caller = crate::ai_host::WeaveLensCaller::Admin {
        admin: admin.proof,
        auth: auth.clone(),
        actor: admin.person,
    };
    let client_surface = input.surface.or(client_surface);
    let input = WeaveReportRequest {
        sections: input.sections,
    };
    crate::ai_host::render_live_weave_lens_listing(server, caller, input, client_surface).await
}

/// One of the Admin's saved digests, or the newest, under the current read
/// policy, its lens's frame held for `auth`'s events on the card.
pub(crate) async fn weave_admin_digest(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    admin: BoundWeaveAdmin,
    input: WeaveDigestRequest,
) -> Listed<Option<WeaveDigestView>> {
    let caller = admin.caller();
    let (framed, listed) =
        credential_listing(server, auth, caller, ADMIN_DIGEST, move |_, _, memory| {
            memory.weave_admin_digest_framed(&admin.proof, &input)
        })
        .await;
    let answer = framed.and_then(|framed| {
        framed
            .map(|framed| hold_weave_digest(server, auth, framed))
            .transpose()
    });
    (answer, listed)
}

/// The Admin labels a link its own Admin report shows as wrong, with its
/// grant on the label. The label is not a retraction.
pub(crate) async fn weave_admin_link_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    admin: BoundWeaveAdmin,
    input: WeaveWrongLinkRequest,
) -> Listed<WeaveLinkCorrectionView> {
    let caller = admin.caller();
    credential_listing(
        server,
        auth,
        caller,
        ADMIN_LINK_WRONG,
        move |_, _, memory| memory.weave_admin_wrong_link(&admin.proof, &input),
    )
    .await
}

/// The Admin labels a claim, project, budget or sieve audit row its own
/// Admin report shows as wrong, as a link's is.
pub(crate) async fn weave_admin_item_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    admin: BoundWeaveAdmin,
    input: WeaveWrongItemRequest,
) -> Listed<WeaveItemCorrectionView> {
    let caller = admin.caller();
    credential_listing(
        server,
        auth,
        caller,
        ADMIN_ITEM_WRONG,
        move |_, _, memory| memory.weave_admin_wrong_item(&admin.proof, &input),
    )
    .await
}
