//! The weave Admin's host adapters (OF-499 A3, FIX 9431, FIX 11694): an
//! Admin's live report, its lens, its saved digest and its wrong labels,
//! each over the engine's Admin readers under one current Admin proof, and
//! the served rows `vault.weave.admin.{report,lens,digest,link.wrong,
//! item.wrong}` over them.
//!
//! The proof binds the exact verified slip the request was admitted on, the
//! one Admin membership grant the request names, and the step-up witness
//! (`AdminStepUp`) the person's MFA step-up left (MFA-1 A: an Admin cannot
//! skip it). A served row takes that witness only from the engine's trusted
//! step-up verifier (`Vault::admin_step_up`, which reads the passkey step-up
//! recorded on this exact slip); none reads a caller's claim that a step-up
//! happened, or stands an Owner proof in for it. The engine revalidates the
//! proof in each read's own transaction. Every Owner, person and agent weave
//! door stays as it is, and never asks for this proof.

use std::sync::Arc;

use oneiron::authority::{
    AdminStepUp, AuthenticatedWeaveAdmin, WeaveAdminDigestRequest, WeaveAdminItemWrongRequest,
    WeaveAdminLensRequest, WeaveAdminLinkWrongRequest, WeaveAdminReportRequest,
};
use oneiron::claim::{
    WeaveDigestRequest, WeaveDigestView, WeaveItemCorrectionView, WeaveLinkCorrectionView,
    WeaveReportRequest, WeaveReportView, WeaveWrongItemRequest, WeaveWrongLinkRequest,
};
use oneiron::lens::{GeneratedUiSurfaceCapabilities, LensFrameCard, WeaveLensRequest};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::hold_weave_digest;
use super::host_doors::support::{Listed, credential_listing, refused};
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

fn not_stepped_up() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "a weave admin steps up on this credential first (MFA-1 A: an admin cannot skip it)",
        &[
            "Step up with an enrolled passkey on this same credential (POST /v1/core/step-up/challenge, then POST /v1/core/step-up/passkey), then repeat the call.",
        ],
    )
}

/// The Admin proof a served Admin row runs on: the step-up witness the
/// engine's trusted verifier recorded on this request's own slip
/// (`Vault::admin_step_up`), bound with the Admin membership grant the row
/// names ([`bind_weave_admin`]).
///
/// # Errors
/// `BAD_REQUEST` for a grant that is no 32-hex id; `FORBIDDEN` for a
/// request with no verified slip or no standing step-up on it; the engine's
/// `WEAVE_ADMIN_NOT_CURRENT` when the proof does not hold.
fn stepped_up_admin(
    server: &SyncServer,
    auth: &CoreAuth,
    membership_grant: &str,
) -> MemoryResult<BoundWeaveAdmin> {
    super::owner_binding::host_preflight(server, auth)?;
    let grant = EntityId::from_hex(membership_grant).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            "membership_grant is not a 32-hex membership grant id",
            &["Name your Admin membership grant as vault.members.projection lists it."],
        )
    })?;
    let request = auth
        .verified_slip()
        .ok_or_else(|| not_admin("on the verified slip its request was admitted on"))?;
    let step_up = server
        .vault()
        .admin_step_up(request)?
        .ok_or_else(not_stepped_up)?;
    bind_weave_admin(server, auth, grant, &step_up)
}

/// `vault.weave.admin.report`: the Admin's live weave report.
pub(crate) async fn vault_weave_admin_report(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveAdminReportRequest,
) -> Listed<WeaveReportView> {
    match stepped_up_admin(server, auth, &input.membership_grant) {
        Ok(admin) => weave_admin_report(server, auth, admin, input.request).await,
        Err(refusal) => refused(refusal),
    }
}

/// `vault.weave.admin.lens`: the Admin's live report rendered into its lens.
pub(crate) async fn vault_weave_admin_lens(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    client_surface: Option<GeneratedUiSurfaceCapabilities>,
    input: WeaveAdminLensRequest,
) -> Listed<LensFrameCard> {
    match stepped_up_admin(server, auth, &input.membership_grant) {
        Ok(admin) => weave_admin_lens(server, auth, admin, client_surface, input.request).await,
        Err(refusal) => refused(refusal),
    }
}

/// `vault.weave.admin.digest`: one of the Admin's saved digests, or the
/// newest.
pub(crate) async fn vault_weave_admin_digest(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveAdminDigestRequest,
) -> Listed<Option<WeaveDigestView>> {
    match stepped_up_admin(server, auth, &input.membership_grant) {
        Ok(admin) => weave_admin_digest(server, auth, admin, input.request).await,
        Err(refusal) => refused(refusal),
    }
}

/// `vault.weave.admin.link.wrong`: the Admin labels a link its report
/// shows as wrong.
pub(crate) async fn vault_weave_admin_link_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveAdminLinkWrongRequest,
) -> Listed<WeaveLinkCorrectionView> {
    match stepped_up_admin(server, auth, &input.membership_grant) {
        Ok(admin) => weave_admin_link_wrong(server, auth, admin, input.request).await,
        Err(refusal) => refused(refusal),
    }
}

/// `vault.weave.admin.item.wrong`: the Admin labels a row its report shows
/// as wrong.
pub(crate) async fn vault_weave_admin_item_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveAdminItemWrongRequest,
) -> Listed<WeaveItemCorrectionView> {
    match stepped_up_admin(server, auth, &input.membership_grant) {
        Ok(admin) => weave_admin_item_wrong(server, auth, admin, input.request).await,
        Err(refusal) => refused(refusal),
    }
}
