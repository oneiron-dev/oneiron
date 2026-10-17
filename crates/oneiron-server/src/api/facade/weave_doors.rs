//! The weave lens's host doors (OF-499): the one-tap wrong control a person
//! uses on a link, claim, project or budget row in their own report, the live report rendered into its
//! lens on this server's model, and a saved digest whose lens card's frame
//! this server holds. The generated HTTP facade handler and the MCP
//! dispatcher both call these through `host_doors`. Each answers beside the
//! rows its reads listed (`host_door_lists`).
use std::sync::Arc;

use oneiron::claim::{
    WeaveDigestFramed, WeaveDigestRequest, WeaveDigestView, WeaveItemCorrectionView,
    WeaveLinkCorrectionView, WeaveReportRequest, WeaveWrongItemRequest, WeaveWrongLinkRequest,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::lens::LensFrameCard;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, off_runtime_listing, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.weave.link.wrong`: a live person labels a link in their own
/// person lens as wrong, under their own proof. The label is not a
/// retraction; the loops learn from it. An agent's credential carries no
/// person proof, so it is refused here, as the engine refuses an agent
/// reader.
pub(crate) async fn vault_weave_link_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveWrongLinkRequest,
) -> Listed<WeaveLinkCorrectionView> {
    const VERB: &str = "vault.weave.link.wrong";
    let (proof, caller) = match person_lens(server, auth, VERB, "labels a link") {
        Ok(bound) => bound,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.weave_wrong_link(None, &proof, &input)
    })
    .await
}

/// `vault.weave.owner.link.wrong`: the owner labels a link it sees in the
/// owner lens as wrong, under its live owner proof, as
/// `POST /v1/owner/weave/link/wrong` does. The owner lens card's wrong
/// controls call it; a person's call `vault.weave.link.wrong`.
pub(crate) async fn vault_weave_owner_link_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveWrongLinkRequest,
) -> Listed<WeaveLinkCorrectionView> {
    const VERB: &str = "vault.weave.owner.link.wrong";
    let owner = match owner_lens(server, auth, VERB, "labels a link") {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let locality = auth.locality();
    off_runtime_listing(VERB, move |producers| {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .listing_producers(producers)
            .weave_owner_wrong_link(&owner, &input)
    })
    .await
}

/// `vault.weave.item.wrong`: a live person labels a claim, project or
/// budget row in their own person lens as wrong, under their own proof, as
/// `vault.weave.link.wrong` labels a link. The record stays; the loops
/// learn from the label. An agent's credential is refused here.
pub(crate) async fn vault_weave_item_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveWrongItemRequest,
) -> Listed<WeaveItemCorrectionView> {
    const VERB: &str = "vault.weave.item.wrong";
    let (proof, caller) = match person_lens(server, auth, VERB, "labels an item") {
        Ok(bound) => bound,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.weave_wrong_item(None, &proof, &input)
    })
    .await
}

/// `vault.weave.owner.item.wrong`: the owner labels a claim, project or
/// budget row it sees in the owner lens as wrong, under its live owner
/// proof. The owner lens card's item controls call it.
pub(crate) async fn vault_weave_owner_item_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveWrongItemRequest,
) -> Listed<WeaveItemCorrectionView> {
    const VERB: &str = "vault.weave.owner.item.wrong";
    let owner = match owner_lens(server, auth, VERB, "labels an item") {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let locality = auth.locality();
    off_runtime_listing(VERB, move |producers| {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .listing_producers(producers)
            .weave_owner_wrong_item(&owner, &input)
    })
    .await
}

/// A live person's own proof and principal, for a label `act` in their own
/// lens. An agent's credential carries no person proof.
fn person_lens(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    act: &str,
) -> MemoryResult<(AuthenticatedOwner, (EntityId, EdgeActorClass))> {
    let proof = super::shared_act_doors::person(server, auth, verb)?;
    let caller = super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} {act} in the credential's own lens"),
            &["Present your own verified human credential."],
        )
    })?;
    Ok((proof, caller))
}

/// The owner's live proof, for a label `act` in the owner lens.
fn owner_lens(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    act: &str,
) -> MemoryResult<AuthenticatedOwner> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} {act} in the owner lens"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })
}

/// `vault.weave.lens`: the credential's own live weave report, rendered
/// through the weave-report skill into its lens on this server's Dreamer
/// narrative route, as a card whose frame this server holds for the
/// credential's events on it. A person reads the person lens, an agent its
/// own; the owner lens is `POST /v1/owner/weave/lens`. The step spends on
/// the caller's own line.
pub(crate) async fn vault_weave_lens(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveReportRequest,
) -> Listed<LensFrameCard> {
    const VERB: &str = "vault.weave.lens";
    let (actor, class) = match super::facade_actor(auth) {
        Ok(caller) => caller,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{VERB} renders the credential's own lens"),
                &["Present a person's or an agent's own credential."],
            ));
        }
    };
    crate::ai_host::render_live_weave_lens_listing(
        server,
        crate::ai_host::WeaveLensCaller::Credential {
            auth: auth.clone(),
            actor,
            class,
        },
        input,
    )
    .await
}

/// `vault.weave.digest` on this server: one of the credential's saved
/// digests, or the newest, under its own read at its locality. A person
/// reads the person lens's, an agent its own; the owner's is
/// `GET /v1/owner/weave/digest`. Its lens is a card whose frame this server
/// holds for the credential's events on it.
pub(crate) async fn vault_weave_digest(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveDigestRequest,
) -> Listed<Option<WeaveDigestView>> {
    const VERB: &str = "vault.weave.digest";
    let caller = match super::facade_actor(auth) {
        Ok(caller) => caller,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{VERB} reads the credential's own digest"),
                &["Present a person's or an agent's own credential."],
            ));
        }
    };
    let (framed, listed) = credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.weave_digest_framed(None, &input)
    })
    .await;
    let answer = framed.and_then(|framed| {
        framed
            .map(|framed| hold_weave_digest(server, auth, framed))
            .transpose()
    });
    (answer, listed)
}

/// A served period, its lens lowered and the lens's frame held for `auth`'s
/// events on the card before the answer leaves.
pub(crate) fn hold_weave_digest(
    server: &SyncServer,
    auth: &CoreAuth,
    framed: WeaveDigestFramed,
) -> MemoryResult<WeaveDigestView> {
    let (view, frame) = framed.lower();
    if let (Some(frame), Some(card)) = (frame, &view.lens) {
        server
            .lens_frames
            .record(auth, frame, card.render.clone())?;
    }
    Ok(view)
}
