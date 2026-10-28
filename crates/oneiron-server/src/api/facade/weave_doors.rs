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

use oneiron::agent_inbox_lens::{InboxLensPage, InboxLensRequest, InboxRunGroupsRequest};
use oneiron::claim::{
    WeaveDigestFeedback, WeaveDigestRendered, WeaveDigestSettingAnswer, WeaveDigestSettingChange,
    WeaveDigestSettingUndo, WeaveReaderRef, WeaveScheduleView,
};
use oneiron::inbox::InboxGroup;
use oneiron::lens::{GeneratedUiSurfaceCapabilities, LensFrameCard};
use oneiron::memory::DreamerAttemptRef;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{EmptyRequest, WeaveEnqueueRequest, WeaveScheduleCleared};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, off_runtime_listing, refused};
use crate::auth::CoreAuth;
use crate::lens_frames::CardOwner;
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
    let caller = super::owner_binding::facade_caller_or(server, auth, || {
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
    super::owner_binding::facade_owner_or(server, auth, || {
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
/// the caller's own line. A run-held render (`owner`, FIX 2612) holds its
/// card for its creating run and subscription, replacing the card that run
/// last rendered for it; any other holds it unowned. The card is lowered
/// for `client_surface`, the profile the caller's MCP call declared (FIX
/// 7969), else for the whole atom kit.
pub(crate) async fn vault_weave_lens(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    owner: Option<CardOwner>,
    client_surface: Option<GeneratedUiSurfaceCapabilities>,
    input: WeaveReportRequest,
) -> Listed<LensFrameCard> {
    const VERB: &str = "vault.weave.lens";
    if let Err(refusal) = super::owner_binding::host_preflight(server, auth) {
        return refused(refusal);
    }
    let (actor, class) = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{VERB} renders the credential's own lens"),
                &["Present a person's or an agent's own credential."],
            ));
        }
    };
    let caller = crate::ai_host::WeaveLensCaller::Credential {
        auth: auth.clone(),
        actor,
        class,
    };
    match owner {
        Some(owner) => {
            crate::ai_host::render_live_weave_lens_for_run(
                server,
                caller,
                input,
                owner,
                client_surface,
            )
            .await
        }
        None => {
            crate::ai_host::render_live_weave_lens_listing(server, caller, input, client_surface)
                .await
        }
    }
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
    if let Err(refusal) = super::owner_binding::host_preflight(server, auth) {
        return refused(refusal);
    }
    let caller = match super::facade_actor(server, auth) {
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

pub(crate) async fn vault_weave_enqueue(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WeaveEnqueueRequest,
) -> Listed<DreamerAttemptRef> {
    const VERB: &str = "vault.weave.enqueue";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::weave_enqueue(&memory, &owner, input)
    })
    .await
}

pub(crate) async fn vault_weave_schedules_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    _input: EmptyRequest,
) -> Listed<Vec<WeaveScheduleView>> {
    const VERB: &str = "vault.weave.schedules.list";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::weave_schedules(&memory, &owner)
    })
    .await
}

pub(crate) async fn vault_weave_schedules_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WeaveScheduleView,
) -> Listed<WeaveScheduleView> {
    const VERB: &str = "vault.weave.schedules.put";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::weave_schedule_put(&memory, &owner, input)
    })
    .await
}

pub(crate) async fn vault_weave_schedules_clear(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WeaveReaderRef,
) -> Listed<WeaveScheduleCleared> {
    const VERB: &str = "vault.weave.schedules.clear";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::weave_schedule_clear(&memory, &owner, input)
    })
    .await
}

/// `vault.weave.setting_changes.list`: the Coach's changes to the owner's
/// own digest settings, newest first, under the owner's proof (FIX 5495).
pub(crate) async fn vault_weave_setting_changes_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    _input: EmptyRequest,
) -> Listed<Vec<WeaveDigestSettingChange>> {
    const VERB: &str = "vault.weave.setting_changes.list";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::weave_setting_changes(&memory, &owner)
    })
    .await
}

/// `vault.weave.setting_changes.answer`: the owner accepts, as his own act,
/// or declines one proposed change to his digest settings.
pub(crate) async fn vault_weave_setting_changes_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WeaveDigestSettingAnswer,
) -> Listed<WeaveDigestSettingChange> {
    const VERB: &str = "vault.weave.setting_changes.answer";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::weave_setting_change_answer(&memory, &owner, input)
    })
    .await
}

/// `vault.weave.setting_changes.undo`: the owner's one-tap undo of an
/// applied or accepted change to his digest settings.
pub(crate) async fn vault_weave_setting_changes_undo(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WeaveDigestSettingUndo,
) -> Listed<WeaveDigestSettingChange> {
    const VERB: &str = "vault.weave.setting_changes.undo";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::weave_setting_change_undo(&memory, &owner, input)
    })
    .await
}

/// `vault.weave.digest_feedback.put`: what the owner tells the Coach about
/// his own digest.
pub(crate) async fn vault_weave_digest_feedback_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WeaveDigestFeedback,
) -> Listed<WeaveDigestFeedback> {
    const VERB: &str = "vault.weave.digest_feedback.put";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::weave_digest_feedback_put(&memory, &owner, input)
    })
    .await
}

pub(crate) async fn vault_weave_owner_digest_render(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    _input: EmptyRequest,
) -> Listed<Option<WeaveDigestRendered>> {
    const VERB: &str = "vault.weave.owner.digest.render";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.weave_digest_render(Some(&owner))
    })
    .await
}

pub(crate) async fn vault_inbox_concerns_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    _input: EmptyRequest,
) -> Listed<DreamerAttemptRef> {
    const VERB: &str = "vault.inbox.concerns.review";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::inbox_concerns_review(&memory, &owner)
    })
    .await
}

pub(crate) async fn vault_inbox_lens(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: InboxLensRequest,
) -> Listed<InboxLensPage> {
    const VERB: &str = "vault.inbox.lens";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.inbox_lens_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_inbox_groups(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: InboxRunGroupsRequest,
) -> Listed<Vec<InboxGroup>> {
    const VERB: &str = "vault.inbox.groups";
    let owner = match super::host_doors::support::owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.inbox_run_groups(&owner, &input)
    })
    .await
}
