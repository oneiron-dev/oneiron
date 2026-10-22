//! Where the receive-pack decision (FIX 6867, G1-PUSH) meets the serving
//! plane: the host's checked serving entry, the push admission every
//! receive-pack advertisement and RPC runs through on both seams and both
//! routes, and the admission stamp (moved here from `serve`) that carries
//! the admitted authority onto the push's evidence and intent.
//!
//! The decision is [`crate::Vault::admit_git_receive_pack_in_txn`]'s; this
//! module only hands it the pusher the host proved, as a sidecar beside the
//! request, never anything decoded from the request's remote user, query
//! or body. The in-process entries (`serve`, `serve_bounded`,
//! `serve_with_authority`, `serve_bounded_with_authority`) pass no host
//! sidecar: their pusher is the vault's owner or no one.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;

use super::bounds::ExchangeBounds;
use super::door::{DoorAdmissionStamp, DoorHook, DoorSeam, NoopDoorHook};
use super::paths::{origin_repo_dir, serve_failed};
use super::serve::{ServeReport, ServeSink, ServeTerms, serve_request, unpinned_repo_ref};
use super::serve_cmd::ServeRequest;
use crate::Vault;
use crate::credential_door::CredentialDoorService;
use crate::error::{CodeError, Error, Result};
use crate::federation::GitPushCaller;
use crate::federation::git_push::{GitPushStamp, ServedPushRepo};
use crate::origin::residence::OriginAuthorityLease;

/// Who a serve invocation pushes as: the pusher a host transport proved
/// (`None` when its request named none), or an in-process caller whose
/// remote user is the owner or no one.
#[derive(Clone, Copy)]
pub(super) enum ServeCaller<'a> {
    Host(Option<&'a GitPushCaller>),
    InProcess,
}

/// [`super::serve_bounded_with_authority`] for a host transport, with the
/// pusher it authenticated: the one entry that can admit anyone but the
/// owner. `caller` is the host's sidecar, built from the credential it
/// verified; `None` pushes as no one.
///
/// # Errors
/// [`CodeError::GitPushCapabilityRequired`] for a push no arm admits, and
/// every refusal `serve_bounded_with_authority` makes.
#[expect(clippy::too_many_arguments)]
pub fn serve_bounded_as(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    bounds: ExchangeBounds,
    authority: Option<&OriginAuthorityLease>,
    caller: Option<&GitPushCaller>,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    let terms = ServeTerms {
        seam,
        authority,
        idle: bounds.idle,
        scan: bounds.scan,
        spill_floor: bounds.spill_floor,
        wait_for_repository: false,
        push_wait: Some(bounds.repository_wait),
        caller: ServeCaller::Host(caller),
        read: None,
    };
    serve_request(vault, repo_name, request, terms, body, sink)
}

/// The host's preflight of one push, before it queues it or reads a body
/// byte: the same decision the serving plane makes again under the
/// repository's coordinator and the final intent writer makes once more.
/// A request that is no push passes.
///
/// # Errors
/// [`CodeError::GitPushCapabilityRequired`] for a push no arm admits; a
/// repository that does not resolve; a store failure.
pub fn admit_receive_pack(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    caller: Option<&GitPushCaller>,
) -> Result<()> {
    let repo_dir = origin_repo_dir(vault, repo_name)?;
    admit_push(
        vault,
        request,
        repo_name,
        &repo_dir,
        ServeCaller::Host(caller),
    )
    .map(drop)
}

/// The push decision for one request: every receive-pack advertisement and
/// RPC, on both seams and both routes. `None` for a request that is no
/// push. The host's pusher must be the request's own remote user.
pub(super) fn admit_push(
    vault: &Vault,
    request: &ServeRequest,
    repo_name: &str,
    repo_dir: &Path,
    caller: ServeCaller<'_>,
) -> Result<Option<GitPushStamp>> {
    if !request.is_push() {
        return Ok(None);
    }
    let no_principal = || {
        Error::Code(CodeError::GitPushCapabilityRequired {
            repo: repo_name.to_owned(),
            reason: "the push names no registered principal".to_owned(),
        })
    };
    let remote_user = request.remote_user.as_deref().ok_or_else(no_principal)?;
    let pusher = match caller {
        ServeCaller::Host(Some(caller)) if caller.principal().to_hex() == remote_user => {
            caller.clone()
        }
        ServeCaller::Host(Some(_)) => {
            return Err(serve_failed("the pusher is not the request's principal"));
        }
        ServeCaller::Host(None) => return Err(no_principal()),
        ServeCaller::InProcess => {
            GitPushCaller::in_process(remote_user).ok_or_else(no_principal)?
        }
    };
    let ticket = request
        .query_string
        .split('&')
        .find_map(|pair| pair.strip_prefix("checkout-lease="));
    let served = ServedPushRepo::resolve(vault, repo_name, repo_dir);
    let txn = vault.store.env.read_txn()?;
    let admission = vault.admit_git_receive_pack_in_txn(&txn, &pusher, &served, ticket)?;
    Ok(Some(admission.into_stamp()))
}

/// Stamps the admission before any subprocess exists.
///
/// The transport has already proved a registered principal and a write scope by
/// the time this runs, and the push decision has admitted `push`; the door
/// derives its record from both (and from a presented slip, when Phase B
/// starts presenting one). `peer_addr` is passed through unread on purpose —
/// the door's own contract is that "localhost" describes a route and never a
/// principal.
///
/// This is also where the landed door's catastrophe dial reaches the push: the
/// `Landed` seam admits the `door:receive-pack` effector here, with no slip
/// required, so an operator-narrowed effector set closes the push path BEFORE
/// the backend is spawned and before a single pushed byte is read. The `Noop`
/// seam refuses nothing past the push decision, which is its whole contract.
pub(super) fn stamp_admission(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    repo_dir: &Path,
    seam: DoorSeam,
    push: Option<GitPushStamp>,
) -> Result<Option<DoorAdmissionStamp>> {
    if !request.is_receive_pack() {
        return Ok(None);
    }
    let principal_ref = request
        .remote_user
        .as_deref()
        .ok_or_else(|| serve_failed("receive-pack requires a registered principal"))?;
    let push = push.ok_or_else(|| serve_failed("receive-pack was not admitted to push"))?;
    let repo = unpinned_repo_ref(repo_dir);
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let now = vault.now_recorded_at();
    let operation_id = vault.new_entity_id()?;
    let mut stamp = match seam {
        DoorSeam::Noop => {
            if request
                .query_string
                .split('&')
                .any(|part| part.starts_with("checkout-lease="))
            {
                return Err(serve_failed("checkout lease requires the credential door"));
            }
            NoopDoorHook.admit_receive_pack(
                operation_id,
                None,
                principal_ref,
                &repo,
                peer_addr,
                now,
            )?
        }
        DoorSeam::Landed => {
            let door = CredentialDoorService::new(Arc::clone(vault));
            let mut tickets = request
                .query_string
                .split('&')
                .filter_map(|part| part.strip_prefix("checkout-lease="));
            let ticket = tickets.next();
            if tickets.next().is_some() {
                return Err(serve_failed("ambiguous checkout lease"));
            }
            let credential = ticket
                .map(|ticket| door.checkout_credential(ticket, principal_ref, &repo))
                .transpose()
                .map_err(|error| super::paths::door_refused(&error))?;
            door.admit_receive_pack(
                operation_id,
                credential.as_ref(),
                principal_ref,
                &repo,
                peer_addr,
                now,
            )?
        }
    };
    stamp.push = Some(push);
    Ok(Some(stamp))
}

/// The reason a door window gives the pusher when the final intent writer
/// refused: the typed capability refusal as it is, naming its repo and the
/// missing capability; every other failure the one generic reason.
pub(super) fn intent_refusal_reason(error: &Error) -> String {
    match error {
        Error::Code(refusal @ CodeError::GitPushCapabilityRequired { .. }) => refusal.to_string(),
        _ => "receive-pack intent could not be made durable".to_owned(),
    }
}
