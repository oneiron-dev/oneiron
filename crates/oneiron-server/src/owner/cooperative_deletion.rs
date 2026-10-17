//! Courtesy unsend (OF-273, ARCH-0043 #relationship-lifecycle): after a
//! disconnect the owner asks a former peer to drop what it synced, and sees
//! each ask's delivery status. Asks a former peer sent arrive for review;
//! the owner answers from the menu, and nothing is deleted on receipt.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{
    COOP_DELETION_PEER_PATH, COOP_DELETION_REPLY_PEER_PATH, CooperativeDeletionAnswer,
    CooperativeDeletionNotice, IncomingCooperativeDeletion,
    decode_self_signed_cooperative_deletion_request, parse_hex,
};
use oneiron::task_verb::sdk::{
    CourtesyDeleteAnswerRequest, CourtesyDeleteAskedWorld, CourtesyDeleteChoice,
    CourtesyDeleteIncoming, CourtesyDeleteSendRequest, CourtesyDeleteSent,
};
use rand_core::RngCore;

use super::stamp::rfc3339_secs;
use super::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// One sent ask, as the ledger holds it.
fn sent_ask(notice: CooperativeDeletionNotice) -> CourtesyDeleteSent {
    CourtesyDeleteSent {
        request: notice.request_id,
        pact: notice.connection_id,
        recipient: notice.recipient_id,
        status: notice.status.as_str().to_owned(),
        created: rfc3339_secs(notice.created_at),
        updated: rfc3339_secs(notice.updated_at),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn hex_field<const N: usize>(field: &str, value: &str) -> OwnerResult<[u8; N]> {
    parse_hex(value).ok_or_else(|| OwnerError::Invalid(format!("{field} must be {} hex", N * 2)))
}

/// The full peer URL for `origin` and `path`: HTTPS (HTTP only on loopback),
/// no credentials, path, query or fragment of its own.
fn peer_url(field: &str, origin: &str, path: &str) -> OwnerResult<String> {
    let invalid = || OwnerError::Invalid(format!("{field} must be an https origin"));
    let url = reqwest::Url::parse(origin).map_err(|_| invalid())?;
    if !matches!(url.path(), "" | "/") {
        return Err(invalid());
    }
    let destination = format!("{}{path}", origin.trim_end_matches('/'));
    crate::feedback_delivery::check_endpoint(&destination).map_err(|_| invalid())?;
    Ok(destination)
}

/// Runs `sign` with this host's authority key.
pub(super) fn with_issuer<T>(
    server: &SyncServer,
    sign: impl FnOnce(&HostSlipIssuer) -> oneiron::Result<T>,
) -> OwnerResult<T> {
    if let Some(issuer) = server.managed_issuer.as_ref() {
        return Ok(sign(issuer)?);
    }
    let secret = server.config.auth_secret.as_deref().ok_or_else(|| {
        OwnerError::Refused(
            "this host holds no signing key; send an ask signed by the pinned key".to_owned(),
        )
    })?;
    let issuer = HostSlipIssuer::from_secret(secret.as_bytes())?;
    Ok(sign(&issuer)?)
}

/// Signs (unless the owner brought a signed ask) and queues one ask.
pub(crate) fn send(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &CourtesyDeleteSendRequest,
) -> OwnerResult<CourtesyDeleteSent> {
    let vault = server.vault();
    let pact = hex_field::<32>("pact", &request.pact)?;
    let destination = peer_url("peer", &request.peer, COOP_DELETION_PEER_PATH)?;
    let signed = if let Some(signed) = &request.signed {
        let bytes = STANDARD
            .decode(signed)
            .map_err(|_| OwnerError::Invalid("signed must be base64".to_owned()))?;
        let signed = decode_self_signed_cooperative_deletion_request(&bytes)
            .map_err(|_| OwnerError::Invalid("signed is not a signed ask".to_owned()))?;
        if signed.body.pact_id != pact {
            return Err(OwnerError::Invalid("signed names another pact".to_owned()));
        }
        signed
    } else {
        let worlds = request
            .worlds
            .iter()
            .map(|world| entity_id("worlds", world))
            .collect::<OwnerResult<Vec<_>>>()?;
        let epoch_cutoff = match request.epoch_cutoff {
            Some(epoch) => epoch,
            None => {
                let fold = vault.authority_fold()?;
                let state = fold
                    .federation_pacts
                    .get(&pact)
                    .ok_or_else(|| OwnerError::NotFound("pact", request.pact.clone()))?;
                state.terminal_epoch.unwrap_or(state.pact_epoch)
            }
        };
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        with_issuer(server, |issuer| {
            issuer.sign_cooperative_deletion_request(vault, &pact, worlds, epoch_cutoff, nonce)
        })?
    };
    let notice =
        vault.queue_cooperative_deletion_request_as(owner, &signed, &destination, now())?;
    Ok(sent_ask(notice))
}

/// Every ask this vault sent.
pub(crate) fn sent(server: &SyncServer) -> OwnerResult<Vec<CourtesyDeleteSent>> {
    Ok(server
        .vault()
        .cooperative_deletion_notices()?
        .into_iter()
        .map(sent_ask)
        .collect())
}

/// Every ask filed here, with each named world's stale stamp.
pub(crate) fn incoming(server: &SyncServer) -> OwnerResult<Vec<CourtesyDeleteIncoming>> {
    let vault = server.vault();
    let fold = vault.authority_fold()?;
    vault
        .incoming_cooperative_deletions()?
        .into_iter()
        .map(|filed| incoming_ask(vault, &fold, filed))
        .collect()
}

fn incoming_ask(
    vault: &oneiron::Vault,
    fold: &oneiron::authority::AuthorityFold,
    filed: IncomingCooperativeDeletion,
) -> OwnerResult<CourtesyDeleteIncoming> {
    let pact_status = parse_hex::<32>(&filed.connection_id)
        .and_then(|pact| fold.federation_pacts.get(&pact))
        .map(|state| format!("{:?}", state.status));
    let worlds = filed
        .worlds
        .iter()
        .map(|world| {
            let stamp = oneiron::EntityId::from_hex(world)
                .ok()
                .map(|id| oneiron::federation::foreign_world_stale_stamp(vault, id))
                .transpose()?
                .flatten();
            Ok(CourtesyDeleteAskedWorld {
                world: world.clone(),
                stale: stamp.map(|stamp| format!("{:?}", stamp.reason)),
                stale_epoch: stamp.map(|stamp| stamp.disconnect_epoch),
            })
        })
        .collect::<OwnerResult<Vec<_>>>()?;
    Ok(CourtesyDeleteIncoming {
        request: filed.request_id,
        pact: filed.connection_id,
        pact_status,
        requester: filed.requester_vault_id,
        worlds,
        epoch_cutoff: filed.epoch_cutoff,
        requested: rfc3339_secs(filed.requested_at),
        received: rfc3339_secs(filed.received_at),
        answer: filed.disposition.map(|choice| CourtesyDeleteChoice {
            choice: choice.kind,
            reason_code: choice.reason_code,
            review: choice.review_at.map(rfc3339_secs),
            deleted: choice.deleted,
            recorded: rfc3339_secs(choice.recorded_at),
        }),
        reply_status: filed.reply_status.map(|status| status.as_str().to_owned()),
    })
}

/// Records the owner's choice on one filed ask and, with `reply_to`, queues
/// the signed answer back to the requester.
pub(crate) fn answer(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &CourtesyDeleteAnswerRequest,
) -> OwnerResult<CourtesyDeleteIncoming> {
    let vault = server.vault();
    let pact = hex_field::<32>("pact", &request.pact)?;
    let nonce = hex_field::<16>("request", &request.request)?;
    let destination = request
        .reply_to
        .as_deref()
        .map(|origin| peer_url("reply_to", origin, COOP_DELETION_REPLY_PEER_PATH))
        .transpose()?;
    let delete = request
        .delete
        .iter()
        .map(|id| entity_id("delete", id))
        .collect::<OwnerResult<Vec<_>>>()?;
    let hold = request
        .hold
        .iter()
        .map(|id| entity_id("hold", id))
        .collect::<OwnerResult<Vec<_>>>()?;
    let answer = CooperativeDeletionAnswer {
        kind: request.choice,
        reason_code: request.reason_code.clone(),
        review_at: request.review_at,
        delete,
        hold,
    };
    let mut filed = vault
        .answer_cooperative_deletion_as(owner, &pact, &nonce, &answer, now())
        .map_err(|error| {
            if let Err(refusal) = vault.recheck_owner(owner) {
                return OwnerError::from(refusal);
            }
            OwnerError::Invalid(error.to_string())
        })?;
    if let Some(destination) = destination {
        let reply = with_issuer(server, |issuer| {
            issuer.sign_cooperative_deletion_reply(
                vault,
                &pact,
                nonce,
                request.choice.reply_outcome(),
            )
        })?;
        filed = vault.queue_cooperative_deletion_reply_as(owner, &reply, &destination, now())?;
    }
    let fold = vault.authority_fold()?;
    incoming_ask(vault, &fold, filed)
}
