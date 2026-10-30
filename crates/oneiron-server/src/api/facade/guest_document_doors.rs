//! Guest document envelopes under the owner's or the recipient's own proof.
use std::sync::Arc;

use oneiron::authority::VerifiedSlip;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{GuestDocumentEnvelope, GuestDocumentShareRequest};

use super::host_doors::support::{Listed, internal, owner_proof, refused};
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

fn forbidden() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "guest document export requires the recipient's own live grant-bound credential",
        &["Use a capability slip minted for this live Connect guest grant."],
    )
}

/// The facade checks this before running hooks; the engine rechecks it on export.
pub(super) fn guest_document_reader(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<VerifiedSlip> {
    auth.require(CoreScope::Read).map_err(|_| forbidden())?;
    auth.require_lane_record_scope().map_err(|_| forbidden())?;
    let proof = auth.verified_slip().ok_or_else(forbidden)?;
    if proof.claims().grant_ref.is_none()
        || proof.is_transferred()
        || !auth.credential_is_live(server.vault())
    {
        return Err(forbidden());
    }
    Ok(proof.clone())
}

async fn owner_share(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    input: GuestDocumentShareRequest,
) -> Listed<GuestDocumentEnvelope> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let result = super::clock_ingress::run_blocking(move || {
        crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(oneiron::sync::selector::share_guest_document_as_owner(
                &server.reassert_manager,
                &owner,
                issuer,
                &input,
            ))
        })
        .map_err(|_| internal(verb))?
        .map_err(MemoryError::from)
    })
    .await
    .unwrap_or_else(|_| Err(internal(verb)));
    match result {
        Ok((envelope, rows)) => (Ok(envelope), rows),
        Err(error) => refused(error),
    }
}

/// Shares a locally authored named-world document under an active guest grant.
pub(crate) async fn vault_guests_share(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GuestDocumentShareRequest,
) -> Listed<GuestDocumentEnvelope> {
    owner_share(server, auth, "vault.guests.share", input).await
}

/// The same share door admits local authorship, but refuses foreign-world forwarding.
pub(crate) async fn vault_guests_reshare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GuestDocumentShareRequest,
) -> Listed<GuestDocumentEnvelope> {
    owner_share(server, auth, "vault.guests.reshare", input).await
}

/// Fetches the actual signed update as the recipient, over HTTP or verb RPC.
pub(crate) async fn vault_guests_export_envelope(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GuestDocumentShareRequest,
) -> Listed<GuestDocumentEnvelope> {
    const VERB: &str = "vault.guests.export_envelope";
    let proof = match guest_document_reader(server, auth) {
        Ok(proof) => proof,
        Err(error) => return refused(error),
    };
    let locality = auth.locality();
    let server = Arc::clone(server);
    let result = super::clock_ingress::run_blocking(move || {
        crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(oneiron::sync::selector::export_guest_document_for_guest(
                &server.reassert_manager,
                &proof,
                locality,
                issuer,
                &input,
            ))
        })
        .map_err(|_| internal(VERB))?
        .map_err(MemoryError::from)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    match result {
        Ok((envelope, rows)) => (Ok(envelope), rows),
        Err(error) => refused(error),
    }
}
