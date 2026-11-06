//! The accepted member's original replica source on the bound facade.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::authority::VerifiedSlip;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, SharedReplicaManifest, SharedReplicaManifestRequest, SharedReplicaWindow,
    SharedReplicaWindowRequest,
};

use super::host_doors::support::MaybeListed;
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn forbidden(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} requires the accepted member's own holder-bound credential"),
        &["Use the credential returned by invitation acceptance."],
    )
}

fn member(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<(AuthenticatedOwner, VerifiedSlip)> {
    let reader = person(server, auth, verb)?;
    let slip = auth
        .verified_slip()
        .filter(|slip| slip.claims().grant_ref.is_some() && slip.claims().invitation_ref.is_none())
        .cloned()
        .ok_or_else(|| forbidden(verb))?;
    Ok((reader, slip))
}

pub(super) fn admits(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
    member(server, auth, verb).map(drop)
}

fn selected_member(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    grant: &str,
) -> MemoryResult<(AuthenticatedOwner, VerifiedSlip)> {
    let proof = member(server, auth, verb)?;
    let selected = EntityId::from_hex(grant).map_err(|_| forbidden(verb))?;
    let bound = proof
        .1
        .claims()
        .grant_ref
        .as_deref()
        .ok_or_else(|| forbidden(verb))?;
    if EntityId::from_hex(bound).map_err(|_| forbidden(verb))? != selected {
        return Err(forbidden(verb));
    }
    Ok(proof)
}

pub(crate) async fn vault_members_replica_manifest(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedReplicaManifestRequest,
) -> MaybeListed<SharedReplicaManifest> {
    const VERB: &str = "vault.members.replica_manifest";
    let proof = selected_member(server, auth, VERB, &input.grant);
    let (answer, rows) = as_person_naming(
        server,
        VERB,
        proof,
        move |server, (reader, slip)| {
            sdk::read_shared_replica_manifest_listing(server.vault(), &reader, slip.scope(), input)
        },
        |(_, rows)| Some(rows.clone()),
    )
    .await;
    (answer.map(|(reply, _)| reply), rows)
}

pub(crate) async fn vault_members_replica_window(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedReplicaWindowRequest,
) -> MaybeListed<SharedReplicaWindow> {
    const VERB: &str = "vault.members.replica_window";
    let proof = selected_member(server, auth, VERB, &input.grant);
    let (answer, rows) = as_person_naming(
        server,
        VERB,
        proof,
        move |server, (reader, slip)| {
            sdk::read_shared_replica_window_listing(server.vault(), &reader, slip.scope(), input)
        },
        |(_, rows)| Some(rows.clone()),
    )
    .await;
    (answer.map(|(reply, _)| reply), rows)
}
