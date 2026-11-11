//! Request-bound publication grants kept by the home beside their generation.
//! The issuer's native signature admits an offer; the proved executor alone
//! reads it. Outer keys remain sealed. Rows retire with the generation.

use super::bundle::{
    Asked, denied, entries_in, entry_in, hex, owner_machine_in, sealed_generation_hex,
};
use crate::authority::{AuthorityEntryHash, AuthorityFold, Destination, PeerMachine};
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{SealedBundleGeneration, SealedPublicationGrant};
use crate::{EntityId, Vault};

// A separate key family in the existing LIVE bundle-access table. Pad-access
// capture and grant parsing continue to use their own g: and q: families.
const GRANTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_ACCESS);

/// One current publication request an old reader may grant the newest kept generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingPublicationGrant {
    pub generation: SealedBundleGeneration,
    pub request: AuthorityEntryHash,
    pub executor: EntityId,
}

fn generation_prefix(generation: &SealedBundleGeneration) -> String {
    format!("p:{}:", sealed_generation_hex(generation))
}

fn grant_key(
    generation: &SealedBundleGeneration,
    request: &AuthorityEntryHash,
    executor: EntityId,
) -> String {
    format!(
        "{}{}:{}",
        generation_prefix(generation),
        hex(request),
        executor.to_hex()
    )
}

fn home_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<EntityId> {
    crate::identity::read_machine_id_in_txn(vault, txn)?.ok_or_else(denied)
}

fn requested_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    peer: PeerMachine,
    request: AuthorityEntryHash,
) -> Result<(EntityId, EntityId)> {
    let executor = owner_machine_in(vault, txn, peer, true, Asked::named(Some(request)))?;
    let home = home_in(vault, txn)?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if !super::bundle::asked_of(&fold, Some(home), executor, Asked::Named(request)) {
        return Err(denied());
    }
    Ok((executor, home))
}

fn held_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    generation: &SealedBundleGeneration,
    request: &AuthorityEntryHash,
    executor: EntityId,
) -> Result<Option<SealedPublicationGrant>> {
    GRANTS
        .get_bytes(&vault.store, txn, &grant_key(generation, request, executor))?
        .map(|bytes| SealedPublicationGrant::from_bytes(&bytes))
        .transpose()
}

fn current(
    grant: &SealedPublicationGrant,
    fold: &AuthorityFold,
    home: EntityId,
    generation: SealedBundleGeneration,
    request: AuthorityEntryHash,
    executor: EntityId,
) -> bool {
    grant.generation() == generation
        && *grant.request() == request
        && grant.executor() == executor
        && grant.admitted_for(fold, Destination::Machine(home))
}

/// Current requests for this home whose newest kept generation has no current
/// offer. Only a current proved owner machine may enumerate work to issue.
/// The native sealer must still open both actual objects before it issues one.
pub fn pending_publication_grants(
    vault: &Vault,
    peer: PeerMachine,
) -> Result<Vec<PendingPublicationGrant>> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    let PeerMachine::Proven { machine, key } = peer else {
        return Err(denied());
    };
    if fold.trusted_machine(machine).is_none() || fold.machine_proof_key(machine) != Some(key) {
        return Err(denied());
    }
    let home = home_in(vault, &txn)?;
    let Some(entry) = entries_in(vault, &txn)?.pop() else {
        return Ok(Vec::new());
    };
    let mut pending = Vec::new();
    for (request, executor) in
        crate::world_keys::publication_grant_requests(&fold, Destination::Machine(home))
    {
        let offered = held_in(vault, &txn, &entry.generation, &request, executor)?;
        if offered
            .as_ref()
            .is_some_and(|grant| current(grant, &fold, home, entry.generation, request, executor))
        {
            continue;
        }
        pending.push(PendingPublicationGrant {
            generation: entry.generation,
            request,
            executor,
        });
    }
    Ok(pending)
}

/// Keeps a native signed pair only while its generation is kept and its exact
/// issuer, pending request, home, executor and recipient key stand in this writer.
/// The uploader's socket is not the grant's authority.
pub fn offer_publication_grant(vault: &Vault, grant: &SealedPublicationGrant) -> Result<()> {
    let bytes = grant.to_bytes()?;
    vault.with_write_txn_grouped(|txn| {
        let home = home_in(vault, txn)?;
        let fold = vault.authority_fold_readonly_in_txn(txn)?;
        if entry_in(vault, txn, &grant.generation())?.is_none()
            || !grant.admitted_for(&fold, Destination::Machine(home))
        {
            return Err(denied());
        }
        GRANTS.put(
            &vault.store,
            txn,
            &grant_key(&grant.generation(), grant.request(), grant.executor()),
            &bytes,
        )
    })
}

/// The current offer for this socket's proved executor and exact pending
/// request. Admission is checked again here; actual body AEAD and publisher
/// checks remain the executor's native open, not a claim made by the home.
pub fn publication_grant(
    vault: &Vault,
    peer: PeerMachine,
    generation: SealedBundleGeneration,
    request: AuthorityEntryHash,
) -> Result<Option<SealedPublicationGrant>> {
    let txn = vault.store.env.read_txn()?;
    let (executor, home) = requested_in(vault, &txn, peer, request)?;
    if entry_in(vault, &txn, &generation)?.is_none() {
        return Ok(None);
    }
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    Ok(held_in(vault, &txn, &generation, &request, executor)?
        .filter(|grant| current(grant, &fold, home, generation, request, executor)))
}

/// An executor that could not open the current objects with an offered pair
/// asks for a fresh one. Only that exact offer is removed, so a concurrent
/// replacement is kept. A rewrite of pads may change its outer key without
/// changing the generation.
pub fn invalidate_publication_grant(
    vault: &Vault,
    peer: PeerMachine,
    grant: &SealedPublicationGrant,
) -> Result<()> {
    let bytes = grant.to_bytes()?;
    vault.with_write_txn_grouped(|txn| {
        let (executor, _) = requested_in(vault, txn, peer, *grant.request())?;
        if executor != grant.executor() {
            return Err(denied());
        }
        let key = grant_key(&grant.generation(), grant.request(), executor);
        if GRANTS.get_bytes(&vault.store, txn, &key)?.as_deref() == Some(bytes.as_slice()) {
            GRANTS.delete(&vault.store, txn, &key)?;
        }
        Ok(())
    })
}

pub(super) fn retire_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    generation: &SealedBundleGeneration,
) -> Result<()> {
    GRANTS.delete_from(&vault.store, txn, generation_prefix(generation).as_bytes())?;
    Ok(())
}
