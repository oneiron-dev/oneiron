//! The exact attempt an asked executor makes to publish the vault's sealed
//! bundle for the owner's request (FIX 4787, CALLS BUNDLE_PUBLISH_RECONCILE).
//!
//! Before its commit the executor persists the attempt: the request, the
//! home, itself, the generation and the sealed bundle's ciphertext digest.
//! The home records a commit made for the request in the commit's own
//! transaction (`sync::residence`'s commit receipt). Before the executor
//! assembles another upload for a request with an unresolved attempt, it
//! reads that record back:
//! - a commit the home recorded for the request, this executor's, enacts it;
//! - a home that recorded none frees a retry, which persists its own attempt;
//! - a home that does not answer leaves the outcome uncertain, and the
//!   request pending.
//!
//! An attempt stays, with no expiry and no count bound, until its request
//! has its result here, whatever generations the home retires meanwhile.

use serde::Deserialize;
use serde_json::json;

use super::{ResidenceRpc, refused, storage};
use crate::Vault;
use crate::authority::AuthorityEntryHash;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::residence::{
    sealed_digest_from_hex, sealed_digest_hex, sealed_generation_from_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::SealedBundleGeneration;

/// This machine's unresolved attempts, by request.
const ATTEMPTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_ATTEMPT);

/// The home (16) ‖ the executor (16) ‖ the generation (24) ‖ the digest (32).
const ATTEMPT_LEN: usize = 16 + 16 + 24 + 32;

/// The home's read of the commit it recorded for a request.
const STATUS_RPC: &str = "residence.bundle.commit.status";

/// How an asked executor makes sure one request stands behind one commit
/// (CALLS BUNDLE_PUBLISH_RECONCILE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishReconcile {
    /// The exact attempt (request, home, executor, generation, bundle
    /// digest) is persisted before the commit. Before another upload is
    /// assembled for the request, the home's record of the request's commit
    /// is read: a commit of this executor's enacts, none frees a retry, and
    /// no answer leaves the request pending. No expiry and no count bound:
    /// an attempt goes once its request has its result.
    PersistedExactAttempt,
}

const BUNDLE_PUBLISH_RECONCILE: PublishReconcile = PublishReconcile::PersistedExactAttempt;

/// One attempt, as persisted before its commit. Ids and a ciphertext digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BundleAttempt {
    pub(crate) home: EntityId,
    pub(crate) executor: EntityId,
    pub(crate) generation: SealedBundleGeneration,
    /// BLAKE3 of the sealed bundle's bytes.
    pub(crate) bundle_digest: [u8; 32],
}

impl BundleAttempt {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATTEMPT_LEN);
        out.extend_from_slice(self.home.as_bytes());
        out.extend_from_slice(self.executor.as_bytes());
        out.extend_from_slice(&self.generation.to_bytes());
        out.extend_from_slice(&self.bundle_digest);
        out
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != ATTEMPT_LEN {
            return Err(Error::InvalidKey);
        }
        let id = |range: std::ops::Range<usize>| -> Result<EntityId> {
            let bytes: [u8; 16] = raw[range].try_into().map_err(|_| Error::InvalidKey)?;
            EntityId::from_bytes(bytes).map_err(|_| Error::InvalidKey)
        };
        Ok(Self {
            home: id(0..16)?,
            executor: id(16..32)?,
            generation: SealedBundleGeneration::from_bytes(&raw[32..56])?,
            bundle_digest: raw[56..].try_into().map_err(|_| Error::InvalidKey)?,
        })
    }
}

/// What the home's record says of a request's commit.
pub(super) enum Reconciled {
    /// The home recorded a commit of this executor's for the request: it is
    /// enacted.
    Committed,
    /// No attempt stands unresolved, or the home recorded no commit for the
    /// request: an upload may be assembled.
    Open,
    /// An attempt stands unresolved and the home did not answer for it: the
    /// outcome is uncertain, and the request stays pending.
    Uncertain,
}

#[derive(Deserialize)]
struct StatusReply {
    receipt: Option<StatusReceipt>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusReceipt {
    generation: String,
    bundle_digest: String,
}

/// Persists this install's exact attempt to publish `generation`, whose
/// sealed bundle's digest is `bundle_digest`, to `home` for `request`, before
/// its commit, replacing an attempt the home's record showed never landed.
/// An install with no machine identity is no executor and persists nothing.
pub(super) fn persist(
    vault: &Vault,
    request: AuthorityEntryHash,
    home: EntityId,
    generation: SealedBundleGeneration,
    bundle_digest: [u8; 32],
) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        let Some(executor) = crate::identity::read_machine_id_in_txn(vault, wtxn)? else {
            return Ok(());
        };
        let attempt = BundleAttempt {
            home,
            executor,
            generation,
            bundle_digest,
        };
        ATTEMPTS.put(
            &vault.store,
            wtxn,
            &sealed_digest_hex(&request),
            &attempt.encode(),
        )
    })
}

/// Forgets every attempt whose request has its result here: it is resolved.
pub(super) fn settle(vault: &Vault) -> Result<()> {
    let resolved: Vec<String> = {
        let txn = vault.store.env.read_txn()?;
        let fold = vault.authority_view_readonly_in_txn(&txn)?;
        let mut resolved = Vec::new();
        for row in ATTEMPTS.iter_raw_from(&vault.store, &txn, &[])? {
            let (key, _) = row?;
            let Ok(key) = String::from_utf8(key) else {
                continue;
            };
            if sealed_digest_from_hex(&key)
                .is_some_and(|request| fold.owner_work_result(&request).is_some())
            {
                resolved.push(key);
            }
        }
        resolved
    };
    if resolved.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for key in &resolved {
            ATTEMPTS.delete(&vault.store, wtxn, key)?;
        }
        Ok(())
    })
}

/// Reads the home's record of `request`'s commit, which `rpc` reaches as
/// `home`, when an attempt of this install's for that home stands
/// unresolved (CALLS BUNDLE_PUBLISH_RECONCILE). A record that does not parse
/// is a refused reply; a read that did not reach the home is an error.
pub(super) async fn reconcile(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    request: AuthorityEntryHash,
    home: EntityId,
) -> std::result::Result<Reconciled, TransportError> {
    let unresolved = vault
        .unresolved_bundle_attempt(request)
        .map_err(storage)?
        .is_some_and(|attempt| attempt.home == home);
    match BUNDLE_PUBLISH_RECONCILE {
        PublishReconcile::PersistedExactAttempt if !unresolved => return Ok(Reconciled::Open),
        PublishReconcile::PersistedExactAttempt => {}
    }
    let reply = match rpc
        .call(STATUS_RPC, json!({"request": sealed_digest_hex(&request)}))
        .await?
    {
        Ok(reply) => reply,
        Err(_) => return Ok(Reconciled::Uncertain),
    };
    let reply: StatusReply = serde_json::from_value(reply).map_err(|_| refused())?;
    let Some(receipt) = reply.receipt else {
        return Ok(Reconciled::Open);
    };
    sealed_generation_from_hex(&receipt.generation).ok_or_else(refused)?;
    sealed_digest_from_hex(&receipt.bundle_digest).ok_or_else(refused)?;
    Ok(Reconciled::Committed)
}

impl Vault {
    /// The attempt this install persisted for the bundle publication
    /// `request` and has not resolved, when it is this install's (FIX 4787):
    /// `None` with none, or with one another machine id persisted here.
    pub(crate) fn unresolved_bundle_attempt(
        &self,
        request: AuthorityEntryHash,
    ) -> Result<Option<BundleAttempt>> {
        let txn = self.store.env.read_txn()?;
        let me = crate::identity::read_machine_id_in_txn(self, &txn)?;
        Ok(ATTEMPTS
            .get_bytes(&self.store, &txn, &sealed_digest_hex(&request))?
            .map(|raw| BundleAttempt::decode(&raw))
            .transpose()?
            .filter(|attempt| Some(attempt.executor) == me))
    }
}
