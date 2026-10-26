//! The owner's one typed confirm over a restore's pending credentials
//! (FIX-LIST 10671 (b), Engine 10-22 21:4x): "the source is gone, keep
//! these", once for the whole batch a restore left pending on its source's
//! evidence, never a block. Any live vault Owner, a co-Owner included, gives
//! it: no clearance, grant, carrier or signing key, or recovery root is
//! asked.
//!
//! The confirm releases the source-evidence condition alone. Each row lands
//! as the image carried it, its saved ciphertext back, unless an erase
//! fenced it (here, or in the source where the source reads now), an
//! admitted revoke ended it, or any write replaced its row since: those stay
//! as they are. No key is minted, so a value whose key custody does not hold
//! lands sealed and still unavailable. The batch is applied under one
//! recorded election, value-free: who, when, the typed confirm and what each
//! credential came to. It says the owner elected to keep without source
//! verification, never that the source was checked, and names a value
//! recovered only where it read back under its key. A repeat returns that
//! receipt; rows a fault left pending are judged again under it.

use std::collections::BTreeMap;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::{PENDING, PendingCredentialResult, Settle, settle_in_txn, source_evidence};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::side_table::{self, Named, SideTable};
use crate::store::{FenceLookup, Store};
use crate::vault::Vault;

/// What the receipt of a released batch says: the owner's election, never
/// a check of the source.
pub const PENDING_CREDENTIAL_RELEASE_NOTE: &str =
    "owner elected to keep without source verification";

/// Each released batch's receipt, by batch.
const RELEASE: SideTable<EntityId, ReleaseRow, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_RESTORE_RELEASE);

/// The owner's one typed answer to a restore's pending credential batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingCredentialConfirmation {
    /// "The source is gone, keep these": every credential the batch holds
    /// pending on its source's evidence lands as the image carried it,
    /// unverified against that source.
    KeepWithoutSource,
}

impl PendingCredentialConfirmation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeepWithoutSource => "keep_without_source",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        (text == Self::KeepWithoutSource.as_str()).then_some(Self::KeepWithoutSource)
    }
}

/// One credential a batch holds pending, by its handle, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCredentialCard {
    pub handle: String,
    pub generation: u32,
}

/// What one credential of a released batch came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCredentialOutcome {
    pub handle: String,
    pub generation: u32,
    pub result: PendingCredentialResult,
}

/// The receipt of a released batch: value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCredentialReleaseReceipt {
    pub batch: EntityId,
    /// The owner who confirmed; none once his identity is erased.
    pub by: Option<EntityId>,
    pub at: u64,
    pub confirmation: PendingCredentialConfirmation,
    pub outcomes: Vec<PendingCredentialOutcome>,
}

impl PendingCredentialReleaseReceipt {
    /// What the receipt says of the election
    /// ([`PENDING_CREDENTIAL_RELEASE_NOTE`]).
    pub fn note(&self) -> &'static str {
        PENDING_CREDENTIAL_RELEASE_NOTE
    }
}

/// One restore's batch, for the owner's card: what waits on its source, and
/// the receipt of his confirm, if he gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCredentialBatch {
    pub batch: EntityId,
    pub pending: Vec<PendingCredentialCard>,
    pub released: Option<PendingCredentialReleaseReceipt>,
}

impl PendingCredentialBatch {
    fn empty(batch: EntityId) -> Self {
        Self {
            batch,
            pending: Vec::new(),
            released: None,
        }
    }
}

/// One released batch's receipt as it rests.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRow {
    /// The owner PERSON who confirmed; none once his identity is erased.
    by: Option<EntityId>,
    at: u64,
    confirmation: PendingCredentialConfirmation,
    outcomes: Vec<ReleaseOutcome>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseOutcome {
    credential: EntityId,
    generation: u32,
    result: PendingCredentialResult,
}

impl ReleaseRow {
    fn receipt(
        self,
        store: &Store,
        txn: &RoTxn<'_>,
        batch: EntityId,
    ) -> PendingCredentialReleaseReceipt {
        PendingCredentialReleaseReceipt {
            batch,
            by: self.by,
            at: self.at,
            confirmation: self.confirmation,
            outcomes: self
                .outcomes
                .into_iter()
                .map(|outcome| PendingCredentialOutcome {
                    handle: handle(store, txn, &outcome.credential),
                    generation: outcome.generation,
                    result: outcome.result,
                })
                .collect(),
        }
    }
}

/// Credential `id`'s handle in `store`, else its id.
fn handle(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> String {
    super::super::storage_seal::credential_handle(store, txn, id, &id.to_hex())
}

fn not_owner() -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(
        "only a vault owner keeps a restore's pending credentials",
    ))
}

/// Revalidates `owner` in `txn`: his proof, and that he is a live owner of
/// this vault, a co-Owner included.
fn live_owner_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    txn: &RoTxn<'_>,
) -> Result<EntityId> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return Err(not_owner());
    }
    Ok(actor)
}

impl Vault {
    /// Every restore batch whose credentials wait on their source's
    /// evidence, and every batch an owner released, for the owner's card
    /// (FIX-LIST 10671 (b)): handles and generations, never a value.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is no live
    /// owner's of this vault; storage faults.
    pub fn pending_credential_batches_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<PendingCredentialBatch>> {
        let txn = self.store.env.read_txn()?;
        live_owner_in_txn(self, owner, &txn)?;
        let mut batches: BTreeMap<EntityId, PendingCredentialBatch> = BTreeMap::new();
        for ((batch, id), saved) in PENDING.scan(&self.store, &txn)? {
            batches
                .entry(batch)
                .or_insert_with(|| PendingCredentialBatch::empty(batch))
                .pending
                .push(PendingCredentialCard {
                    handle: handle(&self.store, &txn, &id),
                    generation: saved.generation,
                });
        }
        for (batch, release) in RELEASE.scan(&self.store, &txn)? {
            batches
                .entry(batch)
                .or_insert_with(|| PendingCredentialBatch::empty(batch))
                .released = Some(release.receipt(&self.store, &txn, batch));
        }
        Ok(batches.into_values().collect())
    }

    /// The owner's one typed confirm over restore batch `batch`
    /// (`confirmation`, CALLS CUSTODY_PENDING_SOURCE_POLICY): every credential
    /// it holds pending on its source's evidence lands as the image carried
    /// it, judged in this writer, the owner revalidated there. An erase that
    /// fenced one, here or in the source where the source reads now, an
    /// admitted revoke, or a write that replaced its row since leaves it as
    /// it is; no key is minted. Returns the batch's receipt, recorded in the
    /// same commit; a repeat with nothing left returns it unchanged.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is no live
    /// owner's of this vault; [`SecretError::SecretRefNotFound`] for a batch
    /// this vault holds neither pending nor released; storage faults.
    pub fn release_pending_credential_batch_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        batch: &EntityId,
        confirmation: PendingCredentialConfirmation,
        at: u64,
    ) -> Result<PendingCredentialReleaseReceipt> {
        match (super::CUSTODY_PENDING_SOURCE_POLICY, confirmation) {
            (
                super::CustodyPendingSourcePolicy::ReReadPerHandleOrTypedOwnerBatchKeep,
                PendingCredentialConfirmation::KeepWithoutSource,
            ) => {}
        }
        // An erase the source names, where it reads now, still stands: its
        // evidence is read once, outside the writer.
        let source = {
            let txn = self.store.env.read_txn()?;
            let first = PENDING
                .iter_from(&self.store, &txn, batch.as_bytes())?
                .next()
                .transpose()?;
            first.map(|(_, saved)| saved.source)
        };
        let mut evidence = source.and_then(|source| source_evidence(&source));
        let (release, erased) = self.with_write_txn(|wtxn| {
            let actor = live_owner_in_txn(self, owner, wtxn)?;
            let held = PENDING.scan_from(&self.store, wtxn, batch.as_bytes())?;
            let mut outcomes = match (RELEASE.get(&self.store, wtxn, batch)?, held.is_empty()) {
                (Some(release), true) => return Ok((release, false)),
                (None, true) => {
                    return Err(Error::Secret(SecretError::SecretRefNotFound {
                        name: format!("pending credential batch {}", batch.to_hex()),
                    }));
                }
                (release, false) => release.map(|release| release.outcomes).unwrap_or_default(),
            };
            let mut erased = false;
            for ((_, id), saved) in &held {
                let settle = match evidence.as_mut().map(|fences| fences.lookup(id)) {
                    Some(FenceLookup::Fenced) => Settle::Erased,
                    _ => Settle::Install,
                };
                let Some(result) = settle_in_txn(self, wtxn, (batch, id), saved, settle)? else {
                    continue;
                };
                erased |= result == PendingCredentialResult::Erased;
                outcomes.retain(|outcome| outcome.credential != *id);
                outcomes.push(ReleaseOutcome {
                    credential: *id,
                    generation: saved.generation,
                    result,
                });
            }
            let release = ReleaseRow {
                by: Some(actor),
                at,
                confirmation,
                outcomes,
            };
            RELEASE.put(&self.store, wtxn, batch, &release)?;
            Ok((release, erased))
        })?;
        if erased {
            self.finish_credential_retirements_after_commit();
        }
        let txn = self.store.env.read_txn()?;
        Ok(release.receipt(&self.store, &txn, *batch))
    }
}

/// Erasing `actor` (FIX 3520): a receipt he confirmed keeps what it records
/// and names no one. One-way, in the erase's own transaction.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_pending_restore_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (batch, mut release) in RELEASE.scan(&vault.store, wtxn)? {
        if release.by == Some(*actor) {
            release.by = None;
            RELEASE.put(&vault.store, wtxn, &batch, &release)?;
        }
    }
    Ok(())
}
