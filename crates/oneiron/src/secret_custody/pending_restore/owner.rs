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
//! receipt, the first confirm's owner, time and words kept.
//!
//! The election stands here while anything of its batch still waits: a row
//! a fault left pending lands on a later custody pass, behind the same
//! checks, with no second confirm. It is kept in a Runtime-tier row, so no
//! image carries it: a receipt an image carried is never an election here.
//! Erasing the owner who confirmed takes his id off the receipt; a scrub
//! that faults never stops his erase, and the next custody pass finishes it.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{PENDING, PendingCredentialResult, Settle, settle_in_txn, source_evidence};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::{FenceLookup, Store};
use crate::vault::Vault;

/// What the receipt of a released batch says: the owner's election, never
/// a check of the source.
pub const PENDING_CREDENTIAL_RELEASE_NOTE: &str =
    "owner elected to keep without source verification";

/// Each released batch's receipt, by batch.
const RELEASE: SideTable<EntityId, ReleaseRow, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_RESTORE_RELEASE);

/// Each batch whose owner's confirm here stands while any of it waits.
const ELECTION: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_RESTORE_ELECTION);

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
    /// Records what credential `credential` came to, in place of what it
    /// came to before.
    fn note(&mut self, credential: EntityId, generation: u32, result: PendingCredentialResult) {
        self.outcomes
            .retain(|outcome| outcome.credential != credential);
        self.outcomes.push(ReleaseOutcome {
            credential,
            generation,
            result,
        });
    }

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
    /// same commit. The first confirm is the election: it stands here for
    /// what a fault left waiting, which the custody passes land under it;
    /// a repeat keeps its owner, time and words, and with nothing left
    /// returns the receipt unchanged.
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
            let existing = RELEASE.get(&self.store, wtxn, batch)?;
            if held.is_empty() {
                return existing.map(|release| (release, false)).ok_or_else(|| {
                    Error::Secret(SecretError::SecretRefNotFound {
                        name: format!("pending credential batch {}", batch.to_hex()),
                    })
                });
            }
            // The first confirm is the election: a repeat keeps its owner,
            // time and words, and judges again only what still waits.
            let mut release = existing.unwrap_or(ReleaseRow {
                by: Some(actor),
                at,
                confirmation,
                outcomes: Vec::new(),
            });
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
                release.note(*id, saved.generation, result);
            }
            RELEASE.put(&self.store, wtxn, batch, &release)?;
            hold_election_in_txn(&self.store, wtxn, batch)?;
            Ok((release, erased))
        })?;
        if erased {
            self.finish_credential_retirements_after_commit();
        }
        let txn = self.store.env.read_txn()?;
        Ok(release.receipt(&self.store, &txn, *batch))
    }
}

/// Keeps batch `batch`'s election standing here while any of it waits, and
/// ends it once none does.
fn hold_election_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, batch: &EntityId) -> Result<()> {
    let waits = PENDING
        .iter_from(store, wtxn, batch.as_bytes())?
        .next()
        .is_some();
    if waits {
        ELECTION.put(store, wtxn, batch, &())
    } else {
        ELECTION.delete(store, wtxn, batch).map(|_| ())
    }
}

/// The batches whose owner's confirm stands here, read in `txn`.
pub(super) fn elected_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<BTreeSet<EntityId>> {
    Ok(ELECTION.scan_keys(store, txn, &[])?.into_iter().collect())
}

/// Records on batch `batch`'s receipt what a custody pass made of each of
/// `results` under its election, the election's owner, time and words kept,
/// and ends the election once nothing of the batch waits.
pub(super) fn record_elected_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    batch: &EntityId,
    results: &[(EntityId, u32, PendingCredentialResult)],
) -> Result<()> {
    if let Some(mut release) = RELEASE.get(store, wtxn, batch)? {
        for (credential, generation, result) in results {
            release.note(*credential, *generation, *result);
        }
        RELEASE.put(store, wtxn, batch, &release)?;
    }
    hold_election_in_txn(store, wtxn, batch)
}

/// Takes the confirming owner off each release receipt whose owner
/// `erased` names, row by row (FIX 3520). A receipt that does not read, and
/// a check or a write that faults, is warned by kind and left for the next
/// custody pass ([`Vault::scrub_erased_release_owners`]). Never fails.
fn scrub_release_owners_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    erased: impl Fn(&RoTxn<'_>, &EntityId) -> Result<bool>,
) {
    let rows = RELEASE
        .iter_raw_from(&vault.store, wtxn, &[])
        .and_then(|rows| rows.collect::<Result<Vec<_>>>());
    let rows = match rows {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "pending credential release receipts did not read; the next custody pass takes \
                 an erased owner off them"
            );
            return;
        }
    };
    for (key, value) in rows {
        let (Some(batch), Ok(mut release)) = (
            <EntityId as SideKey>::decode_key(&key),
            RELEASE.decode_value(&value),
        ) else {
            tracing::warn!("a pending credential release receipt did not read; it is skipped");
            continue;
        };
        let Some(by) = release.by else {
            continue;
        };
        let txn: &RoTxn<'_> = &*wtxn;
        match erased(txn, &by) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a release receipt's owner was not checked; the next custody pass checks it"
                );
                continue;
            }
        }
        release.by = None;
        if let Err(error) = RELEASE.put(&vault.store, wtxn, &batch, &release) {
            tracing::warn!(
                kind = ?error.kind(),
                "an erased owner stayed on a release receipt; the next custody pass takes him off"
            );
        }
    }
}

impl Vault {
    /// Takes off every release receipt an owner a hard-delete marker names:
    /// an erase whose own scrub faulted, finished on a custody pass (FIX
    /// 3520). A fault is warned by kind; the next pass tries again.
    pub(super) fn scrub_erased_release_owners(&self) {
        let erased =
            |txn: &RoTxn<'_>, by: &EntityId| self.local_hard_delete_marker_exists_in_txn(txn, by);
        let owed = (|| -> Result<bool> {
            let txn = self.store.env.read_txn()?;
            for row in RELEASE.iter_raw_from(&self.store, &txn, &[])? {
                let (_, value) = row?;
                if let Ok(ReleaseRow { by: Some(by), .. }) = RELEASE.decode_value(&value)
                    && erased(&txn, &by)?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        })();
        let scrubbed = match owed {
            Ok(false) => return,
            Ok(true) => self.with_write_txn(|wtxn| {
                scrub_release_owners_in_txn(self, wtxn, erased);
                Ok(())
            }),
            Err(error) => Err(error),
        };
        if let Err(error) = scrubbed {
            tracing::warn!(
                kind = ?error.kind(),
                "an erased owner stayed on a release receipt; the next custody pass takes him off"
            );
        }
    }
}

/// Erasing `actor` (FIX 3520): a receipt he confirmed keeps what it records
/// and names no one. In the erase's own transaction, and never its fault: a
/// receipt this does not reach is finished by the next custody pass.
///
/// # Errors
///
/// None: every fault is warned and left owed.
pub(crate) fn erase_pending_restore_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    scrub_release_owners_in_txn(vault, wtxn, |_, by| Ok(by == actor));
    Ok(())
}
