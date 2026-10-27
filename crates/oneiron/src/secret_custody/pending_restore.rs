//! A credential a restore landed pending because the vault whose custody it
//! kept did not read (FIX-LIST 10671 (a), Engine 10-22 21:4x, CALLS `KS-6
//! erase Keep source evidence`, CUSTODY_PENDING_SOURCE_POLICY).
//!
//! A restore that keeps this host's custody reads its source's erase
//! evidence before anything lands; where that read faults, each credential
//! nothing else fences lands withheld, PendingCustody (KS-6 part 2). Before
//! its row becomes the nonce-only placeholder, the restore keeps the row as
//! the image carried it, its value sealed under its generation's key, in one
//! row here, landed in the same commit as the placeholder: never a
//! plaintext, never a key. A row that does not stage is warned, and the
//! credential lands pending as before.
//!
//! The custody passes on upkeep and on the served tick retake each saved
//! row's source evidence, current, with no timer and no owner act: an erase
//! the source names now leaves the credential withheld, erased, its fence
//! owed here; evidence that reads clear lands the row as the image carried
//! it once its value opens under its exact key, and one that does not open
//! stays pending, never recovered; a source that does not read, holds no
//! vault or holds another lineage's leaves it as it is. Each landing is
//! judged again in a writer: a fence here, an admitted revoke, or any write
//! to the row since it landed withheld (a revoke, an erase, a rotation, a
//! newer body) cancels it, its saved row dropped. The owner may keep a whole
//! batch without its source with one typed confirm instead ([`owner`]); his
//! election stands for the batch's rows a fault left waiting, which the
//! custody passes then land behind the same checks. The passes run on
//! upkeep, on the served tick and at a live vault's open; an archived vault
//! runs none.

mod owner;

use std::collections::BTreeMap;

use heed::RwTxn;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, RawValue, SideTable};
use crate::store::{CredentialFences, CustodyBinding, FenceLookup};
use crate::vault::Vault;

pub(crate) use self::owner::erase_pending_restore_actor_in_txn;
pub use self::owner::{
    PENDING_CREDENTIAL_RELEASE_NOTE, PendingCredentialBatch, PendingCredentialCard,
    PendingCredentialConfirmation, PendingCredentialOutcome, PendingCredentialReleaseReceipt,
};

/// How a credential a restore landed pending on its source's evidence is
/// settled (CALLS CUSTODY_PENDING_SOURCE_POLICY, Engine 10-22 21:4x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyPendingSourcePolicy {
    /// Each one re-reads its source's current evidence on the custody passes
    /// that run already, per handle; or the owner keeps the restore's whole
    /// batch with one typed confirm, recorded as his election, never as a
    /// check of the source. No timer, no hold, no refusal.
    ReReadPerHandleOrTypedOwnerBatchKeep,
}

const CUSTODY_PENDING_SOURCE_POLICY: CustodyPendingSourcePolicy =
    CustodyPendingSourcePolicy::ReReadPerHandleOrTypedOwnerBatchKeep;

/// Each saved row, by the restore's batch and the credential's id.
const PENDING: SideTable<(EntityId, EntityId), PendingRestore, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_RESTORE_PENDING);

/// Why a saved row waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PendingRestoreReason {
    /// The source vault whose custody the restore kept did not read.
    SourceEvidenceUnread,
}

/// One credential's row as the image carried it, kept while it waits.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRestore {
    /// The entity row as the image carried it: its value sealed under its
    /// generation's custody key.
    #[serde(with = "bin")]
    row: Vec<u8>,
    /// The digest of the withheld row the restore landed in its place.
    landed: [u8; 32],
    /// The generation its value is sealed at.
    generation: u32,
    /// The custody binding the restore kept, whose source did not read.
    #[serde(with = "bin")]
    source: Vec<u8>,
    reason: PendingRestoreReason,
}

/// What a pending credential came to (FIX-LIST 10671).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingCredentialResult {
    /// Its row landed as the image carried it, and its value opens under
    /// its key here.
    Readable,
    /// Its row landed as the image carried it, but its key does not open it
    /// here: re-enter or reissue it.
    StillUnavailable,
    /// An erase fenced it: it stays withheld, its value unavailable.
    Erased,
    /// A revoke, an erase, a rotation or a newer write replaced its row
    /// since: the saved row went, unlanded.
    Superseded,
    /// Its fence or its row did not read: it stays pending.
    Pending,
}

impl PendingCredentialResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Readable => "readable",
            Self::StillUnavailable => "still_unavailable",
            Self::Erased => "erased",
            Self::Superseded => "superseded",
            Self::Pending => "pending",
        }
    }
}

/// Byte strings as msgpack bin, not arrays of numbers.
mod bin {
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                Ok(bytes.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(bytes)
            }
        }
        input.deserialize_bytes(Visitor)
    }
}

/// The rows a restore keeping this host's custody lands beside each
/// credential it withholds pending because its source did not read: staged
/// before the destination exists and landed with the image's rows, in one
/// commit. Nothing is kept on any other route.
pub(crate) struct PendingRestoreStage {
    /// The restore's batch and the binding it kept, raw, when it keeps rows.
    keeping: Option<(EntityId, Vec<u8>)>,
    rows: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PendingRestoreStage {
    /// A stage for a restore keeping `source`'s custody, whose source did
    /// not read; none keeps anything.
    pub(crate) fn keeping(source: Option<&CustodyBinding>) -> Self {
        let keeping = source.and_then(|binding| match binding.to_raw() {
            Ok(raw) => Some((fresh_batch(), raw)),
            Err(_) => {
                tracing::warn!(
                    "a restore's custody binding did not encode; its pending credentials land \
                     withheld as before"
                );
                None
            }
        });
        Self {
            keeping,
            rows: Vec::new(),
        }
    }

    /// Keeps `raw`, credential `id`'s row as the image carried it, sealed at
    /// `generation`, beside `withheld`, the row it lands as. A row that does
    /// not encode is warned: the credential lands withheld as before.
    pub(crate) fn keep(&mut self, id: &EntityId, generation: u32, raw: &[u8], withheld: &[u8]) {
        let Some((batch, source)) = &self.keeping else {
            return;
        };
        let saved = PendingRestore {
            row: raw.to_vec(),
            landed: *blake3::hash(withheld).as_bytes(),
            generation,
            source: source.clone(),
            reason: PendingRestoreReason::SourceEvidenceUnread,
        };
        match PENDING.encode_value(&saved) {
            Ok(value) => self.rows.push((PENDING.key_bytes(&(*batch, *id)), value)),
            Err(error) => tracing::warn!(
                credential = %id.to_hex(),
                kind = ?error.kind(),
                "a pending credential's row did not stage; it lands withheld as before"
            ),
        }
    }

    /// The `vault_meta` rows to land with the image's.
    pub(crate) fn into_rows(self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.rows
    }

    /// Whether `vault_meta` row `key`, `value` is a saved row an image
    /// carried for a cloud registration slot: a copy served beside its
    /// source drops each, so neither a pass nor the owner's confirm lands a
    /// slot its fork withholds (CALLS G7_COPY_RECOVERY). A saved row that
    /// does not read goes too.
    pub(crate) fn copy_withholds(key: &[u8], value: &[u8]) -> bool {
        key.starts_with(PENDING.decl().prefix)
            && PENDING
                .decode_value(value)
                .ok()
                .and_then(|saved| {
                    let body = saved.row.get(ENTITY_METADATA_HEADER_LEN..)?;
                    super::storage_seal::decode_stored_custody_body(body).ok()
                })
                .is_none_or(|stored| super::is_cloud_registration_slot(&stored.record.name))
    }
}

/// A fresh batch id: one per restore.
fn fresh_batch() -> EntityId {
    loop {
        let mut bytes = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        if let Ok(batch) = EntityId::from_bytes(bytes) {
            return batch;
        }
    }
}

/// The current evidence of the source a saved row names, read now: `None`
/// when its binding, or the source, does not read.
fn source_evidence(source: &[u8]) -> Option<CredentialFences> {
    match <CustodyBinding as RawValue>::from_raw(source) {
        Ok(binding) => CredentialFences::retake_source(&binding),
        Err(_) => {
            tracing::warn!(
                "a pending credential restore's source binding did not read; it stays pending"
            );
            None
        }
    }
}

/// How one saved row is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settle {
    /// Its source's current evidence names an erase of it.
    Erased,
    /// Its source's evidence read clear: it lands once its value opens
    /// under its exact key.
    InstallIfOpens,
    /// The owner keeps it without its source: it lands, opening or not.
    Install,
}

/// Settles credential `id`'s saved row in `batch`, `saved` as it was read,
/// in `wtxn`; `None` when another pass settled it first. Never past a fence
/// here, an admitted revoke, or any write to its row since it landed
/// withheld, and never a key minted. A check that does not read leaves it
/// pending, warned.
fn settle_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    (batch, id): (&EntityId, &EntityId),
    saved: &PendingRestore,
    settle: Settle,
) -> Result<Option<PendingCredentialResult>> {
    let store = &vault.store;
    let key = (*batch, *id);
    if PENDING.get(store, wtxn, &key)?.as_ref() != Some(saved) {
        return Ok(None);
    }
    let result = match store.credential_fence_in_txn(wtxn, id) {
        FenceLookup::Faulted => return Ok(Some(PendingCredentialResult::Pending)),
        FenceLookup::Fenced => PendingCredentialResult::Erased,
        FenceLookup::Clear if settle == Settle::Erased => {
            store.put_credential_fence_owed_in_txn(wtxn, id)?;
            PendingCredentialResult::Erased
        }
        FenceLookup::Clear => match landed_unchanged_in_txn(vault, wtxn, id, saved) {
            None => return Ok(Some(PendingCredentialResult::Pending)),
            Some(false) => PendingCredentialResult::Superseded,
            Some(true) => {
                let opens = super::storage_seal::stored_row_opens(
                    &saved.row,
                    id,
                    saved.generation,
                    |id, generation| store.read_credential_value_leaf(id, generation),
                );
                if !opens && settle == Settle::InstallIfOpens {
                    return Ok(Some(PendingCredentialResult::Pending));
                }
                store.entities.put(wtxn, id.as_bytes(), &saved.row)?;
                if opens {
                    PendingCredentialResult::Readable
                } else {
                    PendingCredentialResult::StillUnavailable
                }
            }
        },
    };
    PENDING.delete(store, wtxn, &key)?;
    Ok(Some(result))
}

/// Whether credential `id`'s row is still the withheld one the restore
/// landed, with no admitted revoke of it; `None`, warned, when either does
/// not read.
fn landed_unchanged_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    saved: &PendingRestore,
) -> Option<bool> {
    let read = (|| -> Result<bool> {
        let unchanged = vault
            .store
            .port_entity_raw_wiped(txn, id)?
            .is_some_and(|row| blake3::hash(&row).as_bytes() == &saved.landed);
        Ok(unchanged && !super::control::custody_revoked_in_txn(vault, txn, id)?)
    })();
    match read {
        Ok(unchanged) => Some(unchanged),
        Err(error) => {
            tracing::warn!(
                credential = %id.to_hex(),
                kind = ?error.kind(),
                "a pending credential's row did not read; it stays pending"
            );
            None
        }
    }
}

impl Vault {
    /// Retakes the current source evidence of every credential a restore
    /// left pending on it (CALLS CUSTODY_PENDING_SOURCE_POLICY): each source
    /// read once, outside any writer, then each row judged again in one
    /// writer ([`settle_in_txn`]). An erase the source names leaves it
    /// withheld, its fence owed here, and the finisher runs; evidence that
    /// reads clear lands its row once its value opens under its exact key;
    /// a batch whose owner's confirm stands here lands without its source,
    /// its receipt told. Returns how many it settled.
    fn resolve_pending_credential_restores(&self) -> Result<usize> {
        match CUSTODY_PENDING_SOURCE_POLICY {
            CustodyPendingSourcePolicy::ReReadPerHandleOrTypedOwnerBatchKeep => {}
        }
        let (held, elected) = {
            let txn = self.store.env.read_txn()?;
            (
                PENDING.scan(&self.store, &txn)?,
                owner::elected_in_txn(&self.store, &txn)?,
            )
        };
        let mut sources: BTreeMap<Vec<u8>, Option<CredentialFences>> = BTreeMap::new();
        let mut due = Vec::new();
        for ((batch, id), saved) in held {
            let evidence = sources
                .entry(saved.source.clone())
                .or_insert_with(|| source_evidence(&saved.source));
            let lookup = evidence.as_mut().map(|fences| fences.lookup(&id));
            // A standing election asks nothing of the source, but an erase
            // the source names still lands.
            let settle = match (lookup, elected.contains(&batch)) {
                (Some(FenceLookup::Fenced), _) => Settle::Erased,
                (_, true) => Settle::Install,
                (Some(FenceLookup::Clear), false) => Settle::InstallIfOpens,
                (Some(FenceLookup::Faulted) | None, false) => continue,
            };
            due.push((batch, id, saved, settle));
        }
        if due.is_empty() {
            return Ok(0);
        }
        let (settled, erased) = self.with_write_txn(|wtxn| {
            let mut settled = 0;
            let mut erased = false;
            let mut told: BTreeMap<EntityId, Vec<_>> = BTreeMap::new();
            for (batch, id, saved, settle) in &due {
                match settle_in_txn(self, wtxn, (batch, id), saved, *settle)? {
                    None | Some(PendingCredentialResult::Pending) => {}
                    Some(result) => {
                        settled += 1;
                        erased |= result == PendingCredentialResult::Erased;
                        if elected.contains(batch) {
                            told.entry(*batch)
                                .or_default()
                                .push((*id, saved.generation, result));
                        }
                    }
                }
            }
            for (batch, results) in &told {
                owner::record_elected_in_txn(&self.store, wtxn, batch, results)?;
            }
            Ok((settled, erased))
        })?;
        if erased {
            self.finish_credential_retirements_after_commit();
        }
        Ok(settled)
    }

    /// [`Self::resolve_pending_credential_restores`] for a custody pass that
    /// goes on without it (upkeep, the served tick, a live vault's open),
    /// after the release receipts' owed scrub: a failure is logged by kind
    /// and the next pass retries. An archived vault runs neither.
    pub(crate) fn resolve_pending_credential_restores_logged(&self) {
        if self.store.refuse_archived().is_err() {
            return;
        }
        self.scrub_erased_release_owners();
        match self.resolve_pending_credential_restores() {
            Ok(0) => {}
            Ok(settled) => tracing::info!(
                settled,
                "pending credential restores settled from their source's evidence"
            ),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "pending credential restores were not judged again; the next pass retries"
            ),
        }
    }
}
