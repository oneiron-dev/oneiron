//! The sealed snapshot store (DESIGN-V2 §7, V2-R3): each snapshot's body
//! sealed under its own data key in a file of its own under the vault root,
//! its wrapped key in the vault's one-key custody alone, and its catalog
//! row. Vault methods only: a worker gets plaintext regions from the host,
//! never a key, the database or a file.
//!
//! A publish seals the body, writes it beside its final name, syncs it,
//! renames it in and syncs the directory; then one transaction rechecks the
//! admission generation (an erase moves it inside its own transaction, so
//! the two serialize), publishes the wrapped key to custody, writes the row
//! and retires the session's earlier snapshot: the prior one stands until
//! its replacement commits. A retirement deletes the row and stages the
//! key's retirement in one transaction; after the commit the custody
//! finisher retires the key and the bodies no row names are unlinked.
//!
//! A read checks the row first: an absent row, a standing retirement, a
//! missing key, a lock or erase since the admission are cold, and a body
//! that is missing or does not open retires its row. A body opens under its
//! own row alone: the catalog id and the manifest are its associated data.
//! The wrapped key's bytes never reach the row, the body, a log, an error
//! or a receipt; the copy a call holds is wiped before it returns.
use std::collections::BTreeSet;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::sync::MutexGuard;
use std::time::{SystemTime, UNIX_EPOCH};

use heed::RwTxn;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::catalog::{
    self, CATALOG, SNAPSHOT_RECORD_SCHEMA, SnapshotClass, SnapshotDependencies, SnapshotId,
    SnapshotManifest, SnapshotPins, SnapshotRecord,
};
use super::lifecycle::SnapshotAdmission;
use super::retention::SnapshotBudget;
use super::seal::{SealedSnapshot, WrappedSnapshotKey, open_snapshot, seal_snapshot};
use crate::Vault;
use crate::error::{Error, Result};
use crate::store::{INFERENCE_SNAPSHOT_WRAPPED_KEY_BYTES, Store};

/// The vault subkey every snapshot's data key is wrapped under.
const WRAP_CONTEXT: &str = "oneiron/inference-snapshot/wrap/v1";
/// The domain a body's associated data opens with.
const AAD_DOMAIN: &[u8] = b"oneiron/inference-snapshot/manifest/v1\0";
const BODY_SUFFIX: &str = ".seal";
/// A body being written, before its rename.
const STAGING_SUFFIX: &str = ".seal.part";

/// What a park hands the store with a snapshot's plaintext: what it was
/// computed from and under, the worker's hash of it, and its class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotPublish {
    pub manifest: SnapshotManifest,
    pub dependencies: SnapshotDependencies,
    /// The worker's SHA-256 of the plaintext, checked here before sealing.
    pub snapshot_sha256: [u8; 32],
    pub class: SnapshotClass,
    pub recompute_ms: Option<u64>,
    pub authority_generation: Option<u64>,
}

/// What a reconcile found: rows retired because their body was missing or
/// did not parse, and body files unlinked because no row names them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotReconcile {
    pub retired: u64,
    pub unlinked: u64,
}

fn corrupt() -> Error {
    Error::CorruptedIndex("inference snapshot")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// The SHA-256 of `bytes`, as the worker hashes its serialized state.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn body_name(id: &SnapshotId) -> String {
    format!("{}{BODY_SUFFIX}", id.to_hex())
}

/// The catalog id a body or staging file name carries.
fn named_id(name: &str) -> Option<SnapshotId> {
    let hex = name
        .strip_suffix(STAGING_SUFFIX)
        .or_else(|| name.strip_suffix(BODY_SUFFIX))?;
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(SnapshotId(id))
}

/// `catalog id ‖ manifest`, after the domain: what each chunk of a body
/// binds, so it opens under its own row alone.
fn associated_data(id: &SnapshotId, manifest: &SnapshotManifest) -> Result<Vec<u8>> {
    let manifest = rmp_serde::to_vec_named(manifest).map_err(|_| corrupt())?;
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 16 + manifest.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&id.0);
    aad.extend_from_slice(&manifest);
    Ok(aad)
}

/// Whether two manifests are the same exact session: one snapshot each is
/// kept, the latest.
fn same_session(a: &SnapshotManifest, b: &SnapshotManifest) -> bool {
    a.vault == b.vault
        && a.read_scope == b.read_scope
        && a.conversation == b.conversation
        && a.fold_epoch == b.fold_epoch
        && a.conditioning == b.conditioning
        && a.compatibility == b.compatibility
}

/// Writes `body` as `id`'s body file in `dir`: beside its name, synced,
/// renamed in, and the directory synced.
fn write_body(dir: &Path, id: &SnapshotId, body: &[u8]) -> Result<()> {
    fs::create_dir_all(dir)?;
    let staging = dir.join(format!("{}{STAGING_SUFFIX}", id.to_hex()));
    let written = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&staging, dir.join(body_name(id)))?;
        crate::store::sync_dir(dir)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&staging);
    }
    written
}

/// Takes the row `id` out of the catalog and stages its key's retirement,
/// both in `wtxn`: from the commit on no open finds it, and a restored
/// earlier image cannot open its key. The body file and the custody entry
/// go after the commit. `true` when a row was there.
///
/// # Errors
/// Custody and storage faults.
pub(super) fn retire_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, id: &SnapshotId) -> Result<bool> {
    let gone = CATALOG.delete(store, wtxn, id)?;
    store.stage_inference_snapshot_retirement_in_txn(wtxn, &id.0)?;
    Ok(gone)
}

/// The wrapped key's bytes, checked to be the custody entry's width.
fn checked_key(wrapped: WrappedSnapshotKey) -> Result<WrappedSnapshotKey> {
    let width = Zeroizing::new(wrapped.to_bytes()).len();
    if width == INFERENCE_SNAPSHOT_WRAPPED_KEY_BYTES {
        Ok(wrapped)
    } else {
        wrapped.retire();
        Err(corrupt())
    }
}

impl Vault {
    /// Seals `plaintext` as a new snapshot under `admission` and publishes
    /// it: its body file, its key in custody and its row, retiring the same
    /// session's earlier snapshot in the row's transaction. `Ok(None)`, and
    /// nothing kept, when the snapshot may not be kept: a lock or erase
    /// since the admission, a locked key, a dependency set that is not
    /// precise, a manifest field unknown, a hash that does not match, or no
    /// room inside `budget`. Never a refusal of the turn that made it.
    ///
    /// # Errors
    /// Storage, custody and file faults.
    pub fn publish_inference_snapshot(
        &self,
        admission: &SnapshotAdmission,
        budget: SnapshotBudget,
        publish: SnapshotPublish,
        plaintext: &[u8],
    ) -> Result<Option<SnapshotId>> {
        let keepable = publish.dependencies.precise
            && publish.manifest.compatibility.complete()
            && sha256(plaintext) == publish.snapshot_sha256;
        if !keepable || !self.snapshot_admission_holds(admission) {
            return Ok(None);
        }
        let Ok(key) = self.vault_subkey(WRAP_CONTEXT) else {
            return Ok(None);
        };
        let id = SnapshotId::random()?;
        let aad = associated_data(&id, &publish.manifest)?;
        let (wrapped, sealed) = seal_snapshot(&key, &aad, plaintext)?;
        drop(key);
        let wrapped = checked_key(wrapped)?;
        let body = sealed.to_bytes();
        let now = now_ms();
        let record = SnapshotRecord {
            schema: SNAPSHOT_RECORD_SCHEMA,
            id,
            seal_id: sealed.seal_id(),
            manifest: publish.manifest,
            dependencies: publish.dependencies,
            plaintext_bytes: u64::try_from(plaintext.len()).map_err(|_| corrupt())?,
            sealed_bytes: u64::try_from(body.len()).map_err(|_| corrupt())?,
            snapshot_sha256: publish.snapshot_sha256,
            class: publish.class,
            created_ms: now,
            last_used_ms: now,
            reuse_count: 0,
            recompute_ms: publish.recompute_ms,
            pins: SnapshotPins {
                admission_generation: admission.generation(),
                erase_generation: admission.erase_generation(),
                authority_generation: publish.authority_generation,
            },
        };
        let ledger = self.snapshot_ledger();
        let reserved = ledger.reserve(budget, Some(record.sealed_bytes), &[]);
        let mut reservation = match reserved {
            Ok(Some(reservation)) => reservation,
            other => {
                wrapped.retire();
                return other.map(|_| None);
            }
        };
        let published = if ledger.charge(&mut reservation, record.sealed_bytes) {
            self.commit_snapshot(admission, &record, &wrapped, &body)
        } else {
            Ok(false)
        };
        ledger.release(reservation);
        wrapped.retire();
        match published {
            Ok(true) => {
                self.finish_inference_snapshot_retirements_after_commit();
                Ok(Some(id))
            }
            Ok(false) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Writes `record`'s body, then rechecks `admission` and commits its
    /// key and row, retiring the same session's earlier rows. `false`, the
    /// body unlinked, when a lock or erase came first.
    fn commit_snapshot(
        &self,
        admission: &SnapshotAdmission,
        record: &SnapshotRecord,
        wrapped: &WrappedSnapshotKey,
        body: &[u8],
    ) -> Result<bool> {
        let store = &self.store;
        let _files = store.inference_snapshots.files();
        let dir = store.inference_snapshot_dir();
        write_body(&dir, &record.id, body)?;
        let committed = (|| -> Result<bool> {
            let mut wtxn = store.env.write_txn()?;
            if !self.snapshot_admission_holds(admission) {
                return Ok(false);
            }
            let earlier: Vec<SnapshotId> = catalog::rows(store, &wtxn)?
                .into_iter()
                .filter(|(_, row)| {
                    row.as_ref()
                        .is_some_and(|row| same_session(&row.manifest, &record.manifest))
                })
                .map(|(id, _)| id)
                .collect();
            store.publish_inference_snapshot_key_in_txn(&mut wtxn, &record.id.0, wrapped)?;
            CATALOG.put(store, &mut wtxn, &record.id, record)?;
            for id in earlier {
                retire_in_txn(store, &mut wtxn, &id)?;
            }
            wtxn.commit()?;
            Ok(true)
        })();
        if !matches!(committed, Ok(true)) {
            let _ = fs::remove_file(dir.join(body_name(&record.id)));
        }
        committed
    }

    /// Opens snapshot `id` under `admission`: its row and its plaintext,
    /// wiped on drop. `Ok(None)` is cold: no row, a row that may serve no
    /// restore, a standing retirement, no key, a locked key, or a lock or
    /// erase since the admission. A body that is missing or does not open,
    /// or whose plaintext does not match its row, retires the row.
    ///
    /// # Errors
    /// Storage, custody and file faults.
    pub fn read_inference_snapshot(
        &self,
        admission: &SnapshotAdmission,
        id: &SnapshotId,
    ) -> Result<Option<(SnapshotRecord, Zeroizing<Vec<u8>>)>> {
        let store = &self.store;
        if !self.snapshot_admission_holds(admission) {
            return Ok(None);
        }
        let (record, wrapped) = {
            // The writer keeps the custody finisher off the key between the
            // row's check and the key's read.
            let wtxn = store.env.write_txn()?;
            let record = match CATALOG.get(store, &wtxn, id) {
                Ok(Some(record)) if record.reusable() => record,
                Ok(_) => return Ok(None),
                Err(_) => {
                    drop(wtxn);
                    self.retire_inference_snapshot(id)?;
                    return Ok(None);
                }
            };
            match store.read_inference_snapshot_key(&wtxn, &id.0) {
                Ok(Some(wrapped)) => (record, wrapped),
                Ok(None) => return Ok(None),
                Err(_) => {
                    drop(wtxn);
                    self.retire_inference_snapshot(id)?;
                    return Ok(None);
                }
            }
        };
        let opened = self.open_body(&record, &wrapped);
        wrapped.retire();
        let plaintext = match opened? {
            Some(Some(plaintext)) => plaintext,
            Some(None) => {
                self.retire_inference_snapshot(id)?;
                return Ok(None);
            }
            None => return Ok(None),
        };
        if !self.snapshot_admission_holds(admission) {
            return Ok(None);
        }
        self.note_inference_snapshot_reuse(id)?;
        Ok(Some((record, plaintext)))
    }

    /// `record`'s plaintext: `Some(None)` when its body is missing, does not
    /// open or does not match the row, and `None` while the key is locked.
    fn open_body(
        &self,
        record: &SnapshotRecord,
        wrapped: &WrappedSnapshotKey,
    ) -> Result<Option<Option<Zeroizing<Vec<u8>>>>> {
        let path = self
            .store
            .inference_snapshot_dir()
            .join(body_name(&record.id));
        let body = match fs::read(path) {
            Ok(body) => body,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Some(None)),
            Err(error) => return Err(error.into()),
        };
        let Ok(key) = self.vault_subkey(WRAP_CONTEXT) else {
            return Ok(None);
        };
        let aad = associated_data(&record.id, &record.manifest)?;
        let plaintext = SealedSnapshot::parse(&body)
            .ok()
            .filter(|sealed| {
                sealed.seal_id() == record.seal_id && body.len() as u64 == record.sealed_bytes
            })
            .and_then(|sealed| open_snapshot(&key, wrapped, &aad, &sealed).ok())
            .filter(|plaintext| {
                plaintext.len() as u64 == record.plaintext_bytes
                    && sha256(plaintext) == record.snapshot_sha256
            });
        Ok(Some(plaintext))
    }

    /// Counts one restore `id` served, and when.
    fn note_inference_snapshot_reuse(&self, id: &SnapshotId) -> Result<()> {
        let store = &self.store;
        let mut wtxn = store.env.write_txn()?;
        if let Some(mut record) = CATALOG.get(store, &wtxn, id)? {
            record.reuse_count = record.reuse_count.saturating_add(1);
            record.last_used_ms = now_ms();
            CATALOG.put(store, &mut wtxn, id, &record)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Retires snapshot `id`: its row goes and its key's retirement is
    /// staged in one transaction, then both are carried out. `true` when a
    /// row was there.
    ///
    /// # Errors
    /// Storage and custody faults.
    pub fn retire_inference_snapshot(&self, id: &SnapshotId) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let gone = retire_in_txn(&self.store, &mut wtxn, id)?;
        wtxn.commit()?;
        self.finish_inference_snapshot_retirements_after_commit();
        Ok(gone)
    }

    /// Carries out every staged snapshot retirement, an interrupted
    /// process's included: a row whose key is absent is retired first, so
    /// the custody finisher never retires the key of a row that stands;
    /// then the keys retire, and the body files no row names are
    /// unlinked. Startup and housekeeping run it.
    ///
    /// # Errors
    /// Storage, custody and file faults.
    pub fn finish_inference_snapshot_retirements(&self) -> Result<()> {
        let files = self.store.inference_snapshots.files();
        self.sweep_inference_snapshots(&files).map(drop)
    }

    /// [`Self::finish_inference_snapshot_retirements`] unless a publication
    /// or a sweep holds the body files: then nothing is done.
    ///
    /// # Errors
    /// Storage, custody and file faults.
    pub(crate) fn try_finish_inference_snapshot_retirements(&self) -> Result<()> {
        let Some(files) = self.store.inference_snapshots.try_files() else {
            return Ok(());
        };
        self.sweep_inference_snapshots(&files).map(drop)
    }

    /// [`Self::finish_inference_snapshot_retirements`] under the body files'
    /// guard `_files`, with the number of body files unlinked.
    fn sweep_inference_snapshots(&self, _files: &MutexGuard<'_, ()>) -> Result<u64> {
        let store = &self.store;
        let kept = {
            let txn = store.env.read_txn()?;
            !catalog::rows(store, &txn)?.is_empty()
        };
        if kept {
            // A row whose key is absent (a standing retirement, a key gone)
            // is dead: it retires before the finisher runs. A key that does
            // not read keeps its row for the next pass.
            let mut wtxn = store.env.write_txn()?;
            let mut dead = Vec::new();
            for (id, _) in catalog::rows(store, &wtxn)? {
                match store.read_inference_snapshot_key(&wtxn, &id.0) {
                    Ok(Some(wrapped)) => wrapped.retire(),
                    Ok(None) => dead.push(id),
                    Err(error) => tracing::warn!(
                        kind = ?error.kind(),
                        "an inference snapshot key did not read; its row is kept"
                    ),
                }
            }
            if !dead.is_empty() {
                for id in &dead {
                    retire_in_txn(store, &mut wtxn, id)?;
                }
                wtxn.commit()?;
            }
        }
        store.finish_inference_snapshot_retirements()?;
        let named: BTreeSet<SnapshotId> = {
            let txn = store.env.read_txn()?;
            catalog::rows(store, &txn)?
                .into_iter()
                .map(|(id, _)| id)
                .collect()
        };
        let dir = store.inference_snapshot_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        let mut unlinked = 0;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let id = name.to_str().and_then(named_id);
            if id.is_some_and(|id| named.contains(&id)) {
                continue;
            }
            fs::remove_file(entry.path())?;
            unlinked += 1;
        }
        if unlinked > 0 {
            crate::store::sync_dir(&dir)?;
        }
        Ok(unlinked)
    }

    /// Brings the catalog and the body files back in step at startup: a
    /// row whose body file is missing or is not the length it names
    /// retires, and every file no row names is unlinked, with the staged
    /// retirements carried out. Publication waits for it.
    ///
    /// # Errors
    /// Storage, custody and file faults.
    pub fn reconcile_inference_snapshots(&self) -> Result<SnapshotReconcile> {
        let store = &self.store;
        let mut retired = 0;
        let files = store.inference_snapshots.files();
        let dir = store.inference_snapshot_dir();
        let mut wtxn = store.env.write_txn()?;
        for (id, record) in catalog::rows(store, &wtxn)? {
            let whole = record.is_some_and(|record| {
                fs::metadata(dir.join(body_name(&id)))
                    .is_ok_and(|meta| meta.is_file() && meta.len() == record.sealed_bytes)
            });
            if !whole && retire_in_txn(store, &mut wtxn, &id)? {
                retired += 1;
            }
        }
        wtxn.commit()?;
        let unlinked = self.sweep_inference_snapshots(&files)?;
        Ok(SnapshotReconcile { retired, unlinked })
    }
}
