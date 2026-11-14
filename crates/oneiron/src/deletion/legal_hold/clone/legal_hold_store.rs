//! An owner's hold store: sealed copies outside the vault (ARCH-0038
//! #legal-hold, LEGAL-HOLD-USE = B as a clone, owner 2026-11-05).
//!
//! On a hold, exactly what the order covers is copied into sealed captures
//! in the same frame format a host receives, written to a directory instead
//! of a socket: `<store>/<vault id hex>/<hold id hex>/<capture id
//! hex>.clone`. Each hold mints its own key pair; its secret is wrapped to
//! the install-level hold-store key in the device keystore and kept beside
//! the captures as `hold.key`. The copy outlives a full vault erase while
//! the hold runs: its key never lives in the vault's own key custody, and
//! the store never lies inside the vault directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use heed::RoTxn;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, Kek, OpenKey, OpenPolicy, Purpose,
    SealKey, SealParams, SuiteId, WrapType, seal_with_aad,
};
use oneiron_keystore::{KeystoreSlot, SlotKind};
use oneiron_vault_contract::host_legal::{
    CaptureExtent, CaptureRequest, CaptureScope, CaptureSource,
};
use zeroize::Zeroizing;

use super::super::{HoldCloneCapture, LegalHoldTarget};
use super::collector::{CaptureSink, Collector, SummaryCounts};
use super::messages::{RowKind, capture_rows_in_txn};
use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result, SecretError};
use crate::store::GateCloneComponent;

/// The epoch `hold.key` envelopes seal under.
const HOLD_KEY_EPOCH: u64 = 1;

/// The recipient a `hold.key` envelope binds.
const HOLD_KEY_RECIPIENT: &[u8] = b"oneiron/legal-hold-store/hold-key/v1";

/// The label a hold's 32-byte seed expands under into its key pair.
const HOLD_SECRET_LABEL: &[u8] = b"oneiron/legal-hold-store/hold-secret/v1";

/// The payload suite of a `hold.key` envelope.
const HOLD_KEY_SUITE: SuiteId = SuiteId::XCHACHA20POLY1305_V1;

/// The install's owner-hold store at its configured root.
pub(crate) struct LegalHoldStore {
    root: PathBuf,
}

/// The configured owner-hold store: its root created owner-only when
/// missing, then canonicalized. Refused when unset, or when the root lies
/// inside the vault's own directory, where an erase would reach it.
pub(crate) fn configured(vault: &Vault) -> Result<LegalHoldStore> {
    let Some(root) = vault.config.legal_hold_store.clone() else {
        return Err(Error::InvalidConfig("no legal hold store is set".into()));
    };
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&root)?;
    let root = root.canonicalize()?;
    if root.starts_with(&vault.path().canonicalize()?) {
        return Err(Error::InvalidConfig(
            "the legal hold store lies inside the vault; it would be erased with it".into(),
        ));
    }
    Ok(LegalHoldStore { root })
}

impl LegalHoldStore {
    /// The hold's directory: the vault id keeps two vaults of one install apart.
    pub(crate) fn hold_dir(&self, vault: &Vault, hold: &EntityId) -> PathBuf {
        self.root
            .join(bytes_to_hex_lower(vault.vault_id().as_bytes()))
            .join(hold.to_hex())
    }
}

/// One sealed capture file being written: `<capture>.clone.partial`,
/// renamed to `<capture>.clone` on completion.
pub(crate) struct HoldCloneFile {
    file: File,
    partial: PathBuf,
    target: PathBuf,
    dir: PathBuf,
    finished: bool,
}

impl HoldCloneFile {
    /// Creates the capture's partial file under `dir`, owner-only.
    pub(crate) fn create(dir: &Path, capture_hex: &str) -> Result<Self> {
        let partial = dir.join(format!("{capture_hex}.clone.partial"));
        let target = dir.join(format!("{capture_hex}.clone"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&partial)?;
        Ok(Self {
            file,
            partial,
            target,
            dir: dir.to_path_buf(),
            finished: false,
        })
    }

    /// The finished capture's path, after completion.
    pub(crate) fn path(&self) -> &Path {
        &self.target
    }
}

impl Write for HoldCloneFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl CaptureSink for HoldCloneFile {
    /// Syncs the file, renames it over `<capture>.clone`, and syncs the
    /// directory. A sealed capture is never silently replaced: a target
    /// already there fails the capture instead.
    fn complete(&mut self, _request_digest: &[u8; 32], _transcript: &[u8; 32]) -> Result<()> {
        self.file.sync_all()?;
        if self.target.exists() {
            return Err(
                io::Error::new(io::ErrorKind::AlreadyExists, "legal hold capture exists").into(),
            );
        }
        fs::rename(&self.partial, &self.target)?;
        crate::store::sync_dir(&self.dir)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for HoldCloneFile {
    /// A capture that never completed leaves no partial file.
    fn drop(&mut self) {
        if !self.finished {
            let _ = fs::remove_file(&self.partial);
        }
    }
}

/// Writes one sealed capture per scope kind in `targets` for `hold_id`:
/// `Records` for its record targets, then the gate-decision extents for its
/// gate-partition targets. Each capture streams through a collector in the
/// exact frame format a host receives, sealed to the hold's own key.
///
/// It runs INSIDE the caller's LMDB writer and reads through `txn`, the
/// writer's own view, so the hold row and its copies commit or roll back
/// together. It takes no custody guard: key retirement takes that guard's
/// write half and then the writer, so taking it inside a writer could
/// deadlock; inside the writer no retirement can unlink a key. Result bodies
/// take no whole-set pin either: the single writer excludes a concurrent
/// body release, and each body read pins its own digest before its file
/// opens.
pub(crate) fn write_hold_clone_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    hold_id: EntityId,
    targets: &[LegalHoldTarget],
) -> Result<Vec<HoldCloneCapture>> {
    let store = configured(vault)?;
    let vault_id = *vault.vault_id().as_bytes();
    let dir = store.hold_dir(vault, &hold_id);
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir)?;
    // The hold directory's own entry, durable with its parents.
    crate::store::sync_dir(&store.root)?;
    crate::store::sync_dir(&store.root.join(bytes_to_hex_lower(&vault_id)))?;
    let secret = hold_secret(vault, &vault_id, &hold_id, &dir)?;
    let public = secret.public_key();
    let mut captures = Vec::new();
    let mut written: Vec<PathBuf> = Vec::new();
    let outcome = (|| -> Result<()> {
        let mut record_ids: Vec<[u8; 16]> = targets
            .iter()
            .filter_map(|target| match target {
                LegalHoldTarget::Record(id) => Some(*id.as_bytes()),
                LegalHoldTarget::GatePartition(_) => None,
            })
            .collect();
        if !record_ids.is_empty() {
            record_ids.sort_unstable();
            record_ids.dedup();
            let scope = CaptureScope::Records(record_ids.clone());
            let (request, capture) = capture_request_for(vault, &hold_id, public, scope)?;
            let (capture, path) = write_capture_in(&dir, public, &request, capture, |collector| {
                let counts = capture_rows_in_txn(
                    collector,
                    vault,
                    txn,
                    &record_ids,
                    RowKind::Records,
                    || Ok(()),
                )?;
                Ok((counts, CaptureExtent::Records))
            })?;
            captures.push(capture);
            written.push(path);
        }
        let mut claim_partitions: Vec<[u8; 16]> = targets
            .iter()
            .filter_map(|target| match target {
                LegalHoldTarget::GatePartition(Some(claim)) => Some(*claim.as_bytes()),
                LegalHoldTarget::GatePartition(None) | LegalHoldTarget::Record(_) => None,
            })
            .collect();
        let claim_free = targets
            .iter()
            .any(|target| matches!(target, LegalHoldTarget::GatePartition(None)));
        if !claim_partitions.is_empty() {
            claim_partitions.sort_unstable();
            claim_partitions.dedup();
            let mut decision_ids = Vec::new();
            for claim in &claim_partitions {
                for record in vault.store.gate_decisions_for_claim_in_txn(txn, claim)? {
                    decision_ids.push(record.decision_id.as_bytes());
                }
            }
            decision_ids.sort_unstable();
            decision_ids.dedup();
            let scope = CaptureScope::GateDecisions(decision_ids);
            let (request, capture) = capture_request_for(vault, &hold_id, public, scope)?;
            let (capture, path) = write_capture_in(&dir, public, &request, capture, |collector| {
                stream_gate_decisions(vault, txn, &request, collector)
            })?;
            captures.push(capture);
            written.push(path);
        }
        if claim_free {
            let scope = CaptureScope::AllClaimFreeGateDecisions;
            let (request, capture) = capture_request_for(vault, &hold_id, public, scope)?;
            let (capture, path) = write_capture_in(&dir, public, &request, capture, |collector| {
                stream_gate_decisions(vault, txn, &request, collector)
            })?;
            captures.push(capture);
            written.push(path);
        }
        Ok(())
    })();
    if let Err(error) = outcome {
        for path in &written {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(captures)
}

/// Streams the gate decisions `request`'s scope selects, through the same
/// walk the host channel runs.
fn stream_gate_decisions(
    vault: &Vault,
    txn: &RoTxn<'_>,
    request: &CaptureRequest,
    collector: &mut Collector<'_, HoldCloneFile>,
) -> Result<(SummaryCounts, CaptureExtent)> {
    let mut stored_revision = [0; 32];
    let decisions = vault.store.for_each_gate_clone_component_in_txn(
        txn,
        matches!(&request.scope, CaptureScope::GateDecisions(_)),
        |decision| request.scope.includes(&decision.as_bytes()),
        || Ok(()),
        |decision, component, key, value| {
            let fingerprint = *blake3::hash(value).as_bytes();
            let revision = match component {
                GateCloneComponent::StoredPrimary => {
                    stored_revision = fingerprint;
                    fingerprint
                }
                GateCloneComponent::OpenedPrimary => stored_revision,
                _ => fingerprint,
            };
            collector.component(
                super::source_component(component),
                CaptureSource::GateDecision(decision.as_bytes()),
                component.label(),
                key,
                revision,
                value.len() as u64,
                fingerprint,
                &mut &value[..],
                || Ok(()),
            )
        },
    )?;
    if let CaptureScope::GateDecisions(ids) = &request.scope
        && decisions != ids.len() as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "legal capture selected decision unavailable",
        )
        .into());
    }
    Ok((
        SummaryCounts {
            decisions,
            ..SummaryCounts::default()
        },
        CaptureExtent::GateDecisions,
    ))
}

/// One capture request of `hold` over `scope`, sealed to the hold's key.
fn capture_request_for(
    vault: &Vault,
    hold: &EntityId,
    public: &HybridPublicKey,
    scope: CaptureScope,
) -> Result<(CaptureRequest, EntityId)> {
    let capture = vault.store.clock.entity_id()?;
    let request = CaptureRequest {
        order: *hold.as_bytes(),
        capture: *capture.as_bytes(),
        source_vault: *vault.vault_id().as_bytes(),
        generation: 0,
        ends_at: u64::MAX,
        scope,
        recipient: public.to_bytes(),
    };
    Ok((request, capture))
}

/// Writes one capture: its frames through a collector into its file, and its
/// fingerprint. The caller streams the capture's extent.
fn write_capture_in(
    dir: &Path,
    public: &HybridPublicKey,
    request: &CaptureRequest,
    capture: EntityId,
    stream: impl FnOnce(&mut Collector<'_, HoldCloneFile>) -> Result<(SummaryCounts, CaptureExtent)>,
) -> Result<(HoldCloneCapture, PathBuf)> {
    let mut file = HoldCloneFile::create(dir, &capture.to_hex())?;
    let mut collector = Collector::pinned(&mut file, public, request)?;
    let (counts, extent) = stream(&mut collector)?;
    let fingerprint = collector.finish_counted(counts, extent, || Ok(()))?;
    let path = file.path().to_path_buf();
    Ok((
        HoldCloneCapture {
            capture,
            fingerprint,
        },
        path,
    ))
}

/// The hold's secret: opened from `hold.key`, or minted and written once.
/// Only the 32-byte seed is stored; the pair rebuilds from it.
fn hold_secret(
    vault: &Vault,
    vault_id: &[u8; 32],
    hold: &EntityId,
    dir: &Path,
) -> Result<HybridSecretKey> {
    let store_key = legal_hold_store_key(vault)?;
    let path = dir.join("hold.key");
    match fs::read(&path) {
        Ok(bytes) => open_hold_secret(&store_key, vault_id, hold, &bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            mint_hold_secret(&store_key, vault_id, hold, dir, &path)
        }
        Err(error) => Err(error.into()),
    }
}

/// The install-level hold-store key, created on first use.
fn legal_hold_store_key(vault: &Vault) -> Result<Zeroizing<[u8; 32]>> {
    let keystore = vault.device_keystore().map_err(|_| {
        Error::Secret(SecretError::KeystoreUnavailable(
            "legal holds need this install's keystore",
        ))
    })?;
    let slot = KeystoreSlot {
        vault_id: *vault.vault_id().as_bytes(),
        install: [0; 16],
        kind: SlotKind::LegalHoldStore,
    };
    crate::world_keys::slot_seed(keystore.as_ref(), &slot)
}

/// Mints the hold's secret and writes `hold.key` once: create-new, synced,
/// directory synced. A key another writer just wrote is opened instead.
fn mint_hold_secret(
    store_key: &[u8; 32],
    vault_id: &[u8; 32],
    hold: &EntityId,
    dir: &Path,
    path: &Path,
) -> Result<HybridSecretKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    crate::key_material::os_fill(&mut seed[..])?;
    let secret = HybridSecretKey::from_seed(&seed, HOLD_SECRET_LABEL)
        .map_err(|_| io::Error::other("legal hold key expansion"))?;
    let sealed = seal_hold_seed(store_key, vault_id, hold, &seed)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            let outcome = (|| -> Result<()> {
                file.write_all(&sealed)?;
                file.sync_all()?;
                crate::store::sync_dir(dir)?;
                Ok(())
            })();
            if outcome.is_err() {
                let _ = fs::remove_file(path);
            }
            outcome?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return open_hold_secret(store_key, vault_id, hold, &fs::read(path)?);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(secret)
}

/// The vault id and the hold id a `hold.key` envelope binds.
fn hold_key_binding(vault_id: &[u8; 32], hold: &EntityId) -> [u8; 48] {
    let mut binding = [0u8; 48];
    binding[..32].copy_from_slice(vault_id);
    binding[32..].copy_from_slice(hold.as_bytes());
    binding
}

/// Seals the hold's seed under the hold-store key.
fn seal_hold_seed(
    store_key: &[u8; 32],
    vault_id: &[u8; 32],
    hold: &EntityId,
    seed: &[u8; 32],
) -> Result<Vec<u8>> {
    let binding = hold_key_binding(vault_id, hold);
    let kek = Kek::from_bytes_ref(store_key);
    let params = SealParams {
        suite: HOLD_KEY_SUITE,
        purpose: Purpose::SecretFile,
        epoch: HOLD_KEY_EPOCH,
        key_id: &binding,
        recipient: HOLD_KEY_RECIPIENT,
        vault_id,
    };
    let envelope = seal_with_aad(
        &params,
        SealKey::SymmetricKek(&kek),
        seed,
        &binding,
        &mut getrandom::SysRng,
    )
    .map_err(|_| io::Error::other("legal hold key seal"))?;
    Ok(envelope.to_bytes())
}

/// Opens `hold.key` under the hold-store key.
fn open_hold_secret(
    store_key: &[u8; 32],
    vault_id: &[u8; 32],
    hold: &EntityId,
    sealed: &[u8],
) -> Result<HybridSecretKey> {
    let binding = hold_key_binding(vault_id, hold);
    let kek = Kek::from_bytes_ref(store_key);
    let policy = OpenPolicy {
        purpose: Purpose::SecretFile,
        vault_id,
        recipient: HOLD_KEY_RECIPIENT,
        key_id: &binding,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[HOLD_KEY_SUITE],
        kem_suites: &[],
        min_epoch: HOLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let failed = || io::Error::new(io::ErrorKind::InvalidData, "legal hold key does not open");
    let envelope = Envelope::parse(sealed).map_err(|_| failed())?;
    let seed = envelope
        .open_with_aad(OpenKey::SymmetricKek(&kek), &policy, &binding)
        .map_err(|_| failed())?;
    let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| failed())?;
    let secret = HybridSecretKey::from_seed(&seed, HOLD_SECRET_LABEL).map_err(|_| failed())?;
    Ok(secret)
}

/// Removes the hold's directory with everything under it, ignoring every
/// failure: a failed write's cleanup. The hold id is fresh, so the
/// directory holds only this call's files.
pub(crate) fn remove_hold_dir_best_effort(vault: &Vault, hold: &EntityId) {
    let Ok(store) = configured(vault) else {
        return;
    };
    let _ = fs::remove_dir_all(store.hold_dir(vault, hold));
}

/// Removes the named captures' files, ignoring every failure: a failed
/// widen's cleanup. The hold's key stays.
pub(crate) fn remove_captures_best_effort(
    vault: &Vault,
    hold: &EntityId,
    captures: &[HoldCloneCapture],
) {
    let Ok(store) = configured(vault) else {
        return;
    };
    let dir = store.hold_dir(vault, hold);
    for capture in captures {
        let _ = fs::remove_file(dir.join(format!("{}.clone", capture.capture.to_hex())));
    }
}

/// Removes the hold's `.clone` files the committed row does not name,
/// ignoring every failure: a widen whose commit failed after its files were
/// written. The hold's key stays.
pub(crate) fn remove_unreferenced_captures_best_effort(vault: &Vault, hold: &EntityId) {
    let Ok(store) = configured(vault) else {
        return;
    };
    let dir = store.hold_dir(vault, hold);
    let Ok(txn) = vault.store.env.read_txn() else {
        return;
    };
    let Ok(Some(row)) = crate::store::legal_hold::hold_in_txn(&vault.store, &txn, hold) else {
        return;
    };
    let kept: Vec<[u8; 16]> = row
        .clone_captures
        .iter()
        .map(|capture| *capture.capture.as_bytes())
        .collect();
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = path.extension().is_some_and(|ext| ext == "clone")
            && path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| {
                    EntityId::from_hex(stem).is_ok_and(|id| !kept.contains(id.as_bytes()))
                });
        if stale {
            let _ = fs::remove_file(&path);
        }
    }
}
