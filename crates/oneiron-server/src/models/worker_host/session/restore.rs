//! Restore (DESIGN-V2 §7 residency, V2-R3): a kept snapshot imported into a
//! fresh session for an admitted turn, lazily, when the turn's binding has
//! no session on the qualified worker its lease reached. Qualifying a
//! worker makes nothing warm: only a restore that publishes does.
//!
//! The newest kept snapshot whose vault, read scope, conversation, HEAD,
//! fold epoch and conditioning are the turn's, and whose identity (its
//! epoch left out) is the worker's, is pinned against eviction from here
//! until the session's release is acknowledged or its incarnation reaped
//! (FIX 11221). The turn's own authority rechecks it, in order, before it
//! is decrypted and imported, and again before it is ready: the
//! credential, the read scope and its revocation, the actual HEAD and fold
//! epoch, and every source it depends on. The import stages on a session
//! with a new handle, binding and generation; only after that second
//! recheck is its checkpoint published and the session made ready, at once
//! under the registry's lock and the turn's admission.
//!
//! Any failure drops the session and the turn runs cold, recomputing from
//! source: a lost snapshot is a cache miss, never a failed call or an error
//! the user sees. A snapshot that failed its recheck or that the worker
//! cannot rebuild is retired. A snapshot a sliding window cut between page
//! boundaries carries its state at the boundary below its frontier: its
//! first attach falls there and the worker replays the suffix, counted as
//! a replay. Linear-attention state is exact.
use std::sync::{Arc, PoisonError, Weak};

use oneiron::Vault;
use oneiron::inference_snapshot::{SnapshotAdmission, SnapshotCompatibility, SnapshotRecord};
use oneiron::llm::{
    CacheDigest, CanonicalCheckpointRef, ManifestDigest, MessageStamp, SessionCheckpoint,
    SessionCheckpointed, SessionCreate, SessionCreated, SessionImport, SessionInvalidation,
    SessionKey, SessionOp, SessionOpStamp, SessionResidency, SessionTarget, SnapshotDigest,
    SnapshotMiss,
};
use zeroize::Zeroizing;

use super::lifecycle::{self, Admitted, Counted};
use super::park::{SNAPSHOT_MIN_FRONTIER_TOKENS, device_room, host_room, identity_part, mib};
use super::registry::{self, HostCopy, Phase, Place, Session, send};
use super::{AuthorityVerdict, CheckpointAuthority, RestoreClaim, TURNS, policy};
use crate::models::native_exl3::{OpFault, SnapshotRegion, session_import};

/// A restored session, ready: what the turn forks from.
pub(super) struct Restored {
    pub(super) target: SessionTarget,
    pub(super) generation: u64,
    pub(super) checkpoint: CanonicalCheckpointRef,
}

/// Why a restore went cold, and what it leaves.
struct Cold {
    /// The snapshot failed its recheck or cannot be rebuilt: it is retired.
    retire: bool,
}

const COLD: Cold = Cold { retire: false };
const RETIRE: Cold = Cold { retire: true };

/// What one restore works with.
struct Restore<'a> {
    worker_id: &'a str,
    place: &'a Place,
    key: &'a SessionKey,
    path: &'a [MessageStamp],
    vault: Arc<Vault>,
    authority: Arc<dyn CheckpointAuthority>,
    admission: SnapshotAdmission,
    record: SnapshotRecord,
}

/// The session for `key` on `place`, restored from a kept snapshot under
/// the authority the turn `turn` names, for a turn whose canonical path is
/// `path` and whose vault admitted it as `admitted`. `None` when there is
/// none to restore, or it went cold: the caller creates one.
pub(super) async fn restore(
    worker_id: &str,
    place: &Place,
    key: &SessionKey,
    turn: &ManifestDigest,
    path: &[MessageStamp],
    admitted: Admitted,
) -> Option<Restored> {
    let Admitted::Granted(admission) = admitted else {
        return None;
    };
    let vault = lifecycle::vault(&key.anchor.vault)?;
    let authority = turn_authority(turn)?;
    let record = candidate(&vault, key).await?;
    vault.snapshot_ledger().pin(record.id);
    let restore = Restore {
        worker_id,
        place,
        key,
        path,
        vault,
        authority,
        admission,
        record,
    };
    match restore.run().await {
        Ok(restored) => Some(restored),
        Err((cold, leased)) => {
            lifecycle::count(Counted::RestoreCold);
            restore.went_cold(&cold, leased);
            None
        }
    }
}

/// The authority the turn `turn` names was admitted under, while the turn
/// holds it.
fn turn_authority(turn: &ManifestDigest) -> Option<Arc<dyn CheckpointAuthority>> {
    TURNS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(turn)
        .and_then(Weak::upgrade)
}

/// The newest kept snapshot of `vault` the turn keyed by `key` may restore.
async fn candidate(vault: &Arc<Vault>, key: &SessionKey) -> Option<SnapshotRecord> {
    let reading = Arc::clone(vault);
    let records = tokio::task::spawn_blocking(move || reading.inference_snapshot_records())
        .await
        .ok()?
        .ok()?;
    let wanted = identity_part(&key.identity, &key.conditioning);
    records
        .into_iter()
        .filter(|record| {
            record.manifest.frontier_tokens >= SNAPSHOT_MIN_FRONTIER_TOKENS
                && matches(record, key, &wanted)
        })
        .max_by_key(|record| record.created_ms)
}

/// Whether `record` holds the turn's canonical path as `key` keys it: the
/// same vault, read scope, conversation, HEAD, fold epoch and conditioning,
/// and the identity `wanted` names, field by field, each named. The
/// worker checks the rest of what it was computed with exactly on import.
fn matches(record: &SnapshotRecord, key: &SessionKey, wanted: &SnapshotCompatibility) -> bool {
    let manifest = &record.manifest;
    let kept = &manifest.compatibility;
    let same =
        |kept: &Option<CacheDigest>, now: &Option<CacheDigest>| kept.is_some() && kept == now;
    manifest.vault == key.anchor.vault
        && manifest.read_scope == key.anchor.read_scope
        && manifest.conversation == key.anchor.conversation
        && manifest.head == key.anchor.head
        && manifest.fold_epoch == key.anchor.fold_epoch
        && manifest.conditioning == key.conditioning
        && same(&kept.model, &wanted.model)
        && same(&kept.tokenizer, &wanted.tokenizer)
        && same(&kept.template, &wanted.template)
        && same(&kept.execution_mode, &wanted.execution_mode)
        && same(&kept.cache_mode, &wanted.cache_mode)
        && same(&kept.runtime, &wanted.runtime)
}

impl Restore<'_> {
    /// The checkpoint the snapshot holds, as its manifest names it.
    fn checkpoint(&self) -> CanonicalCheckpointRef {
        let manifest = &self.record.manifest;
        CanonicalCheckpointRef {
            digest: manifest.token_digest,
            head: manifest.head,
            frontier_tokens: manifest.frontier_tokens,
            parent: manifest.parent,
        }
    }

    /// Whether the turn's vault still admits under the admission it ran
    /// under.
    fn admits(&self) -> bool {
        lifecycle::admission(&self.key.anchor.vault) == Some(Admitted::Granted(self.admission))
    }

    /// The restore, in order. `Err` with whether the session it registered
    /// holds the snapshot's pin now. Its host copy (the plaintext, then the
    /// region made of it) runs only while it fits beside the headroom, as a
    /// park's does; the device room is honoured where the ledger knows it,
    /// and elsewhere the worker's own answer decides (`snapshot_busy` is
    /// cold).
    async fn run(&self) -> Result<Restored, (Cold, bool)> {
        self.recheck().await.map_err(|cold| (cold, false))?;
        let bytes = self.record.plaintext_bytes;
        let ledger = super::super::device_ledger(self.worker_id);
        if host_room(bytes) != Some(true) || !device_room(ledger.as_deref(), bytes) {
            return Err((COLD, false));
        }
        let holder = format!("snapshot-restore-{}", policy::next_op_id());
        if let Some(ledger) = &ledger {
            ledger.hold(&holder, mib(bytes));
        }
        let restored = self.import().await;
        if let Some(ledger) = &ledger {
            ledger.release_hold(&holder);
        }
        restored
    }

    /// The turn's authority over the snapshot, off the runtime. A rejection
    /// retires it.
    async fn recheck(&self) -> Result<(), Cold> {
        let authority = Arc::clone(&self.authority);
        let manifest = self.record.manifest.clone();
        let dependencies = self.record.dependencies.clone();
        let revocation = self.record.pins.authority_generation;
        let verdict = tokio::task::spawn_blocking(move || {
            authority.recheck_restore(&RestoreClaim {
                read_scope: manifest.read_scope,
                revocation,
                head: manifest.head,
                fold_epoch: manifest.fold_epoch,
                dependencies: &dependencies,
            })
        })
        .await
        .unwrap_or(AuthorityVerdict::Rejects(
            SessionInvalidation::DisclosureOrScope,
        ));
        match verdict {
            AuthorityVerdict::Holds if self.admits() => Ok(()),
            AuthorityVerdict::Holds => Err(COLD),
            AuthorityVerdict::Rejects(_) => Err(RETIRE),
        }
    }

    /// Decrypts the snapshot, imports it into a fresh session, rechecks it
    /// and publishes it ready.
    async fn import(&self) -> Result<Restored, (Cold, bool)> {
        let plaintext = self.open().await.ok_or((COLD, false))?;
        let created = self.create().await.ok_or((COLD, false))?;
        let target = SessionTarget {
            handle: created.handle,
            binding: self.key.binding(),
        };
        // From here the session holds the pin: its release drops it.
        let region = SnapshotRegion::from_bytes(plaintext.get()).map_err(|_| (COLD, true))?;
        drop(plaintext);
        let region = HostCopy::hold(self.key.anchor.vault, region);
        let body = SessionImport {
            target: target.clone(),
            stamp: SessionOpStamp {
                op_id: policy::next_op_id(),
                generation: created.generation,
            },
            checkpoint: self.checkpoint(),
            snapshot_bytes: self.record.plaintext_bytes,
            snapshot_sha256: SnapshotDigest(self.record.snapshot_sha256),
        };
        let place = self.place;
        let imported = session_import(
            &place.socket,
            &place.epoch,
            &body,
            region.get(),
            &place.worker,
        )
        .await;
        drop(region);
        let imported = imported.map_err(|fault| match fault {
            OpFault::Refused(code)
                if SnapshotMiss::from_code(&code) == Some(SnapshotMiss::Incompatible) =>
            {
                (RETIRE, true)
            }
            OpFault::Refused(_) | OpFault::Cut => (COLD, true),
        })?;
        // The ordered recheck again, before anything is ready.
        self.recheck().await.map_err(|cold| (cold, true))?;
        let publish = SessionCheckpoint {
            target: target.clone(),
            stamp: SessionOpStamp {
                op_id: policy::next_op_id(),
                generation: created.generation,
            },
            staged: imported.staged.digest,
            publish: true,
        };
        let published: SessionCheckpointed = send(place, SessionOp::Checkpoint, &publish, None)
            .await
            .map_err(|_| (COLD, true))?;
        if !published.ready || published.checkpoint.as_ref() != Some(&imported.staged) {
            return Err((COLD, true));
        }
        self.ready(target, published).ok_or((COLD, true))
    }

    /// The snapshot's plaintext, opened under the turn's admission: a body
    /// that does not open retires its row as it is read.
    async fn open(&self) -> Option<HostCopy<Zeroizing<Vec<u8>>>> {
        let vault = Arc::clone(&self.vault);
        let admission = self.admission;
        let id = self.record.id;
        let opened = tokio::task::spawn_blocking(move || {
            vault
                .read_inference_snapshot(&admission, &id)
                .map(|opened| opened.map(|(_, plaintext)| plaintext))
        })
        .await
        .ok()?
        .ok()??;
        lifecycle::count(Counted::Open);
        Some(HostCopy::hold(self.key.anchor.vault, opened))
    }

    /// A fresh session for the turn's key on this incarnation, registered
    /// as restoring and holding the snapshot's pin while the vault admits
    /// under the turn's admission; otherwise its handle is released.
    async fn create(&self) -> Option<SessionCreated> {
        let body = SessionCreate {
            binding: self.key.binding(),
            op_id: policy::next_op_id(),
        };
        let created: SessionCreated = send(self.place, SessionOp::Create, &body, None)
            .await
            .ok()?;
        let session = Session {
            key: self.key.clone(),
            handle: created.handle,
            generation: created.generation,
            published: None,
            residency: SessionResidency::default(),
            pending: None,
            stale: None,
            path: Vec::new(),
            phase: Phase::Restoring,
            basis: None,
            lease: Some(self.record.id),
            restored: None,
        };
        let refused = {
            let mut workers = registry::lock();
            let worker = registry::current(&mut workers, self.worker_id, self.place)?;
            if self.admits() {
                worker.sessions.insert(self.key.binding(), session);
                None
            } else {
                Some(worker.owe(self.key.anchor.vault, session.target(), session.residency))
            }
        };
        if let Some((target, at)) = refused {
            registry::release_later(target, at, SessionInvalidation::Evicted);
            return None;
        }
        Some(created)
    }

    /// Makes the restored session ready, at once under the registry's lock:
    /// only while the vault still admits under the turn's admission and the
    /// session is still the one this restore registered.
    fn ready(&self, target: SessionTarget, published: SessionCheckpointed) -> Option<Restored> {
        let checkpoint = published.checkpoint?;
        let mut workers = registry::lock();
        if !self.admits() {
            return None;
        }
        let session = registry::current(&mut workers, self.worker_id, self.place)?
            .sessions
            .get_mut(&target.binding)
            .filter(|session| {
                session.handle == target.handle && session.phase == Phase::Restoring
            })?;
        session.published = Some(checkpoint.clone());
        session.generation = published.generation;
        session.residency = published.residency;
        session.path = self.path.to_vec();
        session.phase = Phase::Ready;
        session.restored = Some(checkpoint.frontier_tokens);
        lifecycle::count(Counted::Import);
        Some(Restored {
            target,
            generation: published.generation,
            checkpoint,
        })
    }

    /// After a cold restore: the session it registered dropped, whose
    /// release drops the pin, or else the pin dropped here; and the snapshot
    /// retired when it failed its recheck or cannot be rebuilt.
    fn went_cold(&self, cold: &Cold, leased: bool) {
        let id = self.record.id;
        if leased {
            registry::drop_session(
                self.worker_id,
                &self.place.epoch,
                &self.key.binding(),
                SessionInvalidation::Evicted,
            );
        } else {
            self.vault.snapshot_ledger().unpin(&id);
        }
        if cold.retire {
            // On a task of its own: the cold turn does not wait for it.
            let vault = Arc::clone(&self.vault);
            tokio::task::spawn_blocking(move || {
                if let Err(error) = vault.retire_inference_snapshot(&id) {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a kept model snapshot that went cold was not retired; housekeeping retries"
                    );
                }
            });
        }
    }
}
