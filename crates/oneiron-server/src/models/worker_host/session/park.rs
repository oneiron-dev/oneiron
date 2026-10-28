//! Parking (DESIGN-V2 §7 residency, V2-R3): an idle session's published
//! checkpoint exported from its worker, sealed into its vault's snapshot
//! store, and the session released from the device, so a later turn
//! restores it (`restore.rs`) instead of recomputing it.
//!
//! A session becomes a candidate when its commit publishes under a whole
//! dependency set. One sweep per process parks a candidate once it has gone
//! unused for [`PARK_IDLE_AFTER`], or at once when its device has less than
//! [`PARK_PRESSURE_HEADROOMS`] headrooms free. Nothing parks per token, and
//! one park runs at a time.
//!
//! A park's copy is host memory (the export's region, then the buffer read
//! from it): it runs only while that copy and [`SNAPSHOT_HEADROOM_BYTES`]
//! fit in the memory this process may still take, and memory no source
//! measures skips it (FIX 11220). Where the device ledger knows its room
//! the copy holds it there too, with the same headroom left; where it does
//! not, the worker's own answer decides. It exports the checkpoint it
//! claimed, checks the answer names that checkpoint and the region its
//! length, reads the region and drops it at once, rechecks the turn's
//! authority, the session's HEAD and the vault's admission in that order,
//! and seals and publishes the snapshot, the store reserving its disk
//! through the vault's ledger. Only then is the session retired, and its
//! device hold released once the worker has acknowledged the release.
//!
//! A budget crossing evicts or skips, never refuses a turn; a budget that is
//! off or zero purges the vault's kept snapshots (FIX 11214); a snapshot
//! that depends on a world whose sealed copies the owner keeps local is
//! never parked (PAD-FLIP #3914). Every skip is counted by its reason. Any
//! failure leaves the session serving as it was.
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use oneiron::inference_snapshot::retention::{SNAPSHOT_HEADROOM_BYTES, SnapshotBudget};
use oneiron::inference_snapshot::{
    SnapshotAdmission, SnapshotClass, SnapshotCompatibility, SnapshotManifest, SnapshotPublish,
};
use oneiron::llm::{
    CacheDigest, CacheIdentity, CanonicalCheckpointRef, ConditioningDigest, SNAPSHOT_SCHEMA,
    SessionBinding, SessionExport, SessionInvalidation, SessionKey, SessionOpStamp,
    SessionResidency, SessionTarget,
};
use oneiron::{EntityId, Vault};
use oneiron_contracts::limit_ask::available_memory_bytes;
use oneiron_driver::DeviceLedger;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use zeroize::Zeroizing;

use super::lifecycle::{self, Admitted, Counted, Skip};
use super::registry::{self, Basis, HostCopy, Phase, Place, Serves};
use super::{AuthorityVerdict, ReplyCommit, policy};
use crate::models::native_exl3::session_export;

/// How long a published session goes unused before a sweep parks it. A
/// Call: the owner sees it as the pause after which a conversation's next
/// turn restores its state instead of attaching to it on the device.
const PARK_IDLE_AFTER: Duration = Duration::from_secs(300);

/// How often the sweep looks while any candidate stands. A Call.
const PARK_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Pressure: a device with less than this many headrooms free past its
/// rows and holds parks its candidates at once, idle or not. A Call.
const PARK_PRESSURE_HEADROOMS: u64 = 2;

const MIB: u64 = 1024 * 1024;

/// Whether the sweep runs.
static SWEEPING: AtomicBool = AtomicBool::new(false);

/// [`SNAPSHOT_HEADROOM_BYTES`] in MiB, as the device ledger counts.
fn headroom_mib() -> u64 {
    SNAPSHOT_HEADROOM_BYTES / MIB
}

/// `bytes` in MiB, rounded up.
pub(super) fn mib(bytes: u64) -> u64 {
    bytes.div_ceil(MIB)
}

/// Whether a host copy of `bytes` fits in the memory this process may
/// still take with [`SNAPSHOT_HEADROOM_BYTES`] left; `None` when no source
/// measures that memory.
pub(super) fn host_room(bytes: u64) -> Option<bool> {
    let available = available_memory_bytes()?;
    Some(bytes.saturating_add(SNAPSHOT_HEADROOM_BYTES) <= available)
}

/// Whether the device room `ledger` knows leaves room for `bytes` past the
/// headroom: `true` when no ledger or no room is known, the worker's own
/// answer then deciding.
pub(super) fn device_room(ledger: Option<&DeviceLedger>, bytes: u64) -> bool {
    ledger
        .and_then(|ledger| ledger.room_mib(headroom_mib()))
        .is_none_or(|room| room >= mib(bytes))
}

/// A commit published a candidate: starts the sweep on this runtime unless
/// it runs.
pub(super) fn wake() {
    if SWEEPING.swap(true, Ordering::AcqRel) {
        return;
    }
    match Handle::try_current() {
        Ok(runtime) => {
            runtime.spawn(sweep());
        }
        Err(_) => SWEEPING.store(false, Ordering::Release),
    }
}

/// Every [`PARK_SWEEP_INTERVAL`], parks each candidate due in turn, until
/// none stands.
async fn sweep() {
    loop {
        tokio::time::sleep(PARK_SWEEP_INTERVAL).await;
        while let Some(candidate) = next_due() {
            park(candidate).await;
        }
        if !candidates_stand() {
            SWEEPING.store(false, Ordering::Release);
            // A commit that published between the look and the store found
            // the sweep running: look once more.
            if !candidates_stand() || SWEEPING.swap(true, Ordering::AcqRel) {
                return;
            }
        }
    }
}

/// A candidate claimed for its park: the session as it stood, and what its
/// checkpoint was admitted under.
struct Candidate {
    worker_id: String,
    place: Place,
    binding: SessionBinding,
    target: SessionTarget,
    generation: u64,
    checkpoint: CanonicalCheckpointRef,
    residency: SessionResidency,
    key: SessionKey,
    basis: Arc<Basis>,
}

/// Whether `worker_id`'s device is under pressure: less than
/// [`PARK_PRESSURE_HEADROOMS`] headrooms free. Unknown room is none.
fn pressed(worker_id: &str) -> bool {
    super::super::device_ledger(worker_id)
        .and_then(|ledger| ledger.room_mib(headroom_mib() * PARK_PRESSURE_HEADROOMS))
        == Some(0)
}

/// Whether any candidate stands on a worker that exports snapshots.
fn candidates_stand() -> bool {
    registry::lock().values().any(|worker| {
        matches!(worker.serves, Serves::Yes(ops) if ops.snapshot)
            && worker
                .sessions
                .values()
                .any(|session| matches!(session.phase, Phase::Candidate { .. }))
    })
}

/// The next candidate due, claimed as parking: idle long enough, or on a
/// device under pressure. A candidate with nothing to park goes back to
/// ready.
fn next_due() -> Option<Candidate> {
    let worker_ids: Vec<String> = registry::lock().keys().cloned().collect();
    let pressed: BTreeSet<String> = worker_ids.into_iter().filter(|id| pressed(id)).collect();
    let mut workers = registry::lock();
    for (worker_id, worker) in &mut *workers {
        if !matches!(worker.serves, Serves::Yes(ops) if ops.snapshot) {
            continue;
        }
        let place = worker.place.clone();
        for (binding, session) in &mut worker.sessions {
            let Phase::Candidate { since } = session.phase else {
                continue;
            };
            if since.elapsed() < PARK_IDLE_AFTER && !pressed.contains(worker_id) {
                continue;
            }
            let (Some(checkpoint), Some(basis)) =
                (session.published.clone(), session.basis.clone())
            else {
                session.phase = Phase::Ready;
                continue;
            };
            let candidate = Candidate {
                worker_id: worker_id.clone(),
                place,
                binding: *binding,
                target: session.target(),
                generation: session.generation,
                checkpoint,
                residency: session.residency,
                key: session.key.clone(),
                basis,
            };
            session.phase = Phase::Parking;
            return Some(candidate);
        }
    }
    None
}

/// Parks `candidate`, or counts why not; a session not parked goes back to
/// ready, and parks again only once its next commit publishes.
async fn park(candidate: Candidate) {
    if let Err(skipped) = attempt(&candidate).await {
        if let Some(skip) = skipped {
            lifecycle::count(Counted::Skipped(skip));
        }
        let mut workers = registry::lock();
        if let Some(session) =
            registry::current(&mut workers, &candidate.worker_id, &candidate.place)
                .and_then(|worker| worker.sessions.get_mut(&candidate.binding))
                .filter(|session| {
                    session.handle == candidate.target.handle && session.phase == Phase::Parking
                })
        {
            session.phase = Phase::Ready;
        }
    }
}

/// One park: `Err` with the reason it was skipped, or `None` when it failed
/// or a turn took the session back.
async fn attempt(candidate: &Candidate) -> Result<(), Option<Skip>> {
    let vault_ref = candidate.key.anchor.vault;
    let vault = lifecycle::vault(&vault_ref).ok_or(None)?;
    let Some(Admitted::Granted(admission)) = lifecycle::admission(&vault_ref) else {
        return Err(None);
    };
    let scope = &candidate.basis.scope;
    if scope.read_scope != candidate.key.anchor.read_scope || !scope.dependencies.precise {
        return Err(Some(Skip::Unsupported));
    }
    let budget = lifecycle::budget(&vault_ref);
    if budget.limit() == 0 {
        purge(&vault, budget).await;
        return Err(Some(Skip::Budget));
    }
    if kept_local(&vault, &scope.dependencies.worlds).await? {
        return Err(Some(Skip::KeptLocal));
    }
    // The size the worker measured, when it did: the export's region is
    // checked again once its length is known.
    let estimate = candidate.residency.unique_bytes;
    if estimate.is_some_and(|bytes| bytes > budget.limit()) {
        return Err(Some(Skip::Oversize));
    }
    room(estimate.unwrap_or(0))?;
    let ledger = super::super::device_ledger(&candidate.worker_id);
    if estimate.is_some_and(|bytes| !device_room(ledger.as_deref(), bytes)) {
        return Err(Some(Skip::NoRoom));
    }
    let holder = format!("snapshot-park-{}", policy::next_op_id());
    if let (Some(ledger), Some(bytes)) = (&ledger, estimate) {
        ledger.hold(&holder, mib(bytes));
    }
    let parked = seal(candidate, &vault, admission, budget).await;
    if parked.is_ok() {
        retire(candidate).await;
    }
    // The device hold goes only once the worker has answered the release.
    if let Some(ledger) = &ledger {
        ledger.release_hold(&holder);
    }
    parked
}

/// Whether a host copy of `bytes` may be taken now: `Err` with the reason
/// it may not.
fn room(bytes: u64) -> Result<(), Option<Skip>> {
    match host_room(bytes) {
        Some(true) => Ok(()),
        Some(false) => Err(Some(Skip::NoRoom)),
        None => Err(Some(Skip::UnknownRoom)),
    }
}

/// A budget that is off or zero: every kept snapshot of the vault not
/// pinned goes (FIX 11214).
async fn purge(vault: &Arc<Vault>, budget: SnapshotBudget) {
    let vault = Arc::clone(vault);
    let purged =
        tokio::task::spawn_blocking(move || vault.snapshot_ledger().enforce_budget(budget, 0, &[]))
            .await;
    if let Ok(Err(error)) = purged {
        tracing::warn!(kind = ?error.kind(), "a snapshot budget's purge failed; the next park retries");
    }
}

/// Whether `worlds` names a world whose sealed copies the owner keeps off
/// this host, as the vault's posture places it (a hosted vault's host is
/// not his). `Err(None)` when his settings do not read.
async fn kept_local(vault: &Arc<Vault>, worlds: &[EntityId]) -> Result<bool, Option<Skip>> {
    let reading = Arc::clone(vault);
    let kept = tokio::task::spawn_blocking(move || {
        reading.inference_snapshot_worlds_kept_local(reading.is_host_readable())
    })
    .await
    .map_err(|_| None)?
    .map_err(|_| None)?;
    Ok(worlds.iter().any(|world| kept.contains(world.as_bytes())))
}

/// Exports the candidate's checkpoint, checks and reads it, rechecks what
/// it was admitted under, and seals and publishes it. The region and the
/// buffer go as soon as they are read.
async fn seal(
    candidate: &Candidate,
    vault: &Arc<Vault>,
    admission: SnapshotAdmission,
    budget: SnapshotBudget,
) -> Result<(), Option<Skip>> {
    let vault_ref = candidate.key.anchor.vault;
    let body = SessionExport {
        target: candidate.target.clone(),
        stamp: SessionOpStamp {
            op_id: policy::next_op_id(),
            generation: candidate.generation,
        },
        checkpoint: candidate.checkpoint.clone(),
    };
    let place = &candidate.place;
    let (answer, region) = session_export(&place.socket, &place.epoch, &body, &place.worker)
        .await
        .map_err(|_| None)?;
    let region = HostCopy::hold(vault_ref, region);
    lifecycle::count(Counted::Park);
    let bytes = region.get().len();
    if answer.checkpoint != candidate.checkpoint || answer.snapshot_bytes != bytes {
        return Err(None);
    }
    if bytes > budget.limit() {
        return Err(Some(Skip::Oversize));
    }
    // Reading the region makes a second copy.
    room(bytes)?;
    if lifecycle::admission(&vault_ref) != Some(Admitted::Granted(admission)) {
        return Err(None);
    }
    let plaintext = region.get().read().map_err(|_| None)?;
    drop(region);
    let plaintext = HostCopy::hold(vault_ref, Zeroizing::new(plaintext));
    let compatibility =
        compatibility(&candidate.key, plaintext.get()).ok_or(Some(Skip::Unsupported))?;
    recheck(candidate).await?;
    if !claimed(candidate) || lifecycle::admission(&vault_ref) != Some(Admitted::Granted(admission))
    {
        return Err(None);
    }
    let publish = SnapshotPublish {
        manifest: manifest(candidate, compatibility),
        dependencies: candidate.basis.scope.dependencies.clone(),
        snapshot_sha256: answer.snapshot_sha256.0,
        class: SnapshotClass::Interactive,
        recompute_ms: None,
        authority_generation: candidate.basis.scope.revocation,
    };
    let sealing = Arc::clone(vault);
    let published = tokio::task::spawn_blocking(move || {
        let published =
            sealing.publish_inference_snapshot(&admission, budget, publish, plaintext.get());
        drop(plaintext);
        published
    })
    .await
    .map_err(|_| None)?;
    match published {
        Ok(Some(_)) => {
            lifecycle::count(Counted::Seal);
            Ok(())
        }
        // Nothing kept while the admission still holds: no room inside the
        // budget beside what is pinned.
        Ok(None) if vault.snapshot_admission_holds(&admission) => Err(Some(Skip::Budget)),
        Ok(None) => Err(None),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a model session's snapshot was not kept");
            Err(None)
        }
    }
}

/// The turn's authority, rechecked off the runtime: a rejection drops the
/// session, as a commit's would.
async fn recheck(candidate: &Candidate) -> Result<(), Option<Skip>> {
    let basis = Arc::clone(&candidate.basis);
    let verdict = tokio::task::spawn_blocking(move || {
        // The reply is named by its ids: its text is not kept.
        basis.authority.recheck(&ReplyCommit {
            head: basis.head,
            message: basis.message,
            text: String::new(),
        })
    })
    .await
    .unwrap_or(AuthorityVerdict::Rejects(
        SessionInvalidation::DisclosureOrScope,
    ));
    match verdict {
        AuthorityVerdict::Holds => Ok(()),
        AuthorityVerdict::Rejects(reason) => {
            registry::drop_session(
                &candidate.worker_id,
                &candidate.place.epoch,
                &candidate.binding,
                reason,
            );
            Err(None)
        }
    }
}

/// Whether the session is still the one claimed, parking, at the HEAD and
/// token digest of the checkpoint exported.
fn claimed(candidate: &Candidate) -> bool {
    let mut workers = registry::lock();
    registry::current(&mut workers, &candidate.worker_id, &candidate.place)
        .and_then(|worker| worker.sessions.get(&candidate.binding))
        .is_some_and(|session| {
            session.handle == candidate.target.handle
                && session.generation == candidate.generation
                && session.phase == Phase::Parking
                && session
                    .published
                    .as_ref()
                    .is_some_and(|published| published.same_point(&candidate.checkpoint))
        })
}

/// The parked session, retired once its snapshot is kept, and released:
/// this waits for the worker's acknowledgement. A turn that took it back
/// meanwhile keeps it.
async fn retire(candidate: &Candidate) {
    let retired = {
        let mut workers = registry::lock();
        registry::current(&mut workers, &candidate.worker_id, &candidate.place).and_then(|worker| {
            let parking = worker
                .sessions
                .get(&candidate.binding)
                .is_some_and(|session| {
                    session.handle == candidate.target.handle && session.phase == Phase::Parking
                });
            if parking {
                worker.retire(&candidate.binding)
            } else {
                None
            }
        })
    };
    if let Some((target, place)) = retired {
        registry::release(target, place, SessionInvalidation::Evicted).await;
    }
}

/// The manifest the seal binds: the session's key, the checkpoint exported,
/// and what it was computed with.
fn manifest(candidate: &Candidate, compatibility: SnapshotCompatibility) -> SnapshotManifest {
    let anchor = &candidate.key.anchor;
    let checkpoint = &candidate.checkpoint;
    SnapshotManifest {
        vault: anchor.vault,
        read_scope: anchor.read_scope,
        conversation: anchor.conversation,
        head: checkpoint.head,
        fold_epoch: anchor.fold_epoch,
        frontier_tokens: checkpoint.frontier_tokens,
        token_digest: checkpoint.digest,
        parent: checkpoint.parent,
        conditioning: candidate.key.conditioning,
        compatibility,
    }
}

/// The part of a snapshot's compatibility a turn names before any import:
/// the worker's identity less its epoch, and its execution mode, or where
/// the identity names none (a session worker's hello does not, the mode
/// being the call's) the digest of the call's conditioning, its template
/// arguments and tool definitions.
pub(super) fn identity_part(
    identity: &CacheIdentity,
    conditioning: &ConditioningDigest,
) -> SnapshotCompatibility {
    let mut compatibility = SnapshotCompatibility::from_identity(identity);
    if compatibility.execution_mode.is_none() {
        compatibility.execution_mode =
            cache_digest(b"oneiron.snapshot.execution_mode.v1\0", &conditioning.0);
    }
    compatibility
}

/// What the snapshot was computed with: [`identity_part`], then from the
/// snapshot's own header the KV layout and quantization, the state kind,
/// and the schema. The worker names no attention or position settings
/// apart: the digest of its whole snapshot compatibility, which fixes them
/// with the weights and the layout, stands for them. `None` when the
/// header does not read or a field is left unnamed.
fn compatibility(key: &SessionKey, snapshot: &[u8]) -> Option<SnapshotCompatibility> {
    let header = header(snapshot)?;
    let worker = header.get("compatibility")?;
    let mut compatibility = identity_part(&key.identity, &key.conditioning);
    compatibility.quant = json_digest(b"oneiron.snapshot.quant.v1\0", worker.get("kv")?);
    compatibility.attention = json_digest(b"oneiron.snapshot.attention.v1\0", worker);
    compatibility.state_schema = u32::try_from(SNAPSHOT_SCHEMA).ok();
    compatibility.state_kinds = Some(vec![worker.get("state")?.as_str()?.to_owned()]);
    compatibility.complete().then_some(compatibility)
}

/// A `snapshot_v1` snapshot's header: `OIRS`, the schema as a u32 and the
/// header's length as a u64, little-endian, then the header's canonical
/// JSON.
fn header(snapshot: &[u8]) -> Option<JsonValue> {
    let (magic, rest) = snapshot.split_first_chunk::<4>()?;
    let (schema, rest) = rest.split_first_chunk::<4>()?;
    let (length, rest) = rest.split_first_chunk::<8>()?;
    if magic != b"OIRS" || u64::from(u32::from_le_bytes(*schema)) != SNAPSHOT_SCHEMA {
        return None;
    }
    let length = usize::try_from(u64::from_le_bytes(*length)).ok()?;
    serde_json::from_slice(rest.get(..length)?).ok()
}

fn json_digest(domain: &[u8], value: &JsonValue) -> Option<CacheDigest> {
    cache_digest(domain, &serde_json::to_vec(value).ok()?)
}

/// The SHA-256 of `domain ‖ bytes`, as a cache digest.
fn cache_digest(domain: &[u8], bytes: &[u8]) -> Option<CacheDigest> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    let hex = hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
    CacheDigest::new(hex).ok()
}
