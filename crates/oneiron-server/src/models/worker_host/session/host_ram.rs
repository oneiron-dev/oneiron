//! Ephemeral authorized-plaintext snapshot bytes in host RAM (FIX 11292,
//! V2-R3): an additive mirror retained after a successful sealed-disk
//! publish, never a sealed-body cache.
//!
//! The tier holds plaintext [`HostCopy`] bytes only; sealed bodies live on
//! disk in the vault's snapshot store, which stays the durable path and the
//! cold fallback. Nothing here persists, and nothing here changes the worker
//! release logic: this map holds references, and dropping a reference never
//! frees an allocation another holder still loans.
//!
//! Accounting: each retained allocation is counted exactly once by its
//! existing [`HostCopy`], which charges its vault until it drops. The map
//! holds one [`Plaintext`] ([`Arc`]) per snapshot; a clone handed out is a
//! loan, never a duplicate payload. Eviction skips loans
//! (`Arc::strong_count() > 1`, an active host import): a loan cannot be
//! preempted, and removing a map reference while a loan stands leaves the
//! allocation counted until the loan drops, including in the existing
//! bounded lock receipt.
//!
//! Authority: the cached [`SnapshotRecord`] is eviction facts only (class,
//! reuse count, last use) and is never authorization. The caller re-resolves
//! the current disk candidate and its pin and runs the core custody/row
//! authorizer before serving a RAM hit; a hit whose row retired, whose key
//! retired, or whose admission moved is cold, exactly as a disk miss is.
//!
//! Admission: [`keep`] and [`get`] check the vault's current admission
//! against the admission they were called under while the map mutex is
//! held, and refuse on any mismatch. Invalidation ([`drop_vault`]) clears
//! the vault's map references through the same mutex after its admission
//! closed or its generation changed, so no insert lands late and no hit
//! serves past a close. Stale-admission references are pruned the same way
//! on every call; their loans, if any, stay counted until dropped.
//!
//! Retention: every call carries its own explicit byte limit; there is no
//! stored cap, no TTL, no timer, and no default. Victims leave in the
//! existing [`choose_victim`] order over [`SnapshotCandidate`] facts, and a
//! new insert that would exceed the cap beside pinned loans is refused, not
//! forced. Zero, oversize, and row/byte-mismatched candidates skip caching
//! only: the sealed path proceeds, and no turn is ever refused here. Under
//! headroom pressure the caller frees idle bytes across vaults through
//! [`evict_idle`] and retries once; expired admissions go first, loans never
//! count as freed.
//!
//! Lock order and caller contract: while the map mutex is held this module
//! takes the lifecycle vaults lock inside [`lifecycle::admission`], and
//! [`prune`] calls its limits closure. Call every function with no session
//! lock held, and pass a closure that reads already-resolved policy only;
//! nothing here awaits or touches the database or the filesystem. The
//! caller screens `fits_host(0)` before [`keep`], so a retained copy plus
//! the headroom still fits beside what the process holds.
//!
//! No GPU residency or hold is inferred from RAM retention.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::inference_snapshot::retention::{SnapshotCandidate, choose_victim};
use oneiron::inference_snapshot::{SnapshotAdmission, SnapshotId, SnapshotRecord};
use oneiron::llm::VaultRef;
use zeroize::Zeroizing;

use super::lifecycle::{self, Admitted};
use super::registry::HostCopy;

/// One retained plaintext allocation: the map's reference. Clones are
/// loans; the allocation drops only once the map reference and every loan
/// are gone, and stays counted by its [`HostCopy`] until then.
pub(super) type Plaintext = Arc<HostCopy<Zeroizing<Vec<u8>>>>;

/// One cached snapshot: what admission retained it, the eviction facts a
/// hit refreshes (never authorization), its retained bytes, and the map's
/// reference to the counted allocation.
struct Cached {
    admission: SnapshotAdmission,
    record: SnapshotRecord,
    bytes: u64,
    plaintext: Plaintext,
}

/// The tier: one map keyed by vault and catalog id.
static RAM: Mutex<BTreeMap<(VaultRef, SnapshotId), Cached>> = Mutex::new(BTreeMap::new());

fn lock() -> MutexGuard<'static, BTreeMap<(VaultRef, SnapshotId), Cached>> {
    RAM.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Unix milliseconds now: a clock read for eviction reuse facts, not a
/// policy constant. Zero when the clock does not read.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// The bytes `plaintext` actually holds, as its [`HostCopy`] counts them.
fn bytes_of(plaintext: &Plaintext) -> u64 {
    u64::try_from(plaintext.get().len()).unwrap_or(u64::MAX)
}

/// Drops every map reference of `vault` not retained under `current`: a
/// close (`None`) or a generation change clears the vault. Loans of dropped
/// references stay counted until they drop.
fn prune_stale(
    ram: &mut BTreeMap<(VaultRef, SnapshotId), Cached>,
    vault: &VaultRef,
    current: Option<Admitted>,
) {
    ram.retain(|(entry_vault, _), cached| {
        entry_vault != vault || Some(Admitted::Granted(cached.admission)) == current
    });
}

/// Drops every map reference of `vault`, loans included: invalidation, or a
/// limit of zero. Loans stay counted until they drop.
fn drop_locked(ram: &mut BTreeMap<(VaultRef, SnapshotId), Cached>, vault: &VaultRef) {
    ram.retain(|(entry_vault, _), _| entry_vault != vault);
}

/// The retained bytes of `vault` still reachable from the map, saturating.
fn vault_total(ram: &BTreeMap<(VaultRef, SnapshotId), Cached>, vault: &VaultRef) -> u64 {
    ram.iter()
        .filter(|((entry_vault, _), _)| entry_vault == vault)
        .fold(0_u64, |total, (_, cached)| {
            total.saturating_add(cached.bytes)
        })
}

/// The eviction facts of one cached row, as [`choose_victim`] orders them.
/// Callers pass unloaned rows only, so none is pinned.
fn candidate_of(cached: &Cached) -> SnapshotCandidate {
    SnapshotCandidate {
        id: cached.record.id,
        bytes: cached.bytes,
        reusable: cached.record.reusable(),
        class: cached.record.class,
        reuse_count: cached.record.reuse_count,
        last_used_ms: cached.record.last_used_ms,
        pinned: false,
    }
}

/// Evicts unloaned references of `vault` in [`choose_victim`] order until
/// `need` more bytes fit `limit`: false when only loans pin the room, which
/// are never preempted.
fn make_room(
    ram: &mut BTreeMap<(VaultRef, SnapshotId), Cached>,
    vault: &VaultRef,
    need: u64,
    limit: u64,
) -> bool {
    loop {
        if vault_total(ram, vault).saturating_add(need) <= limit {
            return true;
        }
        let keys: Vec<(VaultRef, SnapshotId)> = ram
            .iter()
            .filter(|((entry_vault, _), cached)| {
                entry_vault == vault && Arc::strong_count(&cached.plaintext) == 1
            })
            .map(|(key, _)| *key)
            .collect();
        if keys.is_empty() {
            return false;
        }
        let candidates: Vec<SnapshotCandidate> = keys
            .iter()
            .filter_map(|key| ram.get(key))
            .map(candidate_of)
            .collect();
        let Some(victim) = choose_victim(&candidates) else {
            return false;
        };
        ram.remove(&keys[victim]);
    }
}

/// Retains `plaintext` under `record`'s row while `vault` still admits under
/// `admission` and `limit` keeps it: true when cached. The caller screened
/// `fits_host(0)` first and published the sealed body already; this call
/// copies no bytes. A stale admission, a zero limit, a row of another vault,
/// a zero or oversize copy, a row/byte mismatch, or a cap only loans leave
/// no room in skips caching and answers false; the sealed path proceeds. A
/// row already retained is reused as it stands and answers true: publish
/// mints unique ids with immutable bytes, so the same id is never swapped.
pub(super) fn keep(
    vault: VaultRef,
    admission: SnapshotAdmission,
    record: SnapshotRecord,
    plaintext: Plaintext,
    limit: u64,
) -> bool {
    let bytes = bytes_of(&plaintext);
    let mut ram = lock();
    let current = lifecycle::admission(&vault);
    prune_stale(&mut ram, &vault, current);
    if current != Some(Admitted::Granted(admission)) {
        return false;
    }
    if limit == 0 {
        drop_locked(&mut ram, &vault);
        return false;
    }
    if record.manifest.vault != vault {
        return false;
    }
    if bytes == 0 || bytes > limit || record.plaintext_bytes != bytes {
        return false;
    }
    // The row is already retained: reuse it as it stands. Unique publish
    // ids with immutable bytes mean there is no republish to swap in, and
    // nothing is removed, so no loan ever stands outside the cap.
    if ram.contains_key(&(vault, record.id)) {
        return true;
    }
    if !make_room(&mut ram, &vault, bytes, limit) {
        return false;
    }
    ram.insert(
        (vault, record.id),
        Cached {
            admission,
            record,
            bytes,
            plaintext,
        },
    );
    true
}

/// Loans the plaintext retained under `id` while `vault` still admits under
/// `admission`: the caller authorizes the hit against the current disk
/// candidate and pin before import. A hit refreshes eviction reuse facts.
/// A stale admission, a zero limit, or no row answers `None`; a zero limit
/// also drops the vault's references.
pub(super) fn get(
    vault: VaultRef,
    admission: SnapshotAdmission,
    id: &SnapshotId,
    limit: u64,
) -> Option<Plaintext> {
    let mut ram = lock();
    let current = lifecycle::admission(&vault);
    prune_stale(&mut ram, &vault, current);
    if current != Some(Admitted::Granted(admission)) {
        return None;
    }
    if limit == 0 {
        drop_locked(&mut ram, &vault);
        return None;
    }
    let cached = ram.get_mut(&(vault, *id))?;
    cached.record.reuse_count = cached.record.reuse_count.saturating_add(1);
    cached.record.last_used_ms = now_ms();
    Some(Arc::clone(&cached.plaintext))
}

/// Drops every map reference of `vault`, loans included: a lock or an erase
/// calls it after the admission closed or the generation changed, through
/// the same mutex [`keep`] admits under, so no late insert survives it.
/// Loans stay counted until they drop.
pub(super) fn drop_vault(vault: &VaultRef) {
    drop_locked(&mut lock(), vault);
}

/// Brings every vault with references in step: stale admissions go, a zero
/// limit drops the vault, and unloaned references evict in
/// [`choose_victim`] order until the vault fits its limit. Loans pin the
/// room they hold; a vault left over its cap by loans alone keeps them
/// until they drop, and caches nothing new beside them. `limits` names each
/// vault's bytes (zero for off or zero); it reads already-resolved policy
/// only, since it runs under the map mutex.
pub(super) fn prune(limits: impl Fn(&VaultRef) -> u64) {
    let mut ram = lock();
    let mut vaults: Vec<VaultRef> = ram.keys().map(|(vault, _)| *vault).collect();
    vaults.sort();
    vaults.dedup();
    for vault in &vaults {
        let current = lifecycle::admission(vault);
        prune_stale(&mut ram, vault, current);
        let limit = limits(vault);
        if limit == 0 {
            drop_locked(&mut ram, vault);
        } else {
            let _ = make_room(&mut ram, vault, 0, limit);
        }
    }
}

/// [`prune_stale`], answering the bytes it actually freed: stale
/// references drop whether or not they are loaned, but only an unloaned
/// drop frees its allocation, so only those bytes count. Loans of dropped
/// references stay counted until they drop.
fn prune_stale_counted(
    ram: &mut BTreeMap<(VaultRef, SnapshotId), Cached>,
    vault: &VaultRef,
    current: Option<Admitted>,
) -> u64 {
    let mut freed = 0_u64;
    ram.retain(|(entry_vault, _), cached| {
        let stale = entry_vault == vault && Some(Admitted::Granted(cached.admission)) != current;
        if stale && Arc::strong_count(&cached.plaintext) == 1 {
            freed = freed.saturating_add(cached.bytes);
        }
        !stale
    });
    freed
}

/// Frees idle payload bytes across vaults for a park or restore the headroom
/// screen refused: expired admissions first, then unloaned references in
/// [`choose_victim`] order, until at least `need` bytes are actually dropped
/// or nothing unloaned is left. Answers the bytes actually freed: a dropped
/// loan counts nothing, since its allocation stays counted until its owner
/// drops it. The caller rereads available memory and retries once, so this
/// optional cache never starves the current op; `need` derives from the
/// existing headroom-plus-committed deficit, never from a threshold here.
/// Stale and dead-vault admissions prune over every vault with references,
/// not only one: a vault gone unattached or closed loses its refs here too.
pub(super) fn evict_idle(need: u64) -> u64 {
    let mut ram = lock();
    let mut vaults: Vec<VaultRef> = ram.keys().map(|(vault, _)| *vault).collect();
    vaults.sort();
    vaults.dedup();
    let mut freed = 0_u64;
    for vault in &vaults {
        let current = lifecycle::admission(vault);
        freed = freed.saturating_add(prune_stale_counted(&mut ram, vault, current));
    }
    while freed < need {
        // The map lock bars new loans, so an unloaned row stays unloaned
        // until its drop below actually frees it; a loan dropped meanwhile
        // only joins the next pass.
        let keys: Vec<(VaultRef, SnapshotId)> = ram
            .iter()
            .filter(|(_, cached)| Arc::strong_count(&cached.plaintext) == 1)
            .map(|(key, _)| *key)
            .collect();
        if keys.is_empty() {
            break;
        }
        let candidates: Vec<SnapshotCandidate> = keys
            .iter()
            .filter_map(|key| ram.get(key))
            .map(candidate_of)
            .collect();
        let Some(victim) = choose_victim(&candidates) else {
            break;
        };
        if let Some(dropped) = ram.remove(&keys[victim]) {
            freed = freed.saturating_add(dropped.bytes);
        }
    }
    freed
}

/// The tier as it stands: retained references, and their bytes saturating.
pub(super) fn usage() -> (u64, u64) {
    let ram = lock();
    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    for cached in ram.values() {
        entries = entries.saturating_add(1);
        bytes = bytes.saturating_add(cached.bytes);
    }
    (entries, bytes)
}
