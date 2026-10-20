//! The relay locker delete this engine executes (FIX 6826, Engine 10-21).
//!
//! A hosted relay room keeps this vault's backup ciphertext in its locker's
//! objects directory, which the supervisor names to the engine
//! (`relay_locker_bind`). The engine opens it itself, as a directory and
//! never through a link, and holds it open; a rebind replaces it. A relay
//! delete (`relay_delete_execute`) then runs here, never in the relay:
//!
//! - outside the vault's writer, on a blocking thread, the object is opened
//!   in that directory, never through a link, required to be a plain file,
//!   and its bytes hashed against the BLAKE3 digest the delete names;
//! - inside the vault's backup-hold writer exclusion (L04's
//!   [`VaultRelayHoldGuard`], over this vault's own [`oneiron::Vault`]), a
//!   standing legal hold defers it; otherwise the delete is admitted, the
//!   object renamed to a claim name of its own (`.deleting-<object>-<request>`),
//!   the claimed file checked to be the one hashed, unlinked, and the
//!   directory synced. A newer upload that took the name in between is put
//!   back, never deleted.
//!
//! Admission is the one step into that destructive section, Pending to
//! Entered, decided in the job under the writer. It must happen within
//! [`RELAY_DELETE_ADMISSION_MS`] of the request reaching dispatch; past it a
//! delete not yet admitted is expired and answers `admission_timeout`, and
//! an admitted one finishes its unlink and sync however long they take. Jobs
//! run one at a time, so timeouts never pile up writers, and a stop waits for
//! each one started.
//!
//! When the supervisor binds a directory, a claimed file a stopped job left
//! behind goes back to its object name, or is unlinked when a newer upload
//! holds the name; the relay's kept intent then asks again. The relay's
//! listing and reads never show a dot name.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, Once, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use oneiron_vault_contract::relay_delete::{
    RELAY_DELETE_ADMISSION_MS, RelayDeleteIoKind, RelayDeleteStage, RelayDeleteState,
    RelayDeleteUnknown, RelayLockerRefusal, valid_locker_object,
};
use rand_core::{OsRng, RngCore};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags, Stat};
use rustix::io::Errno;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use crate::managed::{
    RelayDeleteDeferral, RelayDeleteHoldError, RelayDeleteHoldGuard, RelayDeleteHoldOutcome,
    RelayDeleteTarget,
};
use crate::owner::backup::VaultRelayHoldGuard;

/// How long a delete has to be admitted, from dispatch.
const ADMISSION: Duration = Duration::from_millis(RELAY_DELETE_ADMISSION_MS);

/// The name a claimed object takes, before its object and request ids.
const CLAIM_PREFIX: &str = ".deleting-";

/// What the unlink step hands the hold guard when it deletes nothing: the
/// answer it recorded says why.
const NOT_DELETED: &str = "the relay delete deleted nothing";

const GUARD_UNAVAILABLE: RelayDeleteState = RelayDeleteState::Unknown {
    reason: RelayDeleteUnknown::GuardUnavailable,
};

/// One vault's relay locker deletes: this boot's instance, the bound objects
/// directory, the jobs and the recheck counter.
pub(super) struct RelayDeleteExecutor {
    /// This boot: 16 random bytes as 32 lowercase hex, fresh each start.
    instance: String,
    /// The objects directory the supervisor bound, held open.
    binding: Mutex<Option<Arc<OwnedFd>>>,
    /// Taken by each job and each bind, one at a time.
    serial: Arc<tokio::sync::Mutex<()>>,
    /// Every job started, kept until it ends.
    jobs: Mutex<Jobs>,
    /// The counter `relay_delete_rechecks` follows: it moves with the vault's
    /// hold rechecks and once per bind.
    rechecks: watch::Sender<u64>,
    /// The vault's own hold guard, made on first use.
    guard: OnceLock<VaultRelayHoldGuard>,
    /// Whether [`Self::rechecks`] follows the guard yet.
    following: Once,
}

/// The jobs a [`RelayDeleteExecutor`] started.
#[derive(Default)]
struct Jobs {
    /// Set on stop: no job starts after.
    stopped: bool,
    running: Vec<JoinHandle<()>>,
}

impl Default for RelayDeleteExecutor {
    fn default() -> Self {
        let mut instance = [0u8; 16];
        OsRng.fill_bytes(&mut instance);
        Self {
            instance: oneiron_vault_contract::hex(&instance),
            binding: Mutex::new(None),
            serial: Arc::default(),
            jobs: Mutex::default(),
            rechecks: watch::channel(0).0,
            guard: OnceLock::new(),
            following: Once::new(),
        }
    }
}

/// One delete, as a job runs it.
pub(super) struct RelayDeleteJob {
    /// What the hold guard checks: this vault, the object and its digest.
    pub(super) target: RelayDeleteTarget,
    /// The request's id, which names the claim.
    pub(super) request_id: String,
}

/// A delete's admission, decided once under its lock.
struct Admission {
    deadline: Instant,
    phase: Mutex<Phase>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Not admitted yet.
    Pending,
    /// In the destructive section, which it finishes.
    Entered,
    /// Past its deadline unadmitted: it never runs.
    Expired,
}

impl Admission {
    fn phase(&self) -> MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Admits the delete while its deadline has not passed, else expires
    /// it; `true` when admitted.
    fn enter(&self) -> bool {
        let mut phase = self.phase();
        if *phase == Phase::Pending {
            *phase = if Instant::now() < self.deadline {
                Phase::Entered
            } else {
                Phase::Expired
            };
        }
        *phase == Phase::Entered
    }

    /// Expires the delete once its deadline passed unadmitted; `true` when
    /// it is expired.
    fn expire_if_due(&self) -> bool {
        let mut phase = self.phase();
        if *phase == Phase::Pending && Instant::now() >= self.deadline {
            *phase = Phase::Expired;
        }
        *phase == Phase::Expired
    }
}

/// What the hash found at the object's name.
enum Candidate {
    /// The named ciphertext, in the file `Stat` identifies.
    Present(Stat),
    /// Nothing.
    Absent,
}

impl RelayDeleteExecutor {
    /// This boot's instance, as `Ping` reports it.
    pub(super) fn instance(&self) -> &str {
        &self.instance
    }

    fn jobs(&self) -> MutexGuard<'_, Jobs> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn binding(&self) -> MutexGuard<'_, Option<Arc<OwnedFd>>> {
        self.binding.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The hold guard over `vault`'s own holds, made once. Its source holds
    /// the vault weakly: a vault that closed reads as unknown.
    fn guard(&self, vault: &Arc<oneiron::Vault>) -> &VaultRelayHoldGuard {
        self.guard.get_or_init(|| {
            let source = Arc::downgrade(vault);
            VaultRelayHoldGuard::new(
                vault.vault_key_vault_id(),
                Arc::new(move || source.upgrade()),
            )
        })
    }

    /// Starts [`Self::rechecks`] following the guard's counter, once. Runs
    /// inside a Tokio runtime.
    fn follow(&self, vault: &Arc<oneiron::Vault>) {
        let guard = self.guard(vault);
        self.following.call_once(|| {
            let mut held = guard.subscribe_rechecks();
            let rechecks = self.rechecks.clone();
            tokio::spawn(async move {
                while held.changed().await.is_ok() {
                    recheck(&rechecks);
                }
            });
        });
    }

    /// Runs `job` on `vault` and answers what became of it: admitted within
    /// the deadline from `dispatched`, or `admission_timeout`. `admission`,
    /// the vault's reap admission, is held until the job ends, past any
    /// answer. A stopping executor answers `not_ready` and starts nothing.
    pub(super) async fn execute(
        self: &Arc<Self>,
        vault: &Arc<oneiron::Vault>,
        job: RelayDeleteJob,
        dispatched: Instant,
        admission: impl Send + 'static,
    ) -> RelayDeleteState {
        self.guard(vault);
        let ticket = Arc::new(Admission {
            deadline: dispatched + ADMISSION,
            phase: Mutex::new(Phase::Pending),
        });
        let (answer, mut answered) = oneshot::channel();
        {
            let mut jobs = self.jobs();
            if jobs.stopped {
                return RelayDeleteState::Unknown {
                    reason: RelayDeleteUnknown::NotReady,
                };
            }
            let started =
                tokio::spawn(Arc::clone(self).run_job(Arc::clone(&ticket), job, admission, answer));
            jobs.running.retain(|running| !running.is_finished());
            jobs.running.push(started);
        }
        tokio::select! {
            state = &mut answered => state.unwrap_or(GUARD_UNAVAILABLE),
            () = tokio::time::sleep_until(ticket.deadline.into()) => {
                if ticket.expire_if_due() {
                    RelayDeleteState::Unknown {
                        reason: RelayDeleteUnknown::AdmissionTimeout,
                    }
                } else {
                    answered.await.unwrap_or(GUARD_UNAVAILABLE)
                }
            }
        }
    }

    /// One job: waits its turn, then hashes and deletes on a blocking thread
    /// holding its turn and `admission`, unless it expired while it waited.
    async fn run_job(
        self: Arc<Self>,
        ticket: Arc<Admission>,
        job: RelayDeleteJob,
        admission: impl Send + 'static,
        answer: oneshot::Sender<RelayDeleteState>,
    ) {
        let serial = Arc::clone(&self.serial).lock_owned().await;
        if ticket.expire_if_due() {
            let _ = answer.send(RelayDeleteState::Unknown {
                reason: RelayDeleteUnknown::AdmissionTimeout,
            });
            return;
        }
        let state = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            let _serial = serial;
            self.run(&job, &ticket)
        })
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(
                panicked = error.is_panic(),
                reason = RelayDeleteUnknown::GuardUnavailable.as_str(),
                "a relay delete job stopped without an answer"
            );
            GUARD_UNAVAILABLE
        });
        let _ = answer.send(state);
    }

    /// The job's blocking part: the hash outside the writer, then the hold
    /// check and, when admitted, the claim, unlink and sync inside it.
    fn run(&self, job: &RelayDeleteJob, ticket: &Admission) -> RelayDeleteState {
        let Some(dir) = self.binding().clone() else {
            return RelayDeleteState::Unknown {
                reason: RelayDeleteUnknown::NotBound,
            };
        };
        let Some(guard) = self.guard.get() else {
            return GUARD_UNAVAILABLE;
        };
        let candidate = match inspect(&dir, &job.target) {
            Ok(candidate) => candidate,
            Err(state) => return state,
        };
        let mut finished = None;
        let mut unlink = || {
            let state = if ticket.enter() {
                destroy(&dir, job, &candidate)
            } else {
                RelayDeleteState::Unknown {
                    reason: RelayDeleteUnknown::AdmissionTimeout,
                }
            };
            finished = Some(state);
            if state.settled() {
                Ok(())
            } else {
                Err(io::Error::other(NOT_DELETED))
            }
        };
        match guard.delete_if_released(&job.target, &mut unlink) {
            Ok(RelayDeleteHoldOutcome::Deleted) | Err(RelayDeleteHoldError::StorageIo(_)) => {
                finished.unwrap_or(GUARD_UNAVAILABLE)
            }
            Ok(RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::HeldUntilRelease)) => {
                RelayDeleteState::Held
            }
            Ok(RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::HoldStateUnknown)) => {
                RelayDeleteState::Unknown {
                    reason: RelayDeleteUnknown::Unresolved,
                }
            }
            Err(RelayDeleteHoldError::GuardUnavailable) => GUARD_UNAVAILABLE,
        }
    }

    /// Binds `objects`, the room's objects directory the supervisor names,
    /// in place of any before it, once no job runs, and puts back what a
    /// stopped job left claimed there; the recheck counter moves, so a
    /// deferred delete asks again. One that does not open leaves no
    /// directory bound.
    pub(super) async fn bind(
        self: &Arc<Self>,
        vault: &Arc<oneiron::Vault>,
        objects: std::path::PathBuf,
    ) -> Result<(), RelayLockerRefusal> {
        self.follow(vault);
        if self.jobs().stopped {
            return Err(RelayLockerRefusal::NotReady);
        }
        let serial = Arc::clone(&self.serial).lock_owned().await;
        let executor = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _serial = serial;
            executor.open(&objects)
        })
        .await
        .unwrap_or(Err(RelayLockerRefusal::OpenFailed))?;
        recheck(&self.rechecks);
        Ok(())
    }

    /// Opens `objects` as a directory, never through a link, recovers its
    /// claims and binds it; unbinds on a failure.
    fn open(&self, objects: &Path) -> Result<(), RelayLockerRefusal> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match rustix::fs::open(objects, flags, Mode::empty()) {
            Ok(dir) => {
                recover(&dir);
                *self.binding() = Some(Arc::new(dir));
                Ok(())
            }
            Err(errno) => {
                *self.binding() = None;
                tracing::warn!(
                    kind = ?io::Error::from(errno).kind(),
                    reason = RelayLockerRefusal::OpenFailed.as_str(),
                    "the relay locker directory did not open; relay deletes stay deferred"
                );
                Err(RelayLockerRefusal::OpenFailed)
            }
        }
    }

    /// The recheck counter now and whether it is past `after`, at once for
    /// a `pinned` boot of `None`; for this boot, once it moves past `after`
    /// or `wait_ms` ends unmoved. Runs inside a Tokio runtime.
    pub(super) async fn rechecks(
        &self,
        vault: &Arc<oneiron::Vault>,
        pinned: Option<&str>,
        after: u64,
        wait_ms: u32,
    ) -> Result<(u64, bool), RelayDeleteUnknown> {
        self.follow(vault);
        if self.jobs().stopped {
            return Err(RelayDeleteUnknown::NotReady);
        }
        let mut counter = self.rechecks.subscribe();
        let current = *counter.borrow_and_update();
        let Some(pinned) = pinned else {
            return Ok((current, current != after));
        };
        if pinned != self.instance {
            return Err(RelayDeleteUnknown::InstanceMismatch);
        }
        if current != after {
            return Ok((current, true));
        }
        let wait = Duration::from_millis(u64::from(wait_ms));
        match tokio::time::timeout(wait, counter.changed()).await {
            Ok(Ok(())) => {
                let moved = *counter.borrow_and_update();
                Ok((moved, moved != after))
            }
            Ok(Err(_)) => Err(RelayDeleteUnknown::GuardUnavailable),
            Err(_) => Ok((current, false)),
        }
    }

    /// Waits for every job started to end, on stop: none is cancelled, and
    /// none starts after.
    pub(super) async fn stopped(&self) {
        let running = {
            let mut jobs = self.jobs();
            jobs.stopped = true;
            std::mem::take(&mut jobs.running)
        };
        for job in running {
            let _ = job.await;
        }
    }
}

/// Moves a recheck counter.
fn recheck(rechecks: &watch::Sender<u64>) {
    rechecks.send_modify(|counter| *counter = counter.wrapping_add(1));
}

/// A `storage_io` answer for `errno` at `stage`.
fn storage(stage: RelayDeleteStage, errno: Errno) -> RelayDeleteState {
    RelayDeleteState::StorageIo {
        stage,
        kind: RelayDeleteIoKind::of(io::Error::from(errno).kind()),
    }
}

/// Opens the target's object in `dir`, never through a link and never
/// waiting on a pipe, requires a plain file and hashes it against the
/// target's digest, outside the writer.
fn inspect(dir: &OwnedFd, target: &RelayDeleteTarget) -> Result<Candidate, RelayDeleteState> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let leaf = match rustix::fs::openat(dir, target.object_id.as_str(), flags, Mode::empty()) {
        Ok(leaf) => leaf,
        Err(Errno::NOENT) => return Ok(Candidate::Absent),
        Err(Errno::LOOP) => {
            return Err(RelayDeleteState::Unknown {
                reason: RelayDeleteUnknown::InvalidTarget,
            });
        }
        Err(errno) => return Err(storage(RelayDeleteStage::Hash, errno)),
    };
    let stat = rustix::fs::fstat(&leaf).map_err(|errno| storage(RelayDeleteStage::Stat, errno))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(RelayDeleteState::Unknown {
            reason: RelayDeleteUnknown::InvalidTarget,
        });
    }
    let mut hasher = blake3::Hasher::new();
    io::copy(&mut File::from(leaf), &mut hasher).map_err(|error| RelayDeleteState::StorageIo {
        stage: RelayDeleteStage::Hash,
        kind: RelayDeleteIoKind::of(error.kind()),
    })?;
    if *hasher.finalize().as_bytes() != target.ciphertext_blake3 {
        return Err(RelayDeleteState::Unknown {
            reason: RelayDeleteUnknown::TargetChanged,
        });
    }
    Ok(Candidate::Present(stat))
}

/// The destructive section, admitted and under the writer. A present
/// candidate is claimed by rename, checked to be the file hashed, unlinked,
/// and the directory synced; a claim that is another file goes back. An
/// absent one, or a name found empty at the claim, is confirmed absent with
/// the directory synced.
fn destroy(dir: &OwnedFd, job: &RelayDeleteJob, candidate: &Candidate) -> RelayDeleteState {
    let object = job.target.object_id.as_str();
    let Candidate::Present(hashed) = candidate else {
        return match rustix::fs::statat(dir, object, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => synced(dir, RelayDeleteState::Absent),
            Ok(_) => RelayDeleteState::Unknown {
                reason: RelayDeleteUnknown::TargetChanged,
            },
            Err(errno) => storage(RelayDeleteStage::Stat, errno),
        };
    };
    let claim = format!("{CLAIM_PREFIX}{object}-{}", job.request_id);
    match rustix::fs::renameat(dir, object, dir, claim.as_str()) {
        Ok(()) => {}
        Err(Errno::NOENT) => return synced(dir, RelayDeleteState::Absent),
        Err(errno) => return storage(RelayDeleteStage::Unlink, errno),
    }
    let claimed = match rustix::fs::statat(dir, claim.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(claimed) => claimed,
        Err(errno) => {
            put_back(dir, &claim, object);
            return storage(RelayDeleteStage::Stat, errno);
        }
    };
    if claimed.st_dev != hashed.st_dev || claimed.st_ino != hashed.st_ino {
        put_back(dir, &claim, object);
        return RelayDeleteState::Unknown {
            reason: RelayDeleteUnknown::TargetChanged,
        };
    }
    if let Err(errno) = rustix::fs::unlinkat(dir, claim.as_str(), AtFlags::empty()) {
        put_back(dir, &claim, object);
        return storage(RelayDeleteStage::Unlink, errno);
    }
    synced(dir, RelayDeleteState::Deleted)
}

/// `state` once `dir` is synced, else the sync's failure.
fn synced(dir: &OwnedFd, state: RelayDeleteState) -> RelayDeleteState {
    match rustix::fs::fsync(dir) {
        Ok(()) => state,
        Err(errno) => storage(RelayDeleteStage::Sync, errno),
    }
}

/// Puts the claimed file `claim` back at `object`, then syncs `dir`. When a
/// newer upload holds the name, the claimed file is superseded and unlinked.
/// One that does neither stays claimed, for the next bind to put back.
fn put_back(dir: &OwnedFd, claim: &str, object: &str) {
    let restored = match rustix::fs::renameat_with(dir, claim, dir, object, RenameFlags::NOREPLACE)
    {
        Err(Errno::EXIST) => rustix::fs::unlinkat(dir, claim, AtFlags::empty()),
        restored => restored,
    };
    if let Err(errno) = restored.and_then(|()| rustix::fs::fsync(dir)) {
        tracing::warn!(
            kind = ?io::Error::from(errno).kind(),
            "a claimed relay locker object did not go back; the next locker bind puts it back"
        );
    }
}

/// Puts back every claimed file a stopped job left in `dir`. A claim name
/// that does not parse stays as it is, logged, and nothing is guessed.
fn recover(dir: &OwnedFd) {
    let entries = match rustix::fs::Dir::read_from(dir) {
        Ok(entries) => entries,
        Err(errno) => {
            tracing::warn!(
                kind = ?io::Error::from(errno).kind(),
                "the relay locker directory did not list; its claimed objects stay"
            );
            return;
        }
    };
    let claims: Vec<Option<String>> = entries
        .map_while(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_bytes()
                .starts_with(CLAIM_PREFIX.as_bytes())
        })
        .map(|entry| entry.file_name().to_str().ok().map(str::to_owned))
        .collect();
    for claim in &claims {
        match claim
            .as_deref()
            .and_then(|claim| Some((claim, claimed_object(claim)?)))
        {
            Some((claim, object)) => put_back(dir, claim, object),
            None => tracing::warn!("a relay locker claim name did not parse; it stays as it is"),
        }
    }
}

/// The object a claim name `.deleting-<object>-<request>` names, split at
/// its last `-`: neither an object (64 lowercase hex or `manifest`) nor a
/// request id (32 lowercase hex) holds one, so a name parses one way or not
/// at all.
fn claimed_object(name: &str) -> Option<&str> {
    let (object, request) = name.strip_prefix(CLAIM_PREFIX)?.rsplit_once('-')?;
    let request_id = request.len() == 32
        && request
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    (request_id && valid_locker_object(object)).then_some(object)
}
