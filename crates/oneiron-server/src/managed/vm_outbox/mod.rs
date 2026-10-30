//! A vault VM's outbox carrier (FIX 5235, FIX 5467): both ends of the one
//! persistent, bidirectional stream on vsock port 1030
//! ([`oneiron_vault_contract::vm_outbox`]).
//!
//! The guest end is `oneiron-vm-outbox` ([`run_vm_outbox`]), a root
//! companion `oneiron-vm-init` starts beside the engine. It lays out the
//! outbox on the vault disk (`/vault/outbox`), the only root writer of its
//! protected members, and carries each outbox kind between that disk and the
//! host. The host end is [`VmOutboxAttachment`], bound to one VM before it
//! starts, which maps each kind onto the host's existing outbox trees
//! ([`VmOutboxHostRoots`]): the node's own shippers read them there, VM
//! running or not, and no second shipper runs.
//!
//! Each end keeps a durable record per member ([`store`]): the version both
//! ends agreed on, the last transfer it took from the other end, and the one
//! it sent that the other end has not acked. A scan compares that record with
//! the member's file ([`scan`]); a session sends the difference and takes the
//! other end's ([`transfer`]). A receiver publishes into its own tree through
//! held directories, never through a link ([`local`]), syncs, records and only
//! then acks. A put whose bytes did not hash to its digest on arrival goes
//! again at its set's pacing, its file read again first, and a file damaged
//! at its source waits, typed, until it changes ([`source_check`]). A copy
//! of a member the carrier never agreed on, kept as the member's origin
//! retired the agreed version, waits, typed, for its owner to remove or keep
//! it ([`diverged`]); a copy he kept moves aside and is listed there until
//! he has it removed ([`aside`]). The guest's lifecycle endpoint reads these
//! states and takes his answers. Nothing
//! here carries a key or a credential, decides a business receipt, schedules
//! or prunes a backup, ages anything out, or caps a file, a set or an
//! outbox; a full disk or an absent host is a typed deferral that keeps the
//! work on both ends and never stops the vault.

mod aside;
mod diverged;
mod endpoint;
mod guest;
mod host;
mod link;
mod local;
mod scan;
mod source_check;
mod store;
mod transfer;

pub(crate) use self::diverged::{DIVERGED_ANSWER_ROUTE, DivergedOwnerAnswer, VmOutboxMemberStatus};
pub(crate) use self::endpoint::{answer_diverged, companion_member_statuses};
pub(super) use self::endpoint::{
    companion_revision, park_companion, register_backup, resume_companion,
};
pub use self::guest::run_vm_outbox;
pub use self::host::{VmOutboxAttachment, VmOutboxHostRoots, read_vm_backup_label};
pub(crate) use self::store::DivergedAnswer;

use self::local::Owner;
use self::store::{MemberRecord, Store};
use oneiron_vault_contract::vm_outbox::{VmOutboxKind, VmOutboxOutcome, VmOutboxSide};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long an idle end waits before it looks for changes again: the
/// cadence of a scan, not a deadline on anything.
const RESCAN_EVERY: Duration = Duration::from_secs(2);
/// The longest a set the other end deferred, or refused a put of as
/// `digest_mismatch`, waits before it is sent again: the pacing of a retry,
/// which doubles from [`RESCAN_EVERY`] up to this so a full disk is not
/// streamed to every two seconds. Nothing is dropped.
const PACE_CEILING: Duration = Duration::from_secs(128);
/// What a kind's wait on its carrier records is said under: no member's
/// name, as no part of one starts with a dot.
const RECORDS_SAID: &str = ".records";

/// One end's roots, kind by kind.
trait Roots: Send {
    /// The kind's root on this end, held; `None` when it has none now.
    fn open(&self, kind: VmOutboxKind) -> std::io::Result<Option<File>>;
    /// Whether this end carries `member` of `kind` (a guest carries only its
    /// registered backup label's).
    fn takes(&self, kind: VmOutboxKind, member: &str) -> bool;
    /// The backup label this end's engine registered, which the guest names
    /// to the host each turn; `None` before a registration, and on the host.
    fn backup_label(&self) -> Option<String> {
        None
    }
}

/// One end of the carrier: its side, whose tree it writes, its roots, its
/// records and its gate.
struct Carrier {
    side: VmOutboxSide,
    owner: Owner,
    roots: Box<dyn Roots>,
    store: Store,
    gate: Arc<Gate>,
    /// What was last said of each member's deferral or failure, so one
    /// repeated every turn is said once.
    said: HashMap<(VmOutboxKind, String), String>,
    /// When each set the other end deferred, or refused a put of as
    /// `digest_mismatch`, goes again, and its step.
    paced: HashMap<(VmOutboxKind, String), (Instant, Duration)>,
    /// The host's, for its session: why its backup sets wait, once a backup
    /// label the guest named was not kept; `None` until then, once one is
    /// kept again, and always on the guest.
    backup_wait: Option<VmOutboxOutcome>,
    /// Why each kind waits on this end's carrier records, once one of them
    /// did not write as its sets were scanned or readied, as a set the other
    /// end sent was applied, as the other end's answer to a set this end
    /// sent was taken, or as this end's copy was offered again. Kept across
    /// sessions until each kept record is written again and a scan of the
    /// kind writes its own.
    record_wait: HashMap<VmOutboxKind, RecordWait>,
    /// The guest's, shared with its lifecycle endpoint: its members'
    /// statuses and the owner's answers to its diverged copies; `None` on
    /// the host.
    board: Option<diverged::Board>,
    /// The host's answers to the guest's keeps and removals of its
    /// kept-aside copies, sent first in its next turn (FIX 11985, FIX 12010);
    /// empty on the guest.
    aside_answers: Vec<oneiron_vault_contract::vm_outbox::VmOutboxFrame>,
}

/// Why a kind waits on this end's carrier records, and when its next scan
/// tries them again, with that scan's step.
struct RecordWait {
    outcome: VmOutboxOutcome,
    at: Instant,
    step: Duration,
    /// Each member's record that did not write, by member: as a set the
    /// other end sent was applied, its file published, so only this record
    /// written whole proves it received (FIX 7891); or as the other end's
    /// durable or refused answer was taken, so only this record retires its
    /// transfer (FIX 7624); or as this end, the member's origin, cleared its
    /// refusal to offer its copy again, so only this record lets a scan
    /// offer it (FIX 6686). Held in memory only.
    retry: BTreeMap<String, MemberRecord>,
}

impl Carrier {
    fn new(
        side: VmOutboxSide,
        owner: Owner,
        roots: Box<dyn Roots>,
        store: Store,
        gate: Arc<Gate>,
    ) -> Self {
        Self {
            side,
            owner,
            roots,
            store,
            gate,
            said: HashMap::new(),
            paced: HashMap::new(),
            backup_wait: None,
            record_wait: HashMap::new(),
            board: None,
            aside_answers: Vec::new(),
        }
    }

    /// Says `what` of `kind`'s `member` once, until something else is said
    /// of it or it goes through.
    fn say(&mut self, kind: VmOutboxKind, member: &str, what: &str) {
        self.say_as("vm_outbox_deferred", kind, member, what);
    }

    /// [`Self::say`] under its own `reason` (FIX 11244).
    fn say_as(&mut self, reason: &'static str, kind: VmOutboxKind, member: &str, what: &str) {
        let key = (kind, member.to_owned());
        if self.said.get(&key).map(String::as_str) == Some(what) {
            return;
        }
        tracing::warn!(
            reason,
            side = ?self.side,
            %kind,
            member,
            what,
            "an outbox carrier change waits; the work is kept on both ends"
        );
        self.said.insert(key, what.to_owned());
    }

    /// Forgets what was said of `member`, which went through.
    fn settled(&mut self, kind: VmOutboxKind, member: &str) {
        self.said.remove(&(kind, member.to_owned()));
    }

    /// Paces `set` after a deferral: it goes again after one step, each step
    /// twice the last, up to [`PACE_CEILING`]. Returns when, and the step.
    fn pace(&mut self, kind: VmOutboxKind, set: &str) -> (Instant, Duration) {
        let key = (kind, set.to_owned());
        let step = self
            .paced
            .get(&key)
            .map_or(RESCAN_EVERY, |(_, step)| (*step * 2).min(PACE_CEILING));
        let paced = (Instant::now() + step, step);
        self.paced.insert(key, paced);
        paced
    }

    /// Why `kind` waits on this end's carrier records, if it does: none of
    /// its sets is sent, and the other end's are taken whole and answered
    /// with this.
    fn record_waits(&self, kind: VmOutboxKind) -> Option<&VmOutboxOutcome> {
        self.record_wait.get(&kind).map(|wait| &wait.outcome)
    }

    /// Makes `kind` wait on this end's carrier records, one of which `error`
    /// did not write, until a later scan of the kind writes them. That scan
    /// is due after one step, each twice the last, up to [`PACE_CEILING`];
    /// for a `set` whose records did not write as it was readied, when the
    /// set goes again, so the same turn readies it once more.
    fn records_failed(&mut self, kind: VmOutboxKind, set: Option<&str>, error: &std::io::Error) {
        let (at, step) = match set {
            Some(set) => self.pace(kind, set),
            None => {
                let step = self
                    .record_wait
                    .get(&kind)
                    .map_or(RESCAN_EVERY, |wait| (wait.step * 2).min(PACE_CEILING));
                (Instant::now() + step, step)
            }
        };
        let outcome = self.records_outcome(error);
        self.say(
            kind,
            RECORDS_SAID,
            &format!("its carrier records do not write: {error}"),
        );
        // The applied records still to write again stay with the wait.
        let retry = self
            .record_wait
            .remove(&kind)
            .map(|wait| wait.retry)
            .unwrap_or_default();
        self.record_wait.insert(
            kind,
            RecordWait {
                outcome,
                at,
                step,
                retry,
            },
        );
    }

    /// Makes `kind` wait on its carrier records, as [`Self::records_failed`],
    /// once `error` did not write `member`'s `record` as a set the other end
    /// sent was applied, as its answer to one this end sent was taken, or as
    /// this end's copy was offered again, and keeps `record` to write again
    /// before the wait can end.
    fn received_failed(
        &mut self,
        kind: VmOutboxKind,
        member: &str,
        record: MemberRecord,
        error: &std::io::Error,
    ) {
        self.records_failed(kind, None, error);
        if let Some(wait) = self.record_wait.get_mut(&kind) {
            wait.retry.insert(member.to_owned(), record);
        }
    }

    /// Forgets a record of `kind`'s `member` kept to write again, once a
    /// later one for it wrote.
    fn received_written(&mut self, kind: VmOutboxKind, member: &str) {
        if let Some(wait) = self.record_wait.get_mut(&kind) {
            wait.retry.remove(member);
        }
    }

    /// Writes again, whole, each record of `kind` kept by
    /// [`Self::received_failed`], under the gate as a local commit, so a
    /// parked end waits first: `true` once none is kept. One that does not
    /// write again stays kept with every one not yet tried, and the kind
    /// waits one more step. A draining end writes none.
    fn retry_received_records(&mut self, kind: VmOutboxKind) -> bool {
        let Some(wait) = self.record_wait.get_mut(&kind) else {
            return true;
        };
        if wait.retry.is_empty() {
            return true;
        }
        let gate = Arc::clone(&self.gate);
        let held = gate.hold();
        if *held == Mode::Draining {
            return false;
        }
        while let Some((member, record)) = wait.retry.pop_first() {
            if let Err(error) = self.store.rewrite(kind, &member, record.clone()) {
                wait.retry.insert(member, record);
                self.records_failed(kind, None, &error);
                return false;
            }
        }
        true
    }

    /// Ends `kind`'s wait on its carrier records, once a scan of it wrote
    /// them and no record left unwritten is kept to write again.
    fn records_written(&mut self, kind: VmOutboxKind) {
        if self
            .record_wait
            .get(&kind)
            .is_some_and(|wait| wait.retry.is_empty())
        {
            self.record_wait.remove(&kind);
            self.settled(kind, RECORDS_SAID);
        }
    }

    /// Offers this end's copy of `kind`'s `member` again, once the other end
    /// asked to retire a version of it this end does not hold. This end is
    /// its origin, so both ends converge on its copy, and a refusal of that
    /// copy the other end gave before no longer stands: the other end's
    /// copy is gone (FIX 6686). A record that does not write is kept to
    /// write again, as [`Self::received_failed`] keeps one, so the kind
    /// waits on its records until it is written and the next scan offers
    /// the copy.
    fn reoffer(&mut self, kind: VmOutboxKind, member: &str) {
        let mut record = self.store.get(kind, member);
        if record.refused.take().is_some()
            && let Err(error) = self.store.put(kind, member, record.clone())
        {
            self.received_failed(kind, member, record, &error);
        }
    }
}

/// Whether an end takes and makes changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Open,
    /// Before a snapshot: nothing new is published or recorded until resumed.
    Parked,
    /// At a stop or destroy: new transfers are denied, and nothing new goes.
    Draining,
}

/// An end's mode, held for each local commit, so parking or draining it
/// returns only once no commit is running and none starts.
#[derive(Debug, Default)]
pub(super) struct Gate {
    mode: Mutex<Mode>,
    changed: Condvar,
}

impl Gate {
    fn lock(&self) -> MutexGuard<'_, Mode> {
        self.mode.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The gate, held, once the end is not parked. A commit runs while it is
    /// held; the caller reads the mode to deny new work while draining.
    fn hold(&self) -> MutexGuard<'_, Mode> {
        let mut mode = self.lock();
        while *mode == Mode::Parked {
            mode = self
                .changed
                .wait(mode)
                .unwrap_or_else(PoisonError::into_inner);
        }
        mode
    }

    /// Waits while the end is parked; `false` once it drains.
    fn proceed(&self) -> bool {
        *self.hold() != Mode::Draining
    }

    /// Waits for one rescan period or a change of mode, then as
    /// [`Self::proceed`].
    fn idle(&self) -> bool {
        let mode = self.lock();
        let (mode, _) = self
            .changed
            .wait_timeout(mode, RESCAN_EVERY)
            .unwrap_or_else(PoisonError::into_inner);
        drop(mode);
        self.proceed()
    }

    fn set(&self, to: Mode) {
        *self.lock() = to;
        self.changed.notify_all();
    }

    /// Parks the end before a snapshot: an in-flight commit finishes first,
    /// and nothing new is published until [`Self::resume`].
    pub(super) fn park(&self) {
        self.set(Mode::Parked);
    }

    /// Opens the end again after a park, a restore or a new start.
    pub(super) fn resume(&self) {
        self.set(Mode::Open);
    }

    /// Denies new transfers and lets the in-flight commit finish.
    pub(super) fn drain(&self) {
        self.set(Mode::Draining);
    }
}
