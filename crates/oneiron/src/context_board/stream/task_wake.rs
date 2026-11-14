//! Restart-safe TASK wakes (census L2-38; ARCH-0067 `#stream-narrowed-built`).
//!
//! A failed TASK owes its owner a WAKE, and a queued consult owes one to the
//! actor it addresses. The board publisher routes that WAKE to the live
//! connections that may read the TASK ([`BoardStreamRegistry::publish_task_state`]).
//! Before this module the queue it landed in was the only record: an actor with
//! no live connection got nothing, and a restart or a reattach emptied every
//! queue.
//!
//! Now the publisher also stages each wake the TASK owes, in the commit it
//! reads ([`Vault::stage_task_wakes`]): a presence row per (TASK, kind,
//! recipient) holding the occurrence's envelope id, and nothing of the TASK.
//! A TASK that no longer owes the wake (its failure acknowledged or retried,
//! its consult answered or readdressed) loses the row at its next pass. When
//! a connection attaches, or binds its first reader, the host reads the staged
//! rows again with [`PendingTaskWake::read_all`], re-reads each TASK, admits
//! each connection under its own read of the TASK, and hands the live ones to
//! [`BoardStreamRegistry::publish_task_wakes`]. That offers each wake once per
//! connection, under the envelope id of the TASK's current committed state.
//! An offer records the failed attempt heads it covered, and the live route
//! and this pass both skip a connection already offered the occurrence they
//! carry, so no connection hears one occurrence twice, whichever path offered
//! it first. A later failure of the same TASK adds a head, so it is a new
//! occurrence to every connection, also to one that heard the earlier one.
//! As with room wakes, a wake that stays live is offered again after a
//! restart or a reattach, and the host inbox drops an occurrence it has
//! already acknowledged.
//!
//! The rows are node-local runtime state: a restore never takes them from an
//! image, and sync never carries them. The TASK stays the durable, synced
//! mailbox. Boundary: the publisher stages after the TASK's commit, so a
//! process that dies between that commit and the publisher's pass, or a
//! publisher that lags behind the announcements, still loses that one
//! occurrence until the TASK's next write, as before.

use std::collections::{BTreeMap, BTreeSet};

use super::events::{BoardEvent, RouteObservation, SubscriptionScope};
use super::frames::StreamConnectionId;
use super::provenance::VerifiedOwnTaskEvent;
use super::publish::CommittedTaskBoardState;
use super::registry::BoardStreamRegistry;
use crate::error::Error;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, Vault};

/// Staged TASK wakes. Key: id16(TASK), the kind's tag byte, id16(recipient).
/// Value: the envelope id the wake was staged under (UTF-8).
const STAGED: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::CONTEXT_BOARD_TASK_WAKE);

/// The bytes of one staged row's key: two ids and a tag.
const STAGED_KEY_LEN: usize = 16 + 1 + 16;

/// Which wake a committed TASK owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaskWakeKind {
    /// A failed TASK's wake to its owner.
    Failed,
    /// A queued consult's wake to the actor it addresses.
    Arrived,
}

impl TaskWakeKind {
    /// The kind's word in an envelope id, `<task id>:<word>:<revision>`
    /// (ARCH-0067 `#wake-envelope-id`).
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Arrived => "arrived",
        }
    }

    /// The subscription a connection hears this kind under.
    #[must_use]
    pub const fn scope(self) -> SubscriptionScope {
        match self {
            Self::Failed => SubscriptionScope::MyTasks,
            Self::Arrived => SubscriptionScope::ConsultsToMe,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Failed => b'f',
            Self::Arrived => b'a',
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            b'f' => Some(Self::Failed),
            b'a' => Some(Self::Arrived),
            _ => None,
        }
    }
}

/// One wake a committed TASK owes now, and to whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct OwedTaskWake {
    pub(super) kind: TaskWakeKind,
    pub(super) recipient: EntityId,
}

/// One staged TASK wake as stored: its TASK, kind and recipient, and the
/// envelope id it was staged under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedTaskWake {
    task: EntityId,
    kind: TaskWakeKind,
    recipient: EntityId,
    event_ref: String,
}

impl StagedTaskWake {
    #[must_use]
    pub fn task(&self) -> EntityId {
        self.task
    }

    #[must_use]
    pub fn kind(&self) -> TaskWakeKind {
        self.kind
    }

    #[must_use]
    pub fn recipient(&self) -> EntityId {
        self.recipient
    }

    fn key(&self) -> Vec<u8> {
        staged_key(self.task, self.kind, self.recipient)
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let invalid = || Error::CorruptedIndex("staged board TASK wake");
        if key.len() != STAGED_KEY_LEN {
            return Err(invalid());
        }
        let id = |bytes: &[u8]| -> Result<EntityId> {
            let bytes: [u8; 16] = bytes.try_into().map_err(|_| invalid())?;
            EntityId::from_bytes(bytes).map_err(|_| invalid())
        };
        Ok(Self {
            task: id(&key[..16])?,
            kind: TaskWakeKind::from_tag(key[16]).ok_or_else(invalid)?,
            recipient: id(&key[17..])?,
            event_ref: String::from_utf8(value.to_vec()).map_err(|_| invalid())?,
        })
    }
}

fn staged_key(task: EntityId, kind: TaskWakeKind, recipient: EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(STAGED_KEY_LEN);
    key.extend_from_slice(task.as_bytes());
    key.push(kind.tag());
    key.extend_from_slice(recipient.as_bytes());
    key
}

/// One staged TASK wake that is still live: its TASK, read again now, still
/// owes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTaskWake {
    state: CommittedTaskBoardState,
    kind: TaskWakeKind,
    recipient: EntityId,
}

/// What one read of the staged TASK wakes found: the live wakes to offer, and
/// the staged rows no longer live, which the host settles unsent.
#[derive(Debug, Default)]
pub struct TaskWakeRead {
    pub pending: Vec<PendingTaskWake>,
    pub spent: Vec<StagedTaskWake>,
}

impl PendingTaskWake {
    /// Every staged TASK wake, each TASK read again now
    /// ([`CommittedTaskBoardState::read`]). A row its TASK still owes is
    /// pending; any other row is spent. A TASK that does not read is logged
    /// and its rows are left staged for the next pass.
    pub fn read_all(vault: &Vault) -> Result<TaskWakeRead> {
        let mut by_task: BTreeMap<EntityId, Vec<StagedTaskWake>> = BTreeMap::new();
        for staged in vault.staged_task_wakes()? {
            by_task.entry(staged.task).or_default().push(staged);
        }
        let mut read = TaskWakeRead::default();
        for (task, rows) in by_task {
            let state = match CommittedTaskBoardState::read(vault, task) {
                Ok(state) => state,
                Err(error) => {
                    tracing::warn!(
                        task = %task.to_hex(),
                        kind = ?error.kind(),
                        "a staged board TASK wake's TASK did not read; left staged"
                    );
                    continue;
                }
            };
            for row in rows {
                match &state {
                    Some(state) if state.owes(row.kind, row.recipient) => {
                        read.pending.push(Self {
                            state: state.clone(),
                            kind: row.kind,
                            recipient: row.recipient,
                        });
                    }
                    _ => read.spent.push(row),
                }
            }
        }
        Ok(read)
    }

    /// The TASK this wake names.
    #[must_use]
    pub fn task(&self) -> EntityId {
        self.state.task()
    }

    #[must_use]
    pub fn kind(&self) -> TaskWakeKind {
        self.kind
    }

    /// The actor this wake wakes.
    #[must_use]
    pub fn recipient(&self) -> EntityId {
        self.recipient
    }
}

impl Vault {
    /// Stages the wakes `task` owes now and drops the staged ones it no
    /// longer owes. `state` is the TASK's committed board read; `None` when
    /// the board no longer shows the TASK, which owes nothing. A TASK whose
    /// staged rows already match opens no write.
    pub fn stage_task_wakes(
        &self,
        task: EntityId,
        state: Option<&CommittedTaskBoardState>,
    ) -> Result<()> {
        let owed: BTreeMap<Vec<u8>, Vec<u8>> = match state {
            Some(state) => state
                .owed_wakes()
                .iter()
                .map(|owed| {
                    (
                        staged_key(task, owed.kind, owed.recipient),
                        state.occurrence_ref(owed.kind.word()).into_bytes(),
                    )
                })
                .collect(),
            None => BTreeMap::new(),
        };
        let staged: BTreeMap<Vec<u8>, Vec<u8>> = {
            let txn = self.store.env.read_txn()?;
            STAGED
                .scan_from(&self.store, &txn, task.as_bytes())?
                .into_iter()
                .collect()
        };
        if owed == staged {
            return Ok(());
        }
        self.with_write_txn(|txn| {
            for key in STAGED.scan_keys(&self.store, txn, task.as_bytes())? {
                if !owed.contains_key(&key) {
                    STAGED.delete(&self.store, txn, &key)?;
                }
            }
            for (key, event_ref) in &owed {
                STAGED.put(&self.store, txn, key, event_ref)?;
            }
            Ok(())
        })
    }

    /// Every staged TASK wake, in TASK order.
    pub fn staged_task_wakes(&self) -> Result<Vec<StagedTaskWake>> {
        let txn = self.store.env.read_txn()?;
        STAGED
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(key, value)| StagedTaskWake::decode(&key, &value))
            .collect()
    }

    /// Deletes the staged rows `spent` names, each only while it still holds
    /// the envelope id it was read with: a row the publisher staged again
    /// meanwhile, for a new occurrence, stays.
    pub fn settle_task_wakes(&self, spent: &[StagedTaskWake]) -> Result<()> {
        if spent.is_empty() {
            return Ok(());
        }
        self.with_write_txn(|txn| {
            for row in spent {
                let key = row.key();
                if STAGED.get(&self.store, txn, &key)?.as_deref() == Some(row.event_ref.as_bytes())
                {
                    STAGED.delete(&self.store, txn, &key)?;
                }
            }
            Ok(())
        })
    }
}

/// One TASK wake's offers are kept under its TASK, kind and recipient, hex.
type OfferKey = (String, TaskWakeKind, String);

/// What one connection was offered of one TASK wake.
#[derive(Debug, Default)]
struct Offered {
    /// The occurrence its latest offer named: the envelope id a staged row of
    /// that occurrence holds (`StagedTaskWake::event_ref`).
    occurrence: String,
    /// The failed attempt heads its offers covered
    /// ([`CommittedTaskBoardState::wake_heads`]).
    heads: BTreeSet<String>,
}

/// The connections each TASK wake was offered to, by TASK, kind and recipient.
#[derive(Debug, Default)]
pub(super) struct PublishedTaskWakes {
    offered: BTreeMap<OfferKey, BTreeMap<StreamConnectionId, Offered>>,
}

impl PublishedTaskWakes {
    /// Forgets what was offered to `connection` once its queue is gone, so a
    /// connection attached again under the same id is offered each live wake
    /// anew.
    pub(super) fn forget(&mut self, connection: &StreamConnectionId) {
        self.offered.retain(|_, offered| {
            offered.remove(connection);
            !offered.is_empty()
        });
    }

    /// Whether `connection` was already offered the occurrence `heads` names:
    /// an offer of this wake covered every one of those failed attempt heads.
    /// A failed TASK wakes its owner again for each new failed head, so an
    /// offer of an earlier failure does not cover a later one. A consult's
    /// wake names no head: any offer of it while it is owed covers it.
    fn heard(&self, key: &OfferKey, connection: &StreamConnectionId, heads: &[String]) -> bool {
        self.offered
            .get(key)
            .and_then(|offered| offered.get(connection))
            .is_some_and(|offer| heads.iter().all(|head| offer.heads.contains(head)))
    }

    /// Records that each of `connections` was offered `occurrence`, whose
    /// failed attempt heads are `heads`.
    fn record(
        &mut self,
        key: OfferKey,
        connections: impl IntoIterator<Item = StreamConnectionId>,
        occurrence: &str,
        heads: &[String],
    ) {
        let offered = self.offered.entry(key).or_default();
        for connection in connections {
            let offer = offered.entry(connection).or_default();
            occurrence.clone_into(&mut offer.occurrence);
            offer.heads.extend(heads.iter().cloned());
        }
    }

    /// Forgets the offers of the occurrence a spent staged row held. An offer
    /// of a later occurrence of the same wake stays: a pass that read the row
    /// spent before that occurrence was staged and offered must not make it
    /// heard again by a connection that already heard it.
    fn forget_spent(&mut self, row: &StagedTaskWake) {
        let key = (row.task.to_hex(), row.kind, row.recipient.to_hex());
        let Some(offered) = self.offered.get_mut(&key) else {
            return;
        };
        offered.retain(|_, offer| offer.occurrence != row.event_ref);
        if offered.is_empty() {
            self.offered.remove(&key);
        }
    }

    /// Keeps only the offers of the wakes `state` still owes.
    pub(super) fn keep_owed(&mut self, state: &CommittedTaskBoardState) {
        let owed: BTreeSet<(TaskWakeKind, String)> = state
            .owed_wakes()
            .iter()
            .map(|owed| (owed.kind, owed.recipient.to_hex()))
            .collect();
        let task_ref = state.task_ref();
        self.offered.retain(|(task, kind, recipient), _| {
            task != task_ref || owed.contains(&(*kind, recipient.clone()))
        });
    }
}

impl BoardStreamRegistry {
    /// Routes the `kind` wake `state` owes `recipient` to that actor's
    /// subscribed connections `admit` accepts and not offered this occurrence
    /// yet, by a live route or a staged pass, and records each as offered.
    pub(super) fn route_task_wake(
        &mut self,
        state: &CommittedTaskBoardState,
        kind: TaskWakeKind,
        recipient: &str,
        admit: impl Fn(&StreamConnectionId) -> bool,
    ) -> RouteObservation {
        let scope = kind.scope();
        let key = (state.task_ref().to_owned(), kind, recipient.to_owned());
        let heads = state.wake_heads(kind);
        let occurrence = state.occurrence_ref(kind.word());
        let fresh: BTreeSet<StreamConnectionId> = self
            .connections
            .iter()
            .filter(|(connection, st)| {
                st.actor_ref == recipient
                    && st.subscribed.contains(&scope)
                    && !self.published_task_wakes.heard(&key, connection, heads)
                    && admit(connection)
            })
            .map(|(connection, _)| connection.clone())
            .collect();
        if fresh.is_empty() {
            return RouteObservation::default();
        }
        let event = VerifiedOwnTaskEvent {
            task_ref: state.task_ref().to_owned(),
            actor_ref: recipient.to_owned(),
            event_ref: occurrence.clone(),
        };
        let line = state.line().to_owned();
        let event = match kind {
            TaskWakeKind::Failed => BoardEvent::OwnTaskFailed { event, line },
            TaskWakeKind::Arrived => BoardEvent::ConsultArrived { event, line },
        };
        let routed = self.route_event_where(event, |connection, _| fresh.contains(connection));
        self.published_task_wakes
            .record(key, fresh, &occurrence, heads);
        routed
    }

    /// Offers each live staged wake to every subscribed connection of its
    /// recipient that `admit` accepts and that was not offered that
    /// occurrence yet, so a connection that attaches after the wake was
    /// routed, or after a restart, still hears it, and one that heard an
    /// earlier failure of the TASK hears a later one. `admit` is the host's
    /// read of the wake's TASK under the connection's own reader, as for a
    /// live route.
    pub fn publish_task_wakes(
        &mut self,
        pending: Vec<PendingTaskWake>,
        admit: impl Fn(&StreamConnectionId, &PendingTaskWake) -> bool,
    ) -> RouteObservation {
        let mut observed = RouteObservation::default();
        for wake in pending {
            let recipient = wake.recipient.to_hex();
            let routed = self.route_task_wake(&wake.state, wake.kind, &recipient, |connection| {
                admit(connection, &wake)
            });
            observed.wake_enqueued += routed.wake_enqueued;
        }
        observed
    }

    /// The connections that would be offered `wake` if the host admits them:
    /// its recipient's subscribed connections not offered that occurrence
    /// yet. The host reads the TASK only under these connections' readers.
    #[must_use]
    pub fn task_wake_candidates(&self, wake: &PendingTaskWake) -> Vec<StreamConnectionId> {
        let recipient = wake.recipient.to_hex();
        let scope = wake.kind.scope();
        let key = (
            wake.state.task_ref().to_owned(),
            wake.kind,
            recipient.clone(),
        );
        let heads = wake.state.wake_heads(wake.kind);
        self.connections
            .iter()
            .filter(|(connection, st)| {
                st.actor_ref == recipient
                    && st.subscribed.contains(&scope)
                    && !self.published_task_wakes.heard(&key, connection, heads)
            })
            .map(|(connection, _)| connection.clone())
            .collect()
    }

    /// Forgets the offers of every wake of `task`: the board no longer shows
    /// it, so it owes none.
    pub fn forget_task_wakes(&mut self, task: EntityId) {
        let task_ref = task.to_hex();
        self.published_task_wakes
            .offered
            .retain(|(task, _, _), _| *task != task_ref);
    }

    /// Forgets the offers of the staged wakes a read found spent, each only
    /// for the occurrence its row held, as [`Vault::settle_task_wakes`]
    /// deletes a row only while it holds that occurrence.
    pub fn forget_spent_task_wakes(&mut self, spent: &[StagedTaskWake]) {
        for row in spent {
            self.published_task_wakes.forget_spent(row);
        }
    }
}
