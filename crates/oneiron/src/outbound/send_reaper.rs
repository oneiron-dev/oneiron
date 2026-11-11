//! The send executor lease's handover when its machine closes or vanishes
//! (FIX 4747 slice 4; canon ARCH-0019 hosting: "Lease handover order: an
//! always-on machine, then any live linked machine, else pause and resume;
//! within world privacy and capability", with the orphaned-attempt reaper as
//! the fallback; ARCH-0023b, pending outbound send).
//!
//! A machine that shuts down gracefully releases the leases it holds
//! ([`Vault::release_send_executor_leases`]). On every machine, the host's
//! housekeeping pass runs the reaper ([`Vault::reap_connector_send_leases`]):
//! it takes a TASK whose lease is expired, its holder's released one or one
//! no pass renewed, when this machine can send it and the ruled order lets
//! it. A TASK no machine can take waits, and is taken when one comes up. The
//! same pass renews this machine's own lease on a TASK whose attempt is held
//! paused here, which no executor pass renews while it stays paused.
//! Concurrent takers resolve as the lease does: whole-row LWW and the fence,
//! so at most one sends once copies agree and the loser stands down. The
//! taker's send goes under a generation above the first, so it is looked up
//! at its provider before it goes.
//!
//! World privacy: no world residency or privacy check exists on the send
//! path, and the connector-send TASK names no world, so the reaper applies
//! none. A TASK a device-only world keeps never reaches another machine.
//! Entry: `Vault::reap_connector_send_leases`.

use std::collections::BTreeMap;

use super::BRIDGE_OUTBOUND_ATTEMPT_KIND;
use super::connector_task::{
    ConnectorSendAttemptPayload, ConnectorSendTask, SendExecutorHandover, SendExecutorLease,
    connector_send_attempt_payload, hand_over_connector_send_task_in_txn,
    open_send_executor_leases_in, release_send_executor_lease_in_txn,
    renew_send_executor_lease_in_txn, send_executor_lease_in, send_executor_lease_renewal,
};
use super::executor::connector_task_ledger_attempt_ids;
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptState, EnqueueAttempt};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::{IntentLedgerError, supersede_stood_down_intents_in_txn};

/// How long after an expired lease's `held_until` a machine that is not an
/// always-on one waits before it takes the TASK (FIX 4747 slice 4), so an
/// always-on machine able to send it, which takes at expiry, goes first.
/// Engine call (CALLS, FIX 4747): five minutes, five housekeeping ticks.
const SEND_EXECUTOR_HANDOVER_GRACE_SECS: u64 = 5 * 60;

/// What one reaper pass came to (FIX 4747 slice 4).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectorSendLeaseReap {
    /// TASKs this machine took, each with its local attempt queued.
    pub taken: usize,
    /// TASKs with an expired lease this machine left for now: the ruled
    /// order puts an always-on machine first, or this machine cannot send
    /// them. They wait.
    pub waiting: usize,
    /// This machine's own leases it renewed, each on a TASK whose attempt is
    /// held paused here.
    pub renewed: usize,
}

impl Vault {
    /// FIX 4747 (review #6574): a new serve run over a vault that stayed open
    /// takes, renews and reaps executor leases again, its connector sends'
    /// and its agent runs'. The embedded engine calls it when it serves
    /// again after a stop, once the stopped run's workers have joined, so no
    /// pass of that run outlives the release; an app whose lid or sleep hook
    /// released the leases calls it when the machine wakes.
    pub fn resume_executor_leases(&self) {
        self.executor_leases_released
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Releases every send executor lease this machine holds on a TASK that
    /// still permits a send (FIX 4747 slice 4), in one writer: each keeps its
    /// holder and generation and is held until now, so another machine's
    /// reaper may take it at once. The host calls it as it shuts down
    /// gracefully, before its device-sync link stops; an app's lid or sleep
    /// hook calls it before the machine sleeps. This machine's send in flight
    /// still passes its fence until another machine takes the lease, and a
    /// pass of its own executor after the release, or the reaper's renewal of
    /// a send held paused here, renews the lease again. Returns how many it
    /// released.
    ///
    /// # Errors
    /// Storage errors.
    pub fn release_send_executor_leases(&self) -> Result<usize, Error> {
        self.executor_leases_released
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let now = self.now_recorded_at();
        let (node_id, held) = {
            let rtxn = self.store.env.read_txn()?;
            let Some(node_id) = crate::identity::read_client_id_in_txn(self, &rtxn)? else {
                return Ok(0);
            };
            let held: Vec<EntityId> = open_send_executor_leases_in(self, &rtxn)?
                .into_iter()
                .filter(|(_, lease)| lease.node_id == node_id && !lease.expired_at(now))
                .map(|(task_ref, _)| task_ref)
                .collect();
            (node_id, held)
        };
        if held.is_empty() {
            return Ok(0);
        }
        self.with_write_txn_grouped(|wtxn| {
            let mut released = 0_usize;
            for task_ref in held {
                if release_send_executor_lease_in_txn(self, wtxn, task_ref, node_id, now)? {
                    released += 1;
                }
            }
            Ok(released)
        })
    }

    /// The orphaned-send reaper (FIX 4747 slice 4): takes each connector-send
    /// TASK whose send executor lease is expired, in the ruled order, when
    /// this machine can send it. A lease another machine holds is taken by
    /// the handover, at the next generation; this machine's own expired
    /// lease, with no attempt of it queued here, is renewed. Each take, in
    /// one writer, moves the lease, supersedes the TASK's local sends this
    /// machine's executor stood down, and queues the local connector-send
    /// attempt the executor runs, unless one is queued here already. The
    /// ruled order is `send_executor_handover_due`; `holds_channel` is the
    /// host's read-only check that this machine holds what the TASK's channel
    /// needs, the check its sink makes before a send. A TASK neither lets
    /// this machine take waits. In one writer of its own, the pass renews
    /// this machine's lease on each TASK whose attempt is held paused here,
    /// so a send this machine holds does not move while it is up.
    ///
    /// # Errors
    /// Storage errors.
    pub fn reap_connector_send_leases(
        &self,
        holds_channel: &dyn Fn(&ConnectorSendTask) -> bool,
    ) -> Result<ConnectorSendLeaseReap, Error> {
        if self
            .executor_leases_released
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(ConnectorSendLeaseReap::default());
        }
        let now = self.now_recorded_at();
        let node_id = crate::identity::load_or_mint_client_id(self)?;
        let (leases, local, always_on) = {
            let rtxn = self.store.env.read_txn()?;
            let leases: Vec<_> = open_send_executor_leases_in(self, &rtxn)?
                .into_iter()
                .filter(|(_, lease)| lease.node_id == node_id || lease.expired_at(now))
                .collect();
            if leases.is_empty() {
                return Ok(ConnectorSendLeaseReap::default());
            }
            let local = local_connector_send_attempts_in(self, &rtxn)?;
            // The candidacy fold is read only when an expired lease asks
            // the ruled order.
            let ordered = leases.iter().any(|(task_ref, lease)| {
                lease.expired_at(now) && (lease.node_id != node_id || !local.contains_key(task_ref))
            });
            let always_on = ordered && send_handover_always_on_in(self, &rtxn, node_id)?;
            (leases, local, always_on)
        };
        let mut reap = ConnectorSendLeaseReap::default();
        let mut renew = Vec::new();
        for (task_ref, lease) in leases {
            let local_attempt = local.get(&task_ref).copied();
            // This machine's own attempt queued here renews the lease at its
            // next claim; one held paused here is renewed below.
            if lease.node_id == node_id
                && let Some(paused) = local_attempt
            {
                if paused && send_executor_lease_renewal(lease.held_until, now).is_some() {
                    renew.push(task_ref);
                }
                continue;
            }
            if !lease.expired_at(now) {
                continue;
            }
            if !send_executor_handover_due(lease, always_on, now) {
                reap.waiting += 1;
                continue;
            }
            let task = match self.connector_send_task(&task_ref) {
                Ok(Some(task)) => task,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        task = %task_ref.to_hex(),
                        kind = ?error.kind(),
                        "the send lease reaper passed over a connector-send TASK it could not read"
                    );
                    continue;
                }
            };
            if !holds_channel(&task) {
                reap.waiting += 1;
                continue;
            }
            let enqueue = local_attempt.is_none();
            match take_expired_connector_send_task(self, &task, lease, node_id, enqueue, now) {
                Ok(Some(taken)) => {
                    tracing::info!(
                        task = %task_ref.to_hex(),
                        node_id,
                        generation = taken.generation,
                        expired_node_id = lease.node_id,
                        expired_generation = lease.generation,
                        always_on,
                        "the send lease reaper took a connector send whose lease expired"
                    );
                    reap.taken += 1;
                }
                Ok(None) => {}
                // One TASK's failed take leaves it waiting and the pass goes on.
                Err(error) => {
                    tracing::warn!(
                        task = %task_ref.to_hex(),
                        kind = ?error.kind(),
                        "the send lease reaper could not take a connector send; it waits"
                    );
                    reap.waiting += 1;
                }
            }
        }
        if !renew.is_empty() {
            reap.renewed = renew.len();
            self.with_write_txn_grouped(|wtxn| {
                for task_ref in renew {
                    renew_send_executor_lease_in_txn(self, wtxn, task_ref, now, now)?;
                }
                Ok(())
            })?;
        }
        if reap.taken > 0 {
            self.store.notify_attempt_observers();
        }
        Ok(reap)
    }
}

/// Whether the ruled handover order lets this machine take a TASK whose
/// lease expired at `lease.held_until`, at `now` (FIX 4747 slice 4; canon
/// ARCH-0019 "an always-on machine, then any live linked machine"). Engine
/// call (CALLS, FIX 4747): an always-on machine (`always_on`) takes at
/// expiry; any other live machine, as this one is while it runs the pass,
/// only [`SEND_EXECUTOR_HANDOVER_GRACE_SECS`] later, so an always-on machine
/// able to send goes first. With no machine able, the TASK waits.
fn send_executor_handover_due(lease: SendExecutorLease, always_on: bool, now: u64) -> bool {
    let due_at = if always_on {
        lease.held_until
    } else {
        lease
            .held_until
            .saturating_add(SEND_EXECUTOR_HANDOVER_GRACE_SECS)
    };
    now >= due_at
}

/// Whether this machine (`node_id`) is an always-on one for the handover
/// order, read in `txn` (FIX 4747 slice 4). Engine call (CALLS, FIX 4747):
/// its own home candidacy says it is a cloud node or an always-on local
/// machine, by the signed declaration of this node that stands as one of the
/// owner's machines (FIX 4898), or by the candidacy its host kept for itself.
/// A fold this snapshot cannot read leaves the host's own candidacy alone.
fn send_handover_always_on_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    node_id: u64,
) -> Result<bool, Error> {
    let declared = match crate::authority::election_home_candidacies_in_txn(
        &vault.store,
        vault.privacy_posture(),
        txn,
    ) {
        Ok(declared) => declared.unwrap_or_default(),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the send lease reaper read no home candidacy declaration; the host's own \
                 candidacy alone says whether this machine is always on"
            );
            Vec::new()
        }
    };
    if declared.iter().any(|candidacy| {
        candidacy.node_id == node_id
            && candidacy.owner_machine
            && (candidacy.cloud || candidacy.always_on)
    }) {
        return Ok(true);
    }
    let kept = crate::dreamer_runner::DreamerRunnerStore::new(vault)
        .home_candidates_in_txn(txn)?
        .unwrap_or_default();
    Ok(kept.iter().any(|candidate| {
        candidate.node_id == node_id && (candidate.cloud || candidate.always_on_local)
    }))
}

/// The connector-send TASKs with an attempt still queued, leased, parked or
/// held paused in this machine's own queue, read in `txn`, each with
/// whether one of its attempts here is held paused.
fn local_connector_send_attempts_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, bool>, Error> {
    let mut local = BTreeMap::new();
    for attempt in AttemptQueue::new(vault)
        .kind_working_rows_in_txn(txn, BRIDGE_OUTBOUND_ATTEMPT_KIND)?
        .into_iter()
        .filter(|attempt| attempt.state.is_pending())
    {
        let Some(task_ref) =
            serde_json::from_slice::<ConnectorSendAttemptPayload>(&attempt.payload)
                .ok()
                .and_then(|payload| EntityId::from_hex(&payload.task_ref).ok())
        else {
            continue;
        };
        let paused = local.entry(task_ref).or_insert(false);
        *paused |= attempt.state == AttemptState::Paused;
    }
    Ok(local)
}

/// Takes `task`, whose lease `expired` this pass judged expired, for this
/// machine (`node_id`) in one writer (FIX 4747 slice 4), while the TASK
/// still holds exactly that lease: the handover moves the lease here at the
/// next generation, or renews this machine's own; the TASK's local sends
/// this machine's executor stood down are superseded, so the new attempt
/// can send; and with `enqueue`, the local connector-send attempt the
/// executor runs is queued as the scheduler queues it. Returns the lease the
/// TASK now holds; `None` when the TASK moved on since: a renewal, a
/// release, another machine's take, or a terminal outcome.
fn take_expired_connector_send_task(
    vault: &Vault,
    task: &ConnectorSendTask,
    expired: SendExecutorLease,
    node_id: u64,
    enqueue: bool,
    now: u64,
) -> Result<Option<SendExecutorLease>, Error> {
    let ledger_attempt_ids = connector_task_ledger_attempt_ids(task)?;
    let payload = connector_send_attempt_payload(task.task_ref)?;
    let dedupe_actor_ref = task.actor_ref.to_hex();
    vault.with_write_txn_grouped(|wtxn| {
        if send_executor_lease_in(vault, &*wtxn, task.task_ref)? != Some(expired) {
            return Ok(None);
        }
        let taken =
            match hand_over_connector_send_task_in_txn(vault, wtxn, task.task_ref, node_id, now)? {
                SendExecutorHandover::Closed => return Ok(None),
                SendExecutorHandover::Moved(lease) | SendExecutorHandover::AlreadyHeld(lease) => {
                    lease
                }
            };
        for ledger_attempt_id in ledger_attempt_ids {
            supersede_stood_down_intents_in_txn(vault, wtxn, ledger_attempt_id).map_err(
                |error| match error {
                    IntentLedgerError::Engine(error) => error,
                    _ => Error::CorruptedIndex("outbound intent ledger row"),
                },
            )?;
        }
        if enqueue {
            crate::ports::JobQueue::port_job_enqueue_scoped(
                vault,
                wtxn,
                EnqueueAttempt {
                    kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                    payload,
                    dedupe_key: task.intent.idempotency_key.clone(),
                    run_id: task.intent.job_ref.clone(),
                    now,
                },
                crate::ports::JobScope {
                    task_ref: Some(task.task_ref.to_hex()),
                    dedupe_actor_ref: Some(&dedupe_actor_ref),
                },
            )?;
        }
        Ok(Some(taken))
    })
}
