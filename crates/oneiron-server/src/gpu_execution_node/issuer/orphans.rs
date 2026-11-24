//! What the issuer does with a key a node holds that it has no dispatch row for (pass 33 row R4,
//! 8.5): [`JobOrphanKeys`], the reconcile's [`OrphanKeys`] hook.
//!
//! - Every such key gets a `JOB_ORPHAN` row, which `vault.machines.execution.get` shows.
//! - A live one is asked to stop, at the reconcile and at each housekeeping pass, until the node
//!   answers its terminal receipt. Nothing is ever submitted for it.
//! - An ended one keeps its terminal receipt. When it ran, its occupied seconds are recorded
//!   against the allocation generation its receipt's hold named, charged to no family (EM-15 =
//!   A): a restored issuer cannot spend the same seconds twice. The allocation's side of that
//!   record is the ledger's ([`UnattributedLedger`]); the orphan row keeps the seconds either way.
//!
//! Every receipt is checked first: signed by the node it came from, for this issuer and key.

use std::sync::Arc;

use oneiron::job_dispatch::machine_records::{JobOrphan, UnattributedSeconds};
use oneiron::machine_signature::MachineSignatures;
use oneiron::{EntityId, Vault};

use super::clock::IssuerClock;
use super::node_client::JobNodeClient;
use super::reconcile::OrphanKeys;
use crate::gpu_execution_node::wire::{
    JobState, JobStatusAnswer, JobStatusRequest, KeyEntry, SignedJobReceipt,
};

/// The allocation's record of an orphan's unattributed seconds (EM-15 = A; OPUS-LE-LEDGER's
/// `record_node_answer_in_txn` once it lands). It is told each node's orphans that ran once the
/// node's whole listing was read, never page by page.
pub trait UnattributedLedger: Send + Sync {
    /// `machine` answered its whole listing; `ran` holds each orphan that occupied a device,
    /// with the generation its hold named and its seconds.
    fn record_node_answer(&self, machine: EntityId, ran: &[UnattributedSeconds]);
}

/// The ledger hook until the allocation's writer lands: it logs what it would record. The
/// orphan rows keep the seconds.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoggedUnattributedLedger;

impl UnattributedLedger for LoggedUnattributedLedger {
    fn record_node_answer(&self, machine: EntityId, ran: &[UnattributedSeconds]) {
        for seconds in ran {
            tracing::warn!(
                machine = %machine.to_hex(),
                reservation = %seconds.reservation,
                generation = seconds.generation,
                secs = seconds.secs,
                "vault_machine: unattributed seconds of an orphan key, not yet recorded in the allocation"
            );
        }
    }
}

/// The reconcile's orphan hook: `JOB_ORPHAN` rows, a stop for each live key, and the
/// unattributed seconds of each that ran.
pub struct JobOrphanKeys {
    pub vault: Arc<Vault>,
    /// This install's MACHINE: the issuer a receipt must name.
    pub issuer: EntityId,
    pub client: Arc<dyn JobNodeClient>,
    pub signer: Arc<dyn MachineSignatures>,
    pub clock: Arc<dyn IssuerClock>,
    pub ledger: Arc<dyn UnattributedLedger>,
}

/// The wire name of a key's state, as the orphan row keeps it.
fn state_name(state: JobState) -> &'static str {
    match state {
        JobState::Held => "held",
        JobState::Accepted => "accepted",
        JobState::Staging => "staging",
        JobState::Launching => "launching",
        JobState::Running => "running",
        JobState::Ending => "ending",
        JobState::Ended => "ended",
    }
}

impl JobOrphanKeys {
    /// `signed` checked: signed by `node`, for this issuer and `key`.
    fn checked(&self, node: EntityId, key: &str, signed: &SignedJobReceipt) -> bool {
        let receipt = &signed.receipt;
        receipt.machine == node
            && receipt.issuer == self.issuer
            && receipt.key == key
            && signed.verify(self.signer.as_ref()).is_ok()
    }

    /// Records what the issuer saw of `key` on `node`: its state, and its terminal receipt
    /// with its unattributed seconds once it ended. Answers the row; `None` when the store
    /// refused the write (logged; the next pass writes it).
    fn record(
        &self,
        node: EntityId,
        key: &str,
        state: Option<JobState>,
        ended: Option<&SignedJobReceipt>,
        stop_sent: bool,
    ) -> Option<JobOrphan> {
        let now_ms = self.clock.now_ms();
        let ended_bytes = ended.and_then(|signed| oneiron_organ_protocol::to_vec(signed).ok());
        let unattributed = ended.and_then(|signed| unattributed_of(signed, now_ms));
        let written =
            self.vault
                .record_job_orphan(node, key, state.map(state_name), now_ms, |row| {
                    if stop_sent && row.stop_sent_at_ms.is_none() {
                        row.stop_sent_at_ms = Some(now_ms);
                    }
                    if row.ended.is_none()
                        && let Some(bytes) = ended_bytes
                    {
                        row.ended = Some(bytes);
                        row.unattributed = unattributed;
                    }
                });
        match written {
            Ok(row) => Some(row),
            Err(error) => {
                tracing::warn!(node = %node.to_hex(), key, %error, "vault_machine: orphan key not recorded");
                None
            }
        }
    }

    /// Asks `node` to stop the live `key` and records the answer: a terminal receipt ends the
    /// orphan; anything else leaves it live for the next pass.
    fn stop(&self, node: EntityId, key: &str) -> Option<JobOrphan> {
        let answer = self.client.job_status(
            node,
            &JobStatusRequest::Stop {
                key: key.to_owned(),
            },
        );
        match answer {
            Ok(JobStatusAnswer::Known(signed)) if self.checked(node, key, &signed) => {
                let ended = (signed.receipt.state == JobState::Ended).then_some(&signed);
                self.record(node, key, Some(signed.receipt.state), ended, true)
            }
            Ok(other) => {
                tracing::warn!(node = %node.to_hex(), key, answer = super::status_answer_kind(&other), "vault_machine: an orphan key's stop got no receipt; asked again at the next pass");
                self.record(node, key, None, None, true)
            }
            Err(error) => {
                tracing::warn!(node = %node.to_hex(), key, %error, "vault_machine: an orphan key's stop did not arrive; asked again at the next pass");
                self.record(node, key, None, None, true)
            }
        }
    }

    /// The housekeeping pass over `node`'s live orphans (pass 33, 8.5: a live orphan gets `Stop`
    /// until a terminal receipt). `None` passes over every machine's.
    pub fn follow_live_orphans(&self, node: Option<EntityId>) {
        let orphans = match self.vault.job_orphans(node) {
            Ok(orphans) => orphans,
            Err(error) => {
                tracing::warn!(%error, "vault_machine: orphan keys not read");
                return;
            }
        };
        for orphan in orphans.iter().filter(|orphan| orphan.is_live()) {
            if let Some(row) = self.stop(orphan.machine, &orphan.key)
                && let Some(ran) = row.unattributed
            {
                self.ledger
                    .record_node_answer(orphan.machine, std::slice::from_ref(&ran));
            }
        }
    }
}

/// The unattributed seconds of an orphan's terminal receipt: only a key that ran, whose
/// receipt names its hold and measured its seconds. A lost box's unknown seconds are not
/// invented here; its receipt stays on the row.
fn unattributed_of(signed: &SignedJobReceipt, now_ms: u64) -> Option<UnattributedSeconds> {
    let receipt = &signed.receipt;
    if !receipt.started {
        return None;
    }
    let hold = receipt.hold.as_ref()?;
    Some(UnattributedSeconds {
        reservation: hold.reservation.clone(),
        generation: hold.generation,
        secs: receipt.measured_secs?,
        recorded_at_ms: now_ms,
    })
}

impl OrphanKeys for JobOrphanKeys {
    fn unknown_key(&self, node: EntityId, entry: &KeyEntry) {
        match (&entry.ended, entry.state) {
            (Some(signed), JobState::Ended) if self.checked(node, &entry.key, signed) => {
                self.record(node, &entry.key, Some(JobState::Ended), Some(signed), false);
            }
            (_, JobState::Ended) => {
                tracing::warn!(node = %node.to_hex(), key = %entry.key, "vault_machine: an ended orphan key came with no receipt of its own");
                self.record(node, &entry.key, Some(JobState::Ended), None, false);
            }
            (_, state) => {
                self.record(node, &entry.key, Some(state), None, false);
                self.stop(node, &entry.key);
            }
        }
    }

    fn listing_complete(&self, node: EntityId) {
        let ran: Vec<UnattributedSeconds> = match self.vault.job_orphans(Some(node)) {
            Ok(orphans) => orphans
                .into_iter()
                .filter_map(|orphan| orphan.unattributed)
                .collect(),
            Err(error) => {
                tracing::warn!(node = %node.to_hex(), %error, "vault_machine: orphan keys not read");
                return;
            }
        };
        if !ran.is_empty() {
            self.ledger.record_node_answer(node, &ran);
        }
    }
}
