//! Where one document batch goes, chosen before any of its rows is admitted
//! (FIX 9486).
//!
//! An endpoint whose batches route through the GPU pool sends each batch to
//! one destination: a leased pod, or the configured endpoint on this device
//! when no pod is healthy. The destination is picked first and held,
//! unchanged, through every request of the batch, the lease check after
//! each answer and the mark each vector is stored with. Only then is each
//! row judged for that destination: a pod is off this device whatever the
//! primary's label says, so a row goes there only when no world keeps it on
//! this device ([`PodRelease`]) and, where the section configures an egress
//! list, the list allows it ([`EgressPredicate::decide`]). Every other row, denied or with no verdict,
//! embeds on the primary, the on-device endpoint; the batch is never failed
//! because one row cannot leave, and the answers are put back in row order.

use std::sync::{Arc, Weak};

use oneiron::embed::{EgressDecision, EgressPredicate, PendingEmbeddingInput};
use oneiron::federation::derivation::DerivationScope;

use super::{PodRoute, pod_error};
use crate::runtime::{GpuDerivationJob, GpuLeaseGuard, GpuRegistryError};

/// The vault's world release toward a pod: for each row, in order, whether
/// it may leave this device for a destination nobody proved.
pub(crate) trait PodRelease: Send + Sync {
    fn released(&self, rows: &[oneiron::EntityId]) -> oneiron::Result<Vec<bool>>;
}

/// The release of the vault a serving process holds, read at each batch.
/// Held weakly, so the embedder never keeps a closed vault open: once the
/// vault is gone, no row is released.
pub(crate) struct VaultRelease(Weak<oneiron::Vault>);

impl VaultRelease {
    pub(crate) fn new(vault: &Arc<oneiron::Vault>) -> Self {
        Self(Arc::downgrade(vault))
    }
}

impl PodRelease for VaultRelease {
    fn released(&self, rows: &[oneiron::EntityId]) -> oneiron::Result<Vec<bool>> {
        match self.0.upgrade() {
            Some(vault) => vault.rows_released_off_device(rows),
            None => Ok(vec![false; rows.len()]),
        }
    }
}

/// Where a document batch goes, fixed before its rows are admitted.
pub(super) enum EmbeddingDestination {
    /// The configured endpoint, on this device: every row may go.
    Primary,
    /// The pool's pods, off this device.
    Pod(PodTarget),
}

/// Which pod a batch goes to.
pub(super) enum PodTarget {
    /// A pod leased for the whole batch: every request of the batch goes to
    /// it, and an answer that comes back after the lease lapsed is dropped.
    Lease(GpuLeaseGuard),
    /// A vault bound to an account: each request is a derivation job bound
    /// to the rows it carries, so the job is acquired over the admitted
    /// rows before its door is chosen, and sealed to the account. A pool
    /// with no healthy pod then sends those rows through the on-device
    /// primary, which may take any row.
    Derivation(DerivationScope),
}

/// The destination of the next document batch on `pods`: a leased pod, the
/// account-bound pool, or the primary when no pod is healthy. Chosen before
/// any row of the batch is judged.
pub(super) fn select_batch_destination(pods: &PodRoute) -> oneiron::Result<EmbeddingDestination> {
    if let Some(scope) = pods.scope {
        return Ok(EmbeddingDestination::Pod(PodTarget::Derivation(scope)));
    }
    match pods.pool.acquire() {
        Ok(lease) => Ok(EmbeddingDestination::Pod(PodTarget::Lease(lease))),
        Err(GpuRegistryError::Unavailable) => Ok(EmbeddingDestination::Primary),
        Err(error) => Err(pod_error(&error)),
    }
}

/// For each row of `inputs`, in order, whether it goes to `destination`'s
/// pod: never for the primary; for a pod, only a row no world keeps on this
/// device and, when the section configures an egress list, that the list
/// allows (`Deny` and no verdict keep it home). A row whose world cannot be
/// read stays too. A row that stays embeds on the primary.
pub(super) fn partition_released_rows(
    destination: &EmbeddingDestination,
    pods: &PodRoute,
    inputs: &[PendingEmbeddingInput],
) -> oneiron::Result<Vec<bool>> {
    if matches!(destination, EmbeddingDestination::Primary) {
        return Ok(vec![false; inputs.len()]);
    }
    // With no configured list, the world release alone judges each row, as
    // rows reached a pod before the list existed.
    let allowed: Vec<bool> = match pods.egress.as_deref() {
        Some(egress) => inputs
            .iter()
            .map(|input| egress_allows(egress, input))
            .collect(),
        None => vec![true; inputs.len()],
    };
    if !allowed.contains(&true) {
        return Ok(allowed);
    }
    let rows: Vec<oneiron::EntityId> = inputs.iter().map(|input| input.entity_id).collect();
    // A release the vault could not read keeps every row home: they embed on
    // the on-device primary, and the batch still runs.
    let released = match pods.release.released(&rows) {
        Ok(released) => released,
        Err(error) => {
            tracing::warn!(
                %error,
                rows = rows.len(),
                "world release unread; the batch embeds on-device"
            );
            return Ok(vec![false; inputs.len()]);
        }
    };
    if released.len() != rows.len() {
        return Err(oneiron::Error::InvariantViolation(
            "the vault judged another number of rows than it was asked",
        ));
    }
    Ok(allowed
        .into_iter()
        .zip(released)
        .map(|(allowed, released)| allowed && released)
        .collect())
}

fn egress_allows(egress: &dyn EgressPredicate, input: &PendingEmbeddingInput) -> bool {
    egress.decide(input) == EgressDecision::Allow
}

impl PodRoute {
    /// Sends one request of a batch to its pod `target`. An answer from a
    /// pod whose lease lapsed meanwhile (preempted, or unhealthy at the last
    /// poll) is dropped, and the worker's retry sends the rows again. A
    /// derivation request's job is acquired before its door is chosen, so a
    /// pool with no healthy pod rides the primary door instead of falling
    /// back inside a pod-door send.
    pub(super) fn post_to(
        &self,
        http: &super::HttpEmbedder,
        target: &PodTarget,
        texts: &[&str],
        side: super::Side<'_>,
    ) -> oneiron::Result<super::Answer> {
        match target {
            PodTarget::Lease(lease) => {
                let answer = http.post_at(&self.client, lease.url(), texts, side, Ok)?;
                if lease.is_live() {
                    Ok(answer)
                } else {
                    Err(pod_error(&GpuRegistryError::LeaseExpired))
                }
            }
            PodTarget::Derivation(scope) => {
                let scope = *scope;
                let computation = format!("embed:{}", http.model_key).into_bytes();
                let job = match self.pool.acquire_derivation(
                    scope,
                    computation,
                    super::batch_digest(texts),
                ) {
                    Ok(job) => job,
                    Err(error) => return Err(pod_error(&error)),
                };
                self.post_with_job(http, job, scope, texts, side)
            }
        }
    }

    /// Sends one derivation request through its held `job`: the job was
    /// acquired over these rows before the request's door was chosen, and
    /// seals the answer to `scope`'s account.
    pub(super) fn post_with_job(
        &self,
        http: &super::HttpEmbedder,
        job: GpuDerivationJob,
        scope: DerivationScope,
        texts: &[&str],
        side: super::Side<'_>,
    ) -> oneiron::Result<super::Answer> {
        let url = job.url().to_owned();
        http.post_at(&self.client, &url, texts, side, |body| {
            if !job.is_live() {
                return Err(pod_error(&GpuRegistryError::LeaseExpired));
            }
            let sealed = job.complete(body).map_err(|error| pod_error(&error))?;
            sealed
                .read(scope.owner())
                .map(<[u8]>::to_vec)
                .ok_or_else(|| pod_error(&GpuRegistryError::InvalidInput))
        })
    }
}
