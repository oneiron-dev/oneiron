//! Provider-independent, own-home catch-up over the existing embedding queue.

use std::sync::Arc;

use super::retained_pending::{
    OpenedRetainedHomeClaim, discard_current_copy, discard_current_copy_in_txn,
};
use super::{ReceivedHomeClaimVector, claim_source_in_txn, locality, replica_matches_in_txn};
use crate::embed::{PendingEmbeddingInput, PendingEmbeddingPayload};
use crate::housekeeping::HousekeepingBudget;
use crate::{EntityId, Error, Result, Vault};

enum Candidate {
    End,
    Skip,
    Claim(EntityId, Option<Vec<u8>>),
}

fn pending_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<PendingEmbeddingInput>> {
    let Some(token) = vault.store.pending_embedding_token(txn, id)? else {
        return Ok(None);
    };
    let lease =
        crate::embed::tolerate_undecodable_lease(crate::embed::PENDING_EMBEDDING_LEASE.get(
            &vault.store,
            txn,
            &crate::side_table::HexId(*id),
        ))?;
    if lease.is_some_and(|lease| {
        lease.token == token && lease.expires_at_ms > crate::embed::unix_millis_now()
    }) {
        return Ok(None);
    }
    let Some(source) = claim_source_in_txn(vault, txn, id)? else {
        return Ok(None);
    };
    Ok(Some(PendingEmbeddingInput {
        entity_id: *id,
        payload: PendingEmbeddingPayload::ClaimBody(
            source[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec(),
        ),
        pending_embedding_token: token,
    }))
}

fn next_candidate(vault: &Arc<Vault>) -> Result<Candidate> {
    let Some(row) = vault.next_claim_vector_job()? else {
        return Ok(Candidate::End);
    };
    let Some(job) = row.job else {
        return Ok(Candidate::Skip);
    };
    let txn = vault.store.env.read_txn()?;
    Ok(
        if pending_claim_in_txn(vault, &txn, &job.entity_id)?.is_some() {
            Candidate::Claim(job.entity_id, row.copy)
        } else {
            Candidate::Skip
        },
    )
}

impl Vault {
    /// Reuses retained default CLAIM copies, then asks the live own home when
    /// available, without requiring an embedder. Misses retain work and leases.
    /// The caller holds its write admission until this pass returns.
    pub async fn reuse_pending_home_claim_vectors(
        self: &Arc<Self>,
        budget: HousekeepingBudget,
    ) -> Result<usize> {
        let home = self.embedding_home();
        let deadline = budget.deadline();
        let mut copied = 0;
        while !deadline.passed() {
            let vault = Arc::clone(self);
            let candidate = tokio::task::spawn_blocking(move || next_candidate(&vault))
                .await
                .map_err(|error| Error::Io(std::io::Error::other(error)))??;
            let (id, copy) = match candidate {
                Candidate::End => break,
                Candidate::Skip => continue,
                Candidate::Claim(id, copy) => (id, copy),
            };
            if deadline.passed() {
                break;
            }
            if let Some(bytes) = copy {
                let vault = Arc::clone(self);
                let reused = tokio::task::spawn_blocking(move || {
                    vault.complete_retained_home_claim(id, bytes)
                })
                .await
                .map_err(|error| Error::Io(std::io::Error::other(error)))?;
                match reused {
                    Ok(true) => {
                        copied += 1;
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => tracing::debug!(
                        entity = %id.to_hex(),
                        error = ?error.kind(),
                        "retained home CLAIM copy attempt returned an error"
                    ),
                }
            }
            if deadline.passed() {
                break;
            }
            let Some(home) = &home else {
                continue;
            };
            let Some(received) = home.default_claim_vector(id).await? else {
                continue;
            };
            let vault = Arc::clone(self);
            copied += usize::from(
                tokio::task::spawn_blocking(move || vault.complete_unleased_home_claim(received))
                    .await
                    .map_err(|error| Error::Io(std::io::Error::other(error)))??,
            );
        }
        Ok(copied)
    }

    pub(super) fn complete_pending_retained_home_claim(&self, id: &EntityId) -> Result<bool> {
        let bytes = {
            let txn = self.store.env.read_txn()?;
            crate::sync::queue::embed_job_home_claim_copy_in_txn(&self.store, &txn, id)?
        };
        let Some(bytes) = bytes else {
            return Ok(false);
        };
        self.complete_retained_home_claim(*id, bytes)
    }

    fn complete_retained_home_claim(&self, id: EntityId, bytes: Vec<u8>) -> Result<bool> {
        let copy = match OpenedRetainedHomeClaim::open(self, &id, bytes.clone()) {
            Ok(Some(copy)) => copy,
            Ok(None) => {
                discard_current_copy(self, &id, &bytes)?;
                return Ok(false);
            }
            Err(error) => {
                discard_current_copy(self, &id, &bytes)?;
                return Err(error);
            }
        };
        self.complete_home_claim(&copy.received, Some(&copy))
    }

    fn complete_unleased_home_claim(&self, received: ReceivedHomeClaimVector) -> Result<bool> {
        self.complete_home_claim(&received, None)
    }

    fn complete_home_claim(
        &self,
        received: &ReceivedHomeClaimVector,
        retained: Option<&OpenedRetainedHomeClaim>,
    ) -> Result<bool> {
        let Some((locality, _)) = locality(received.vector.locality) else {
            return Ok(false);
        };
        let Ok(vector) =
            crate::store::decode_vector_row(&received.vector.row, self.config.dimensions)
        else {
            return Ok(false);
        };
        if !vector.iter().all(|value| value.is_finite()) {
            return Ok(false);
        }
        let mut copied = false;
        self.with_write_txn_grouped(|txn| {
            let id = received.vector.entity_id;
            if let Some(copy) = retained
                && !copy.current_in_txn(self, txn)?
            {
                discard_current_copy_in_txn(self, txn, &id, copy.bytes())?;
                return Ok(());
            }
            let Some(input) = pending_claim_in_txn(self, txn, &id)? else {
                return Ok(());
            };
            if !replica_matches_in_txn(self, txn, &input, received)? {
                return Ok(());
            }
            crate::batch::apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                txn,
                vec![crate::batch::BatchOp::Vector {
                    id,
                    vector,
                    pending_embedding_token: Some(input.pending_embedding_token),
                    provenance: Some(received.vector.provenance.clone()),
                }],
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
            copied = self
                .store
                .pending_embedding_token_in_txn(txn, &id)?
                .is_none();
            if copied {
                crate::embed::locality::stamp_embedding_locality_in_txn(self, txn, &id, locality)?;
                crate::sync::queue::delete_embed_job_in_txn(&self.store, txn, &id)?;
            }
            Ok(())
        })?;
        Ok(copied)
    }
}
