//! Provider-independent, own-home catch-up over the existing embedding queue.

use std::sync::Arc;

use super::{ReceivedHomeClaimVector, claim_source_in_txn, locality, replica_matches_in_txn};
use crate::embed::{PendingEmbeddingInput, PendingEmbeddingPayload};
use crate::housekeeping::HousekeepingBudget;
use crate::sync::connection::HomeSearch;
use crate::{EntityId, Error, Result, Vault};

enum Candidate {
    End,
    Skip,
    Claim(EntityId),
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

fn next_candidate(vault: &Vault, home: &HomeSearch) -> Result<Candidate> {
    let Some(row) = home.next_claim_vector_job()? else {
        return Ok(Candidate::End);
    };
    let Some(job) = row.job else {
        return Ok(Candidate::Skip);
    };
    let txn = vault.store.env.read_txn()?;
    Ok(
        if pending_claim_in_txn(vault, &txn, &job.entity_id)?.is_some() {
            Candidate::Claim(job.entity_id)
        } else {
            Candidate::Skip
        },
    )
}

impl Vault {
    /// Copies current default CLAIM vectors from the live own home without
    /// requiring an embedder. Misses retain the original work and leases.
    /// The caller holds its write admission until this pass returns.
    pub async fn reuse_pending_home_claim_vectors(
        self: &Arc<Self>,
        budget: HousekeepingBudget,
    ) -> Result<usize> {
        let Some(home) = self.embedding_home() else {
            return Ok(0);
        };
        let deadline = budget.deadline();
        let mut copied = 0;
        while !deadline.passed() {
            let vault = Arc::clone(self);
            let selection = Arc::clone(&home);
            let candidate = tokio::task::spawn_blocking(move || next_candidate(&vault, &selection))
                .await
                .map_err(|error| Error::Io(std::io::Error::other(error)))??;
            let id = match candidate {
                Candidate::End => break,
                Candidate::Skip => continue,
                Candidate::Claim(id) => id,
            };
            if deadline.passed() {
                break;
            }
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

    fn complete_unleased_home_claim(&self, received: ReceivedHomeClaimVector) -> Result<bool> {
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
            let Some(input) = pending_claim_in_txn(self, txn, &id)? else {
                return Ok(());
            };
            if !replica_matches_in_txn(self, txn, &input, &received)? {
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
