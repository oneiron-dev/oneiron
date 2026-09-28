//! Vault-local, non-serializable producer observations. No diagnostic or
//! claim body has a decoder that can manufacture these entries.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{ExecutedModelWitness, ModelId};
use crate::self_heal::tier1_source::VerifiedSourceSet;
use rand_core::RngCore;

#[derive(Clone)]
pub(super) enum WitnessKind {
    Diagnostic {
        body_hash: [u8; 32],
        sources: VerifiedSourceSet,
        detector_id: String,
        observed_at: i64,
    },
    Execution {
        body_hash: [u8; 32],
        attempt_id: AttemptId,
        run_ref: Option<String>,
        request_hash: [u8; 32],
        model: ModelId,
        observed_at: i64,
    },
}

#[derive(Clone)]
pub(super) struct WitnessEntry {
    pub(super) nonce: [u8; 16],
    pub(super) kind: WitnessKind,
}

impl WitnessEntry {
    pub(super) fn new(kind: WitnessKind) -> Self {
        let mut nonce = [0; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        Self { nonce, kind }
    }
}

/// Opaque observation of this specific open vault. A caller cannot construct
/// or deserialize one, and a handle from another vault is never valid here.
pub struct Tier1Observation<'vault> {
    pub(super) vault: &'vault Vault,
    pub(super) id: EntityId,
    pub(super) nonce: [u8; 16],
}

impl Vault {
    /// A producer emitted this diagnostic after checking its exact base
    /// sources. The registration happens only after the diagnostic commits.
    pub(crate) fn capture_tier1_diagnostic(
        &self,
        id: EntityId,
        sources: VerifiedSourceSet,
    ) -> Result<()> {
        if !self.config.failure_signals.exports() {
            return Ok(());
        }
        let body = self.get(&id)?.ok_or(Error::EntityNotFound)?;
        let event = crate::self_heal::decode_diagnostic_event_body(&body)?;
        if crate::self_heal::diagnostic_event_id(&event.detector_id, &body) != id {
            return Err(Error::InvariantViolation(
                "tier-1 diagnostic address changed",
            ));
        }
        let observed_at = i64::try_from(event.valid_from)
            .map_err(|_| Error::ArithmeticOverflow("failure signal observation time"))?;
        self.store.diagnostics.failure_signals.register(
            id,
            WitnessKind::Diagnostic {
                body_hash: *blake3::hash(&body).as_bytes(),
                sources,
                detector_id: event.detector_id,
                observed_at,
            },
        )
    }

    pub(crate) fn capture_tier1_point_producer(&self, ids: &[EntityId]) -> Result<()> {
        if !self.config.failure_signals.exports() {
            return Ok(());
        }
        for id in ids {
            let Some(body) = self.get(id)? else {
                continue;
            };
            let event = crate::self_heal::decode_diagnostic_event_body(&body)?;
            let txn = self.store.env.read_txn()?;
            let sources = crate::self_heal::tier1_source::VerifiedSourceSet::point_producer(
                &self.store,
                &txn,
                &event,
            );
            drop(txn);
            if let Ok(sources) = sources {
                self.capture_tier1_diagnostic(*id, sources)?;
            }
        }
        Ok(())
    }

    /// A model-judged or centroid window. Every run, and a centroid's pinned
    /// vector snapshot, is re-read from base before the witness exists.
    pub(crate) fn capture_tier1_retrieval_window(
        &self,
        id: EntityId,
        runs: &[crate::store::RetrievalRunRecord],
        centroid_snapshot: Option<[u8; 32]>,
    ) -> Result<()> {
        if !self.config.failure_signals.exports() {
            return Ok(());
        }
        let txn = self.store.env.read_txn()?;
        let mut sources = VerifiedSourceSet::retrieval_window(&self.store, &txn, runs)?;
        if let Some(hash) = centroid_snapshot {
            sources = sources.with_centroid_snapshot(&self.store, &txn, hash)?;
        }
        drop(txn);
        self.capture_tier1_diagnostic(id, sources)
    }

    /// An adapter may supply receipt bytes, but only a byte-identical base
    /// Gate projection can become a witness. Unverifiable drafts still emit
    /// diagnostics; they cannot become exportable observations.
    pub(crate) fn capture_tier1_receipt_window(
        &self,
        ids: &[EntityId],
        receipts: &[crate::receipt::ReceiptRecord],
    ) -> Result<()> {
        if !self.config.failure_signals.exports() {
            return Ok(());
        }
        for id in ids {
            let Some(body) = self.get(id)? else {
                continue;
            };
            let event = crate::self_heal::decode_diagnostic_event_body(&body)?;
            let txn = self.store.env.read_txn()?;
            let sources = VerifiedSourceSet::receipt_window(
                &self.store,
                &txn,
                receipts,
                &event.evidence_refs,
            );
            drop(txn);
            if let Ok(sources) = sources {
                self.capture_tier1_diagnostic(*id, sources)?;
            }
        }
        Ok(())
    }

    /// Executed steps enter only from the fresh provider-completion branch,
    /// never from a memo index, recovery replay, or arbitrary claim put.
    pub(crate) fn capture_tier1_executed_step(
        &self,
        witness: &ExecutedModelWitness<'_>,
    ) -> Result<()> {
        if !self.config.failure_signals.exports() {
            return Ok(());
        }
        let (owner, claim_id, attempt_id, run_ref, request_hash, model, at_ms) = witness.parts();
        if !std::ptr::eq(self, owner) {
            return Err(Error::InvariantViolation(
                "step completion belongs to another vault",
            ));
        }
        let Some(attempt) = AttemptQueue::new(self).get(attempt_id)? else {
            return Ok(());
        };
        if attempt.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND
            || attempt.run_id.as_deref() != run_ref
        {
            return Ok(());
        }
        let body = self.get(&claim_id)?.ok_or(Error::EntityNotFound)?;
        let claim = self.get_claim(&claim_id)?.ok_or(Error::EntityNotFound)?;
        if crate::llm::terminal_step_identity(&claim)
            != Some((attempt_id, request_hash, model.clone()))
        {
            return Err(Error::InvariantViolation(
                "finished step claim differs from executed request",
            ));
        }
        let observed_at = i64::try_from(at_ms / 1_000)
            .map_err(|_| Error::ArithmeticOverflow("failure signal observation time"))?;
        self.store.diagnostics.failure_signals.register(
            claim_id,
            WitnessKind::Execution {
                body_hash: *blake3::hash(&body).as_bytes(),
                attempt_id,
                run_ref: run_ref.map(str::to_owned),
                request_hash,
                model: model.clone(),
                observed_at,
            },
        )
    }

    /// Resolve only observations captured by an engine producer in this open
    /// vault. Looking up an arbitrary stored diagnostic or step returns None.
    pub fn tier1_observation(&self, id: EntityId) -> Result<Option<Tier1Observation<'_>>> {
        Ok(self
            .store
            .diagnostics
            .failure_signals
            .witness(id)?
            .map(|entry| Tier1Observation {
                vault: self,
                id,
                nonce: entry.nonce,
            }))
    }
}
