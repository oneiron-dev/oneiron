//! Core claim/witness/read verbs of the actor-scoped surface.

use napi_derive::napi;
use oneiron::{ClaimListFilter, SafeDeleteReason};

use super::boundary::{boundary_error, facade_error, ts_from_engine};
use super::bridge::ActorScopedVault;
use super::convert::{
    claim_view_from_engine, commit_receipt_from_engine, entity_view_from_engine,
    forget_active_matches, gate_receipt_from_engine, witness_receipt_from_engine,
    witness_turn_to_engine,
};
use super::dtos::{
    NapiClaimInput, NapiClaimListFilter, NapiClaimView, NapiCommitReceipt, NapiDeleteReceipt,
    NapiEntityView, NapiForgetSelector, NapiGateReceipt, NapiPendingWrite, NapiWitnessReceipt,
    NapiWitnessTurn,
};
use super::numeric::claim_input_to_engine;

#[napi]
impl ActorScopedVault {
    /// Witnesses one turn (create-or-get CONVERSATION/TURN + gated MESSAGE
    /// puts + edges + BM25 indexing, one atomic batch).
    ///
    /// Every MESSAGE clears the engine's approval-ceiling door (ONE-1686)
    /// inside that batch's transaction: the bound actor scope must carry
    /// authority for the envelope it presents, and a refusal on any message
    /// lands nothing at all — no message, turn, edge or text posting.
    #[napi]
    pub fn witness(&self, turn: NapiWitnessTurn) -> napi::Result<NapiWitnessReceipt> {
        let engine_turn = witness_turn_to_engine(&turn).map_err(boundary_error)?;
        let receipt = self.facade()?.witness(&engine_turn).map_err(facade_error)?;
        Ok(witness_receipt_from_engine(receipt))
    }

    /// Commits claims, one individually gated write per element; rejected
    /// elements come back with approval `rejected` and persist nothing.
    #[napi]
    pub fn commit(&self, claims: Vec<NapiClaimInput>) -> napi::Result<Vec<NapiCommitReceipt>> {
        let mut engine_claims = Vec::with_capacity(claims.len());
        for claim in &claims {
            engine_claims.push(claim_input_to_engine(claim).map_err(facade_error)?);
        }
        let receipts = self
            .facade()?
            .commit(&engine_claims)
            .map_err(facade_error)?;
        Ok(receipts
            .into_iter()
            .map(commit_receipt_from_engine)
            .collect())
    }

    /// Commits one claim with single-cardinality auto-supersede.
    #[napi]
    pub fn claim_upsert(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        let engine_claim = claim_input_to_engine(&claim).map_err(facade_error)?;
        let receipt = self
            .facade()?
            .claim_upsert(&engine_claim)
            .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Typed convenience: `remember` = claimUpsert with auto-supersede.
    /// NO natural-language parsing on this surface (EF-126 out of chain).
    #[napi]
    pub fn remember(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        self.claim_upsert(claim)
    }

    /// Retracts an active claim by ref.
    #[napi]
    pub fn claim_retract(&self, claim_ref: String) -> napi::Result<NapiCommitReceipt> {
        let receipt = self
            .facade()?
            .claim_retract(&claim_ref)
            .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Typed convenience: retract-with-receipt by short ref or
    /// `{subjectRef, predicate}` selector (all active matches retract).
    #[napi]
    pub fn forget(&self, selector: NapiForgetSelector) -> napi::Result<Vec<NapiCommitReceipt>> {
        let facade = self.facade()?;
        if let Some(short_ref) = &selector.short_ref {
            let receipt = facade.claim_retract(short_ref).map_err(facade_error)?;
            return Ok(vec![commit_receipt_from_engine(receipt)]);
        }
        let (Some(subject_ref), Some(predicate)) = (&selector.subject_ref, &selector.predicate)
        else {
            return Err(boundary_error(
                "forget selector needs shortRef, or subjectRef + predicate".to_owned(),
            ));
        };
        let receipts =
            forget_active_matches(&facade, subject_ref, predicate).map_err(facade_error)?;
        Ok(receipts
            .into_iter()
            .map(commit_receipt_from_engine)
            .collect())
    }

    /// Lists claims by subject/predicate/lifecycle, bounded by `limit`.
    #[napi]
    pub fn claim_list(&self, filter: NapiClaimListFilter) -> napi::Result<Vec<NapiClaimView>> {
        let views = self
            .facade()?
            .claim_list(&ClaimListFilter {
                subject_ref: filter.subject_ref,
                predicate: filter.predicate,
                lifecycle: filter.lifecycle,
                limit: filter.limit as usize,
            })
            .map_err(facade_error)?;
        views
            .into_iter()
            .map(|view| claim_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Supersession timeline for one claim, oldest first.
    #[napi]
    pub fn claim_history(&self, claim_ref: String) -> napi::Result<Vec<NapiClaimView>> {
        let views = self
            .facade()?
            .claim_history(&claim_ref)
            .map_err(facade_error)?;
        views
            .into_iter()
            .map(|view| claim_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Deletes an entity under a NAMED reason (`user_delete` |
    /// `user_hard_delete` | `gdpr_delete` | `policy_delete`). There is no
    /// bool-delete on this surface.
    #[napi]
    pub fn safe_delete(
        &self,
        entity_ref: String,
        reason: String,
    ) -> napi::Result<NapiDeleteReceipt> {
        let reason = SafeDeleteReason::parse(&reason).ok_or_else(|| {
            boundary_error(format!(
                "unknown delete reason {reason:?}; use user_delete, user_hard_delete, gdpr_delete, or policy_delete"
            ))
        })?;
        let receipt = self
            .facade()?
            .safe_delete(&entity_ref, reason)
            .map_err(facade_error)?;
        Ok(NapiDeleteReceipt {
            existed: receipt.existed,
            reason: receipt.reason,
            receipt_ref: receipt.receipt_ref,
        })
    }

    /// Gated writes parked for consent.
    #[napi]
    pub fn pending_writes(&self, limit: u32) -> napi::Result<Vec<NapiPendingWrite>> {
        let records = self
            .facade()?
            .pending_writes(limit as usize)
            .map_err(facade_error)?;
        records
            .into_iter()
            .map(|record| {
                Ok(NapiPendingWrite {
                    claim_ref: record.claim_ref,
                    decision_ref: record.decision_ref,
                    created_at: ts_from_engine(record.created_at, "created_at")
                        .map_err(boundary_error)?,
                    reason_codes: record.reason_codes,
                    dreamer_run_id: record.dreamer_run_id,
                })
            })
            .collect()
    }

    /// Gate decision receipts.
    #[napi]
    pub fn receipts(&self, limit: u32) -> napi::Result<Vec<NapiGateReceipt>> {
        let records = self
            .facade()?
            .receipts(limit as usize)
            .map_err(facade_error)?;
        records
            .into_iter()
            .map(|record| gate_receipt_from_engine(record).map_err(boundary_error))
            .collect()
    }

    /// Hydrates short refs (or hex ids) to full entity views.
    #[napi]
    pub fn hydrate(&self, refs: Vec<String>) -> napi::Result<Vec<NapiEntityView>> {
        let views = self.facade()?.hydrate(&refs).map_err(facade_error)?;
        views
            .into_iter()
            .map(|view| entity_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Reads one entity; `null` when absent.
    #[napi]
    pub fn get_entity(&self, entity_ref: String) -> napi::Result<Option<NapiEntityView>> {
        let view = self
            .facade()?
            .get_entity(&entity_ref)
            .map_err(facade_error)?;
        view.map(|v| entity_view_from_engine(v).map_err(boundary_error))
            .transpose()
    }
}
