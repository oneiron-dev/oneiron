//! Core claim/witness/read verbs of the actor-scoped surface.
//!
//! Each verb that is an SDK row runs its row's verb hooks around the engine
//! call (ARCH-0080 §3), as every other door to the row does.

use napi_derive::napi;
use oneiron::task_verb::sdk::{
    ClaimRefRequest, CommitRequest, EntityRequest, ForgetPredicateRequest, ForgetRequest,
    HydrateRequest, ReceiptsRequest, SafeDeleteRequest, VAULT_RECEIPTS_LIMIT_DEFAULT,
};
use oneiron::task_verb::verb_hook_boundary::typed_row;
use oneiron::{ClaimListFilter, SafeDeleteReason};

use super::boundary::{boundary_error, facade_error, ts_from_engine};
use super::bridge::ActorScopedVault;
use super::convert::{
    claim_view_from_engine, commit_receipt_from_engine, entity_view_from_engine,
    forget_active_matches, gate_receipt_from_engine, read_receipt_from_engine,
    witness_receipt_from_engine, witness_turn_to_engine,
};
use super::dtos::{
    NapiClaimInput, NapiClaimListFilter, NapiClaimViews, NapiCommitReceipt, NapiDeleteReceipt,
    NapiEntityRead, NapiEntityViews, NapiForgetSelector, NapiGateReceipt, NapiPendingWrite,
    NapiWitnessReceipt, NapiWitnessTurn,
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
        let memory = self.facade()?;
        let receipt = typed_row(&memory, "vault.witness", engine_turn, |turn| {
            memory.witness(&turn)
        })
        .map_err(facade_error)?;
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
        let memory = self.facade()?;
        let receipts = typed_row(
            &memory,
            "vault.commit",
            CommitRequest {
                claims: engine_claims,
            },
            |input| memory.commit(&input.claims),
        )
        .map_err(facade_error)?;
        Ok(receipts
            .into_iter()
            .map(commit_receipt_from_engine)
            .collect())
    }

    /// Commits one claim with single-cardinality auto-supersede.
    #[napi]
    pub fn claim_upsert(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        self.upsert_as("vault.claims.upsert", &claim)
    }

    /// Typed convenience: `remember` = claimUpsert with auto-supersede.
    /// NO natural-language parsing on this surface (EF-126 out of chain).
    #[napi]
    pub fn remember(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        self.upsert_as("vault.remember", &claim)
    }

    /// Retracts an active claim by ref.
    #[napi]
    pub fn claim_retract(&self, claim_ref: String) -> napi::Result<NapiCommitReceipt> {
        let memory = self.facade()?;
        let receipt = typed_row(
            &memory,
            "vault.claims.retract",
            ClaimRefRequest { claim_ref },
            |input| memory.claim_retract(&input.claim_ref),
        )
        .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Typed convenience: retract-with-receipt by short ref or
    /// `{subjectRef, predicate}` selector (all active matches retract).
    #[napi]
    pub fn forget(&self, selector: NapiForgetSelector) -> napi::Result<Vec<NapiCommitReceipt>> {
        let request = match selector {
            NapiForgetSelector {
                short_ref: Some(claim_ref),
                ..
            } => ForgetRequest::Claim(ClaimRefRequest { claim_ref }),
            NapiForgetSelector {
                subject_ref: Some(subject_ref),
                predicate: Some(predicate),
                ..
            } => ForgetRequest::Predicate(ForgetPredicateRequest {
                subject_ref,
                predicate,
            }),
            _ => {
                return Err(boundary_error(
                    "forget selector needs shortRef, or subjectRef + predicate".to_owned(),
                ));
            }
        };
        let facade = self.facade()?;
        let receipts = typed_row(&facade, "vault.forget", request, |request| match request {
            ForgetRequest::Claim(claim) => Ok(vec![facade.claim_retract(&claim.claim_ref)?]),
            ForgetRequest::Predicate(predicate) => {
                forget_active_matches(&facade, &predicate.subject_ref, &predicate.predicate)
            }
        })
        .map_err(facade_error)?;
        Ok(receipts
            .into_iter()
            .map(commit_receipt_from_engine)
            .collect())
    }

    /// Lists claims by subject/predicate/lifecycle, bounded by `limit`,
    /// with the read's receipt.
    #[napi]
    pub fn claim_list(&self, filter: NapiClaimListFilter) -> napi::Result<NapiClaimViews> {
        let memory = self.facade()?;
        let filter = ClaimListFilter {
            subject_ref: filter.subject_ref,
            predicate: filter.predicate,
            lifecycle: filter.lifecycle,
            limit: filter.limit as usize,
        };
        let views = typed_row(&memory, "vault.claims.list", filter, |filter| {
            memory.claim_list(&filter)
        })
        .map_err(facade_error)?;
        claim_views_from_engine(views)
    }

    /// Supersession timeline for one claim, oldest first, with the read's
    /// receipt.
    #[napi]
    pub fn claim_history(&self, claim_ref: String) -> napi::Result<NapiClaimViews> {
        let memory = self.facade()?;
        let views = typed_row(
            &memory,
            "vault.claims.history",
            ClaimRefRequest { claim_ref },
            |input| memory.claim_history(&input.claim_ref),
        )
        .map_err(facade_error)?;
        claim_views_from_engine(views)
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
        let memory = self.facade()?;
        let receipt = typed_row(
            &memory,
            "vault.delete",
            SafeDeleteRequest { entity_ref, reason },
            |input| memory.safe_delete(&input.entity_ref, input.reason),
        )
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
        let memory = self.facade()?;
        let records = typed_row(
            &memory,
            "vault.writes.pending",
            ReceiptsRequest {
                limit: Some(limit as usize),
            },
            |input| memory.pending_writes(input.limit.unwrap_or(VAULT_RECEIPTS_LIMIT_DEFAULT)),
        )
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
        let memory = self.facade()?;
        let records = typed_row(
            &memory,
            "vault.receipts",
            ReceiptsRequest {
                limit: Some(limit as usize),
            },
            |input| memory.receipts(input.limit.unwrap_or(VAULT_RECEIPTS_LIMIT_DEFAULT)),
        )
        .map_err(facade_error)?;
        records
            .into_iter()
            .map(|record| gate_receipt_from_engine(record).map_err(boundary_error))
            .collect()
    }

    /// Hydrates short refs (or hex ids) to full entity views, with the
    /// read's receipt.
    #[napi]
    pub fn hydrate(&self, refs: Vec<String>) -> napi::Result<NapiEntityViews> {
        let memory = self.facade()?;
        let views = typed_row(&memory, "vault.hydrate", HydrateRequest { refs }, |input| {
            memory.hydrate(&input.refs)
        })
        .map_err(facade_error)?;
        Ok(NapiEntityViews {
            value: views
                .value
                .into_iter()
                .map(|view| entity_view_from_engine(view).map_err(boundary_error))
                .collect::<napi::Result<_>>()?,
            narrowing: read_receipt_from_engine(views.receipt).map_err(boundary_error)?,
        })
    }

    /// Reads one entity; `value` is `null` when absent or withheld, and the
    /// receipt says which.
    #[napi]
    pub fn get_entity(&self, entity_ref: String) -> napi::Result<NapiEntityRead> {
        let memory = self.facade()?;
        let view = typed_row(
            &memory,
            "vault.get",
            EntityRequest { entity_ref },
            |input| memory.get_entity(&input.entity_ref),
        )
        .map_err(facade_error)?;
        Ok(NapiEntityRead {
            value: view
                .value
                .map(|view| entity_view_from_engine(view).map_err(boundary_error))
                .transpose()?,
            narrowing: read_receipt_from_engine(view.receipt).map_err(boundary_error)?,
        })
    }
}

impl ActorScopedVault {
    /// One claim with single-cardinality auto-supersede, as row `verb`.
    fn upsert_as(&self, verb: &str, claim: &NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        let engine_claim = claim_input_to_engine(claim).map_err(facade_error)?;
        let memory = self.facade()?;
        let receipt = typed_row(&memory, verb, engine_claim, |claim| {
            memory.claim_upsert(&claim)
        })
        .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }
}

fn claim_views_from_engine(
    views: oneiron::claim::ScopedReadResult<Vec<oneiron::ClaimView>>,
) -> napi::Result<NapiClaimViews> {
    Ok(NapiClaimViews {
        value: views
            .value
            .into_iter()
            .map(|view| claim_view_from_engine(view).map_err(boundary_error))
            .collect::<napi::Result<_>>()?,
        narrowing: read_receipt_from_engine(views.receipt).map_err(boundary_error)?,
    })
}
