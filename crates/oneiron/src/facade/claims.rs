//! Claim lifecycle verbs: commit/upsert/retract, safe delete, and the
//! internal commit-decision plumbing (gate request/resubmit, supersession).
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::support::*;
use super::*;

use std::sync::atomic::Ordering;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::batch::{ApplyOpsGateMode, BatchOp, apply_ops_with_gate_mode};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::companion::companion_value_to_json;
use crate::deletion::{DeleteReason, DeletionGateContext};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};
use crate::temporal::TimeRange;
use crate::write_envelope::{
    ClaimCandidate, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WriteActor, WriteEnvelope, WriteProvenance,
};

/// Predicates with declared multi-cardinality supersession keys (B1c,
/// RATIFY-20260710 R0): the prior-claim match extends
/// `subject+scope+predicate` with `value.question_id`.
pub const MULTI_CARDINALITY_PREDICATES: [&str; 1] = ["eiri.onboarding.answer"];

const MULTI_CARDINALITY_VALUE_KEY: &str = "question_id";

/// One claim to commit. `approval` is deliberately NOT settable by callers
/// (pin 2); the facade computes the request and the gate decides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimInput {
    /// Caller-supplied deterministic 32-hex claim id; `None` ⇒ generated.
    /// Load-bearing for ONE-258's idempotent backfill.
    pub id: Option<String>,
    /// Dotted predicate (open vocabulary; `edge.*` reserved).
    pub predicate: String,
    /// Subject entity ref (short-id ref or 32-hex).
    pub subject_ref: String,
    /// Claim value (JSON, stored as MessagePack).
    pub value: serde_json::Value,
    /// Calibrated-absolute confidence in `[0, 1]`.
    pub confidence: f32,
    /// `ClaimSource::as_str` value: `user_stated`/`observed`/`inferred`/
    /// `imported`/`tool_output`/`generated`.
    pub source: String,
    /// Optional WORLD entity ref.
    pub world_ref: Option<String>,
    /// Optional scope map (e.g. `{"sensitivity": 0}`).
    pub scope: Option<serde_json::Value>,
    /// Validity window start (Unix seconds).
    pub valid_from: Option<u64>,
    /// Validity window end (Unix seconds).
    pub valid_to: Option<u64>,
    /// Backdating passthrough; `None` ⇒ now (Unix seconds).
    pub occurred_at: Option<u64>,
    /// Backdating passthrough; `None` ⇒ now (Unix seconds).
    pub learned_at: Option<u64>,
    /// Optional salience in `[0, 1]`.
    pub salience: Option<f32>,
}

/// Receipt for one committed (or rejected) claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitReceipt {
    /// Short-id ref of the written claim. For a rejected element (approval
    /// `rejected`) no entity exists; this carries the caller-supplied id
    /// hex (or empty when the id itself was invalid).
    pub claim_short_id: String,
    /// Final approval as stored: `auto`/`proposed` (or `rejected` when the
    /// element did not persist).
    pub approval: String,
    /// Short-id ref of the claim this write superseded, if any.
    pub superseded_short_id: Option<String>,
    /// Gate decision ref (`gate:<decision-hex>`) resolvable via
    /// [`MemoryFacade::receipts`]; falls back to a facade marker when no
    /// decision exists (e.g. rejected before the gate ran).
    pub receipt_ref: String,
}

/// Named deletion reasons (S7). There is deliberately NO bare bool delete on
/// this surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeDeleteReason {
    /// Tombstone delete: local body scrubbed to a shell, no receipt.
    UserDelete,
    /// Hard purge + redaction audit receipt + historical sweep.
    UserHardDelete,
    /// Compliance erase (soft-erase pass + purge + receipt + sweep).
    GdprDelete,
    /// Policy-driven erase (same machinery as GDPR).
    PolicyDelete,
}

impl SafeDeleteReason {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDelete => "user_delete",
            Self::UserHardDelete => "user_hard_delete",
            Self::GdprDelete => "gdpr_delete",
            Self::PolicyDelete => "policy_delete",
        }
    }

    /// Parses the stable string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user_delete" => Some(Self::UserDelete),
            "user_hard_delete" => Some(Self::UserHardDelete),
            "gdpr_delete" => Some(Self::GdprDelete),
            "policy_delete" => Some(Self::PolicyDelete),
            _ => None,
        }
    }

    const fn delete_reason(self) -> DeleteReason {
        match self {
            Self::UserDelete => DeleteReason::UserDelete,
            Self::UserHardDelete => DeleteReason::UserHardDelete,
            Self::GdprDelete => DeleteReason::GdprDelete,
            Self::PolicyDelete => DeleteReason::PolicyDelete,
        }
    }
}

/// Receipt for one safe delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteReceipt {
    /// Whether the entity existed before the delete.
    pub existed: bool,
    /// The reason the delete was performed under.
    pub reason: String,
    /// Redaction audit receipt ref (`redaction:<hex>`); `None` for
    /// `user_delete`, which writes no receipt entity by design.
    pub receipt_ref: Option<String>,
}

/// One pending gated write awaiting consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWrite {
    /// 32-hex id of the parked claim.
    pub claim_ref: String,
    /// Gate decision ref (`gate:<hex>`).
    pub decision_ref: String,
    /// Unix seconds the decision was recorded.
    pub created_at: u64,
    /// Gate reason codes (e.g. `gate.pending.actor_ceiling`).
    pub reason_codes: Vec<String>,
    /// Dreamer run lane, when the write came from a consolidation run.
    pub dreamer_run_id: Option<String>,
}

/// One gate decision receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacadeReceipt {
    /// Stable ref (`gate:<decision-hex>`).
    pub receipt_ref: String,
    /// Gate outcome: `allow`/`pending`/`deny`.
    pub outcome: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Gate reason codes.
    pub reason_codes: Vec<String>,
    /// Actor class string the decision was made for.
    pub actor_class: String,
    /// Actor entity hex, when the write carried an envelope.
    pub actor_ref: Option<String>,
    /// Gate content kind (e.g. `claim`).
    pub content_kind: String,
    /// 32-hex id of the claim the decision covers, if any.
    pub claim_ref: Option<String>,
}

pub(super) fn parse_claim_source(value: &str) -> FacadeResult<ClaimSource> {
    ClaimSource::parse(value).ok_or_else(|| {
        FacadeError::bad_request_with(
            format!("unknown claim source {value:?}"),
            &["Use one of: user_stated, observed, inferred, imported, tool_output, generated."],
        )
    })
}

impl MemoryFacade<'_> {
    fn evaluate_deletion_gate(&self) -> FacadeResult<DeletionGateContext> {
        let rtxn = self.vault.store.env.read_txn().map_err(Error::from)?;
        verify_deletion_authority_in_txn(self.vault, &rtxn, self.actor, self.actor_class)?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &rtxn)?;
        Ok(DeletionGateContext::new(
            self.actor,
            self.actor_class,
            crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            policy.read_frontier_hash()?,
        ))
    }

    /// Commits claims through the gated candidate path, one individually
    /// gated write per element (C3: per-element decisions; one bad element
    /// never sinks the others). Rejected elements come back with approval
    /// `rejected` and do not persist.
    pub fn commit(&self, claims: &[ClaimInput]) -> FacadeResult<Vec<CommitReceipt>> {
        Ok(self.commit_all(claims, true, None))
    }

    /// Commits one claim with single-cardinality auto-supersede (S3):
    /// prior Active claim matching `subject+scope+predicate` (plus
    /// `value.question_id` for declared multi-cardinality predicates, B1c)
    /// is superseded by the new revision.
    pub fn claim_upsert(&self, input: &ClaimInput) -> FacadeResult<CommitReceipt> {
        self.commit_one(input, true, None)
    }

    /// Retracts an active claim (deliberate withdrawal; record preserved).
    ///
    /// Authority (fail-closed): the asserted actor is RESOLVED against the
    /// store in the SAME write transaction as the lifecycle change. A verified
    /// `human`-class actor holds the vault owner's memory authority and
    /// may retract any claim; `agent`/`system` actors may retract ONLY
    /// claims whose write-envelope evidence names them as the writing
    /// actor. Everything else is a typed denial — binding an actor key is
    /// not authority (W3).
    ///
    /// Actor binding, authorship, pending-consent closure, gate receipt, and
    /// lifecycle transition share one write transaction, so a same-id
    /// intervening writer cannot turn prior authorization into authority over
    /// the replacement body or recreate actionable pending consent.
    pub fn claim_retract(&self, claim_ref: &str) -> FacadeResult<CommitReceipt> {
        self.claim_retract_with_before_txn(claim_ref, || {})
    }

    fn claim_retract_with_before_txn(
        &self,
        claim_ref: &str,
        before_txn: impl FnOnce(),
    ) -> FacadeResult<CommitReceipt> {
        let id = self.resolve_ref(claim_ref)?;
        let now = crate::unix_seconds_now();
        before_txn();
        let (approval, consent_decision_id) = self.vault.try_with_write_txn(|wtxn| {
            verify_actor_binding_in_txn(self.vault, wtxn, self.actor, self.actor_class)?;
            let body = self
                .vault
                .get_claim_in_txn(wtxn, &id)?
                .ok_or(Error::EntityNotFound)?;
            // Retracting your OWN claim is not an owner power and needs no
            // owner binding; retracting SOMEONE ELSE'S is, so it gets the
            // authority-log teeth.
            if claim_envelope_actor(&body) != Some(self.actor) {
                if self.actor_class != EdgeActorClass::Human {
                    return Err(FacadeError::new(
                        FACADE_CODE_FORBIDDEN,
                        format!(
                            "actor {} ({}) may not retract a claim it did not write",
                            self.actor.to_hex(),
                            self.actor_class.gate_actor_class(),
                        ),
                        &[
                            "Only the writing actor or a human-class owner actor may retract.",
                            "Bind the owner actor key for cross-actor retraction.",
                        ],
                    ));
                }
                verify_owner_actor_binding_in_txn(self.vault, &*wtxn, self.actor)?;
            }
            let consent_receipt = self.vault.retract_claim_in_txn(wtxn, &id, now)?;
            let approval = self.vault.get_claim_in_txn(wtxn, &id)?.map_or_else(
                || "retracted".to_owned(),
                |body| body.approval.as_str().to_owned(),
            );
            Ok((approval, consent_receipt.map(|record| record.decision_id)))
        })?;
        let receipt_ref = match consent_decision_id {
            Some(decision_id) => format!("gate:{}", decision_id.to_hex()),
            None => self
                .latest_decision_ref_for(&id)?
                .unwrap_or_else(|| format!("retract:{}", id.to_hex())),
        };
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval,
            superseded_short_id: None,
            receipt_ref,
        })
    }

    #[cfg(test)]
    pub(super) fn witness_with_pre_txn_hook(
        &self,
        turn: &WitnessTurn,
        before_txn: impl FnOnce(),
    ) -> FacadeResult<WitnessReceipt> {
        self.witness_with_route_and_before_txn(turn, None, before_txn)
    }

    #[cfg(test)]
    pub(super) fn claim_retract_with_pre_txn_hook(
        &self,
        claim_ref: &str,
        before_txn: impl FnOnce(),
    ) -> FacadeResult<CommitReceipt> {
        self.claim_retract_with_before_txn(claim_ref, before_txn)
    }

    #[cfg(test)]
    pub(super) fn claim_upsert_with_pre_txn_hook(
        &self,
        input: &ClaimInput,
        before_txn: impl FnOnce(),
    ) -> FacadeResult<CommitReceipt> {
        self.commit_one_with_before_txn(input, true, None, before_txn)
    }

    /// Deletes an entity under a NAMED reason (S7). `user_delete` is the
    /// tombstone path; the other three run the redaction-audit machinery.
    ///
    /// Authority (fail-closed): deletion is an OWNER verb — the named
    /// reasons are `user_*`/compliance erasures. Only a VERIFIED
    /// `human`-class actor may delete (`Self::verified_actor_class`:
    /// the asserted actor must exist and be a PERSON — asserted class
    /// strings are never trusted); `agent`/`system` actors get a typed
    /// denial (agents withdraw their own claims via
    /// [`Self::claim_retract`]).
    ///
    /// The owner gate is evaluated before deletion TXN1. Sync-enabled deletes
    /// durably stage an authority-required marker + request-keyed recovery
    /// sidecar before the tombstone can commit; TXN3 consumes that sidecar
    /// with `append_gate_decision_in_txn` alongside the purge and distinct
    /// REDACTION_AUDIT execution receipt. Sync-disabled builds append directly
    /// on their first local scrub/purge.
    pub fn safe_delete(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
    ) -> FacadeResult<DeleteReceipt> {
        let gate = self.evaluate_deletion_gate()?;
        let id = self.resolve_ref(entity_ref)?;
        // The re-check the destructive transactions re-run against their OWN
        // views (fix-leg 5 item 1). `FacadeError` is a binding-layer type the
        // engine's `Result` cannot carry, so the refusal is PARKED here and the
        // engine is handed the accurate typed stand-in: a concurrent write
        // invalidated the snapshot the gate decided on. `safe_delete` then swaps
        // the parked error back, so a caller sees the EXACT code and message the
        // pre-transaction gate would have produced (FORBIDDEN for a revoked
        // binding, INVALID_STATE for a broken authority log) rather than a
        // second, weaker vocabulary for the same refusal.
        let refusal: std::cell::RefCell<Option<FacadeError>> = std::cell::RefCell::new(None);
        let reverify = |txn: &heed::RoTxn<'_>| -> Result<(), Error> {
            verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class).map_err(
                |err| {
                    *refusal.borrow_mut() = Some(err);
                    Error::ConcurrentWrite(
                        "deletion authority changed before the destructive commit",
                    )
                },
            )
        };
        let outcome = self
            .vault
            .delete_entity_with_reason_gated(
                &id,
                reason.delete_reason(),
                crate::deletion::GatedDeletion::new(gate, &reverify),
            )
            .map_err(|err| refusal.take().unwrap_or_else(|| FacadeError::from(err)))?;
        Ok(DeleteReceipt {
            existed: outcome.existed,
            reason: reason.as_str().to_owned(),
            receipt_ref: outcome
                .receipt_id
                .map(|receipt| format!("redaction:{}", receipt.to_hex())),
        })
    }

    // ── internals ───────────────────────────────────────────────────────

    pub(super) fn commit_all(
        &self,
        claims: &[ClaimInput],
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
    ) -> Vec<CommitReceipt> {
        let mut receipts = Vec::with_capacity(claims.len());
        for input in claims {
            match self.commit_one(input, auto_supersede, forced_approval) {
                Ok(receipt) => receipts.push(receipt),
                Err(err) => receipts.push(CommitReceipt {
                    claim_short_id: input.id.clone().unwrap_or_default(),
                    approval: "rejected".to_owned(),
                    superseded_short_id: None,
                    receipt_ref: format!("rejected:{}", err.code),
                }),
            }
        }
        receipts
    }

    fn commit_one(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
    ) -> FacadeResult<CommitReceipt> {
        self.commit_one_with_before_txn(input, auto_supersede, forced_approval, || {})
    }

    /// Upserts one claim, running `before_txn` in the window between the
    /// ADVISORY prior-claim lookup and the write transaction.
    ///
    /// That window is the race the in-txn guard closes: the prior discovered
    /// outside the transaction may have moved by the time the transaction
    /// runs. The seam exists so a test can move it deliberately; production
    /// callers pass a no-op.
    fn commit_one_with_before_txn(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
        before_txn: impl FnOnce(),
    ) -> FacadeResult<CommitReceipt> {
        self.verified_actor_class()?;
        let id = id_from_optional_hex(input.id.as_deref())?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self.vault.get_entity_type(&subject)?.is_none() {
            return Err(FacadeError::not_found(format!(
                "claim subject {} does not exist",
                subject.to_hex()
            )));
        }
        let source = parse_claim_source(&input.source)?;
        let value = json_to_rmpv(&input.value);
        let world = match &input.world_ref {
            Some(world_ref) => Some(self.resolve_ref(world_ref)?),
            None => None,
        };
        let scope_rmpv = input.scope.as_ref().map(json_to_rmpv);
        let now = crate::unix_seconds_now();
        let occurred_at = input.occurred_at.unwrap_or(now);
        let learned_at = input.learned_at.unwrap_or(now);

        // ADVISORY only (ONE-1936): this lookup runs outside the transaction,
        // so the prior it names may already be closed by the time the write
        // txn opens. The authority is `supersede_claim_in_txn`'s guard, inside
        // that txn — and a refusal there rolls the staged replacement back
        // with it.
        let prior = if auto_supersede {
            self.find_prior_claim(&subject, input, &id)?
        } else {
            None
        };
        before_txn();

        let mut approval =
            forced_approval.unwrap_or_else(|| requested_approval(source, input.scope.as_ref()));
        // Every commit is ONE engine transaction: gate decision, claim
        // write, and (with a prior revision) the supersession commit or
        // roll back together. No phantom receipts (a decision can never
        // outlive a write that failed later validation) and no orphan
        // revisions behind a rejected receipt. The fail-closed trade: a
        // rolled-back write also drops its gate decision.
        let write = |approval: ClaimApprovalStatus| -> Result<bool, Error> {
            let mut candidate = ClaimCandidate::new(
                input.predicate.clone(),
                ClaimSubject::Entity(subject),
                value.clone(),
                input.confidence,
            )
            .with_validity(input.valid_from, input.valid_to);
            if let Some(salience) = input.salience {
                candidate = candidate.with_salience(salience);
            }
            if let Some(world) = world {
                candidate = candidate.with_world(world);
            }
            if let Some(scope) = scope_rmpv.clone() {
                candidate = candidate.with_scope(scope);
            }
            let envelope = WriteEnvelope::new(
                WriteActor::new(self.actor, self.actor_class),
                source,
                WriteProvenance::new(facade_provenance("commit"))?,
                approval,
            );
            let occurred = TimeRange {
                start: occurred_at,
                end: occurred_at,
            };
            self.vault.with_write_txn(|wtxn| {
                if self
                    .vault
                    .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
                {
                    return Ok(true);
                }
                apply_ops_with_gate_mode(
                    &self.vault.store,
                    &self.vault.config,
                    &self.vault.analyzer,
                    wtxn,
                    vec![BatchOp::ClaimCandidate {
                        id,
                        candidate: Box::new(candidate),
                        envelope,
                        occurred,
                        learned_at,
                        internal_lexical_query_hint: false,
                    }],
                    self.vault.text_index_trusted.load(Ordering::Acquire),
                    ApplyOpsGateMode::new(true, true),
                )?;
                if let Some(old_id) = prior {
                    self.vault
                        .supersede_claim_in_txn(wtxn, &id, &old_id, learned_at)?;
                }
                Ok(false)
            })
        };
        let refused = match write(approval) {
            Ok(refused) => refused,
            Err(err)
                if approval == ClaimApprovalStatus::Auto
                    && err.kind() == ErrorKind::GateWriteRejected =>
            {
                approval = ClaimApprovalStatus::Proposed;
                write(approval)?
            }
            Err(err) => return Err(err.into()),
        };
        if refused {
            return Err(hard_deleted_refusal(&id));
        }

        let superseded_short_id = match prior {
            Some(old_id) => Some(self.short_ref_or_hex(&old_id)?),
            None => None,
        };
        let final_approval = self.vault.get_claim(&id)?.map_or_else(
            || approval.as_str().to_owned(),
            |b| b.approval.as_str().to_owned(),
        );
        let receipt_ref = self
            .latest_decision_ref_for(&id)?
            .unwrap_or_else(|| format!("claim:{}", id.to_hex()));
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval: final_approval,
            superseded_short_id,
            receipt_ref,
        })
    }

    /// Prior-claim match for auto-supersede: `subject+scope+predicate`,
    /// extended with `value.question_id` for declared multi-cardinality
    /// predicates (B1c). Deterministic when multiple actives match: the
    /// newest id (UUIDv7 order) wins.
    fn find_prior_claim(
        &self,
        subject: &EntityId,
        input: &ClaimInput,
        exclude: &EntityId,
    ) -> FacadeResult<Option<EntityId>> {
        let multi_key = if MULTI_CARDINALITY_PREDICATES.contains(&input.predicate.as_str()) {
            Some(input.value.get(MULTI_CARDINALITY_VALUE_KEY).cloned())
        } else {
            None
        };
        let new_scope = input.scope.clone();
        let ids = self.vault.claims_for_subject(subject)?;
        let mut best: Option<EntityId> = None;
        for id in ids {
            if id == *exclude {
                continue;
            }
            let Some(body) = self.vault.get_claim(&id)? else {
                continue;
            };
            if body.lifecycle != ClaimLifecycleStatus::Active || body.predicate != input.predicate {
                continue;
            }
            let prior_scope = body.scope.as_ref().map(companion_value_to_json);
            if prior_scope != new_scope {
                continue;
            }
            if let Some(new_qid) = &multi_key {
                let prior_value = companion_value_to_json(&body.value);
                let prior_qid = prior_value.get(MULTI_CARDINALITY_VALUE_KEY).cloned();
                if prior_qid != *new_qid {
                    continue;
                }
            }
            best = match best {
                Some(current) if current.to_hex() >= id.to_hex() => Some(current),
                _ => Some(id),
            };
        }
        Ok(best)
    }
}

/// Extracts the write-envelope actor stamped into a claim's evidence
/// (gated candidate path). `None` for claims written without an envelope.
fn claim_envelope_actor(body: &ClaimBody) -> Option<EntityId> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    for (key, value) in entries {
        if key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)
            && let Value::Binary(bytes) = value
        {
            let raw: [u8; 16] = bytes.as_slice().try_into().ok()?;
            return EntityId::from_bytes(raw).ok();
        }
    }
    None
}
