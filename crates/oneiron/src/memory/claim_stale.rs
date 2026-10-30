//! Stale-claim producer and caller read-filter controls (RETRIEVAL-04).
//!
//! The producer is the claim demotion ladder as a caller door: decay,
//! weaken, or mark stale, through the caller's own credential with the
//! same in-transaction authority as retraction. The read doors carry the
//! caller's full retrieval filter into the scoped lane, which narrows it
//! against the actor ceiling and returns the narrowing receipt.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::read_lane::fold_receipt;
use super::support::*;
use super::*;

use crate::claim::{
    ClaimDemotionAction, ClaimDemotionRung, ClaimLifecycleStatus, ClaimReadStatus, PointRead,
    ScopedReadResult,
};
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::registry::ENTITY_TYPE_CLAIM;

/// Claim ids read per lane read while listing: a bounded list stops early.
const FILTERED_LIST_READ_CHUNK: usize = 256;

/// Caller-supplied retrieval constraints, the wire form of
/// [`crate::gate::RetrievalFilter`]. Unset fields inherit the actor
/// ceiling; a request only narrows, never widens past it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadFilterInput {
    /// Restrict to these entity types, each as its registry kind
    /// (`CLAIM`, `MESSAGE`, ...), the spelling a read receipt's scope uses.
    #[serde(default, with = "oneiron_contracts::serialize::type_kinds")]
    #[schemars(with = "Option<Vec<String>>")]
    pub entity_types: Option<BTreeSet<u8>>,
    /// Sensitivity ceiling, in 0..=3.
    #[serde(default)]
    pub max_sensitivity_band: Option<u8>,
    /// Ask for stale claims; the ceiling still decides.
    #[serde(default)]
    pub include_stale: Option<bool>,
    /// Drop claims below this confidence, in [0, 1].
    #[serde(default)]
    pub min_confidence: Option<f32>,
    /// Drop claims below this salience, in [0, 1].
    #[serde(default)]
    pub min_salience: Option<f32>,
}

impl ReadFilterInput {
    fn to_filter(&self) -> crate::gate::RetrievalFilter {
        crate::gate::RetrievalFilter {
            entity_types: self.entity_types.clone(),
            max_sensitivity_band: self.max_sensitivity_band,
            include_stale: self.include_stale,
            min_confidence: self.min_confidence,
            min_salience: self.min_salience,
        }
    }
}

/// One demotion rung, as the caller names it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimDemoteActionInput {
    /// Lower the claim_of edge weight in place.
    Decay {
        /// The new claim_of weight; never above the current one.
        new_claim_of_weight: f32,
    },
    /// Supersede with a successor at a lower confidence.
    Weaken {
        /// The successor's confidence; never above the current one.
        new_confidence: f32,
    },
    /// Mark the claim stale in place: retrieval stops surfacing it
    /// unless a read's applied filter includes stale claims.
    Stale,
}

/// `vault.claims.demote` input: one claim, one rung.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimDemoteRequest {
    /// Claim short ref or 32-hex id.
    pub claim_ref: String,
    /// The rung to apply.
    pub action: ClaimDemoteActionInput,
}

/// One applied demotion: the rung now carried and the claim carrying it.
/// A weakening supersedes, so its `claim_ref` is the successor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimDemoteView {
    /// 32-hex id of the claim that now carries the rung.
    pub claim_ref: String,
    /// Short-id ref, when assigned.
    pub short_ref: Option<String>,
    /// `decayed`, `weakened` or `stale`.
    pub rung: String,
    /// Whether the carrying claim is stale.
    pub stale: bool,
    /// Receipt ref for this demotion.
    pub receipt_ref: String,
}

/// `vault.claims.list_filtered` input: the list selectors plus the
/// caller's retrieval filter.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimFilteredListRequest {
    /// Restrict to claims on this subject (short-id ref or hex).
    #[serde(default)]
    pub subject_ref: Option<String>,
    /// Restrict to this predicate.
    #[serde(default)]
    pub predicate: Option<String>,
    /// Restrict to this lifecycle (`active`/`superseded`/`retracted`).
    #[serde(default)]
    pub lifecycle: Option<String>,
    /// Maximum results (required; no unbounded scans).
    pub limit: usize,
    /// Caller retrieval filter; met with the actor ceiling.
    #[serde(default)]
    pub filter: Option<ReadFilterInput>,
}

/// `vault.claims.read_filtered` input: one claim under a caller filter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimFilteredReadRequest {
    /// Claim short ref or 32-hex id.
    pub claim_ref: String,
    /// Caller retrieval filter; met with the actor ceiling.
    #[serde(default)]
    pub filter: Option<ReadFilterInput>,
}

impl Memory<'_> {
    /// Demotes one active claim by one rung through the caller's own
    /// credential. Authority matches retraction, judged inside the write
    /// transaction: the authenticated writing actor, a system actor, or a
    /// verified human vault owner; everyone else is refused. The stale
    /// rung is the producer RETRIEVAL-04 needs: it marks the claim in
    /// place, so surfaceable reads stop returning it while the record
    /// verbs keep serving it as history.
    pub fn claim_demote(&self, input: &ClaimDemoteRequest) -> MemoryResult<ClaimDemoteView> {
        let id = self.resolve_ref(&input.claim_ref)?;
        let action = match input.action {
            ClaimDemoteActionInput::Decay {
                new_claim_of_weight,
            } => ClaimDemotionAction::Decay {
                new_claim_of_weight,
            },
            ClaimDemoteActionInput::Weaken { new_confidence } => {
                ClaimDemotionAction::Weaken { new_confidence }
            }
            ClaimDemoteActionInput::Stale => ClaimDemotionAction::MarkStale,
        };
        let now = self.vault.store.clock.now_recorded_at();
        let demotion = self.with_verified_actor_write_txn(|wtxn| {
            let body = self
                .vault
                .claim_for_restriction_in_txn(wtxn, &id)?
                .ok_or(Error::EntityNotFound)?;
            if crate::claim::is_expression_preference_predicate(&body.predicate) {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "an expression preference is demoted through its own door, not the general one",
                    &["Use the vault's typed expression-preference door."],
                ));
            }
            let owns_claim = crate::batch::authenticated_claim_author_in_txn(
                &self.vault.store,
                wtxn,
                &id,
                &body,
            )?
            .is_some_and(|author| author.entity_ref() == self.actor);
            if self.actor_class == EdgeActorClass::System || owns_claim {
                require_claim_self_grant_in_txn(
                    self.vault,
                    wtxn,
                    crate::WriteActor::new(self.actor, self.actor_class),
                    id,
                    &body,
                    "memory.claim.demote",
                )?;
            } else if self.actor_class == EdgeActorClass::Human {
                verify_owner_actor_binding_in_txn(self.vault, wtxn, self.actor)?;
            } else {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    format!(
                        "actor {} ({}) may not demote a claim it did not write",
                        self.actor.to_hex(),
                        self.actor_class.gate_actor_class(),
                    ),
                    &[
                        "Only the writing actor or a human-class owner actor may demote.",
                        "Bind the owner actor key for cross-actor demotion.",
                    ],
                ));
            }
            Ok(self
                .vault
                .apply_claim_demotion_in_txn(wtxn, &id, action, now)?)
        })?;
        let rung = match demotion.rung {
            ClaimDemotionRung::Decayed => "decayed",
            ClaimDemotionRung::Weakened => "weakened",
            ClaimDemotionRung::Stale => "stale",
        };
        Ok(ClaimDemoteView {
            claim_ref: demotion.claim.to_hex(),
            short_ref: self.short_ref_of(&demotion.claim)?,
            rung: rung.to_owned(),
            stale: demotion.rung == ClaimDemotionRung::Stale,
            receipt_ref: self
                .latest_decision_ref_for(&demotion.claim)?
                .unwrap_or_else(|| format!("demote:{}", demotion.claim.to_hex())),
        })
    }

    /// Lists surfaceable claims under the caller's retrieval filter,
    /// narrowed against the actor ceiling in the lane. Unlike the record
    /// list, this door serves only what retrieval may surface: approved
    /// or auto, active, and stale only when the applied filter includes
    /// stale claims. The receipt states requested, ceiling and applied.
    pub fn claim_list_filtered(
        &self,
        request: &ClaimFilteredListRequest,
    ) -> MemoryResult<ScopedReadResult<Vec<ClaimView>>> {
        if request.limit == 0 {
            return Err(MemoryError::bad_request(
                "claim_list_filtered limit must be at least 1",
            ));
        }
        let lifecycle = match request.lifecycle.as_deref() {
            Some(value) => Some(ClaimLifecycleStatus::parse(value).ok_or_else(|| {
                MemoryError::bad_request_with(
                    format!("unknown lifecycle {value:?}"),
                    &["Use one of: active, superseded, retracted."],
                )
            })?),
            None => None,
        };
        let filter = request.filter.as_ref().map(ReadFilterInput::to_filter);
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let ids = match &request.subject_ref {
            Some(subject_ref) => {
                let subject = self.resolve_ref_in_lane(&lane, subject_ref)?;
                self.vault.claims_for_subject(&subject)?
            }
            None => self.vault.entities_by_type(ENTITY_TYPE_CLAIM)?,
        };
        let mut receipt = None;
        let mut views = Vec::new();
        for chunk in ids.chunks(FILTERED_LIST_READ_CHUNK) {
            if views.len() >= request.limit {
                break;
            }
            let reads: Vec<_> = chunk.iter().copied().map(PointRead::id).collect();
            let ScopedReadResult {
                value,
                receipt: read,
            } = lane.read(&reads, filter.as_ref())?;
            fold_receipt(&mut receipt, read);
            for row in value.into_iter().flatten() {
                if views.len() >= request.limit {
                    break;
                }
                let Some(bytes) = row.body.as_deref() else {
                    continue;
                };
                let body = crate::claim::decode_claim_body(bytes, true)?;
                if request
                    .predicate
                    .as_ref()
                    .is_some_and(|predicate| body.predicate != *predicate)
                    || lifecycle.is_some_and(|lifecycle| body.lifecycle != lifecycle)
                {
                    continue;
                }
                views.push(self.served_claim_view(&row.id, &body)?);
            }
        }
        let receipt = match receipt {
            Some(receipt) => receipt,
            None => lane.read_receipt(filter.as_ref(), 0)?,
        };
        Ok(ScopedReadResult {
            value: views,
            receipt,
        })
    }

    /// Reads one claim as retrieval would surface it, under the caller's
    /// retrieval filter met with the actor ceiling. `None` when absent
    /// or withheld; the receipt says which axes narrowed.
    pub fn claim_read_filtered(
        &self,
        request: &ClaimFilteredReadRequest,
    ) -> MemoryResult<ScopedReadResult<Option<ClaimView>>> {
        let filter = request.filter.as_ref().map(ReadFilterInput::to_filter);
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let id = self.resolve_ref_in_lane(&lane, &request.claim_ref)?;
        let ScopedReadResult { value, receipt } =
            lane.read(&[PointRead::id(id)], filter.as_ref())?;
        let view = match value.into_iter().next().flatten() {
            Some(row) => match row.body.as_deref() {
                Some(bytes) => {
                    let body = crate::claim::decode_claim_body(bytes, true)?;
                    Some(self.served_claim_view(&row.id, &body)?)
                }
                None => None,
            },
            None => None,
        };
        Ok(ScopedReadResult {
            value: view,
            receipt,
        })
    }
}
