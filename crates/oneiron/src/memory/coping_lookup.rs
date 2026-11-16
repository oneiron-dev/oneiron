//! Nearest-state coping lookup over the coping ledger (affect-ei: "Coping
//! lookup is nearest-state. Given the current turn-VAD, query
//! `coping.outcome` for the nearest state by PAD distance, rank by (worked,
//! recency, confidence); below the manifest's cold-start outcome floor the
//! ledger falls back to generic regulation priors at low confidence").

use std::cmp::Ordering;

use super::coping_doors::{
    AdmittedCopingHead, CopingLookup, CopingLookupBasis, CopingLookupOutcome, CopingLookupRequest,
    CopingPrior, require_readable,
};
use super::{ClaimScope, Memory, MemoryError, MemoryResult};
use crate::affect::Vad;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::consent::AuthenticatedOwner;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::write_envelope::coping_outcome::CopingStrategy;
use crate::{EntityId, Error};

/// The outcome count below which the ledger answers generic priors: the
/// starting value of the manifest's `affect_lookup.cold_start_min_outcomes`.
pub(crate) const COPING_COLD_START_MIN_OUTCOMES: u64 = 3;

/// The confidence every generic regulation prior carries: the Low band of
/// the house ladder (below 0.4).
pub(crate) const COPING_PRIOR_CONFIDENCE: f32 = 0.2;

/// Every strategy a generic prior names, in the ledger's own order. No
/// strategy is ranked above another: canon names no per-strategy prior.
const COPING_PRIOR_STRATEGIES: [CopingStrategy; 6] = [
    CopingStrategy::SitSel,
    CopingStrategy::SitMod,
    CopingStrategy::AttDep,
    CopingStrategy::CogChg,
    CopingStrategy::ResMod,
    CopingStrategy::ERFlex,
];

impl Memory<'_> {
    pub fn coping_lookup_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &CopingLookupRequest,
    ) -> MemoryResult<CopingLookup> {
        let person = self.resolve_ref(&input.affected_person_ref)?;
        let turn = self.resolve_ref(&input.current_turn_ref)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.affect_owner_in_txn(&txn, owner)?;
        self.coping_lookup_in_txn(&txn, person, turn, input.scope.as_ref())
    }

    fn coping_lookup_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        turn: EntityId,
        scope: Option<&ClaimScope>,
    ) -> MemoryResult<CopingLookup> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        require_readable(&lane, txn, &[person, turn])?;
        if self.vault.get_entity_type_in_txn(txn, &person)? != Some(ENTITY_TYPE_PERSON) {
            return Err(MemoryError::bad_request("coping lookup requires a PERSON"));
        }
        if self.vault.get_entity_type_in_txn(txn, &turn)? != Some(ENTITY_TYPE_TURN)
            || !self
                .vault
                .store
                .record_hooks
                .spoke_in(self.vault, txn, &person, &turn)?
        {
            return Err(MemoryError::bad_request(
                "coping lookup state must be a turn the PERSON spoke in",
            ));
        }
        let current = self.coping_state_in_txn(txn, &lane, turn)?.ok_or_else(|| {
            MemoryError::bad_request("coping lookup state turn has no VAD annotation")
        })?;
        let mut outcomes = Vec::new();
        let mut observed_n = 0_u64;
        for AdmittedCopingHead {
            strategy_ref,
            learned_at,
            outcome,
        } in self.admitted_coping_heads_in_txn(txn, &lane, person, scope)?
        {
            // A head whose baseline turn has no live VAD names no state.
            let Some(state) = self.coping_state_in_txn(txn, &lane, strategy_ref)? else {
                continue;
            };
            observed_n = observed_n
                .checked_add(outcome.observed_n)
                .ok_or_else(|| MemoryError::bad_request("coping observation count overflow"))?;
            outcomes.push(CopingLookupOutcome {
                pad_distance: pad_distance(current, state),
                state,
                learned_at,
                outcome,
            });
        }
        outcomes.sort_by(nearest_then_ranked);
        let cold_start_min_outcomes = COPING_COLD_START_MIN_OUTCOMES;
        let (basis, priors) = if observed_n < cold_start_min_outcomes {
            (CopingLookupBasis::GenericPriors, generic_priors())
        } else {
            (CopingLookupBasis::Outcomes, Vec::new())
        };
        self.produced_from([person, turn]);
        Ok(CopingLookup {
            affected_person_ref: person.to_hex(),
            current_turn_ref: turn.to_hex(),
            current_state: current,
            basis,
            observed_n,
            cold_start_min_outcomes,
            outcomes,
            priors,
        })
    }

    /// The VAD the coping ledger measures `turn` by, its annotation claim
    /// (when one is stored) readable on `lane` and listed as a producer.
    fn coping_state_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        lane: &ScopedRead<'_>,
        turn: EntityId,
    ) -> MemoryResult<Option<Vad>> {
        let annotation = crate::write_envelope::vad_annotation::vad_annotation_claim_id(
            ENTITY_TYPE_TURN,
            &turn,
        )?;
        if self
            .vault
            .get_entity_type_in_txn(txn, &annotation)?
            .is_some()
        {
            require_readable(lane, txn, &[annotation])?;
            self.produced_from([annotation]);
        }
        Ok(self.vault.coping_state_vad_in_txn(txn, &turn)?)
    }
}

/// Euclidean distance over the canonical VAD floats.
fn pad_distance(from: Vad, to: Vad) -> f32 {
    let valence = f64::from(to.valence) - f64::from(from.valence);
    let arousal = f64::from(to.arousal) - f64::from(from.arousal);
    let dominance = f64::from(to.dominance) - f64::from(from.dominance);
    (valence * valence + arousal * arousal + dominance * dominance).sqrt() as f32
}

/// Nearest state first; within one distance, worked first, then the most
/// recently learned, then the most confident; the claim id breaks a tie.
fn nearest_then_ranked(a: &CopingLookupOutcome, b: &CopingLookupOutcome) -> Ordering {
    a.pad_distance
        .total_cmp(&b.pad_distance)
        .then_with(|| b.outcome.successful.cmp(&a.outcome.successful))
        .then_with(|| b.learned_at.cmp(&a.learned_at))
        .then_with(|| b.outcome.confidence.total_cmp(&a.outcome.confidence))
        .then_with(|| a.outcome.claim_ref.cmp(&b.outcome.claim_ref))
}

fn generic_priors() -> Vec<CopingPrior> {
    COPING_PRIOR_STRATEGIES
        .into_iter()
        .map(|strategy| CopingPrior {
            strategy,
            confidence: COPING_PRIOR_CONFIDENCE,
        })
        .collect()
}
