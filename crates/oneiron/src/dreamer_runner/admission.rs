//! Home-node gate, atomic admission, and the private wake-budget ledger.
//!
//! Admission is ONE `RwTxn` chain: ready-scan, budget read/top-up, queue
//! lease, and the optional durable started-milestone claim co-commit.

use std::collections::HashSet;

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, ClaimAttempt, ClaimOutcome, DialLandingReserve,
    InterveneAttempt,
};
use crate::error::{Error, Result};

use super::claim_authoring::{DreamerClaimAuthoringBudgetTrap, DreamerClaimAuthoringGateDecision};
use super::codec::{
    budget_key, budget_reservation_key, decode_budget_record, decode_budget_reservation,
    decode_home_node_designation, encode_budget_record, encode_budget_reservation,
    encode_home_node_designation, invalid_dreamer_runner, validate_budget_id,
    validate_budget_record, validate_budget_reservation,
};
use super::constants::{
    DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR, DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE,
    DREAMER_PRIVATE_HOME_NODE_KEY, DREAMER_RUNNER_ATTEMPT_KIND,
    DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND,
};
use super::milestone::apply_milestone_claim_in_txn;
use super::store::{DreamerRunnerStore, decode_dreamer_attempt_status};
use super::types::{
    AbortDreamerBudgetReservation, AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt,
    DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerBudgetRecord, DreamerBudgetReservation,
    DreamerBudgetReserveOutcome, DreamerBudgetSettlement, DreamerBudgetSettlementOutcome,
    DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerHomeNodeCandidate,
    DreamerHomeNodeDesignation, DreamerMilestoneKind, DreamerReservedBudget, ReserveDreamerBudget,
    SettleDreamerBudget,
};

struct DreamerKindAdmissionResult {
    outcome: DreamerAdmissionOutcome,
    budget_exhausted_candidate: Option<AttemptId>,
}

impl DreamerRunnerStore<'_> {
    /// Builds a local candidate from the vault's stable sync device identity.
    pub fn local_home_node_candidate(
        &self,
        attached: bool,
        always_on_local: bool,
        primary_device: bool,
    ) -> Result<DreamerHomeNodeCandidate> {
        let node_id = crate::identity::load_or_mint_client_id(self.vault)?;
        Ok(DreamerHomeNodeCandidate {
            node_id,
            cloud: false,
            attached,
            always_on_local,
            primary_device,
        })
    }

    /// Elects and persists the single MACRO home-node designation.
    ///
    /// Election is deterministic over the supplied current candidate set:
    /// attached cloud > always-on local > primary device, with node id as a
    /// stable tie-breaker inside a tier.
    pub fn elect_home_node(
        &self,
        candidates: &[DreamerHomeNodeCandidate],
        now: u64,
    ) -> Result<Option<DreamerHomeNodeDesignation>> {
        let designation = elect_home_node_designation(candidates, now)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        if let Some(designation) = designation {
            let encoded = encode_home_node_designation(&designation)?;
            self.vault
                .store
                .vault_meta
                .put(&mut wtxn, DREAMER_PRIVATE_HOME_NODE_KEY, &encoded)?;
        } else {
            self.vault
                .store
                .vault_meta
                .delete(&mut wtxn, DREAMER_PRIVATE_HOME_NODE_KEY)?;
        }
        wtxn.commit()?;
        Ok(designation)
    }

    /// Reads the persisted MACRO home-node designation, if one exists.
    pub(crate) fn home_node_designation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<DreamerHomeNodeDesignation>> {
        let Some(raw) = self
            .vault
            .store
            .vault_meta
            .get(txn, DREAMER_PRIVATE_HOME_NODE_KEY)?
        else {
            return Ok(None);
        };
        decode_home_node_designation(&raw).map(Some)
    }

    pub fn home_node_designation(&self) -> Result<Option<DreamerHomeNodeDesignation>> {
        let rtxn = self.vault.store.env.read_txn()?;
        self.home_node_designation_in_txn(&rtxn)
    }

    /// Atomically admits the next queued Dreamer attempt.
    ///
    /// A successful admission leases one queue row, mutates the private budget
    /// counter, and optionally writes a durable started milestone claim before
    /// committing. Budget denial commits only queue scan repairs, leaving the
    /// attempt queued and the budget row unchanged.
    pub fn admit_next(&self, input: AdmitDreamerAttempt) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(DREAMER_RUNNER_ATTEMPT_KIND, input)
    }

    /// Atomically admits the next queued SKILL-OPT attempt (ONE-1448).
    ///
    /// Per-device, like MICRO/MESO consolidation and for the same reason: the
    /// queue rows are private runner state, and the job's only output is a
    /// gated proposal. There is no home-node gate here because there is no
    /// canon to serialize — admission does not need to be unique for a
    /// PROPOSAL to be safe.
    pub fn admit_next_skill_optimize(
        &self,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND, input)
    }

    /// Home-aware consolidation admission.
    ///
    /// MICRO/MESO admission remains per-device. MACRO admission requires the
    /// caller's local node id to match the persisted home-node designation.
    pub fn admit_next_consolidation(
        &self,
        mut input: AdmitDreamerConsolidationAttempt,
    ) -> Result<DreamerConsolidationAdmissionOutcome> {
        let claim_authoring_decision = input
            .claim_authoring
            .gate_decision(input.claim_authoring_tier)?;
        let tournament_grant = match claim_authoring_decision {
            DreamerClaimAuthoringGateDecision::SinglePass(_) => None,
            DreamerClaimAuthoringGateDecision::Tournament(grant) => {
                input.admission.reserve_units = grant.reserve_units;
                Some(grant)
            }
        };
        validate_admission_input(&input.admission)?;
        if input.local_node_id == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer local node_id must be nonzero",
            ));
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        if input.scope == DreamerConsolidationScope::Macro {
            let local_node_id =
                crate::identity::load_or_mint_client_id_in_txn(self.vault, &mut wtxn)?;
            if input.local_node_id != local_node_id {
                return Err(invalid_dreamer_runner(
                    "dreamer local node_id does not match vault identity",
                ));
            }

            let Some(designation) = home_node_designation_in_txn(self.vault, &wtxn)? else {
                wtxn.commit()?;
                return Ok(DreamerConsolidationAdmissionOutcome::NoHomeNode);
            };
            if designation.node_id != local_node_id {
                wtxn.commit()?;
                return Ok(DreamerConsolidationAdmissionOutcome::NotHomeNode(
                    designation,
                ));
            }
        }

        let budget_trap_budget_id = input.admission.budget_id.clone();
        let budget_trap_now = input.admission.now;
        let result =
            self.admit_next_kind_in_txn(&mut wtxn, input.scope.attempt_kind(), input.admission)?;
        match (tournament_grant, result.outcome) {
            (Some(grant), DreamerAdmissionOutcome::BudgetExhausted(budget)) => {
                let Some(attempt_id) = result.budget_exhausted_candidate else {
                    wtxn.commit()?;
                    return Ok(DreamerConsolidationAdmissionOutcome::Admission(
                        DreamerAdmissionOutcome::BudgetExhausted(budget),
                    ));
                };
                let intervention = self.attempts.intervene_in_txn(
                    &mut wtxn,
                    InterveneAttempt {
                        id: attempt_id,
                        kind: AttemptInterventionKind::Pause,
                        actor: DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR.to_owned(),
                        note: Some(DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE.to_owned()),
                        now: budget_trap_now,
                    },
                )?;
                wtxn.commit()?;
                Ok(
                    DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(
                        DreamerClaimAuthoringBudgetTrap {
                            attempt_id,
                            budget_id: budget_trap_budget_id,
                            budget,
                            required_units: grant.reserve_units,
                            fanout_m: grant.fanout_m,
                            depth_k: grant.depth_k,
                            intervention_effect: intervention.effect,
                        },
                    ),
                )
            }
            (_, outcome) => {
                wtxn.commit()?;
                Ok(DreamerConsolidationAdmissionOutcome::Admission(outcome))
            }
        }
    }

    fn admit_next_kind(
        &self,
        queue_kind: &str,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        validate_admission_input(&input)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let result = self.admit_next_kind_in_txn(&mut wtxn, queue_kind, input)?;
        wtxn.commit()?;
        Ok(result.outcome)
    }

    fn admit_next_kind_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        queue_kind: &str,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerKindAdmissionResult> {
        let Some(candidate_attempt_id) = self
            .attempts
            .ready_kind_candidate_in_txn(wtxn, queue_kind, input.now)?
        else {
            return Ok(DreamerKindAdmissionResult {
                outcome: DreamerAdmissionOutcome::Empty,
                budget_exhausted_candidate: None,
            });
        };

        let mut budget = read_or_initialize_budget_in_txn(
            self.vault,
            wtxn,
            &input.budget_id,
            input.budget_total_units,
            input.now,
        )?;
        let existing_reservation = read_budget_reservation_in_txn(
            self.vault,
            wtxn,
            &input.budget_id,
            candidate_attempt_id,
        )?;
        if let Some(reservation) = existing_reservation.as_ref() {
            if reservation.reserved_units > budget.reserved_units {
                return Err(invalid_dreamer_runner(
                    "dreamer budget reservation exceeds reserved units",
                ));
            }
            if input.reserve_units > reservation.reserved_units {
                let additional_units = input
                    .reserve_units
                    .checked_sub(reservation.reserved_units)
                    .ok_or(Error::ArithmeticOverflow(
                        "dreamer budget reservation top-up",
                    ))?;
                if additional_units > budget.remaining_units {
                    return Ok(DreamerKindAdmissionResult {
                        outcome: DreamerAdmissionOutcome::BudgetExhausted(budget),
                        budget_exhausted_candidate: Some(candidate_attempt_id),
                    });
                }
            }
        } else if input.reserve_units > budget.remaining_units {
            return Ok(DreamerKindAdmissionResult {
                outcome: DreamerAdmissionOutcome::BudgetExhausted(budget),
                budget_exhausted_candidate: Some(candidate_attempt_id),
            });
        }

        let claim = self.attempts.claim_kind_in_txn(
            wtxn,
            queue_kind,
            ClaimAttempt {
                lease_owner: input.lease_owner,
                now: input.now,
            },
        )?;
        let ClaimOutcome::Claimed(attempt) = claim else {
            return Ok(DreamerKindAdmissionResult {
                outcome: DreamerAdmissionOutcome::Empty,
                budget_exhausted_candidate: None,
            });
        };
        if attempt.id != candidate_attempt_id {
            return Err(invalid_dreamer_runner(
                "dreamer admission claimed unexpected ready attempt",
            ));
        }

        // ONE-1896 §4: the units this admission is about to reserve ARE the
        // attempt's budget, so its LANDING slice is carved here — in the same
        // transaction as the lease, because a leased attempt that has not been
        // told what it may spend on landing cannot land. Ordinary execution is
        // metered with `AttemptRecord::ordinary_budget_limit_units` (this dial
        // MINUS the reserve), which is what makes the reserve unreachable by
        // normal work rather than a rule some meter must remember.
        let attempt = self.attempts.dial_landing_reserve_in_txn(
            wtxn,
            DialLandingReserve {
                id: attempt.id,
                limit_units: input.reserve_units,
                reserve_percent: None,
                now: input.now,
            },
        )?;

        let reservation = if let Some(reservation) = existing_reservation {
            if input.reserve_units > reservation.reserved_units {
                top_up_budget_reservation_in_txn(
                    self.vault,
                    wtxn,
                    &mut budget,
                    reservation,
                    input.reserve_units,
                    input.now,
                )?
            } else {
                reservation
            }
        } else {
            let reservation = DreamerBudgetReservation {
                budget_id: input.budget_id,
                attempt_id: attempt.id,
                reserved_units: input.reserve_units,
                created_at: input.now,
                updated_at: input.now,
            };
            reserve_budget_for_child_in_txn(self.vault, wtxn, &mut budget, &reservation)?;
            reservation
        };

        if let Some(milestone) = input.started_milestone {
            apply_milestone_claim_in_txn(self.vault, wtxn, &attempt, milestone)?;
        }

        let status = decode_dreamer_attempt_status(attempt)?;

        Ok(DreamerKindAdmissionResult {
            outcome: DreamerAdmissionOutcome::Admitted(Box::new(DreamerAdmittedAttempt {
                status,
                budget,
                reservation,
            })),
            budget_exhausted_candidate: None,
        })
    }

    /// Reserves wake-budget units for a known child attempt.
    ///
    /// `admit_next` is the normal spawn path because it co-commits queue
    /// leasing and reservation. This method exists for runner call sites that
    /// already have a child id and still need the same private counter rules.
    pub fn reserve_budget(
        &self,
        input: ReserveDreamerBudget,
    ) -> Result<DreamerBudgetReserveOutcome> {
        validate_budget_id(&input.budget_id)?;
        if input.reserve_units == 0 {
            return Err(invalid_dreamer_runner("dreamer reserve_units must be > 0"));
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        if let Some(reservation) = read_budget_reservation_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.child_attempt,
        )? {
            return Ok(DreamerBudgetReserveOutcome::AlreadyReserved(reservation));
        }

        let mut budget = read_or_initialize_budget_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.budget_total_units,
            input.now,
        )?;
        if input.reserve_units > budget.remaining_units {
            wtxn.commit()?;
            return Ok(DreamerBudgetReserveOutcome::BudgetExhausted(budget));
        }

        let reservation = DreamerBudgetReservation {
            budget_id: input.budget_id,
            attempt_id: input.child_attempt,
            reserved_units: input.reserve_units,
            created_at: input.now,
            updated_at: input.now,
        };
        reserve_budget_for_child_in_txn(self.vault, &mut wtxn, &mut budget, &reservation)?;
        wtxn.commit()?;

        Ok(DreamerBudgetReserveOutcome::Reserved(Box::new(
            DreamerReservedBudget {
                budget,
                reservation,
            },
        )))
    }

    /// Settles a child reservation with actual usage and refunds any unspent
    /// reservation.
    pub fn settle_budget(
        &self,
        input: SettleDreamerBudget,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        validate_budget_id(&input.budget_id)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let reservation_key = budget_reservation_key(&input.budget_id, input.child_attempt)?;
        let Some(reservation) = read_budget_reservation_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.child_attempt,
        )?
        else {
            return Ok(DreamerBudgetSettlementOutcome::NoReservation);
        };

        let budget_key = budget_key(&input.budget_id)?;
        let Some(raw_budget) = self.vault.store.vault_meta.get(&wtxn, &budget_key)? else {
            return Err(invalid_dreamer_runner(
                "dreamer budget reservation missing counter",
            ));
        };
        let mut budget = decode_budget_record(&raw_budget)?;
        if budget.budget_id != input.budget_id {
            return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
        }

        let settlement =
            settle_budget_for_child(&mut budget, reservation, input.actual_units, input.now)?;
        put_budget_record_in_txn(self.vault, &mut wtxn, &settlement.budget)?;
        self.vault
            .store
            .vault_meta
            .delete(&mut wtxn, &reservation_key)?;
        wtxn.commit()?;

        Ok(DreamerBudgetSettlementOutcome::Settled(settlement))
    }

    /// Refunds a child reservation when the child aborts before spending any
    /// budget units.
    pub fn abort_budget_reservation(
        &self,
        input: AbortDreamerBudgetReservation,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        self.settle_budget(SettleDreamerBudget {
            budget_id: input.budget_id,
            child_attempt: input.child_attempt,
            actual_units: 0,
            now: input.now,
        })
    }

    /// Reads a private Dreamer budget row.
    pub fn budget(&self, budget_id: &str) -> Result<Option<DreamerBudgetRecord>> {
        validate_budget_id(budget_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let key = budget_key(budget_id)?;
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_budget_record(&raw).map(Some)
    }

    /// Reads the remaining units in a private Dreamer budget row.
    pub fn remaining_budget(&self, budget_id: &str) -> Result<Option<u64>> {
        self.budget(budget_id)
            .map(|budget| budget.map(|record| record.remaining_units))
    }

    /// Reads a private child reservation row.
    pub fn budget_reservation(
        &self,
        budget_id: &str,
        child_attempt: AttemptId,
    ) -> Result<Option<DreamerBudgetReservation>> {
        validate_budget_id(budget_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let key = budget_reservation_key(budget_id, child_attempt)?;
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_budget_reservation(&raw).map(Some)
    }
}

fn home_node_designation_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
) -> Result<Option<DreamerHomeNodeDesignation>> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(txn, DREAMER_PRIVATE_HOME_NODE_KEY)?
    else {
        return Ok(None);
    };
    decode_home_node_designation(&raw).map(Some)
}

fn elect_home_node_designation(
    candidates: &[DreamerHomeNodeCandidate],
    now: u64,
) -> Result<Option<DreamerHomeNodeDesignation>> {
    let mut seen = HashSet::with_capacity(candidates.len());
    let mut best: Option<(u8, u64, DreamerHomeNodeDesignation)> = None;

    for candidate in candidates {
        if candidate.node_id == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer home node_id must be nonzero",
            ));
        }
        if !seen.insert(candidate.node_id) {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer home node candidate",
            ));
        }

        let Some(class) = candidate.designation_class() else {
            continue;
        };
        let rank = class.rank();
        let designation = DreamerHomeNodeDesignation {
            node_id: candidate.node_id,
            class,
            elected_at: now,
        };
        match best.as_ref() {
            Some((best_rank, best_node_id, _))
                if rank > *best_rank
                    || (rank == *best_rank && candidate.node_id > *best_node_id) => {}
            _ => best = Some((rank, candidate.node_id, designation)),
        }
    }

    Ok(best.map(|(_, _, designation)| designation))
}

fn read_or_initialize_budget_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    budget_id: &str,
    budget_total_units: u64,
    now: u64,
) -> Result<DreamerBudgetRecord> {
    let key = budget_key(budget_id)?;
    let Some(raw) = vault.store.vault_meta.get(wtxn, &key)? else {
        return Ok(DreamerBudgetRecord {
            budget_id: budget_id.to_owned(),
            total_units: budget_total_units,
            remaining_units: budget_total_units,
            reserved_units: 0,
            updated_at: now,
        });
    };
    let record = decode_budget_record(&raw)?;
    if record.budget_id != budget_id {
        return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
    }
    Ok(record)
}

fn put_budget_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerBudgetRecord,
) -> Result<()> {
    let encoded = encode_budget_record(record)?;
    let key = budget_key(&record.budget_id)?;
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

fn read_budget_reservation_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    budget_id: &str,
    child_attempt: AttemptId,
) -> Result<Option<DreamerBudgetReservation>> {
    let reservation_key = budget_reservation_key(budget_id, child_attempt)?;
    let Some(raw) = vault.store.vault_meta.get(txn, &reservation_key)? else {
        return Ok(None);
    };
    let reservation = decode_budget_reservation(&raw)?;
    if reservation.budget_id != budget_id || reservation.attempt_id != child_attempt {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation key/body mismatch",
        ));
    }
    Ok(Some(reservation))
}

fn reserve_budget_for_child_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    budget: &mut DreamerBudgetRecord,
    reservation: &DreamerBudgetReservation,
) -> Result<()> {
    validate_budget_reservation(reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    let reservation_key = budget_reservation_key(&reservation.budget_id, reservation.attempt_id)?;
    if vault
        .store
        .vault_meta
        .get(&*wtxn, &reservation_key)?
        .is_some()
    {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation already exists",
        ));
    }
    if reservation.reserved_units > budget.remaining_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation exceeds remaining units",
        ));
    }

    budget.remaining_units -= reservation.reserved_units;
    budget.reserved_units = budget
        .reserved_units
        .checked_add(reservation.reserved_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget reserved units"))?;
    budget.updated_at = reservation.updated_at;
    put_budget_record_in_txn(vault, wtxn, budget)?;

    let encoded = encode_budget_reservation(reservation)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &reservation_key, &encoded)?;
    Ok(())
}

fn top_up_budget_reservation_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    budget: &mut DreamerBudgetRecord,
    mut reservation: DreamerBudgetReservation,
    required_units: u64,
    now: u64,
) -> Result<DreamerBudgetReservation> {
    validate_budget_reservation(&reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    if required_units <= reservation.reserved_units {
        return Ok(reservation);
    }
    let additional_units = required_units
        .checked_sub(reservation.reserved_units)
        .ok_or(Error::ArithmeticOverflow(
            "dreamer budget reservation top-up",
        ))?;
    if additional_units > budget.remaining_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation top-up exceeds remaining units",
        ));
    }

    budget.remaining_units -= additional_units;
    budget.reserved_units = budget
        .reserved_units
        .checked_add(additional_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget reserved units"))?;
    budget.updated_at = now;

    reservation.reserved_units = required_units;
    reservation.updated_at = now;
    validate_budget_reservation(&reservation)?;
    validate_budget_record(budget)?;

    put_budget_record_in_txn(vault, wtxn, budget)?;
    let reservation_key = budget_reservation_key(&reservation.budget_id, reservation.attempt_id)?;
    let encoded = encode_budget_reservation(&reservation)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &reservation_key, &encoded)?;
    Ok(reservation)
}

fn settle_budget_for_child(
    budget: &mut DreamerBudgetRecord,
    reservation: DreamerBudgetReservation,
    actual_units: u64,
    now: u64,
) -> Result<DreamerBudgetSettlement> {
    validate_budget_reservation(&reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    if reservation.reserved_units > budget.reserved_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation exceeds reserved units",
        ));
    }

    let refunded_units = reservation.reserved_units.saturating_sub(actual_units);
    let over_reserved_units = actual_units.saturating_sub(reservation.reserved_units);
    let remaining_after_refund = budget
        .remaining_units
        .checked_add(refunded_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget refund units"))?;
    if over_reserved_units > remaining_after_refund {
        return Err(invalid_dreamer_runner(
            "dreamer budget settlement exceeds remaining units",
        ));
    }

    budget.reserved_units -= reservation.reserved_units;
    budget.remaining_units = remaining_after_refund - over_reserved_units;
    budget.updated_at = now;
    validate_budget_record(budget)?;

    Ok(DreamerBudgetSettlement {
        budget: budget.clone(),
        reservation,
        actual_units,
        refunded_units,
        over_reserved_units,
    })
}

fn validate_admission_input(input: &AdmitDreamerAttempt) -> Result<()> {
    validate_budget_id(&input.budget_id)?;
    if input.reserve_units == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer admission reserve_units must be > 0",
        ));
    }
    if input
        .started_milestone
        .as_ref()
        .is_some_and(|milestone| milestone.kind != DreamerMilestoneKind::Started)
    {
        return Err(invalid_dreamer_runner(
            "dreamer admission milestone must be started",
        ));
    }
    Ok(())
}
