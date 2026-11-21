//! Bound Psych Mirror generation with borrowed pass resources and
//! request-hash receipts (untangle 6.9i).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use super::DreamerAttemptBinding;
use super::extraction_execution::join_extraction_thread;
use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::dreamer_consolidation::psych_profile_step::{
    PreparedPsychProfileStep, attach_psych_profile_tiers, execute_bound_psych_profile_step,
    prepare_psych_profile_step,
};
use crate::dreamer_consolidation::{RoleCall, StepChargeTally};
use crate::dreamer_wake::WakePassDeadline;
use crate::llm::model_step::{ModelStepReceipt, ModelStepReceiptRequest};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use crate::model_step_context::DurableStepContext;
use crate::snapshot_read::SourceVersion;
use crate::snapshot_read::psych_profile_sources::{
    psych_profile_reader_scope_in_txn, served_profile_claims_in_txn, served_version,
};
use oneiron_model::llm::BudgetGuard;

/// The most claims one profile step reads: canon's 50 source slots.
const PSYCH_PROFILE_STEP_SOURCES: usize = 50;

/// Names only the served claim versions a bound psych profile step may send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PsychProfileStepRequest {
    /// The claims the profile reads, in the order the model reads them,
    /// each at the version the attempt's sources page served.
    pub sources: Vec<SourceVersion>,
}

/// Borrows the narrative role and the original attempt's pass resources for
/// one step.
pub struct PsychProfileStepLoan<'a> {
    /// Holds the narrative role resolved through the native role routing rules.
    pub call: RoleCall<'a>,
    /// Borrows the admitted attempt's own pass guard.
    pub guard: &'a BudgetGuard,
    /// Borrows the original wake-pass deadline and finalize window.
    pub deadline: &'a WakePassDeadline,
    /// Holds the attempt's frozen Unix time in milliseconds.
    pub now_ms: u64,
    /// Borrows the terminal tally shared with this attempt's outcome.
    pub charges: &'a Mutex<StepChargeTally>,
    /// Borrows the independent runtime that drives the joined step thread.
    pub runtime: &'a Handle,
}

impl DreamerAttemptBinding {
    /// Checks the cited claims, then borrows the narrative role for the
    /// original attempt.
    pub(super) fn psych_profile_step_submit(
        &self,
        input: PsychProfileStepRequest,
    ) -> MemoryResult<ModelStepReceipt> {
        let (prepared, subject) = self.checked_psych_profile_step(&input)?;
        let lender = self
            .lender
            .as_ref()
            .ok_or_else(psych_profile_loan_unavailable)?;
        let mut step = |loan: PsychProfileStepLoan<'_>| -> MemoryResult<ModelStepReceipt> {
            self.check()?;
            let result = join_extraction_thread(|| {
                let ctx = DurableStepContext {
                    vault: &self.vault,
                    attempt_id: self.lease.attempt(),
                    run_id: self.run.clone(),
                    envelope_actor: self.actor(),
                    subject,
                    deadline: Some(loan.deadline),
                    now_ms: loan.now_ms,
                    spend_scope: None,
                    wake_pass_bound: true,
                };
                loan.runtime
                    .block_on(execute_bound_psych_profile_step(&ctx, &prepared, &loan))
            })?;
            self.check()?;
            Ok(result)
        };
        lender
            .lend_psych_profile_step(&mut step)?
            .ok_or_else(psych_profile_loan_unavailable)
    }

    /// Reads the receipt of this attempt's finished profile step by its step
    /// hash. It answers only while the attempt's key still serves every
    /// claim the step read, at the version it read: the step's terminal
    /// record names them. A step that read a claim the key no longer serves
    /// at that version answers not found, as an unknown hash does. A
    /// finished receipt carries the checked tiers as its JSON, as the submit
    /// does.
    pub(super) fn psych_profile_step_receipt(
        &self,
        input: ModelStepReceiptRequest,
    ) -> MemoryResult<ModelStepReceipt> {
        let key = self
            .psych_profile_key()
            .ok_or_else(|| super::facet_refused(self.facet))?;
        if input.live_run.is_some() {
            return Err(MemoryError::bad_request(
                "a bound psych profile receipt takes no live_run",
            ));
        }
        let hash = psych_profile_step_hash(&input.step_key)?;
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let read = memory.read_lane(ClaimReadStatus::Recorded)?;
        let _pins = read.prepare_point_read::<MemoryError>()?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        self.check_in_txn(&txn)?;
        memory.prove_read_authority_in_txn(&txn)?;
        let scope = psych_profile_reader_scope_in_txn(&memory, &txn)?;
        let mut receipt = read
            .read_projected_in_txn(&txn, &[], None, |txn, _| {
                let served: BTreeMap<EntityId, SourceVersion> =
                    served_profile_claims_in_txn(vault, txn, &read, scope.as_ref(), &key)?
                        .iter()
                        .map(|claim| (claim.claim, served_version(claim)))
                        .collect();
                crate::llm::request_hash_step_receipt_in_txn(
                    vault,
                    txn,
                    self.lease.attempt(),
                    &hash,
                    |version| Ok(served.get(&version.entity) == Some(version)),
                )
                .map_err(MemoryError::from)
            })?
            .value;
        attach_psych_profile_tiers(&mut receipt)?;
        Ok(receipt)
    }

    /// Checks every cited version against the claims the attempt's key
    /// serves now, in one snapshot, and keeps only their served words.
    fn checked_psych_profile_step(
        &self,
        input: &PsychProfileStepRequest,
    ) -> MemoryResult<(PreparedPsychProfileStep, EntityId)> {
        let key = self
            .psych_profile_key()
            .ok_or_else(|| super::facet_refused(self.facet))?;
        if input.sources.is_empty() || input.sources.len() > PSYCH_PROFILE_STEP_SOURCES {
            return Err(MemoryError::bad_request(format!(
                "a psych profile step cites between 1 and {PSYCH_PROFILE_STEP_SOURCES} claims"
            )));
        }
        let mut cited = BTreeSet::new();
        if !input
            .sources
            .iter()
            .all(|source| cited.insert(source.entity))
        {
            return Err(MemoryError::bad_request(
                "a psych profile step cites each claim once",
            ));
        }
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let read = memory.read_lane(ClaimReadStatus::Recorded)?;
        let _pins = read.prepare_point_read::<MemoryError>()?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        self.check_in_txn(&txn)?;
        memory.prove_read_authority_in_txn(&txn)?;
        let scope = psych_profile_reader_scope_in_txn(&memory, &txn)?;
        let checked = read.read_projected_in_txn(&txn, &[], None, |txn, _| {
            let mut served: BTreeMap<EntityId, _> =
                served_profile_claims_in_txn(vault, txn, &read, scope.as_ref(), &key)?
                    .into_iter()
                    .map(|claim| (claim.claim, claim))
                    .collect();
            let mut claims = Vec::with_capacity(input.sources.len());
            for source in &input.sources {
                let Some(claim) = served
                    .remove(&source.entity)
                    .filter(|claim| served_version(claim) == *source)
                else {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "a psych profile step cites a claim its key does not serve at that version",
                        &["Page the key's sources again and cite the versions it serves."],
                    ));
                };
                claims.push(claim);
            }
            Ok(prepare_psych_profile_step(&claims))
        })?;
        Ok((checked.value, key.person))
    }
}

/// The step hash a psych profile receipt read names: 64 lowercase hex
/// digits, as the submit's receipt spells it.
fn psych_profile_step_hash(value: &str) -> MemoryResult<[u8; 32]> {
    let malformed =
        || MemoryError::bad_request("a psych profile step key must be 64 lowercase hex digits");
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(malformed());
    }
    let mut hash = [0; 32];
    for (out, pair) in hash.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| malformed())?;
        *out = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
    }
    Ok(hash)
}

/// Keeps the no-loan refusal identical for every host that lends no profile
/// step.
fn psych_profile_loan_unavailable() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        "no psych profile step loan is lent to this attempt",
        &["The psych profile attempt parks until its host lends a narrative step."],
    )
}
