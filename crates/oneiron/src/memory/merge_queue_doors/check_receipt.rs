//! `vault.code.checks.get` (FIX 6869, G4 PR2): the owner's read of the
//! retained checker receipts behind one inputs reference of one work row.
//!
//! CALL Q `code_check_receipt_view`: a reference names an inputs digest,
//! not an attempt, and one work keeps every generation, so the read answers
//! EVERY retained receipt of that digest in saved order. No latest attempt
//! is guessed, no pass is recomputed, no check runs and no limit applies.
//! `passes` is a saved contract verdict bound to that very receipt, else
//! none; a Baseline receipt records no verdict and a reused one copies no
//! run. `check_status` is unchanged.
use serde::{Deserialize, Serialize};

use super::*;
use crate::contract_oracle::ContractOracle;
use crate::merge_queue::{
    CheckPhase, QUEUE_CHECK_CANDIDATE_PREFIX, QueueCheckHoldReason, QueueCheckReceipt,
};

/// One inputs reference of one checker work row to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeCheckReceiptRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// The work reference a checker door returned, 64 hex characters.
    pub work_ref: String,
    /// One of that work's `receipt_refs`: `queue-check:v1:<inputs digest>`.
    pub receipt_ref: String,
}

/// One phase command's recorded result: its exit status or the signal
/// that ended it, and the BLAKE3 of its recorded output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckCommandResult {
    pub index: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_blake3: String,
    pub stderr_blake3: String,
}

/// One retained receipt of the digest: its generation and attempt, the
/// exact target and plan, what it recorded, and its bound saved verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckAttemptView {
    pub generation: u32,
    pub phase: QueueCheckPhase,
    pub commit: String,
    pub tree: String,
    pub plan_digest: String,
    pub inputs_digest: String,
    pub attempt_id: String,
    pub attempt_count: u32,
    /// Whether the inputs agreed before and after the run; `None` when no
    /// run is recorded.
    pub stable_inputs: Option<bool>,
    pub completed: bool,
    /// The saved phase result.
    pub tests_passed: Option<bool>,
    pub commands: Vec<CodeCheckCommandResult>,
    pub hold: Option<QueueCheckHoldReason>,
    pub configuration_keys: Vec<String>,
    pub verdict_ref: Option<String>,
    /// The bound saved verdict's own result; `None` without one.
    pub passes: Option<bool>,
    /// The earlier receipt digest a reused receipt copied its result from.
    pub reused_from: Option<String>,
}

/// Every retained receipt of one inputs reference, in saved order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckReceiptView {
    pub repo: EntityId,
    pub work_ref: String,
    pub receipt_ref: String,
    pub receipts: Vec<CodeCheckAttemptView>,
}

impl Memory<'_> {
    /// `vault.code.checks.get`: authenticates the owner before any lookup,
    /// resolves the stored repository and its work, and projects every
    /// retained receipt of the named digest. `None` when no readable work
    /// or receipt matches.
    pub fn merge_queue_check_receipt_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeCheckReceiptRequest,
    ) -> MemoryResult<Option<CodeCheckReceiptView>> {
        self.merge_queue_owner(owner)?;
        let digest = input
            .receipt_ref
            .strip_prefix(QUEUE_CHECK_CANDIDATE_PREFIX)
            .filter(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| {
                MemoryError::bad_request("receipt_ref is not a queue-check inputs reference")
            })?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        let Some(work) = queue.check_work(&input.work_ref)? else {
            return Ok(None);
        };
        if work.repo != repo.repo || work.store != repo.identity.as_hex() {
            return Ok(None);
        }
        let oracle = ContractOracle::new(self.vault);
        let mut receipts = Vec::new();
        for receipt in work
            .receipts
            .iter()
            .filter(|receipt| receipt.inputs_digest == digest)
        {
            if receipt.inputs.digest()? != receipt.inputs_digest
                || receipt.inputs.store != work.store
                || receipt.inputs.repo != work.repo
            {
                return Err(MemoryError::from(crate::Error::CorruptedIndex(
                    "a retained check receipt is not bound to its inputs",
                )));
            }
            let passes = match &receipt.verdict_ref {
                Some(id) => oracle
                    .verdict(id)?
                    .filter(|verdict| {
                        verdict.candidate == format!("{QUEUE_CHECK_CANDIDATE_PREFIX}{digest}")
                    })
                    .map(|verdict| verdict.passes()),
                None => None,
            };
            receipts.push(attempt_view(receipt, passes));
        }
        if receipts.is_empty() {
            return Ok(None);
        }
        Ok(Some(CodeCheckReceiptView {
            repo: repo.repo,
            work_ref: work.work_ref().to_owned(),
            receipt_ref: input.receipt_ref,
            receipts,
        }))
    }
}

/// One receipt as the wire carries it: recorded results and hashes, never
/// argv, environment or command exhaust.
fn attempt_view(receipt: &QueueCheckReceipt, passes: Option<bool>) -> CodeCheckAttemptView {
    let target = &receipt.inputs.target;
    let commands = receipt
        .run
        .as_ref()
        .map(|run| {
            run.commands
                .iter()
                .enumerate()
                .map(|(index, command)| CodeCheckCommandResult {
                    index: u32::try_from(index).unwrap_or(u32::MAX),
                    exit_code: command.status,
                    signal: command.signal,
                    stdout_blake3: blake3::hash(&command.stdout).to_hex().to_string(),
                    stderr_blake3: blake3::hash(&command.stderr).to_hex().to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    CodeCheckAttemptView {
        generation: receipt.generation,
        phase: match target.phase() {
            CheckPhase::Fast => QueueCheckPhase::Fast,
            CheckPhase::Slow => QueueCheckPhase::Slow,
        },
        commit: target.commit().to_owned(),
        tree: target.tree().to_owned(),
        plan_digest: receipt.inputs.plan_digest.clone(),
        inputs_digest: receipt.inputs_digest.clone(),
        attempt_id: crate::entity_id::bytes_to_hex_lower(receipt.attempt.as_bytes()),
        attempt_count: receipt.attempt_count,
        stable_inputs: receipt
            .run
            .as_ref()
            .map(|run| run.input_before == run.input_after),
        completed: receipt.tests_passed.is_some()
            && receipt.hold.is_none()
            && receipt.need.is_none(),
        tests_passed: receipt.tests_passed,
        commands,
        hold: receipt.hold.as_ref().map(|hold| hold.reason),
        configuration_keys: receipt
            .need
            .as_ref()
            .map(|need| need.keys.clone())
            .unwrap_or_default(),
        verdict_ref: receipt.verdict_ref.clone(),
        passes,
        reused_from: receipt.reused_from.clone(),
    }
}
