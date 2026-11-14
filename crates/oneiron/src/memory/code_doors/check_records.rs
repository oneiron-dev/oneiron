//! `vault.code.checks.records` (ARCH-0068 #rc5-check-reuse, FIX
//! [L4-30-CHECK-REUSE-RECORD]): the owner's read of the native check records
//! one attempt made in its own checkout.
//!
//! Lists the attempt's records with producer, command, output, observed pass,
//! stability, request revision, engine-captured input versions, the reuse
//! source, the completion void and stated limits. An attempt with no records
//! answers an empty list, not an error. Owner only.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::*;
use crate::attempt_queue::AttemptId;
use crate::check_record::{
    AttemptCheckRecord, CHECK_RECORD_DECLARED, CHECK_RECORD_LIMITS, CHECK_RECORDS, CheckAfter,
    CheckInputVersions, CheckReuseSourceView,
};
use crate::entity_id::bytes_to_hex_lower;

/// The attempt whose native check records to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeCheckRecordsRequest {
    /// The attempt id, 32 lower-hex characters, as the receipt views render it.
    pub attempt_id: String,
}

/// The run that produced a native check, as the owner reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckProducerView {
    /// The attempt id, 32 lower-hex characters.
    pub attempt_id: String,
    pub generation: u32,
    /// The executor run, 32 lower-hex characters.
    pub executor_run: String,
    /// The TASK, 32 lower-hex characters.
    pub task: String,
    /// The PROJECT, 32 lower-hex characters.
    pub project: String,
}

/// One native check record, as the owner reads it: every stored field, the
/// finish flattened to `None` while the check runs, and the stated limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckRecordView {
    /// The check id, 32 lower-hex characters.
    pub check: String,
    pub producer: CodeCheckProducerView,
    /// The CODE anchor, 32 lower-hex characters.
    pub repo: String,
    /// The full Git ref the run edits through this checkout.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The native command, argv in order.
    pub command: Vec<String>,
    /// The declared toolchain, names to stored values.
    pub toolchain: BTreeMap<String, String>,
    /// The declared environment names, sorted; values are never stored.
    pub environment_names: Vec<String>,
    /// Whether the check depends on the world outside the checkout.
    pub world: bool,
    /// The input versions the engine captured before the command ran.
    pub inputs: CheckInputVersions,
    /// Whether the check finished.
    pub finished: bool,
    /// What the engine captured again after the command ended; `None` while the check runs.
    pub after: Option<CheckAfter>,
    /// The command's exit status; `None` while the check runs, or when a signal ended it.
    pub exit_status: Option<i32>,
    /// The stored artifact version holding the command's output; `None` while the check runs.
    pub output: Option<String>,
    /// The observed pass; `None` while the check runs.
    pub passed: Option<bool>,
    /// Whether the inputs held still; `None` while the check runs.
    pub stable: Option<bool>,
    /// The check this record reused instead of running; `None` for a check the run ran.
    pub reused_from: Option<CheckReuseSourceView>,
    /// Whether the completion found the published tree differed from the reused one.
    pub voided: bool,
    /// The four canon limits the record states.
    pub limits: Vec<String>,
    /// What the producer states as declared.
    pub declared: Vec<String>,
}

/// Every native check record of one attempt, in check id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCheckRecordsView {
    /// The attempt id, 32 lower-hex characters.
    pub attempt_id: String,
    pub records: Vec<CodeCheckRecordView>,
}

/// One record as the wire carries it: hex ids, the flattened finish, and the stated limits.
fn record_view(record: &AttemptCheckRecord) -> CodeCheckRecordView {
    let finish = record.finish.as_ref();
    CodeCheckRecordView {
        check: record.check.to_hex(),
        producer: CodeCheckProducerView {
            attempt_id: bytes_to_hex_lower(record.producer.attempt.as_bytes()),
            generation: record.producer.generation,
            executor_run: record.producer.executor_run.to_hex(),
            task: record.producer.task.to_hex(),
            project: record.producer.project.to_hex(),
        },
        repo: record.repo.to_hex(),
        git_ref: record.git_ref.clone(),
        checkout: record.checkout.clone(),
        epoch: record.epoch,
        command: record.command.clone(),
        toolchain: record.toolchain.clone(),
        environment_names: record.environment_names.clone(),
        world: record.world,
        inputs: record.inputs.clone(),
        finished: finish.is_some(),
        after: finish.map(|finished| finished.after.clone()),
        exit_status: finish.and_then(|finished| finished.exit_status),
        output: finish.map(|finished| finished.output.as_str().to_owned()),
        passed: finish.map(|finished| finished.passed),
        stable: finish.map(|finished| finished.stable),
        reused_from: record.reused_from.as_ref().map(CheckReuseSourceView::from),
        voided: record.voided,
        limits: CHECK_RECORD_LIMITS.map(str::to_owned).to_vec(),
        declared: CHECK_RECORD_DECLARED.map(str::to_owned).to_vec(),
    }
}

/// The request's attempt id, as the receipt views render it: 32 hex
/// characters of the attempt's bytes.
fn check_records_attempt(attempt_id: &str) -> MemoryResult<AttemptId> {
    let entity = EntityId::from_hex(attempt_id)
        .map_err(|_| MemoryError::bad_request("attempt_id is not a 32-character hex attempt id"))?;
    AttemptId::from_bytes(entity.as_bytes())
        .map_err(|_| MemoryError::bad_request("attempt_id is not a 32-character hex attempt id"))
}

impl Memory<'_> {
    /// The CALL behind this door: check record reads act as the authenticated
    /// owner. The proof must be live on this vault and name this handle's own
    /// human actor. An agent never borrows it.
    fn check_records_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "check record reads act as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(actor)
    }

    /// `vault.code.checks.records`: lists the native check records `attempt_id`
    /// made in its own checkout, in check id order. An attempt with no records
    /// answers an empty list.
    pub fn code_check_records_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeCheckRecordsRequest,
    ) -> MemoryResult<CodeCheckRecordsView> {
        self.check_records_owner(owner)?;
        let attempt = check_records_attempt(&input.attempt_id)?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let rows = CHECK_RECORDS.scan_from(&self.vault.store, &txn, attempt.as_bytes())?;
        Ok(CodeCheckRecordsView {
            attempt_id: input.attempt_id,
            records: rows
                .into_iter()
                .map(|(_, record)| record_view(&record))
                .collect(),
        })
    }
}
