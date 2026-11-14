//! Doors for retained code-run result body redaction integration tests.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::{
    CodeRunRawOutput, CodeRunReplayRecord, CodeRunResultBinding, ExecutorStorage, ResultRead,
};
use crate::engine_executor::is_result_output_path;
use crate::secret_lease::SecretTaintRef;
use crate::store::result_manifest::ResultOccurrence;
use crate::{EntityId, Error, Result, Vault};

// The executor's constant is private to its module; use its result path layout.
const SCRIPT_OUTPUT_DIR: &str = "executor/repl";

/// Publishes a complete body through the real scanning sink and binds its name.
/// Appends to an existing replay record without replacing its other results.
///
/// # Errors
///
/// Invalid result names, sink or publication failures, and replay storage errors.
pub fn store_code_run_result_body(
    vault: &Vault,
    run_id: EntityId,
    name: &str,
    bytes: &[u8],
) -> Result<EntityId> {
    if !CodeRunResultBinding::is_valid_name(name) {
        return Err(Error::InvalidClaimBody("invalid fixture result name"));
    }
    let path = format!("{SCRIPT_OUTPUT_DIR}/store/{name}.result");
    let mut sink = vault.code_run_output_sink()?;
    sink.write(bytes)?;
    let output = vault.publish_code_run_output(path.clone(), sink, true, Some(run_id))?;
    let mut record = match vault.get_code_run_replay_record(&run_id)? {
        Some(record) => record,
        None => CodeRunReplayRecord::with_determinism(run_id, None),
    };
    record.bindings.retain(|binding| binding.name != name);
    record.bindings.push(CodeRunResultBinding::new(
        name,
        output.handle.clone(),
        path.clone(),
    ));
    record.outputs.push(output);
    vault.put_code_run_replay_record(&record)?;
    Ok(ResultOccurrence::owned(run_id, &path)?.id())
}

/// Attaches lease refs with the real tainted-output and inheritance writers.
/// A separate clean source carries the refs because re-putting the target
/// after custody registration would sweep its known value out of storage.
///
/// # Errors
///
/// Missing occurrences, invalid refs, and body, custody or mark storage errors.
pub fn mark_result_body_with_lease_refs(
    vault: &Vault,
    run_id: EntityId,
    occurrence: EntityId,
    refs: &[SecretTaintRef],
) -> Result<()> {
    let output = result_output(vault, run_id, occurrence)?;
    let source_owner = EntityId::now();
    let bytes = b"fixture taint source\n";
    let source = CodeRunRawOutput::from_bytes(
        format!("{SCRIPT_OUTPUT_DIR}/store/lease_taint_source.result"),
        bytes,
    )?;
    vault.put_code_run_raw_output_tainted(Some(source_owner), &source, bytes, refs)?;
    vault.inherit_code_run_result_marks(run_id, &output, &[(source_owner, source)])
}

/// Returns the reader's preflight verdict for this exact owned occurrence.
///
/// # Errors
///
/// Missing occurrences, invalid occurrence ids, and result taint storage errors.
pub fn result_read_preflight(
    vault: &Vault,
    run_id: EntityId,
    occurrence: EntityId,
) -> Result<serde_json::Value> {
    let output = result_output(vault, run_id, occurrence)?;
    let storage = ExecutorStorage::Canonical(vault);
    match ResultRead::new(&storage, run_id, output, None, None, false)? {
        Ok(read) => Ok(read.preflight()),
        Err(refused) => Ok(refused),
    }
}

/// Reads the stored bytes, without passing through a redacted result view.
///
/// # Errors
///
/// Missing occurrences or bodies, and raw body storage or integrity errors.
pub fn stored_result_bytes(
    vault: &Vault,
    run_id: EntityId,
    occurrence: EntityId,
) -> Result<Vec<u8>> {
    let output = result_output(vault, run_id, occurrence)?;
    vault
        .get_code_run_raw_output(&output)?
        .ok_or(Error::CorruptedIndex("fixture result body missing"))
}

/// Reads the stored occurrence's secret-scan mark through its canonical door.
///
/// # Errors
///
/// Missing occurrences and result-mark storage errors.
pub fn stored_result_mark(
    vault: &Vault,
    run_id: EntityId,
    occurrence: EntityId,
) -> Result<Option<String>> {
    let output = result_output(vault, run_id, occurrence)?;
    vault.code_run_raw_output_secret(Some(run_id), &output)
}

/// Withdraws this occurrence through the canonical retrieval stale writer.
/// Its result reads then carry `response_erased`, not a redacted view.
///
/// # Errors
///
/// Missing occurrences, deletion guards, and withdrawal storage errors.
pub fn withdraw_result_body(vault: &Vault, run_id: EntityId, occurrence: EntityId) -> Result<()> {
    let output = result_output(vault, run_id, occurrence)?;
    let occurrence = ResultOccurrence::owned(run_id, &output.path)?.id();
    let mut txn = vault.store.env.write_txn()?;
    crate::ports::RetrievalIndex::port_retrieval_mark_stale(vault, &mut txn, &occurrence)?;
    Ok(txn.commit()?)
}

fn result_output(
    vault: &Vault,
    run_id: EntityId,
    occurrence: EntityId,
) -> Result<CodeRunRawOutput> {
    let record = vault
        .get_code_run_replay_record(&run_id)?
        .ok_or(Error::CorruptedIndex("fixture run has no replay record"))?;
    for output in record.outputs {
        if is_result_output_path(&output.path)
            && ResultOccurrence::owned(run_id, &output.path)?.id() == occurrence
        {
            return Ok(output);
        }
    }
    Err(Error::CorruptedIndex("fixture result occurrence missing"))
}
