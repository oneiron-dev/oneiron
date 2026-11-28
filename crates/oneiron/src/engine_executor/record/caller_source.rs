//! The caller's own code of a caller-source run, kept as a body the run owns (FIX
//! EXECUTE-CALLER-CODE).
//!
//! Such a run is entered with its explicit code, so its first entry keeps the exact bytes as one
//! of the run's outputs, at [`CALLER_SOURCE_OUTPUT_PATH`], through the run's own body store: an
//! occurrence the run owns, with its descriptor and marks, that an erase of the run's actor
//! releases as it releases the run's other replies. Unlike the caller task, the body is written
//! on every storage the run may use (canonical and off-record session storage alike): a source
//! run cannot run without it. There is no dispatcher declaration: the entry passes its explicit
//! code, and the body holds it byte for byte. The finished body commits with the record's
//! creation, in one writer, so a refusal leaves neither (FIX 6592). A read takes it only while
//! the run still holds that occurrence, so an erased, withheld or drifted body is no code. The
//! config hash binds the code's content hash, so the same run id with other code fails the
//! existing config check.
//!
//! The body's presence in the record's manifest marks a source run:
//! [`refuse_caller_source_as_task`] refuses such a run entered through the task REPL before the
//! config marker check, and [`verify_caller_source`] proves the held bytes still hash to the
//! digest after it.

use super::super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::code_run::{
    CodeRunReplayRecord, ExecutorStorage, FinishedOutput, continuation_seed_body_in_txn,
};
use crate::{Error, Result, Vault};
use oneiron_contracts::fingerprint::ContentHash;

/// Where a run keeps its caller's own code (FIX EXECUTE-CALLER-CODE). A control path of the
/// run, never one a guest reads back.
const CALLER_SOURCE_OUTPUT_PATH: &str = "executor/repl/run.caller-source.txt";

/// Whether the record's manifest lists a caller-source body (FIX EXECUTE-CALLER-CODE): the mark
/// of a source run. Reads the manifest alone, never a body.
pub(in crate::engine_executor) fn has_caller_source(record: &CodeRunReplayRecord) -> bool {
    record
        .outputs
        .iter()
        .any(|output| output.path == CALLER_SOURCE_OUTPUT_PATH)
}

/// Refuses a caller-source run entered through the task REPL (FIX EXECUTE-CALLER-CODE). The mode
/// reads from the record's manifest alone, so the check runs before the config marker check,
/// which assumes the entry's own mode. A source run is never resumed as a task run.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the record holds a caller-source body.
pub(in crate::engine_executor) fn refuse_caller_source_as_task(
    record: &CodeRunReplayRecord,
) -> EngineExecutorResult<()> {
    if has_caller_source(record) {
        return Err(Error::InvalidConfig(
            "engine executor caller-source run cannot resume as a task run".to_owned(),
        )
        .into());
    }
    Ok(())
}

/// Finishes `code` as the caller-source body of `record` (FIX EXECUTE-CALLER-CODE): the exact
/// bytes the caller-source entry runs, through the run's unswept program sink (as a step's
/// program: byte for byte, never swept), joined to the record's manifest. It publishes nothing:
/// the body's row, marks and descriptor commit only with the record's creation, in one writer,
/// so a refusal leaves neither (FIX 6592).
///
/// # Errors
///
/// A caller-source body the record already lists, and storage errors finishing the body.
pub(in crate::engine_executor) fn record_caller_source(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    code: &str,
) -> EngineExecutorResult<FinishedOutput> {
    if has_caller_source(record) {
        return Err(Error::InvalidClaimBody("duplicate executor output path").into());
    }
    let mut sink = storage.code_run_script_sink()?;
    sink.write(code.as_bytes())?;
    let input_rows = crate::code_run::resident_tool_answer_rows(record, None);
    let finished =
        storage.finish_code_run_output(CALLER_SOURCE_OUTPUT_PATH.to_owned(), sink, input_rows)?;
    record.outputs.push(finished.output.clone());
    Ok(finished)
}

/// The digest `code` must hash to under `config` (FIX EXECUTE-CALLER-CODE): `Some` when the
/// entry's explicit code hashes to the digest its config binds, `None` otherwise. The loader
/// reports the mismatch with its own message per path.
pub(in crate::engine_executor) fn caller_source_code_digest(
    config: &EngineExecutorConfig,
    code: &str,
) -> Option<ContentHash> {
    config
        .caller_source_digest
        .filter(|digest| *digest == ContentHash::of(code.as_bytes()))
}

/// Proves the caller-source body `record` keeps still hashes to `digest` (FIX EXECUTE-CALLER-CODE):
/// the manifest lists it, the run still holds it, and its bytes hash to the digest the config
/// binds. On canonical storage the read goes through the run's own held occurrence, so a
/// released, withheld or drifted body is no code. On session storage (whose overlay keeps no
/// owned-occurrence descriptor) the run's replies must stand, the occurrence must read clean,
/// and the routed bytes hash to the digest. Undecodable bytes are no code on either route.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the manifest lists no body, no usable body is held, the
/// held bytes do not decode, or they hash to another digest; storage errors reading the body.
pub(in crate::engine_executor) fn verify_caller_source(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    digest: ContentHash,
) -> EngineExecutorResult<()> {
    if !has_caller_source(record) {
        return Err(Error::InvalidConfig(
            "engine executor caller-source body is missing".to_owned(),
        )
        .into());
    }
    let text = match storage {
        ExecutorStorage::Canonical(vault) => {
            let _custody = vault.store.gate_custody_read_guard()?;
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            caller_source_in_txn(vault, &txn, record)?
        }
        // A session on an on-record stretch reads base rows: the same held-occurrence check
        // as canonical, in the composed snapshot.
        ExecutorStorage::Session(binding)
            if binding.route.target() == crate::session_overlay::RouteTarget::Base =>
        {
            let _custody = binding.session.custody_read_guard()?;
            binding.answered(|| {
                binding.session.read_composed_in_vault(|vault, _, txn| {
                    caller_source_in_txn(vault, txn, record)
                })
            })?
        }
        ExecutorStorage::Session(_) => {
            let output = record
                .outputs
                .iter()
                .find(|output| output.path == CALLER_SOURCE_OUTPUT_PATH)
                .ok_or_else(missing_caller_source_body)?;
            // An erase of the run's actor took its replies, or the secret scan marked this
            // occurrence or taint refs reach it: the body is not held for this entry.
            if storage.code_run_response_erased(record.run_id)? {
                return Err(missing_caller_source_body().into());
            }
            let (taint, _) = storage.code_run_result_taint(Some(record.run_id), output)?;
            if taint.is_tainted() {
                return Err(missing_caller_source_body().into());
            }
            match storage.get_code_run_raw_output(output)? {
                Some(bytes) => {
                    let text = String::from_utf8(bytes).map_err(|_| {
                        Error::InvalidConfig(
                            "engine executor caller-source body is not UTF-8".to_owned(),
                        )
                    })?;
                    Some(text)
                }
                None => None,
            }
        }
    };
    let Some(text) = text else {
        return Err(missing_caller_source_body().into());
    };
    if ContentHash::of(text.as_bytes()) != digest {
        return Err(Error::InvalidConfig(
            "engine executor caller-source body differs from its config digest".to_owned(),
        )
        .into());
    }
    Ok(())
}

/// The refusal for a caller-source body the loader cannot use (FIX EXECUTE-CALLER-CODE): none
/// was written, or it was released, withheld or drifted.
pub(in crate::engine_executor) fn missing_caller_source_body() -> Error {
    Error::InvalidConfig(
        "engine executor caller-source body is missing, released, withheld, or drifted".to_owned(),
    )
}

/// The caller's own code `record`'s run keeps (FIX EXECUTE-CALLER-CODE), read in `txn` through
/// the run's own held occurrence of the body. `None` when the run keeps no caller source, or its
/// body is released, withheld or drifted.
///
/// # Errors
///
/// Storage errors reading the body or bytes that are not UTF-8.
pub(super) fn caller_source_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &CodeRunReplayRecord,
) -> Result<Option<String>> {
    let Some(output) = record
        .outputs
        .iter()
        .find(|output| output.path == CALLER_SOURCE_OUTPUT_PATH)
    else {
        return Ok(None);
    };
    let Some(bytes) = continuation_seed_body_in_txn(vault, txn, record.run_id, output)? else {
        return Ok(None);
    };
    String::from_utf8(bytes).map(Some).map_err(|_| {
        Error::InvalidConfig("engine executor caller-source body is not UTF-8".to_owned())
    })
}
