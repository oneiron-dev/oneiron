//! Frozen callable cases (FIX 12093). Each call of a callable skill whose
//! answer passed its return contract is kept as a case: its arguments, that
//! answer, and the caller it was made for. The helper gate scores a
//! Candidate helper and its parent on the parent's cases, each run here as a
//! call runs, in the same sandbox and under the same contract.

use std::io::Read;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{
    CallableSkillAnswer, bind_isolated_lane, callable_script, callable_tier, invalid, matches_shape,
};
use crate::code_run::{CodeRunDeterminism, SelfCall, SelfDispatchOutcome, SelfFailedResult};
use crate::code_sandbox::{SandboxBoundaryContract, SandboxGuestTier};
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStream, SelfDispatchResponse,
    StepCancellation,
};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::skill::helper::CallableCase;
use crate::skill::{SkillRecord, SkillRole};
use crate::skill_hub::HubFile;
use crate::{EntityId, Vault};

/// Most frozen cases one skill keeps: as a new one lands, the oldest past
/// it go. The helper gate reads up to this many of a parent's (CALL).
const FROZEN_CASES_PER_SKILL: usize = 64;

/// Largest call frozen, its arguments and its answer as JSON text together;
/// a larger call is not kept (CALL).
const FROZEN_CASE_MAX_BYTES: u64 = 64 * 1024;

/// Key: id16 (the skill that ran) + u64be at + u64be step seq + receipt.
const CASES: SideTable<Vec<u8>, FrozenCall, Named> =
    SideTable::new(&side_table::SKILL_CALLABLE_CASE);

/// One frozen call, as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FrozenCall {
    /// The attempt pack receipt of the call's caller.
    receipt: String,
    /// The skill revision that answered.
    version: String,
    /// The actor the call was made for.
    caller: Option<EntityId>,
    /// JSON text.
    arguments: String,
    /// JSON text: the answer that passed the return contract.
    answer: String,
}

/// Where a call that passed was made.
pub(super) struct FrozenCallSite<'a> {
    pub(super) receipt: String,
    pub(super) version: &'a str,
    pub(super) seq: u64,
    pub(super) at: u64,
    pub(super) caller: Option<EntityId>,
}

/// Keeps one call that passed its contract as a case of `skill`, the skill
/// that ran. Capture only: the call has already succeeded, and nothing here
/// changes what it answers.
pub(super) fn freeze_callable_case(
    vault: &Vault,
    skill: &EntityId,
    site: FrozenCallSite<'_>,
    args: &JsonValue,
    answer: &mut CallableSkillAnswer,
) -> Result<()> {
    let arguments =
        serde_json::to_string(args).map_err(|_| invalid("call arguments cannot be encoded"))?;
    if answer.byte_len().saturating_add(arguments.len() as u64) > FROZEN_CASE_MAX_BYTES {
        return Ok(());
    }
    let mut text = String::new();
    answer.reader()?.read_to_string(&mut text)?;
    let mut key = skill.as_bytes().to_vec();
    key.extend_from_slice(&site.at.to_be_bytes());
    key.extend_from_slice(&site.seq.to_be_bytes());
    key.extend_from_slice(site.receipt.as_bytes());
    let row = FrozenCall {
        receipt: site.receipt,
        version: site.version.to_owned(),
        caller: site.caller,
        arguments,
        answer: text,
    };
    vault.with_write_txn_grouped(|txn| {
        CASES.put(&vault.store, txn, &key, &row)?;
        let kept = CASES.scan_keys(&vault.store, &*txn, skill.as_bytes())?;
        for old in kept.iter().take(kept.len().saturating_sub(FROZEN_CASES_PER_SKILL)) {
            CASES.delete(&vault.store, txn, old)?;
        }
        Ok(())
    })
}

/// The frozen cases the helper gate scores `helper` on: its parent's calls,
/// newest first, each named by its receipt, with the answer it gave as the
/// expected one and its caller as its author. A call the helper's own author
/// made is left out, since a helper's author never supplies the cases that
/// promote it. A helper with no parent has none.
///
/// # Errors
///
/// Storage errors.
pub fn callable_helper_cases(vault: &Vault, helper: &EntityId) -> Result<Vec<CallableCase>> {
    let Some(record) = vault.get_skill_record(helper)? else {
        return Ok(Vec::new());
    };
    let Some(parent) = record.forked_from else {
        return Ok(Vec::new());
    };
    let rtxn = vault.store.env.read_txn()?;
    let author = crate::memory::skill_author_in_txn(vault, &rtxn, helper, &record)?;
    let mut cases = Vec::new();
    for row in CASES.iter_rev_from(&vault.store, &rtxn, parent.as_bytes())? {
        let (_, frozen) = row?;
        if author.is_some() && frozen.caller == author {
            continue;
        }
        let (Ok(arguments), Ok(expected)) = (
            serde_json::from_str(&frozen.arguments),
            serde_json::from_str(&frozen.answer),
        ) else {
            continue;
        };
        cases.push(CallableCase {
            case_ref: frozen.receipt,
            arguments,
            expected,
            source_author: frozen.caller,
        });
        if cases.len() == FROZEN_CASES_PER_SKILL {
            break;
        }
    }
    Ok(cases)
}

/// Runs one frozen case on `files`, the exact source of `skill` at `record`,
/// as a call runs it: the same arguments line and preparation, its tier's
/// sandbox with no host file or credential services, and the same check
/// against its return contract. Its clock is `frozen_unix_ms` and its seed
/// comes from the case's ref, so both arms of a pair run alike. Nothing a
/// call records is written: no lease, witness or credit. The guest's
/// `self.*` calls fail, so a source that needs one fails the case.
///
/// `true` when the answer equals the case's expected one (JSON values equal,
/// object members in any order). A run that does not finish, fails, or
/// answers outside its contract does not pass.
///
/// # Errors
///
/// Only what stops the run before it starts: no isolated lane on this host
/// for a tier that needs one, its egress settings, a broken ancestry.
pub fn callable_case_passes(
    vault: &Arc<Vault>,
    skill: &EntityId,
    (record, files): (&SkillRecord, &[HubFile]),
    case: &CallableCase,
    runtime: &mut dyn JsCodeModeRuntime,
    frozen_unix_ms: u64,
) -> Result<bool> {
    let Some(call) = record.call.as_ref() else {
        return Ok(false);
    };
    if record.role != SkillRole::Callable || !matches_shape(&case.arguments, &call.arguments) {
        return Ok(false);
    }
    let Some(source) = files
        .iter()
        .find(|file| file.path == call.reference)
        .and_then(|file| std::str::from_utf8(&file.content).ok())
    else {
        return Ok(false);
    };
    let tier = callable_tier(vault, skill, record)?;
    if tier != SandboxGuestTier::FirstPartyDreamer {
        crate::code_sandbox::microvm::select_backend_for_tier(tier)?;
    }
    let run_id = EntityId::now();
    bind_isolated_lane(vault, runtime, run_id, tier)?;
    let script = callable_script(&case.arguments, source)?;
    let prepared = crate::code_sandbox::source::prepare_source(&script).with_prelude_lines(1);
    let mut host = CaseHost {
        answer: CallableSkillAnswer::spool(),
    };
    let ran = runtime.run_prepared_step_cancellable(
        JsCodeModeStep {
            run_id,
            seq: 0,
            script: &script,
            boundary: SandboxBoundaryContract::for_tier(tier).without_host_services(),
            determinism: CodeRunDeterminism::new(
                frozen_unix_ms,
                *blake3::hash(case.case_ref.as_bytes()).as_bytes(),
            ),
        },
        &prepared,
        &mut host,
        &StepCancellation::never(),
    );
    let Ok(outcome) = ran else {
        return Ok(false);
    };
    let mut answer = host.answer;
    if !outcome.done || answer.write(outcome.observation.as_bytes()).is_err() {
        return Ok(false);
    }
    if !matches!(answer.check(&call.returns, None), Ok(Some(_))) {
        return Ok(false);
    }
    let given: Option<JsonValue> = answer
        .reader()
        .ok()
        .and_then(|reader| serde_json::from_reader(reader).ok());
    Ok(given.as_ref() == Some(&case.expected))
}

/// A frozen case's host: it keeps the `finish` answer, as a call's does, and
/// fails every `self.*` call, since a case runs for no caller.
struct CaseHost {
    answer: CallableSkillAnswer,
}

impl JsCodeModeHost for CaseHost {
    fn write_output(&mut self, stream: JsCodeModeStream<'_>, frame: &[u8]) -> Result<bool> {
        match stream {
            JsCodeModeStream::Finish { start } => {
                if start {
                    self.answer.restart()?;
                }
                self.answer.write(frame)?;
            }
            JsCodeModeStream::Store { .. } => return Err(invalid("store needs a result store")),
            JsCodeModeStream::Console | JsCodeModeStream::File(_) => {}
        }
        Ok(true)
    }

    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        Ok(SelfDispatchResponse {
            outcome: SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: "callable_case_no_caller".to_owned(),
            }),
            budget: None,
            view: None,
        })
    }
}
