//! Callable skill execution through the caller's existing sandbox runtime and host.

use serde_json::Value as JsonValue;

#[cfg(test)]
mod tests;

use crate::attempt_queue::AttemptRecord;
use crate::claim::ClaimSource;
use crate::code_run::CodeRunDeterminism;
use crate::code_sandbox::{SandboxBoundaryContract, SandboxGuestTier};
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use crate::error::{ArtifactError, Error, Result};
use crate::skill::SkillRole;
use crate::{EntityId, Vault};

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

/// Imported source and local revisions descended from it stay on the foreign
/// tier. A generated wrapper must not launder imported script into first-party
/// host imports merely by changing its record's `source` to Generated.
fn callable_tier(vault: &Vault, record: &crate::skill::SkillRecord) -> Result<SandboxGuestTier> {
    let mut current = record.clone();
    for _ in 0..64 {
        if current.source == ClaimSource::Imported {
            return Ok(SandboxGuestTier::Foreign);
        }
        let optimized_parent = current.provenance.as_map().and_then(|entries| {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some("optimizeOfEntity"))
                .and_then(|(_, value)| value.as_str())
        });
        let parent = match optimized_parent {
            Some(hex) => Some(
                EntityId::from_hex(hex)
                    .map_err(|_| invalid("invalid callable optimizer ancestor"))?,
            ),
            None => current.forked_from,
        };
        let Some(parent) = parent else {
            return Ok(SandboxGuestTier::FirstPartyDreamer);
        };
        current = vault
            .get_skill_record(&parent)?
            .ok_or(invalid("callable ancestor is missing"))?;
    }
    Err(invalid("callable ancestry exceeds sandbox trust bound"))
}

fn matches_shape(value: &JsonValue, shape: &JsonValue) -> bool {
    match shape {
        JsonValue::String(kind) => match kind.as_str() {
            "string" => value.is_string(),
            "number" => value.is_number(),
            "integer" => value.is_i64() || value.is_u64(),
            "boolean" => value.is_boolean(),
            "object" => value.is_object(),
            "array" => value.is_array(),
            "null" => value.is_null(),
            _ => false,
        },
        JsonValue::Object(fields) => value.as_object().is_some_and(|actual| {
            actual.len() == fields.len()
                && fields.iter().all(|(name, kind)| {
                    actual
                        .get(name)
                        .is_some_and(|item| matches_shape(item, kind))
                })
        }),
        JsonValue::Array(items) if items.len() == 1 => value
            .as_array()
            .is_some_and(|actual| actual.iter().all(|item| matches_shape(item, &items[0]))),
        _ => false,
    }
}

/// Loads a callable into the real attempt manifest, resolves its script from
/// the hash-checked stored source tree and uses the SAME runtime/host/run id
/// supplied by the caller. It neither mints a child nor a new authority lease.
/// Imported code and its local descendants always use the foreign microVM
/// tier. Local code uses the caller's first-party sandbox; neither path widens
/// the caller's host bridge or creates another authority lease.
/// An outcome is credited separately once the attempt has a terminal receipt.
#[expect(
    clippy::too_many_arguments,
    reason = "the caller lends its existing lease, runtime, host, and deterministic step identity"
)]
pub fn execute_callable_skill(
    vault: &Vault,
    leased: &AttemptRecord,
    skill: &EntityId,
    executor: &str,
    args: &JsonValue,
    runtime: &mut dyn JsCodeModeRuntime,
    host: &mut dyn JsCodeModeHost,
    run_id: EntityId,
    seq: u64,
    determinism: CodeRunDeterminism,
    at: u64,
) -> Result<JsCodeModeStepOutcome> {
    // Validate before appending a manifest entry; failed argument admission
    // must not assert that the body was loaded.
    let record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    let call = record
        .call
        .as_ref()
        .ok_or(invalid("skill is not callable"))?;
    if record.role != SkillRole::Callable || !matches_shape(args, &call.arguments) {
        return Err(invalid("call arguments differ from the skill contract"));
    }
    if leased
        .run_id
        .as_deref()
        .is_some_and(|bound| bound != run_id.to_hex())
    {
        return Err(invalid(
            "callable run id differs from the caller's leased run",
        ));
    }
    let loaded = vault.load_leased_callable_skill_pack(leased, skill, at)?;
    let tier = callable_tier(vault, &loaded.record)?;
    let call = loaded
        .record
        .call
        .ok_or(invalid("loaded skill has no call contract"))?;
    let file = loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == call.reference))
        .ok_or(invalid("call reference is absent from stored skill source"))?;
    let source = std::str::from_utf8(&file.content)
        .map_err(|_| invalid("call reference must contain UTF-8 JavaScript"))?;
    // JSON serialization safely embeds the arguments as a JS expression.
    // No host pathname or executable binary ever enters the guest.
    let script = format!(
        "const skillArgs = {};\n{source}",
        serde_json::to_string(args).map_err(|_| invalid("call arguments cannot be encoded"))?
    );
    crate::skill_reliability::record_callable_invocation(
        vault,
        leased,
        skill,
        executor,
        &loaded.record.version,
        None,
    )?;
    let outcome = runtime.run_step(
        JsCodeModeStep {
            run_id,
            seq,
            script: &script,
            boundary: SandboxBoundaryContract::for_tier(tier),
            determinism,
        },
        host,
    )?;
    if !outcome.done {
        return Err(invalid("callable skill did not finish"));
    }
    let output: JsonValue = serde_json::from_str(&outcome.observation)
        .map_err(|_| invalid("callable skill returned non-JSON output"))?;
    if !matches_shape(&output, &call.returns) {
        return Err(invalid("callable skill return differs from its contract"));
    }
    crate::skill_reliability::record_callable_invocation(
        vault,
        leased,
        skill,
        executor,
        &loaded.record.version,
        Some(&outcome.observation),
    )?;
    Ok(outcome)
}
