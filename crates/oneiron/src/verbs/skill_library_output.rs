//! Move native skill-library documents through the core SDK result boundary.

use serde_json::Value;

use super::{SkillLibraryPage, SkillLibraryRestoreReceipt, SkillLibraryView, encode};
use crate::memory::MemoryResult;

struct SkillJson {
    provenance: Value,
    call: Option<(Value, Value)>,
}

pub(super) fn view(mut output: SkillLibraryView) -> MemoryResult<Value> {
    let values = take(&mut output);
    let mut encoded = encode(output)?;
    restore_values(&mut encoded, values);
    Ok(encoded)
}

pub(super) fn page(mut output: SkillLibraryPage) -> MemoryResult<Value> {
    let values: Vec<_> = output.skills.iter_mut().map(take).collect();
    let mut encoded = encode(output)?;
    for (index, values) in values.into_iter().enumerate() {
        restore_values(&mut encoded["skills"][index], values);
    }
    Ok(encoded)
}

pub(super) fn restored(mut output: SkillLibraryRestoreReceipt) -> MemoryResult<Value> {
    let values = match &mut output {
        SkillLibraryRestoreReceipt::Restored { skill, .. } => Some(take(skill)),
        SkillLibraryRestoreReceipt::PendingAdmission { .. }
        | SkillLibraryRestoreReceipt::Refused { .. } => None,
    };
    let mut encoded = encode(output)?;
    if let Some(values) = values {
        restore_values(&mut encoded["skill"], values);
    }
    Ok(encoded)
}

fn take(output: &mut SkillLibraryView) -> SkillJson {
    SkillJson {
        provenance: output.provenance.take(),
        call: output
            .call
            .as_mut()
            .map(|call| (call.arguments.take(), call.returns.take())),
    }
}

fn restore_values(encoded: &mut Value, values: SkillJson) {
    encoded["provenance"] = values.provenance;
    if let Some((arguments, returns)) = values.call {
        encoded["call"]["arguments"] = arguments;
        encoded["call"]["returns"] = returns;
    }
}
