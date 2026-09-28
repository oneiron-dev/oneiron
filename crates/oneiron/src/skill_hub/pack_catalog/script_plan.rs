//! One qualified execution shape for both pack admission and foreign launch.
#[cfg(any(test, feature = "microvm-firecracker"))]
use std::collections::BTreeMap;

use oneiron_sandbox_contract::{OutputReservation, ProgramBudget, WorkspacePath, WorkspaceShape};
#[cfg(any(test, feature = "microvm-firecracker"))]
use serde_json::Value;

use super::{PackAdapter, PackRuntimeRecipe, PackSource, invalid};
#[cfg(any(test, feature = "microvm-firecracker"))]
use crate::code_sandbox::SandboxProposalWrite;
use crate::{Result, skill_hub::HubFile};

const OUTPUT_PATH: &str = "/mnt/workspace/adapter-output.json";
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_GRANT_PRELUDE_BYTES: usize = 128 * 1024;

fn shape<T>(result: oneiron_sandbox_contract::Result<T>) -> Result<T> {
    result.map_err(|error| invalid(error.reason()))
}

/// Immutable source and its complete reserved execution shape. No caller can
/// shrink this snapshot after qualification or silently add an output later.
pub(crate) struct ScriptExecutionPlan {
    files: Vec<HubFile>,
    source_shape: WorkspaceShape,
    reserved_shape: WorkspaceShape,
    script_index: usize,
    output: ScriptOutputContract,
    program: ProgramBudget,
}
impl ScriptExecutionPlan {
    pub(crate) fn from_source(source: &PackSource, runtime: &PackRuntimeRecipe) -> Result<Self> {
        let Some(PackAdapter::Script(script_path)) = &source.manifest().adapter else {
            return Err(invalid("pack does not declare a script adapter"));
        };
        if runtime.adapter != PackAdapter::Script(script_path.clone())
            || runtime.runtime_id != crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME
        {
            return Err(invalid(
                "script runtime does not bind declared QuickJS adapter",
            ));
        }
        let mut snapshot = WorkspaceShape::new();
        let mut script_index = None;
        for (index, file) in source.files().iter().enumerate() {
            let path = shape(WorkspacePath::from_relative(&file.path))?;
            shape(snapshot.add_file(&path, file.content.len()))?;
            if file.path == *script_path {
                script_index = Some(index);
            }
        }
        let script_index =
            script_index.ok_or_else(|| invalid("declared adapter script is absent"))?;
        let output = ScriptOutputContract::new()?;
        let reserved_shape = shape(snapshot.with_output(&output.reservation))?;
        let program = shape(ProgramBudget::new(MAX_GRANT_PRELUDE_BYTES))?;
        shape(program.qualify_source(source.files()[script_index].content.len()))?;
        Ok(Self {
            files: source.files().to_vec(),
            source_shape: snapshot,
            reserved_shape,
            script_index,
            output,
            program,
        })
    }
    pub(super) fn qualified_shape(&self) -> Result<()> {
        if self.source_shape.file_count() != self.files.len()
            || self.reserved_shape.total_bytes()
                != self.source_shape.total_bytes() + self.output.reservation.max_bytes()
        {
            return Err(invalid(
                "script execution shape changed after qualification",
            ));
        }
        shape(
            self.program
                .qualify_source(self.files[self.script_index].content.len()),
        )
    }
    #[cfg(any(test, feature = "microvm-firecracker"))]
    pub(crate) fn files(&self) -> &[HubFile] {
        debug_assert_eq!(self.source_shape.file_count(), self.files.len());
        debug_assert_eq!(
            self.reserved_shape.total_bytes(),
            self.source_shape.total_bytes() + self.output.reservation.max_bytes()
        );
        &self.files
    }
    #[cfg(any(test, feature = "microvm-firecracker"))]
    pub(crate) fn assemble_program(&self, grants: &BTreeMap<String, Value>) -> Result<String> {
        let script = std::str::from_utf8(&self.files[self.script_index].content)
            .map_err(|_| invalid("adapter script is not UTF-8"))?;
        let prelude = GrantPrelude::encode(grants)?;
        shape(self.program.assemble(script.len(), prelude.0.len()))?;
        Ok(format!("{}{script}", prelude.0))
    }
    #[cfg(any(test, feature = "microvm-firecracker"))]
    pub(crate) fn output_bytes(&self, write: &SandboxProposalWrite) -> Result<Vec<u8>> {
        self.output.bytes(write)
    }
}

#[cfg(any(test, feature = "microvm-firecracker"))]
struct GrantPrelude(String);
#[cfg(any(test, feature = "microvm-firecracker"))]
impl GrantPrelude {
    fn encode(grants: &BTreeMap<String, Value>) -> Result<Self> {
        let json = serde_json::to_string(grants)
            .map_err(|_| invalid("script grant mapping encoding failed"))?;
        let prelude = format!("const packGrants = Object.freeze({json});\n");
        if prelude.len() > MAX_GRANT_PRELUDE_BYTES {
            return Err(invalid("injected script exceeds grant reservation"));
        }
        Ok(Self(prelude))
    }
}

struct ScriptOutputContract {
    reservation: OutputReservation,
}
impl ScriptOutputContract {
    fn new() -> Result<Self> {
        Ok(Self {
            reservation: shape(OutputReservation::new(
                shape(WorkspacePath::parse(OUTPUT_PATH))?,
                MAX_OUTPUT_BYTES,
            ))?,
        })
    }
    #[cfg(any(test, feature = "microvm-firecracker"))]
    fn bytes(&self, write: &SandboxProposalWrite) -> Result<Vec<u8>> {
        // Firecracker lowers every guest write against the exact source
        // snapshot. The only admitted output is a NEW, bounded file edit.
        let SandboxProposalWrite::FileEdit(file) = write else {
            return Err(invalid("pack script emitted non-output proposal"));
        };
        let edit = &file.edit;
        if file.path.as_str() != self.reservation.path().as_str()
            || file.base_content_hash != *blake3::hash(b"").as_bytes()
            || edit.path != self.reservation.path().relative()
            || edit.start != 0
            || edit.end != 0
            || !edit.expected.is_empty()
            || edit.new_path.is_some()
            || edit.replacement.len() > self.reservation.max_bytes()
        {
            return Err(invalid("pack script output outside qualified contract"));
        }
        Ok(edit.replacement.as_bytes().to_vec())
    }
}

/// Protocol conformance uses the same output contract as the pack plan.
#[cfg(all(test, feature = "microvm-firecracker", target_os = "linux"))]
pub(crate) fn script_output_bytes(write: &SandboxProposalWrite) -> Result<Vec<u8>> {
    ScriptOutputContract::new()?.bytes(write)
}
