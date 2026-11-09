//! The artifact write rows a host runs with their `content_base64` already
//! decoded into a file (FIX 22074, Engine rulings E1 = C, E2 = A): the
//! facade spools a large upload and decodes its content before the call,
//! never holding the string or its bytes whole. The row runs through its one
//! verb-hook boundary as [`super::invoke`] runs it, on the call's input with that
//! member empty. A call no hook is live on reads its bytes from the file
//! through the row's `_file` engine fn, behind the same checks as its plain
//! fn. A call a hook is live on gets the string back in its args before any
//! hook reads them, and runs as JSON, as every call ran before.

use std::fs::File;

use super::{
    decode, encode, invoke_vault_artifacts_append, invoke_vault_artifacts_create,
    invoke_vault_artifacts_propose_output, vault_artifacts_append_file,
    vault_artifacts_create_file, vault_artifacts_propose_output_file,
};
use crate::memory::{Memory, MemoryError, MemoryResult};

/// The member whose string the file holds.
const CONTENT_MEMBER: &str = "content_base64";

/// Whether `verb` is a row [`invoke_blob_input`] runs.
#[must_use]
pub fn takes_blob_input(verb: &str) -> bool {
    matches!(
        verb,
        "vault.artifacts.create" | "vault.artifacts.append" | "vault.artifacts.propose_output"
    )
}

/// Runs `verb`, one of `vault.artifacts.create`, `.append` and
/// `.propose_output` ([`takes_blob_input`]), on `head`, its input with
/// `content_base64` the empty string, and `body`, the file of the bytes the
/// caller's `content_base64` decoded to as standard base64. The file stays
/// unchanged while the call runs. Its result comes back beside the
/// content-free notice bit of its pre chain, as `invoke_with_notice` gives
/// it (FIX 12517).
///
/// The result's errors are [`super::invoke`]'s; a `verb` that takes no
/// file, and the file's read errors.
pub fn invoke_blob_input(
    memory: &Memory<'_>,
    verb: &str,
    head: serde_json::Value,
    body: &File,
) -> (MemoryResult<serde_json::Value>, Option<bool>) {
    if !takes_blob_input(verb) {
        let refused = MemoryError::bad_request(format!("{verb} takes no content file"));
        return (Err(refused), None);
    }
    let held = match body.try_clone() {
        Ok(held) => held,
        Err(error) => return (Err(crate::Error::from(error).into()), None),
    };
    let _held = crate::runtime_hooks::verb::hold_member(CONTENT_MEMBER, held);
    crate::task_verb::verb_hook_boundary::row_holding_member(
        memory,
        &crate::verbs::VERB_TABLE,
        verb,
        head,
        |value, untouched| {
            if !untouched {
                // The args a hook read, or a saved call's: the member is in them.
                return match verb {
                    "vault.artifacts.create" => invoke_vault_artifacts_create(memory, value),
                    "vault.artifacts.append" => invoke_vault_artifacts_append(memory, value),
                    _ => invoke_vault_artifacts_propose_output(memory, value),
                };
            }
            let file = crate::blob_artifact::BlobBodyFile::measure(body)?;
            match verb {
                "vault.artifacts.create" => {
                    encode(vault_artifacts_create_file(memory, decode(value)?, &file)?)
                }
                "vault.artifacts.append" => {
                    encode(vault_artifacts_append_file(memory, decode(value)?, &file)?)
                }
                _ => encode(vault_artifacts_propose_output_file(
                    memory,
                    decode(value)?,
                    &file,
                )?),
            }
        },
    )
}
