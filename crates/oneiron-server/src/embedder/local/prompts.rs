//! What a query and a document carry before their text, read from the
//! checkpoint's own `config_sentence_transformers.json`.
//!
//! sentence-transformers' own resolution, kept (`encode_query` and
//! `encode_document`). A query takes, first match wins:
//!
//! 1. `query_instruction`, the host's text outright;
//! 2. `query_prompt_name`, a prompt the host names from the file;
//! 3. the file's prompt named `query`;
//! 4. the file's `default_prompt_name`;
//! 5. no prompt.
//!
//! A document takes the first of `document`, `passage` or `corpus`, then
//! `default_prompt_name`, then none. A checkpoint without the file carries no
//! prompt at all.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

/// The optional file the prompts live in.
pub(super) const PROMPT_FILE: &str = "config_sentence_transformers.json";

/// Names a document prompt may go by, in sentence-transformers' order.
const DOCUMENT_PROMPT_NAMES: [&str; 3] = ["document", "passage", "corpus"];

#[derive(Debug, Default, Deserialize)]
struct PromptFile {
    #[serde(default)]
    prompts: BTreeMap<String, String>,
    #[serde(default)]
    default_prompt_name: Option<String>,
}

/// The text each side carries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct Prompts {
    pub(super) query: String,
    pub(super) document: String,
}

/// Resolves both prompts for the checkpoint in `model_dir`, or, given
/// `None`, for a checkpoint whose prompt file is not read
/// ([`super::model_manager::reads_prompt_file`]).
///
/// A name that the file does not carry is refused, never skipped: the prompt
/// decides where every query lands, and a silently missing one is a different
/// space.
pub(super) fn resolve(
    model_dir: Option<&Path>,
    query_instruction: Option<&str>,
    query_prompt_name: Option<&str>,
) -> oneiron::Result<Prompts> {
    let read = model_dir.map(|dir| std::fs::read_to_string(dir.join(PROMPT_FILE)));
    let file = match read {
        None => PromptFile::default(),
        Some(Ok(raw)) => serde_json::from_str::<PromptFile>(&raw).map_err(|e| {
            oneiron::Error::InvalidConfig(format!("embedder model {PROMPT_FILE}: {e}"))
        })?,
        Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => PromptFile::default(),
        Some(Err(error)) => return Err(oneiron::Error::Io(error)),
    };
    let named = |name: &str| -> oneiron::Result<String> {
        file.prompts.get(name).cloned().ok_or_else(|| {
            oneiron::Error::InvalidConfig(format!(
                "embedder prompt {name:?} is not in the model's {PROMPT_FILE} (it has {:?})",
                file.prompts.keys().collect::<Vec<_>>()
            ))
        })
    };
    let fallback = file.default_prompt_name.as_deref().map(named).transpose()?;
    let query = match (query_instruction, query_prompt_name) {
        (Some(text), _) => text.to_owned(),
        (None, Some(name)) => named(name)?,
        (None, None) => file
            .prompts
            .get("query")
            .cloned()
            .or_else(|| fallback.clone())
            .unwrap_or_default(),
    };
    let document = DOCUMENT_PROMPT_NAMES
        .iter()
        .find_map(|name| file.prompts.get(*name).cloned())
        .or(fallback)
        .unwrap_or_default();
    Ok(Prompts { query, document })
}
