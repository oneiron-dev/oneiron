//! Receipt stamp for a compiled prompt package.

pub const PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION: &str = "oneiron.prompt_recompile.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptRecompileStamp {
    pub schema_version: String,
    pub prompt_path: String,
    pub compiled_at_secs: u64,
    pub source_fingerprint: String,
    /// Hash of resolved package files, before host sections or memory assembly.
    pub resolved_fingerprint: String,
    /// Hash of the exact system message sent to the model. `None` for a
    /// resolved file that has not yet been assembled into a session request.
    pub assembled_fingerprint: Option<String>,
    pub source_paths: Vec<String>,
}
