//! Dispatch and execution door validators and bounded-encoding helpers.

use serde::Serialize;

use crate::code_sandbox::microvm::ExecutionBudget;

use super::connector::{
    BYOA_MAX_EXHAUST_STREAM_BYTES, BYOA_MAX_EXHAUST_TOTAL_BYTES, ByoEndpointSpec,
    ByoaConnectorSpec, CliSandboxSpec, MAX_ARGV_ENTRIES, MAX_ARGV_ENTRY_LEN, MAX_BASE_URL_LEN,
    MAX_CHECKPOINT_FRONTIER_ENTRIES, MAX_CHECKPOINT_FRONTIER_ENTRY_LEN, MAX_CREDENTIAL_HANDLES,
    MAX_EGRESS_PROFILE_REF_LEN, MAX_MODEL_SLUG_ENTRIES, MAX_MODEL_SLUG_LEN, MAX_PROGRAM_LEN,
    MAX_SERVER_REF_LEN, ProtocolAttachSpec, SHELL_METACHARACTERS,
};
use super::error::{
    ByoaResult, ERR_ARGV_ENTRY, ERR_ARGV_TOO_LONG, ERR_BASE_URL, ERR_CHECKPOINT_FRONTIER,
    ERR_CREDENTIAL_HANDLES, ERR_EGRESS_PROFILE_REF, ERR_EXECUTION_BUDGET, ERR_EXHAUST_EMPTY,
    ERR_EXHAUST_TOO_LARGE, ERR_MODEL_SLUG, ERR_PROGRAM, ERR_SERVER_REF, ERR_SLUG_MAP_EMPTY,
    ERR_SLUG_MAP_TOO_LARGE, invalid,
};
use super::exhaust::ByoaExhaust;
fn is_bounded_printable(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

/// Refuses a connector no executor could honestly run.
///
/// # Errors
///
/// Returns [`ByoaError::Store`] naming the field that failed.
pub fn validate_connector(connector: &ByoaConnectorSpec) -> ByoaResult<()> {
    match connector {
        ByoaConnectorSpec::Endpoint(spec) => validate_endpoint(spec),
        ByoaConnectorSpec::ProtocolAttach(spec) => validate_protocol_attach(spec),
        ByoaConnectorSpec::CliSandbox(spec) => validate_cli_sandbox(spec),
    }
}

pub(super) fn validate_endpoint(spec: &ByoEndpointSpec) -> ByoaResult<()> {
    let base_url = spec.base_url.as_str();
    if !is_bounded_printable(base_url, MAX_BASE_URL_LEN)
        || base_url.chars().any(char::is_whitespace)
        || base_url.contains('\\')
    {
        return Err(invalid(ERR_BASE_URL));
    }
    // URL parsers normalize hostless forms and backslashes. Refuse those
    // spellings, all user-info (even empty), and query/fragment credentials
    // before passing the structurally parsed endpoint to a host transport.
    let authority = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .ok_or_else(|| invalid(ERR_BASE_URL))?
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty() && !authority.contains('@'))
        .ok_or_else(|| invalid(ERR_BASE_URL))?;
    let url = reqwest::Url::parse(base_url).map_err(|_| invalid(ERR_BASE_URL))?;
    if url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || authority.ends_with(':')
    {
        return Err(invalid(ERR_BASE_URL));
    }
    if spec.model_slug_map.is_empty() {
        return Err(invalid(ERR_SLUG_MAP_EMPTY));
    }
    if spec.model_slug_map.len() > MAX_MODEL_SLUG_ENTRIES {
        return Err(invalid(ERR_SLUG_MAP_TOO_LARGE));
    }
    for slug in spec.model_slug_map.keys() {
        if !is_bounded_printable(slug, MAX_MODEL_SLUG_LEN) {
            return Err(invalid(ERR_MODEL_SLUG));
        }
    }
    Ok(())
}

fn validate_protocol_attach(spec: &ProtocolAttachSpec) -> ByoaResult<()> {
    if !is_bounded_printable(&spec.server_ref, MAX_SERVER_REF_LEN) {
        return Err(invalid(ERR_SERVER_REF));
    }
    Ok(())
}

pub(super) fn validate_cli_sandbox(spec: &CliSandboxSpec) -> ByoaResult<()> {
    let program = spec.program.as_str();
    if !is_bounded_printable(program, MAX_PROGRAM_LEN)
        || program.chars().any(char::is_whitespace)
        || program.chars().any(|c| SHELL_METACHARACTERS.contains(&c))
    {
        return Err(invalid(ERR_PROGRAM));
    }
    if spec.argv.len() > MAX_ARGV_ENTRIES {
        return Err(invalid(ERR_ARGV_TOO_LONG));
    }
    for arg in &spec.argv {
        // An argument MAY be empty — an empty argv slot is meaningful to many
        // programs — but it may not be unbounded or carry control bytes.
        if arg.len() > MAX_ARGV_ENTRY_LEN || arg.chars().any(char::is_control) {
            return Err(invalid(ERR_ARGV_ENTRY));
        }
    }
    if !is_bounded_printable(&spec.egress_profile_ref, MAX_EGRESS_PROFILE_REF_LEN) {
        return Err(invalid(ERR_EGRESS_PROFILE_REF));
    }
    if spec.credential_handles.len() > MAX_CREDENTIAL_HANDLES {
        return Err(invalid(ERR_CREDENTIAL_HANDLES));
    }
    Ok(())
}

pub(super) fn validate_execution_budget(budget: ExecutionBudget) -> ByoaResult<()> {
    if !budget.is_bounded()
        || budget.wall_clock_secs > 3600
        || budget.mem_mib > 4096
        || budget.pids > 128
    {
        return Err(invalid(ERR_EXECUTION_BUDGET));
    }
    Ok(())
}

pub(super) fn encode_execution_transcript(value: &impl Serialize) -> ByoaResult<Vec<u8>> {
    struct BoundedBytes(Vec<u8>);
    impl std::io::Write for BoundedBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > BYOA_MAX_EXHAUST_STREAM_BYTES - self.0.len() {
                return Err(std::io::Error::other(ERR_EXHAUST_TOO_LARGE));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut bytes = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut bytes, value).map_err(|_| invalid(ERR_EXHAUST_TOO_LARGE))?;
    Ok(bytes.0)
}

pub(super) fn validate_exhaust(exhaust: &ByoaExhaust) -> ByoaResult<()> {
    if exhaust.is_empty() {
        return Err(invalid(ERR_EXHAUST_EMPTY));
    }
    let mut total = 0_usize;
    for stream in [
        exhaust.transcript.as_deref().unwrap_or_default(),
        exhaust.stdout.as_slice(),
        exhaust.stderr.as_slice(),
        exhaust.diff_bundle.as_deref().unwrap_or_default(),
    ] {
        if stream.len() > BYOA_MAX_EXHAUST_STREAM_BYTES {
            return Err(invalid(ERR_EXHAUST_TOO_LARGE));
        }
        total = total
            .checked_add(stream.len())
            .ok_or_else(|| invalid(ERR_EXHAUST_TOO_LARGE))?;
    }
    if exhaust.checkpoint_frontier.len() > MAX_CHECKPOINT_FRONTIER_ENTRIES {
        return Err(invalid(ERR_CHECKPOINT_FRONTIER));
    }
    for entry in &exhaust.checkpoint_frontier {
        if !is_bounded_printable(entry, MAX_CHECKPOINT_FRONTIER_ENTRY_LEN) {
            return Err(invalid(ERR_CHECKPOINT_FRONTIER));
        }
        total = total
            .checked_add(entry.len())
            .ok_or_else(|| invalid(ERR_EXHAUST_TOO_LARGE))?;
    }
    if total > BYOA_MAX_EXHAUST_TOTAL_BYTES {
        return Err(invalid(ERR_EXHAUST_TOO_LARGE));
    }
    Ok(())
}
