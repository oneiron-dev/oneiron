//! Dispatch and execution door validators and the execution transcript encoders.

use serde::Serialize;

use crate::code_sandbox::microvm::ExecutionBudget;

use super::connector::{
    ByoEndpointSpec, ByoaConnectorSpec, CliSandboxSpec, MAX_ARGV_ENTRIES, MAX_BASE_URL_LEN,
    MAX_CHECKPOINT_FRONTIER_ENTRIES, MAX_CHECKPOINT_FRONTIER_ENTRY_LEN, MAX_CREDENTIAL_HANDLES,
    MAX_EGRESS_PROFILE_REF_LEN, MAX_MODEL_SLUG_ENTRIES, MAX_MODEL_SLUG_LEN, MAX_PROGRAM_LEN,
    MAX_SERVER_REF_LEN, ProtocolAttachSpec, SHELL_METACHARACTERS,
};
use super::error::{
    ByoaError, ByoaResult, ERR_ARGV_ENTRY, ERR_ARGV_TOO_LONG, ERR_BASE_URL,
    ERR_CHECKPOINT_FRONTIER, ERR_CREDENTIAL_HANDLES, ERR_EGRESS_PROFILE_REF, ERR_EXECUTION_BUDGET,
    ERR_EXHAUST_EMPTY, ERR_EXHAUST_ENCODE, ERR_EXHAUST_TAINT, ERR_MODEL_SLUG, ERR_PROGRAM,
    ERR_SERVER_REF, ERR_SLUG_MAP_EMPTY, ERR_SLUG_MAP_TOO_LARGE, invalid,
};
use super::exhaust::ByoaExhaust;
use super::stream::{ByoaStream, ByoaStreamWriter};
fn is_bounded_printable(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

/// Refuses a connector no executor could honestly run.
///
/// # Errors
///
/// Returns [`ByoaError::Store`](crate::dispatch_byoa::ByoaError::Store) naming the field that failed.
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
        // programs — and of any length, but it may not carry control bytes.
        // Its length is measured where the row is written, never refused.
        if arg.chars().any(char::is_control) {
            return Err(invalid(ERR_ARGV_ENTRY));
        }
    }
    if !is_bounded_printable(&spec.egress_profile_ref, MAX_EGRESS_PROFILE_REF_LEN) {
        return Err(invalid(ERR_EGRESS_PROFILE_REF));
    }
    if spec.credential_handles.len() > MAX_CREDENTIAL_HANDLES {
        return Err(invalid(ERR_CREDENTIAL_HANDLES));
    }
    if let Some(pin) = &spec.staged_input {
        super::staged_input::validate_staged_input(pin)?;
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

/// Encodes `value` as JSON into an exhaust stream, held in memory up to the
/// inline budget and spooled past it; never refused for its size.
pub(super) fn encode_execution_transcript(value: &impl Serialize) -> ByoaResult<ByoaStream> {
    /// The stream the encoder writes into, keeping the spool's own refusal.
    struct Spooling {
        stream: ByoaStreamWriter,
        refused: Option<ByoaError>,
    }
    impl std::io::Write for Spooling {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.stream.append(bytes).map_err(|refused| {
                self.refused = Some(refused);
                std::io::Error::other(ERR_EXHAUST_ENCODE)
            })?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Spooling {
        stream: ByoaStream::writer(None, None),
        refused: None,
    };
    if serde_json::to_writer(&mut sink, value).is_err() {
        return Err(sink.refused.unwrap_or_else(|| invalid(ERR_EXHAUST_ENCODE)));
    }
    sink.stream.finish()
}

/// How many bytes `value` encodes to as JSON, counted as they are written and
/// never held.
pub(super) fn encoded_json_len(value: &impl Serialize) -> ByoaResult<u64> {
    struct Counted(u64);
    impl std::io::Write for Counted {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len() as u64;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counted = Counted(0);
    serde_json::to_writer(&mut counted, value).map_err(|_| invalid(ERR_EXHAUST_ENCODE))?;
    Ok(counted.0)
}

/// Something durable was captured, every checkpoint frontier entry passes
/// its checks, and the taint refs are well formed. No stream is refused for
/// its size.
pub(super) fn validate_exhaust(exhaust: &ByoaExhaust) -> ByoaResult<()> {
    if exhaust.is_empty() {
        return Err(invalid(ERR_EXHAUST_EMPTY));
    }
    if exhaust.checkpoint_frontier.len() > MAX_CHECKPOINT_FRONTIER_ENTRIES {
        return Err(invalid(ERR_CHECKPOINT_FRONTIER));
    }
    for entry in &exhaust.checkpoint_frontier {
        if !is_bounded_printable(entry, MAX_CHECKPOINT_FRONTIER_ENTRY_LEN) {
            return Err(invalid(ERR_CHECKPOINT_FRONTIER));
        }
    }
    crate::secret_rotation::validate_taint_refs(&exhaust.secret_taint_refs)
        .map_err(|_| invalid(ERR_EXHAUST_TAINT))
}
