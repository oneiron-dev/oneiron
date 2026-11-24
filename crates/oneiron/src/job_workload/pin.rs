//! The workload pin (pass 33, `33-exec-node/DESIGN.md` section 5.1): the
//! exact thing the owner allows to run on one of his machines. A pin names
//! a template the serving machine holds, the code revision, the frozen
//! contract, the entry the template admits, the arguments and the resources.
//! It never names a program, an interpreter, an environment or a host path:
//! those are the serving machine's own (section 1, "The wire never carries a
//! program").
//!
//! The issuer keeps the pin in `JOB_WORKLOAD` under its digest, and the job
//! submit carries it to the node, which computes the digest again from the
//! pin it runs. A changed field is a new pin.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The most arguments one pin passes (argv, no shell).
pub const PIN_ARGS_MAX: usize = 64;
/// The most bytes a pin's arguments hold together.
pub const PIN_ARG_BYTES_MAX: usize = 4_096;
/// The most outputs one pin declares.
pub const PIN_OUTPUTS_MAX: usize = 32;

/// The exact workload: template, code revision, contract, entry, arguments
/// and resource request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadPin {
    /// The node's template name, e.g. `open-models`.
    pub template: String,
    /// The template's digest as the node reported it: a changed template is
    /// a new pin.
    pub template_digest: String,
    /// The code revision: 40 lower-hex characters.
    pub commit: String,
    /// The sha256 (lower hex) of the frozen contract file.
    pub contract_sha256: String,
    /// The contract file, relative to the checkout.
    pub contract_path: String,
    /// The entry path, relative to the checkout, that the template's
    /// allow-list admits.
    pub entry: String,
    /// The argument vector, passed with no shell: at most [`PIN_ARGS_MAX`]
    /// items and [`PIN_ARG_BYTES_MAX`] bytes together.
    pub args: Vec<String>,
    pub request: ResourceRequest,
    pub scope: ScopeKind,
    pub network: NetworkMode,
    /// At most [`PIN_OUTPUTS_MAX`] outputs.
    pub outputs: Vec<OutputDecl>,
}

/// What one run of the workload asks of the serving machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    /// GPUs per run: 1 in the first slice.
    pub gpus: u32,
    /// The least GPU memory the run needs, in MiB.
    pub vram_mib: u64,
    /// Host memory, in MiB: the job unit's memory limit.
    pub memory_mib: u64,
    /// Disk the run writes on the node (checkout, outputs, scratch), in MiB.
    pub disk_mib: u64,
    /// The longest the run may occupy its device, in seconds: the node's
    /// cutoff. Never 0.
    pub maximum_secs: u64,
}

/// Which kind of scope the job unit runs in (section 7.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeKind {
    /// The host scope: the job unit's own OS account and cgroup on the node.
    Host,
    /// A container from an image pinned by digest (`name@sha256:...`): a
    /// later row (R8).
    Container { image: String },
}

/// The network the workload sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network: its own empty namespace.
    None,
    /// The host's network, only where the template lists it.
    Host,
}

/// One file the workload writes under its `out/` directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputDecl {
    pub name: String,
    /// Whether the issuer may fetch it (at most one transport piece), where
    /// the template marks the name returnable too.
    pub returnable: bool,
}

impl WorkloadPin {
    /// The pin's digest: sha256, lower hex, of its canonical JSON (every
    /// object's keys sorted), the encoding the GPU quote digest uses. The
    /// issuer keys `JOB_WORKLOAD` by it, and the node computes it again
    /// from the pin it runs.
    ///
    /// # Errors
    /// `InvariantViolation` if the pin does not encode, which a pin of
    /// strings, integers and lists never does.
    pub fn digest(&self) -> crate::Result<String> {
        let bytes = crate::llm::canonical_json_bytes(self)
            .map_err(|_| crate::Error::InvariantViolation("workload pin encode"))?;
        Ok(oneiron_hex::encode(&Sha256::digest(&bytes)))
    }
}
