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

use oneiron_contracts::fingerprint::ContentHash;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::device::DeviceClaim;

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

/// What one run of the workload asks of the serving machine (pass 34,
/// section 2.1): threads, memory and disk, and zero or more device claims.
/// A run with no device claim is a CPU-only run: the same attempt, cutoff,
/// meter and receipt, with no device lease. Devices are matched by kind,
/// features and memory ([`DeviceClaim`]), never by a vendor name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    /// Threads the scope may use at once; 0 takes the template's default.
    pub cpu_threads: u32,
    /// Host memory, in MiB: the scope's memory limit. On a device that
    /// shares the host's memory, the claim's memory is leased beside it
    /// ([`super::DevicePlacement::host_memory_mib`]).
    pub memory_mib: u64,
    /// Disk the run writes on the node (checkout, outputs, scratch), in MiB.
    pub disk_mib: u64,
    /// Empty for a CPU-only run; at most
    /// [`super::REQUEST_DEVICE_CLAIMS_MAX`] claims.
    pub devices: Vec<DeviceClaim>,
    /// The longest the run may occupy its leases, in seconds: the node's
    /// cutoff. It comes from the quote, never from the engine. Never 0.
    pub maximum_secs: u64,
}

/// Which kind of scope the job unit runs in (section 7.8). Externally
/// tagged (`"host"`, or `{"container": {"image": ...}}`), so a node decodes
/// it without buffering the sender's input: an internally tagged enum would
/// nest as deep as a granted peer's bytes do (the organ codec's one
/// exception to its no-recursion rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeKind {
    /// The host scope: the job unit's own OS account and cgroup on the node.
    Host,
    /// A container from an image pinned by digest (`name@sha256:...`): a
    /// later row (R8).
    Container { image: String },
}

/// The network the workload sees.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
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
    /// The pin's digest: the content hash, lower hex, of its canonical JSON
    /// (every object's keys sorted), as the GPU quote digest is made. The
    /// issuer keys `JOB_WORKLOAD` by it, and the node computes it again
    /// from the pin it runs.
    ///
    /// # Errors
    /// `InvariantViolation` if the pin does not encode, which a pin of
    /// strings, integers and lists never does.
    pub fn digest(&self) -> crate::Result<String> {
        let bytes = crate::llm::canonical_json_bytes(self)
            .map_err(|_| crate::Error::InvariantViolation("workload pin encode"))?;
        Ok(ContentHash::of(&bytes).to_hex())
    }
}
