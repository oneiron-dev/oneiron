//! What the engine installs and what a caller asks.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use oneiron::EntityId;
use oneiron_organ_protocol::{DEFAULT_FRAME_LIMIT, TypedBody};
use serde::{Deserialize, Serialize};

use crate::budget::BudgetConfig;

/// Whose code an organ is. Third-party organs need filesystem confinement,
/// which no platform has yet, so the host refuses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganTier {
    FirstParty,
    ThirdParty,
}

/// One installed organ and its install grant.
#[derive(Debug, Clone)]
pub struct OrganSpec {
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub tier: OrganTier,
    /// The organ version the install pinned; `None` accepts any.
    pub version_pin: Option<String>,
    /// The verbs the grant names. The handshake must offer every one.
    pub verbs: Vec<String>,
    /// The input media types the grant names.
    pub media_types: Vec<String>,
    /// Calls the process may run at once.
    pub threads: u16,
    /// The process's memory grant, also its kernel data limit on Linux.
    pub memory_bytes: u64,
    /// What one call books from the shared budget.
    pub call_memory_bytes: u64,
    pub max_call_frame: u32,
    pub max_reply_frame: u32,
    /// The most bytes one reply's outputs may hold together, inline and
    /// region. The host checks sealed sizes before it maps or hashes any.
    /// Outputs are host memory the caller may keep, so they count against
    /// the call's booking, and stay counted until they drop: the host never
    /// allows more than `call_memory_bytes`.
    pub max_output_bytes: u64,
}

impl OrganSpec {
    /// A first-party organ with the default grant: two threads, 512 MiB.
    #[must_use]
    pub fn first_party(name: impl Into<String>, program: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            program: program.into(),
            args: Vec::new(),
            tier: OrganTier::FirstParty,
            version_pin: None,
            verbs: Vec::new(),
            media_types: Vec::new(),
            threads: 2,
            memory_bytes: 512 * 1024 * 1024,
            call_memory_bytes: 128 * 1024 * 1024,
            max_call_frame: DEFAULT_FRAME_LIMIT,
            max_reply_frame: DEFAULT_FRAME_LIMIT,
            max_output_bytes: 128 * 1024 * 1024,
        }
    }
}

/// The host's own settings.
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub budget: BudgetConfig,
    /// Bytes of regions kept for reuse, keyed by content hash.
    pub region_cache_bytes: u64,
    /// Inputs at or under this size ride inside the frame; larger ones cross
    /// as region handles. The bench raises it to measure a socket copy.
    pub inline_max_bytes: usize,
    /// A process idle this long is unloaded.
    pub idle_unload: Duration,
    pub handshake_timeout: Duration,
    /// How long a cancelled call may take to stop before its process is killed.
    pub cancel_grace: Duration,
    /// Sent in the handshake.
    pub engine_version: String,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            budget: BudgetConfig::for_this_machine(),
            region_cache_bytes: 512 * 1024 * 1024,
            inline_max_bytes: oneiron_organ_protocol::INLINE_MAX_BYTES,
            idle_unload: Duration::from_secs(300),
            handshake_timeout: Duration::from_secs(2),
            cancel_grace: Duration::from_millis(100),
            engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

/// Who is waiting on a call. Recall never runs in an organ; organs run at
/// lower OS priority, so every class here yields to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallClass {
    /// A person is waiting.
    Interactive,
    Agent,
    /// The Dreamer, batch work.
    Background,
}

/// One version of one artifact, handed to the organ read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrganInput {
    pub artifact: EntityId,
    pub version: u64,
}

/// One call, as an engine caller asks it.
#[derive(Debug, Clone)]
pub struct OrganCall {
    pub organ: String,
    pub verb: String,
    pub schema: u32,
    pub args: rmpv::Value,
    pub body: Option<TypedBody>,
    pub inputs: Vec<OrganInput>,
    pub class: CallClass,
    pub deadline: Duration,
    /// The grant this call runs under; revoking it stops the call.
    pub grant: String,
}
