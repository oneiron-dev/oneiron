//! What the engine installs and what a caller asks.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use oneiron::EntityId;
use oneiron_organ_protocol::{DEFAULT_FRAME_LIMIT, Hash32, TypedBody};
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
    /// blake3 of the program file the install pinned, as a hub pack names
    /// it. The host hashes the file before each start and refuses a binary
    /// that differs, as a handshake refusal: incompatible until reinstall.
    /// `None` runs whatever file is at `program`.
    pub program_hash: Option<Hash32>,
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
    /// The asks the grant names (protocol 1.1), each with its cap per call.
    /// An ask for any other verb is refused.
    pub asks: Vec<AskGrant>,
    /// Asks of every verb that one call may make.
    pub max_asks: u32,
    /// Answer bytes one call may be lent. They are host memory inside the
    /// call's booking, so the host never lends more than
    /// `call_memory_bytes`.
    pub max_ask_bytes: u64,
    /// Where a granted `net.fetch` may go.
    pub fetch: FetchGrant,
}

/// One ask verb an install grant names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskGrant {
    pub verb: String,
    pub max_per_call: u32,
}

impl AskGrant {
    #[must_use]
    pub fn new(verb: impl Into<String>, max_per_call: u32) -> Self {
        Self {
            verb: verb.into(),
            max_per_call,
        }
    }
}

/// The allowlist of a granted `net.fetch`: every hop's origin must be on
/// it, and every address it reaches must be global unless a CIDR here names
/// it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchGrant {
    pub origins: Vec<FetchOrigin>,
    /// Addresses a fetch may reach that are not global, such as an in-house
    /// timestamp authority.
    pub private_cidrs: Vec<ipnet::IpNet>,
    /// The most body bytes one fetch may bring back.
    pub max_bytes: u64,
}

/// An exact origin: scheme (`https` or `http`), host and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOrigin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl FetchOrigin {
    #[must_use]
    pub fn new(scheme: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            scheme: scheme.into(),
            host: host.into(),
            port,
        }
    }
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
            program_hash: None,
            verbs: Vec::new(),
            media_types: Vec::new(),
            threads: 2,
            memory_bytes: 512 * 1024 * 1024,
            call_memory_bytes: 128 * 1024 * 1024,
            max_call_frame: DEFAULT_FRAME_LIMIT,
            max_reply_frame: DEFAULT_FRAME_LIMIT,
            max_output_bytes: 128 * 1024 * 1024,
            asks: Vec::new(),
            max_asks: 32,
            max_ask_bytes: 16 * 1024 * 1024,
            fetch: FetchGrant {
                max_bytes: 8 * 1024 * 1024,
                ..FetchGrant::default()
            },
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

/// Bytes the caller holds and hands the organ for one call, such as a
/// document the engine prepared in memory. They cross like a vault input,
/// and the host hashes them itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LentInput {
    pub media_type: String,
    pub bytes: Vec<u8>,
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
