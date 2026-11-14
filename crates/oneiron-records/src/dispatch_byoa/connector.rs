//! Moved from `crates/oneiron/src/dispatch_byoa/connector.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::dispatch_attempt_kind::BYOA_ATTEMPT_KIND;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Bytes of one exhaust stream held in memory before the rest spools to disk,
/// and the size of each chunk a longer stream is stored in. Never a refusal:
/// a stream of any length is captured and stored whole.
pub const BYOA_EXHAUST_INLINE_BYTES: usize = 4 * 1024 * 1024;

/// Which of the three v1 connector shapes an attempt row carries.
///
/// The discriminants are the pinned wire values. This type is deliberately NOT
/// serialized: the durable payload carries the connector VARIANT itself, so a
/// row cannot end up with a kind tag that disagrees with the spec beside it.
/// [`Self::wire_value`] is the outward-facing number for configuration and
/// diagnostic surfaces.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByoaConnectorKind {
    Endpoint = 1,
    ProtocolAttach = 2,
    CliSandbox = 3,
}

impl ByoaConnectorKind {
    /// Stable wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::ProtocolAttach => "protocol_attach",
            Self::CliSandbox => "cli_sandbox",
        }
    }

    /// The pinned numeric wire value.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        self as u8
    }
}

/// Typed entity references a dev-runner job carries for erase reach (FIX 7621).
/// Ids only: no diagnostic or evidence text rides this shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevRunnerRefs {
    /// The actor the job runs for.
    pub actor: [u8; 16],
    /// The admitted diagnostic rows its corpus cites.
    pub diagnostics: Vec<[u8; 16]>,
    /// The evidence rows its admitted corpus cites.
    pub evidence: Vec<[u8; 16]>,
}
