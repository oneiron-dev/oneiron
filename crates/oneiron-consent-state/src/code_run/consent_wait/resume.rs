//! Moved from `crates/oneiron/src/code_run/consent_wait/resume.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use crate::runtime_hooks::verb::credential::VerbAskCredentialRef;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The MCP endpoint a run's caller came in by (FIX 4606).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeConsentRunEndpoint {
    /// The primary MCP surface.
    Primary,
    /// The tool-first MCP surface.
    ToolFirst,
}

impl CodeConsentRunEndpoint {
    /// The stable word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::ToolFirst => "tool_first",
        }
    }
}

/// The machine a caller's connection proved, as the request's binding door
/// verified it: its id and the key it proved (FIX 4606). Every read judges
/// that machine again in its own snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentRunPeer {
    pub machine: EntityId,
    pub key: [u8; 32],
}

/// The admitted MCP caller of a code run, as its host bound it on the run
/// (FIX 4606): the run's handle, the exact instrument and door, and where
/// the caller sat. Only a host binds it, from the request it admitted; no
/// guest value reaches it. It is no authority: a host verifies the
/// instrument again before anything runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentRunOrigin {
    /// The caller's handle onto the run: its MCP `run_ref`.
    pub handle: String,
    /// The exact instrument the caller was admitted on, the door it came in
    /// by and whether it sat on this device. The door is the MCP
    /// registration's STREAM connection and ceiling, or the attested owner's
    /// own STREAM connection.
    pub credential: VerbAskCredentialRef,
    /// The MCP endpoint the call came in by.
    pub endpoint: CodeConsentRunEndpoint,
    /// The machine the caller's connection proved; `None` when none was
    /// proved.
    pub peer: Option<CodeConsentRunPeer>,
    /// The off-record session the request named.
    pub session: Option<EntityId>,
    /// The room the request's room turn named.
    pub room_turn: Option<EntityId>,
    /// Whether the request carried a narrower caller's forwarded holder
    /// proof. That proof is fresh for one request only and is not kept, so
    /// no automatic re-entry is made for such a caller.
    pub forwarded_caller: bool,
}
