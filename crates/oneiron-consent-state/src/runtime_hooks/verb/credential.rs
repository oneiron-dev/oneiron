//! Moved from `crates/oneiron/src/runtime_hooks/verb/credential.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Where a credential came from. A logged slip has a reference its host
/// verifies again, and a managed vault's attested owner one whose standing
/// it checks again; any other caller resumes on its own retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerbAskCredentialSource {
    /// A logged capability slip, admitted with its holder's proof.
    Slip {
        /// The logged slip's id.
        slip: [u8; 32],
        /// BLAKE3 of the token presented: a caveated copy is not its mint.
        fingerprint: [u8; 32],
    },
    /// The vault's owner `holder`, whom its supervisor attested with no slip
    /// (FIX 11063): the call runs again only while the vault records him as
    /// its live owner at settlement.
    AttestedOwner { holder: EntityId },
}

/// The exact instrument a credential caller presented, as its host binds it
/// on the caller's handle (`Memory::with_credential_instrument`). It names
/// the credential; it is no authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbAskInstrument {
    pub source: VerbAskCredentialSource,
    /// The vault the credential stands in: the one a slip was minted for, or
    /// the one whose authority the attested owner was admitted in.
    pub vault: [u8; 32],
    /// BLAKE3 of the authority the host projected from it, its principal and
    /// scopes: the ceiling the call was admitted under. The attested owner's
    /// is a record only; his live standing decides at settlement.
    pub ceiling: [u8; 32],
}

/// The MCP registration a paused call was admitted under. This is a ceiling
/// record, not a credential; the host still resolves and proves the live one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbAskMcpCeiling {
    pub actor_ref: EntityId,
    #[serde(with = "mcp_actor_class")]
    pub actor_class: EdgeActorClass,
    pub world: Option<EntityId>,
    pub facets: oneiron_authority::federation::ScopeAxis<oneiron_authority::federation::ScopeId>,
    pub write_facet: Option<EntityId>,
    pub bound_verbs: Option<std::collections::BTreeSet<String>>,
}

mod mcp_actor_class {
    use serde::{Deserialize, Deserializer, Serializer};

    use oneiron_base::edge::EdgeActorClass;

    pub(super) fn serialize<S: Serializer>(
        class: &EdgeActorClass,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_u8(*class as u8)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<EdgeActorClass, D::Error> {
        let byte = u8::deserialize(deserializer)?;
        EdgeActorClass::try_from_u8(byte)
            .ok_or_else(|| serde::de::Error::custom("invalid MCP actor class"))
    }
}

/// The door a credential call came in by, and what it carried beside the
/// call's input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerbAskDoor {
    /// A facade row, in the room turn the call named, if any.
    Facade { room: Option<EntityId> },
    /// A tool-first MCP row, through the connector registration whose STREAM
    /// connection is `connection`, capped by both that registration's saved
    /// `ceiling` and its live authority at settlement.
    Mcp {
        connection: String,
        ceiling: VerbAskMcpCeiling,
    },
    /// A tool-first MCP row the managed vault's console owner called on his
    /// own STREAM `connection`, which no connector registration stands
    /// behind (FIX 5204): one per person, derived from him alone.
    McpOwner { connection: String },
}

/// What a credential call's ask saves to run it again: the exact instrument
/// and the door, where the caller sat included. No authority on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbAskCredentialRef {
    pub instrument: VerbAskInstrument,
    pub door: VerbAskDoor,
    /// Whether the caller sat on this device (DEC-0005).
    pub on_device: bool,
}

impl VerbAskCredentialRef {
    /// Whether a call presenting `call` is the caller this reference was
    /// saved for: the very same reference, or for the attested owner the
    /// same person in the same vault, by whichever door and from wherever
    /// his retry comes (FIX 11063), as any retry of his call was before his
    /// calls saved a reference.
    pub fn same_caller(&self, call: &Self) -> bool {
        match (&self.instrument.source, &call.instrument.source) {
            (
                VerbAskCredentialSource::AttestedOwner { holder: saved },
                VerbAskCredentialSource::AttestedOwner { holder },
            ) => saved == holder && self.instrument.vault == call.instrument.vault,
            _ => self == call,
        }
    }
}
