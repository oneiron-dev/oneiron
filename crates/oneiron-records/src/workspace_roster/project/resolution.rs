//! Moved from `crates/oneiron/src/workspace_roster/project/resolution.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::project::*;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::workspace_roster::project::revision::ProjectRevisionHash;
use serde::Deserialize;
use serde::Serialize;

pub const RESOLUTION_DOMAIN: &[u8] = b"oneiron/project-resolution/v1/";

pub const SEAL_DOMAIN: &[u8] = b"oneiron/project-seal/v1/";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectResolution {
    /// The fork's common anchor.
    pub anchor: ProjectRevisionHash,
    /// The resolutions at `anchor` this one builds on: the tips its signer
    /// saw, sorted and unique (empty for the first).
    pub prior: Vec<ProjectRevisionHash>,
    /// The children it settles: sorted, unique, at least two.
    pub contenders: Vec<ProjectRevisionHash>,
    /// The board-rank child of `anchor` that stands: a contender, or a fresh
    /// v3 sibling over `anchor` written with the envelope.
    pub next: ProjectRevisionHash,
    pub slip_wire: String,
    pub holder_signature: Vec<u8>,
    pub signed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSeal {
    /// A fresh host-signed v3 revision the seal door built and signed.
    pub next: ProjectRevisionHash,
    /// The seal tips it replaces, sorted and unique.
    pub supersedes: Vec<ProjectRevisionHash>,
    pub slip_wire: String,
    pub holder_signature: Vec<u8>,
    pub signed_at: u64,
}

pub fn challenge(domain: &[u8], fields: &impl Serialize) -> Result<Vec<u8>> {
    Ok([domain, blake3::hash(&encode(fields)?).as_bytes()].concat())
}

impl ProjectResolution {
    /// RESOLUTION_DOMAIN || blake3(canonical(project, anchor, prior,
    /// contenders, next, signed_at)), signed through the slip's binding
    /// transcript as proofs are.
    pub fn challenge(&self, project: EntityId) -> Result<Vec<u8>> {
        challenge(
            RESOLUTION_DOMAIN,
            &(
                project,
                self.anchor,
                &self.prior,
                &self.contenders,
                self.next,
                self.signed_at,
            ),
        )
    }
}

impl ProjectSeal {
    /// SEAL_DOMAIN || blake3(canonical(project, next, supersedes, signed_at)).
    pub fn challenge(&self, project: EntityId) -> Result<Vec<u8>> {
        challenge(
            SEAL_DOMAIN,
            &(project, self.next, &self.supersedes, self.signed_at),
        )
    }
}
