//! Moved from `crates/oneiron/src/workspace_roster/project/revision.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::fingerprint::{LegacyDigest, purposes};
pub use oneiron_verb_wire::workspace_roster::project::revision::ProjectRevisionHash;
use serde::Deserialize;
use serde::Serialize;

/// A revision's logical hash over its canonical body. Its companion id derives from
/// it, every replica that holds the revision takes it again, and later revisions name
/// their parents by it, so it keeps its bytes (K, PLAN-UC-04 stage 6.1).
pub fn hash_of(canonical: &[u8]) -> ProjectRevisionHash {
    ProjectRevisionHash(
        LegacyDigest::new(purposes::workspace_roster::PROJECT_REVISION_HASH)
            .raw(canonical)
            .finish(),
    )
}

/// How far a held revision's origin is established. Authentication checks
/// only what its bytes fix for good; standing is judged at every fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionOrigin {
    /// Its immutable slip chain verified: the mint's claims equal the slip's,
    /// the host's signature over them, every caveat transfer signature, and
    /// the last binding signer's signature over the rebuilt challenge.
    /// Boundary rows carry no signature and need none.
    Authenticated,
    /// A Signed row whose parent chain is not held: its challenge cannot be built.
    AwaitingParent,
    /// Its slip's mint is not known: the host signature cannot be checked.
    AwaitingMint,
    /// A check above failed. Kept so a re-sent carrier is recognized; never
    /// folded, counted, recorded as evidence or exported.
    Forged,
}
