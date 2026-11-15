//! Moved from `crates/oneiron/src/workspace_roster/project/revision.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::workspace_roster::project::revision::ProjectRevisionHash;
use serde::Deserialize;
use serde::Serialize;

/// Domain of a revision's logical hash; distinct from every authority-log,
/// slip, challenge, resolution and seal domain.
pub const REVISION_HASH_DOMAIN: &[u8] = b"oneiron/project-revision/v1/";

pub fn hash_of(canonical: &[u8]) -> ProjectRevisionHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVISION_HASH_DOMAIN);
    hasher.update(canonical);
    ProjectRevisionHash(*hasher.finalize().as_bytes())
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
