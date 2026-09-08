//! OF-325 persona snapshot: compile + export the shareable person-card
//! (PSNAP-1, mode A).
//!
//! `compile_persona_snapshot` assembles a strikeable row list — identity
//! line, key relationships, top-salience claims with provenance refs — with
//! the OF-365 disclosure clamp applied AT COMPILE: Tier A (restricted-band
//! or band-ambiguous claims) never enters the row list, and when the card is
//! FOR someone the audience's scoped-read lane clamps what may enter.
//! Third-party rows default COARSE (name + role); claims about others enter
//! the artifact only via explicit un-strike at preview. Agent takes (OF-330
//! asides) are OFF by default, per-card toggled, and always attributed.
//!
//! `export_persona_snapshot` applies the owner's strike-list (the preview is
//! the consent surface), requires consent content-addressed to the exact
//! compile stamp, renders BOTH artifacts from the one compile
//! (MemoryPack-lite JSON + human markdown card, each carrying compiled-at,
//! the stale_after hint, and the persona compile stamp), and persists an
//! engine-authored export record that projects into the receipt family as a
//! Share receipt carrying `persona_compile_stamp` (RCPT-7 field-set seam).
//!
//! Mode B (grant-backed reference over the share surface) is designed but
//! deliberately NOT built here — a handed copy is a copy; revocation means
//! "don't re-issue".

mod codec;
mod compile;
mod export;
mod types;

pub use self::codec::{decode_persona_snapshot_export_body, encode_persona_snapshot_export_body};
pub use self::types::{
    DEFAULT_PERSONA_SNAPSHOT_MAX_CLAIM_ROWS, DEFAULT_PERSONA_SNAPSHOT_MAX_THIRD_PARTY_ROWS,
    DEFAULT_PERSONA_SNAPSHOT_STALE_AFTER_SECS, MEMORY_PACK_LITE_SCHEMA_VERSION,
    PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION, PERSONA_SNAPSHOT_EXPORT_BODY_KEYS,
    PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION, PERSONA_SNAPSHOT_NAME_PREDICATE,
    PERSONA_SNAPSHOT_ROLE_PREDICATE, PersonaSnapshotAgentTake, PersonaSnapshotArtifact,
    PersonaSnapshotCompile, PersonaSnapshotCompileOptions, PersonaSnapshotCompileStamp,
    PersonaSnapshotExportConsent, PersonaSnapshotExportRecord, PersonaSnapshotRow,
    PersonaSnapshotRowKind, PersonaSnapshotStrikeList, STRUCK_IDENTITY_LINE_PLACEHOLDER,
};

pub(crate) use self::codec::validate_persona_snapshot_export_body_bytes;
pub(crate) use self::types::{
    PERSONA_SNAPSHOT_EXPORT_FIELDS_FULL, PERSONA_SNAPSHOT_EXPORT_FIELDS_MINIMAL,
    PERSONA_SNAPSHOT_EXPORT_FIELDS_STANDARD,
};

#[cfg(test)]
mod tests;

// The flat persona_snapshot.rs module used to provide these names to the
// sibling test module through `use super::*`: every persona_snapshot-internal
// item the tests name bare, plus the parent's own imports the tests rely on.
// After the directory split the seam re-imports both so `tests.rs` resolves
// exactly as it did before.
#[cfg(test)]
use self::compile::*;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::BTreeSet;
