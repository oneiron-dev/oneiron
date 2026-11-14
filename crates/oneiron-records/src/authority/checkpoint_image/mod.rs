//! Moved from `crates/oneiron/src/authority/checkpoint_image/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::authority::checkpoint_image::archive::AuthorityArchiveCustodian;
pub use crate::authority::checkpoint_image::archive::AuthorityArchiveManifest;
pub(super) use crate::authority::checkpoint_image::replay::AUTHORITY_RESIDENCE_BODY_OVERFLOW;
pub(super) use crate::authority::checkpoint_image::replay::parents_first_of;
use crate::authority::*;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Cursor;

/// The fold-state schema an image encodes. A decoder refuses any other. 5:
/// each row summary marks whether its body is required (FIX 2988). 6: a
/// machine revision carries its owner say-so's causal past (FIX 4610). 7:
/// the fold keeps each machine's home candidacy (FIX 4898). 8: the owner
/// work fold keeps the owner's cancels of root requests (FIX 4739). 9: the
/// fold admits the owner's device key enrollments and an image carries
/// their bodies, and the retired multi-device entry quorum is gone (FIX 4920).
/// 10: an enrolled owner key starts its own custody line (FIX 5896). 11: a
/// custody request names its authority, an install's or the pinned kit's,
/// and the fold keeps the owner's kit push as a counted request (FIX 6053).
/// 12: the fold admits frontier joins, and an image carries their bodies
/// (FIX 7908). 13: an act-free custodial machine revision lands only as a
/// bootstrap or its carry (FIX 7920), and a pact keeps each party's narrowing
/// (FIX 7933). 14: an owner handover signs its grant ids and an image carries
/// its body (FIX 5765). 15: an image keeps the fold state at each covered row
/// off its frontier as replay evidence (FIX 3007), carries the bodies of home
/// candidacies, federation lifecycle acts and residence rows (FIX 3004, 3005,
/// 5412), and the fold keeps each valid residence directive (FIX 5412). 16:
/// the fold keeps each setting's signed acts, the refused export acts and each agent-carried act's
/// Grant, and an image carries the bodies of both ops (FIX 4624, FIX 5660). 17: the fold keeps each
/// Grant a signed `SlipGrantRevoke` withdrew and its revoke proofs carry one (FIX 1978), a pact
/// that ends keeps no plaintext scope, and one keyed digest over two scopes suspends the pact (FIX
/// 7907). 18: a replay delta keeps a map field's changed entries alone (FIX 11262). 19: anchors
/// sign joins (FIX 8498). 20: the owner work fold keeps the owner's export supplement import marks
/// (FIX 12062). 21: the fold keeps each repository's owner origin cuts (FIX 15740). 22: the fold
/// keeps each predecessor device key's owner-named successor (FIX 11135). 23: replay
/// anchors use only the first parent and overflow keeps a whole-state suffix (FIX 11762).
/// 24: residence compaction excludes the writing install's checkpoint metadata (FIX 18583).
/// 25: a pact keeps the signed nonce and the consent epoch its scope commitment is keyed under
/// (FIX 11730). 26: the fold counts a removal-archive consume's slip consumed (FIX 11862).
/// 27: the fold admits carrier-signed membership execution records, an image carries their
/// bodies, and its revoke facts carry their Grant withdrawals (FIX 12335).
/// 28: a root request's basis carries its bound anchor and its anchor heads' parents (FIX 6556).
/// 29: an owner's agent Grant mint an image carries may name verb classes (FIX 8735).
/// 30: an owner's agent Grant mint an image carries may name a host wallet (FIX 7766).
/// 31: the fold keeps each world an agent edited with all of its edits and their judged strengths,
/// for a view that holds any of those edits' Grants refused (FIX 22381).
/// 32: beside those worlds, an install's fold keeps the cap the fold with no vouch puts on
/// them, so such a view reads them under the same cap (FIX 23218).
/// 33: an owner's agent Grant mint an image carries may bind its repo bounds to one owner
/// working view (row 6 WORKING-VIEW-EDIT).
pub const AUTHORITY_CHECKPOINT_FOLD_SCHEMA: u32 = 33;

/// The domain every encoded image starts with.
pub const AUTHORITY_CHECKPOINT_V2_DOMAIN: &[u8] = b"oneiron/authority/checkpoint/v2";

/// The context of an image's id over its encoded bytes.
pub const AUTHORITY_CHECKPOINT_V2_ID_CONTEXT: &str = "oneiron/authority/checkpoint-v2/id/v1";

/// The encoded size past which a builder compacts its optional replay and
/// residence evidence ([`AuthorityCheckpointV2::compact_optional_evidence`],
/// FIX 11400): an optional-compaction trigger, not a total-image ceiling.
/// Mandatory signed bodies may exceed this trigger.
pub const AUTHORITY_CHECKPOINT_V2_COMPACTION_BYTES: usize = 64 * 1024 * 1024;

/// The context of an archive's content id ([`authority_archive_id`]).
pub const AUTHORITY_ARCHIVE_ID_CONTEXT: &str = "oneiron/authority/archive/id/v1";

/// What the image holds back, typed and never omitted. Each list ascends.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointUnresolved {
    /// Held rows outside `covered`: an ancestor of each is not held here.
    pub held: Vec<AuthorityEntryHash>,
    /// The parents held rows name that no held row is.
    pub missing: Vec<AuthorityEntryHash>,
    /// Covered handoffs in conflict: no successor stands until one settles.
    pub unsettled_handoffs: Vec<AuthorityEntryHash>,
    /// Covered machine revisions and world edits the building install held
    /// back to restriction only.
    pub held_back: Vec<AuthorityEntryHash>,
    /// Covered approvals resting on a key revoked since: whether each has
    /// expired turns on the reader's own first-seen clock, still pending.
    pub stale_approvals: Vec<AuthorityEntryHash>,
}

pub fn refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

pub fn ascending(hashes: &[AuthorityEntryHash]) -> bool {
    hashes.windows(2).all(|pair| pair[0] < pair[1])
}

/// The id of an encoded image: what an attestation names. Signatures never
/// enter it (SLH-DSA is randomized).
pub fn checkpoint_image_id(encoded: &[u8]) -> [u8; 32] {
    blake3::derive_key(AUTHORITY_CHECKPOINT_V2_ID_CONTEXT, encoded)
}
pub mod archive;
pub mod replay;
