//! Moved from `crates/oneiron/src/self_heal/tripwires/policy.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Where one effective tripwire bound came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripwireBoundOrigin {
    /// A trusted policy manifest row states it.
    Manifest,
    /// The trusted rows that state the bounds omit this field, so its
    /// default applies.
    OmittedFieldDefault,
    /// No trusted row states the bounds, so the compiled default applies.
    CompiledFallback,
}

/// One effective tripwire bound and where it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripwireBound {
    /// The number the pass's detectors read.
    pub value: u64,
    /// Where it came from.
    pub origin: TripwireBoundOrigin,
}

/// One trusted policy manifest row a resolved tripwire policy read: its id
/// and the BLAKE3 of the body it was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TripwirePolicySource {
    /// The manifest row's id.
    pub manifest: EntityId,
    /// The BLAKE3 of the row's body as the fold read it.
    pub revision: [u8; 32],
}

/// The tripwire policy one pass applied (FIX 10096): its four effective
/// bounds, each with its origin, the scope they cover, every trusted
/// manifest row that supplied them, sorted by id, and the pass's own id
/// (FIX 10817). Signed with the pass's detector run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripwirePolicyReceipt {
    /// The scope the policy covers.
    pub scope: String,
    /// The fixed-window length, in seconds.
    pub window_secs: TripwireBound,
    /// The consent-storm and consent-queue depth.
    pub consent_depth: TripwireBound,
    /// The actor-write drift threshold.
    pub actor_writes: TripwireBound,
    /// The degraded retrieval runs one window reads as a regression.
    pub retrieval_regressions: TripwireBound,
    /// Every trusted manifest row the bounds came from, by id; none for the
    /// compiled fallback.
    pub sources: Vec<TripwirePolicySource>,
    /// The pass that applied it, minted from the vault clock as the pass
    /// resolves its policy (FIX 10817): two passes under the same policy that
    /// found the same events sign two runs, each kept in its own row, while
    /// every run of one pass names the same pass. `None` only on a receipt
    /// signed before passes had ids, which verifies as it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<EntityId>,
}

impl TripwirePolicyReceipt {
    /// The receipt's bytes as a signed run's transcript carries them.
    pub fn transcript_bytes(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("tripwire policy encode"))
    }
}
