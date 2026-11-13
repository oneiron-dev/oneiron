//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/digest.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::dreamer_runner::maintenance::digest::after_notice::APPLIED_GROUP;
pub use crate::dreamer_runner::maintenance::digest::after_notice::DigestAppliedItem;
pub use crate::dreamer_runner::maintenance::digest::private_sources::DigestPrivateSource;
pub use crate::dreamer_runner::maintenance::digest::view::DigestReadRequest;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The derived group the cleanup line (ARCH-0073, OF-449) renders under.
pub const CLEANUP_GROUP: &str = "dreamer.cleanup";

/// The derived group the NOTE tombstone line (OF-073, FIX 2419) renders
/// under.
pub const NOTE_TOMBSTONE_GROUP: &str = "note.tombstone";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProactivityCadence {
    pub period_secs: u64,
    pub group_by_facet: bool,
    pub urgent_breakthrough: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestProposal {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub claim_ref: EntityId,
    pub revision: [u8; 32],
    pub summary: String,
    /// The private thread turns its words were drawn from when its digest
    /// was assembled (FIX 6411): a viewer reads it only while it reads each
    /// one, whatever its claim's ancestry says later. Empty for words off
    /// every private thread.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_sources: Vec<DigestPrivateSource>,
    /// A private source its ancestry declared did not resolve when its
    /// digest was assembled: no view carries it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unverified: bool,
}

/// One pending training offer the digest carries to the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestOffer {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub offer: EntityId,
    /// The offer digest the owner's answer binds.
    pub digest: String,
    pub summary: String,
}

/// The cleanup cron's after-notice (ARCH-0073 §5): what it archived since
/// the last digest that carried it, and the proposals that wait for the
/// owner. Counts come from recorded decisions, never from the archive's size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestCleanup {
    /// The cleanup decisions this line reports, by id.
    pub decisions: Vec<String>,
    pub archived: u64,
    /// Candidates the accept or the run re-checked and left alone.
    pub skipped: u64,
    /// The open proposals this line reports, by id.
    pub proposals: Vec<String>,
    /// Records those proposals would archive.
    pub proposed: u64,
    pub view: String,
}

impl DigestCleanup {
    /// The rendered items: "archived N", then what waits for review.
    fn summaries(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.decisions.is_empty() {
            out.push(format!("{CLEANUP_GROUP}: archived {}", self.archived));
        }
        if !self.proposals.is_empty() {
            out.push(format!(
                "{CLEANUP_GROUP}: {} to archive wait for review",
                self.proposed
            ));
        }
        out
    }
}

/// The NOTE tombstone review's open proposals no digest carried yet. The
/// line only points at them; the owner accepts or declines each at the view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestNoteTombstones {
    /// The proposals this line reports, as `<note>:<proposed_at>`: a NOTE
    /// archived again is a new proposal.
    pub proposals: Vec<String>,
    pub view: String,
}

impl DigestNoteTombstones {
    fn summary(&self) -> String {
        format!(
            "{NOTE_TOMBSTONE_GROUP}: {} archived NOTEs wait for a tombstone review",
            self.proposals.len()
        )
    }
}
pub mod after_notice;
pub mod private_sources;
pub mod view;
