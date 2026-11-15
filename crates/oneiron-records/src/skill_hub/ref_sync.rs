//! Moved from `crates/oneiron/src/skill_hub/ref_sync.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::write_envelope::skill_source::hub_record::HubPin;
use oneiron_store::write_envelope::skill_source::hub_record::HubSyncPolicy;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// Each policy follows one kind of pin: a commit, a tag, or a frozen content
/// hash. A mirror has no pin of its own, so it has no ref row.
pub fn check_policy_pin(policy: HubSyncPolicy, pin: &HubPin) -> Result<()> {
    match (policy, pin) {
        (HubSyncPolicy::PinnedCommit, HubPin::Commit(_))
        | (HubSyncPolicy::PinnedRef, HubPin::Tag(_) | HubPin::Semver(_))
        | (HubSyncPolicy::ContentHashFrozen, HubPin::ContentHash(_)) => Ok(()),
        _ => Err(invalid("hub ref pin does not fit its sync policy")),
    }
}
