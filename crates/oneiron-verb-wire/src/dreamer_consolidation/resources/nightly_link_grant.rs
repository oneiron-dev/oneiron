//! Moved from `crates/oneiron/src/dreamer_consolidation/resources/nightly_link_grant.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::GrantBound;
use oneiron_store::write_envelope::WriteActor;

/// The owner grants the vault's own Dreamer its existing nightly-link bound.
/// The writer is resolved by the vault, never supplied by the caller.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NightlyLinkGrantRequest {}
