//! Moved from `crates/oneiron/src/secret_custody/reveal/scope.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::secret_custody::reveal::types::RevealGrantScope;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_consent_state::consent::grant::StandingConsentGrant;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::consent_bound::AudienceBound;
use oneiron_store::consent_bound::DisclosureClass;
use oneiron_store::consent_bound::DisclosureEnvelope;
use oneiron_store::consent_bound::GrantBound;

impl RevealGrantScope {
    /// Every scope, the narrowest first: the order a reveal's cover is tried
    /// and the owner's choices are listed.
    pub const ALL: [Self; 4] = [Self::Run, Self::Task, Self::Project, Self::EveryProject];
}
