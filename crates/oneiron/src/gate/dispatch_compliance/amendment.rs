//! Compliance amendment classification and outcome values.

#[doc(hidden)]
pub use oneiron_verb_wire::gate::dispatch_compliance::amendment::ComplianceAmendmentClass;

/// What a proposal did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComplianceAmendmentOutcome {
    /// Activated immediately, with a durable notice.
    Applied {
        /// The now-active pack version.
        pack_version: u32,
        /// The notice persisted alongside the activation.
        notice: String,
    },
    /// Staged. Nothing changed until an owner stamps this exact hash.
    PendingOwnerStamp {
        /// Canonical hash binding the exact proposed rows and version.
        proposal_hash: [u8; 32],
    },
}
