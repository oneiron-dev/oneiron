//! Moved from `crates/oneiron/src/verbs/host/pack_setup.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::verbs::host::pack_setup::PackSetupAnswerRequest;
pub use oneiron_verb_wire::verbs::host::pack_setup::PackSetupCardActionInput;
pub use oneiron_verb_wire::verbs::host::pack_setup::PackSetupRequest;
pub use oneiron_verb_wire::verbs::host::pack_setup::PackSetupVerifyRequest;
use serde::Deserialize;
use serde::Serialize;

/// The owner secrets door to open for one declared credential name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupStoreSecret {
    pub door: String,
    pub connection: String,
    pub name: String,
    /// The binding the stored credential needs, with the read scope.
    pub effector: String,
}
