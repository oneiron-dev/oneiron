//! Moved from `crates/oneiron/src/gate/owner_policy_mutation.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The row's exact scope. A vault row has neither scope key on disk.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum PolicyRowScope {
    Vault,
    World(String),
    Project(String),
    WorldProject { world: String, project: String },
}
