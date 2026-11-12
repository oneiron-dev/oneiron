//! Moved from `crates/oneiron/src/drafter/serving.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::drafter::types::DrafterActor;
use crate::drafter::types::DrafterArtifactFile;
use crate::drafter::types::DrafterServing;
use crate::drafter::types::DrafterVersionState;
use crate::world_keys::vault_key::vocabulary::VaultKeyStatus;
use heed::RoTxn;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::PoisonError;

/// Why a target's binding is not what serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterUnservedReason {
    /// No host that serves the vault's bindings is attached here.
    NoServingHost,
    /// No managed worker of this process serves the target's pins with a
    /// draft.
    NoServingWorker,
    /// The worker that serves the target is shared: this process serves
    /// several vaults, or it calls a worker another process launches for
    /// every vault. Its draft is never rewritten.
    UnsupportedSharedWorker,
    /// The worker is the operator's external endpoint, never restarted by
    /// the engine.
    UnsupportedExternalWorker,
    /// The worker's runtime loads no vault drafter in this release.
    UnsupportedRuntime,
    /// The vault is locked: no private drafter serves while it is.
    VaultLocked,
    /// The bound version may not serve now: not qualified, its artifact key
    /// gone, the policy off, or an excluded world in its ancestry.
    VersionNotServable,
    /// The version's sealed load set did not open or did not verify.
    LoadSetUnverified,
    /// The new worker incarnation did not qualify with the expected draft
    /// identity; stock serves until the binding moves again.
    WorkerRejected,
    /// The binding moved while it was applied; the newer one applies next.
    Superseded,
}
