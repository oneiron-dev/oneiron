//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/coach_diagnostic.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;

/// What proves a producer's revision in force (OF-418 L3), kept whole in an issue's evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectProof {
    /// The skill's admitted head, reached from the base revision through its succession.
    Skill {
        /// The head revision, active and loading as canon.
        head: EntityId,
        /// Its version.
        version: String,
        /// The revisions after the base, oldest first, ending at the head.
        succession: Vec<EntityId>,
        /// When the head superseded its predecessor; `None` for a base revised in place.
        superseded_at: Option<u64>,
    },
    /// The manifest's row while the resolved policy reads it, trusted.
    PolicyManifest {
        /// The manifest.
        manifest: EntityId,
        /// blake3 of its stored row.
        revision: [u8; 32],
        /// Every trusted manifest the resolution reads, by id and row digest.
        trusted_contributors: Vec<(EntityId, [u8; 32])>,
    },
    /// The config the newest unbroken streak of an issue's windows recorded, each run's
    /// record the owner's receipt of the config it ran under.
    Config {
        /// Whose config it is.
        owner: String,
        /// blake3 of the recorded config.
        digest: [u8; 32],
        /// The first run of that streak.
        first_run: [u8; 16],
        /// When it started.
        first_started_at: u64,
    },
}

impl EffectProof {
    /// The proof as a resolution's value reads it, engine-authored.
    pub fn value(&self) -> serde_json::Value {
        match self {
            Self::Skill {
                head,
                version,
                succession,
                superseded_at,
            } => json!({
                "kind": "skill",
                "head": head.to_hex(),
                "version": version,
                "succession": succession.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
                "superseded_at": superseded_at,
            }),
            Self::PolicyManifest {
                manifest,
                revision,
                trusted_contributors,
            } => json!({
                "kind": "policy_manifest",
                "manifest": manifest.to_hex(),
                "revision": bytes_to_hex_lower(revision),
                "trusted_contributors": trusted_contributors
                    .iter()
                    .map(|(id, digest)| json!({
                        "manifest": id.to_hex(),
                        "revision": bytes_to_hex_lower(digest),
                    }))
                    .collect::<Vec<_>>(),
            }),
            Self::Config {
                owner,
                digest,
                first_run,
                first_started_at,
            } => json!({
                "kind": "config",
                "owner": owner,
                "revision": bytes_to_hex_lower(digest),
                "first_run": bytes_to_hex_lower(first_run),
                "first_started_at": first_started_at,
            }),
        }
    }
}
