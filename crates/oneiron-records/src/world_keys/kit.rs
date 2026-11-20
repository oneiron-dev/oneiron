//! Moved from `crates/oneiron/src/world_keys/kit.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::AuthorityEntryHash;
use oneiron_store::recovery_kit::KitCoverage;
use oneiron_store::recovery_kit::KitId;
use oneiron_store::recovery_kit::KitSecretKind;
use oneiron_store::recovery_kit::PieceHome;
use serde::Deserialize;
use serde::Serialize;

/// The label of the vault key's escrow wrap to the current world kit's root.
pub const WORLD_KIT_ESCROW: &str = "world-kit";

/// The passphrase piece's Argon2id cost, as the inventory keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCost {
    pub memory_mib: u32,
    pub passes: u8,
}

/// One kit this vault issued, public facts only: never a piece, point, tag,
/// passphrase, seed or export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredKit {
    pub kit_id: KitId,
    pub kind: KitSecretKind,
    /// The owner's pick per point: `homes[i]` holds x = i + 1.
    pub homes: [PieceHome; 3],
    pub cost: Option<StoredCost>,
    /// What losing one machine leaves, judged from the homes at issue.
    pub coverage: KitCoverage,
    /// The id of the root the kit's seed grows into; `None` for a data-key
    /// kit, which carries the vault data key and no root.
    pub root: Option<[u8; 32]>,
    /// The vault clock, in seconds, at issue.
    pub created_at: u64,
    /// When the owner re-entered pieces and the root went live; `None` while
    /// pending, and always for a data-key kit, which has no confirm. A
    /// pending kit never counts as coverage.
    pub confirmed_at: Option<u64>,
    /// The kit confirmed after this one. Its pieces still rebuild its own
    /// seed: a replaced kit is not a revoked one.
    pub replaced_by: Option<KitId>,
    /// The kits this one's confirm replaced whose pending piece this install
    /// may still keep: a crash before that confirm's settle leaves them, and
    /// the keystore cannot list its slots. The next settle here deletes each
    /// and takes it off the list (FIX 12135). Empty while the kit is
    /// pending, and always for a data-key kit.
    pub stale_pending_pieces: Vec<KitId>,
    /// The root request whose activation issued this kit, by its signed
    /// authority-log entry; `None` for a kit issued at this install's own
    /// kit door, and for a data-key kit (FIX 5585). No confirm reads it.
    pub issued_for: Option<AuthorityEntryHash>,
}

impl StoredKit {
    /// A world kit, confirmed, and no later kit replaced it. A data-key kit
    /// is never current: no world kit replaces it, nor it one.
    #[must_use]
    pub fn current(&self) -> bool {
        self.kind == KitSecretKind::RecoveryRoot
            && self.confirmed_at.is_some()
            && self.replaced_by.is_none()
    }
}
