//! The world kit's public side, shared by `oneiron recovery-kit` and
//! `GET /v1/owner/recovery-kit` (OF-173): the kits a vault issued, which one
//! is current, and what each private world's key is wrapped to here. No
//! piece, passphrase or seed passes through here.

use oneiron::recovery::{KitCoverage, KitId, KitSecretKind, PieceHome};
use oneiron::world_keys::{StoredCost, StoredKit, WorldRecoveryState};
use serde::Serialize;

use super::stamp::rfc3339_secs;
use super::vault_key::hex;

/// One kit as the owner reads it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct KitView {
    pub(crate) kit_id: String,
    pub(crate) kind: KitSecretKind,
    /// The home of each point, x = 1, 2, 3.
    pub(crate) homes: [PieceHome; 3],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) passphrase_cost: Option<StoredCost>,
    /// What losing one machine leaves.
    pub(crate) coverage: KitCoverage,
    /// The root's fingerprint, hex.
    pub(crate) root: String,
    pub(crate) created: String,
    /// When the owner re-entered its pieces; none while it is pending.
    pub(crate) confirmed: Option<String>,
    pub(crate) replaced_by: Option<String>,
}

impl From<StoredKit> for KitView {
    fn from(kit: StoredKit) -> Self {
        Self {
            kit_id: kit_id(kit.kit_id),
            kind: kit.kind,
            homes: kit.homes,
            passphrase_cost: kit.cost,
            coverage: kit.coverage,
            root: hex(&kit.root),
            created: rfc3339_secs(kit.created_at),
            confirmed: kit.confirmed_at.map(rfc3339_secs),
            replaced_by: kit.replaced_by.map(kit_id),
        }
    }
}

/// One private world's no-kit state on this install.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct WorldView {
    pub(crate) world: String,
    /// `covered` means its current key has a wrap to the pinned root, no more.
    pub(crate) state: WorldRecoveryState,
}

/// The vault's kits and what they cover here.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct KitStatusView {
    /// The vault id kits are bound to: `oneiron restore --unlock kit --vault-id`.
    pub(crate) vault_id: Option<String>,
    pub(crate) pinned_root: Option<String>,
    /// The confirmed kit whose root this install pins.
    pub(crate) current: Option<String>,
    pub(crate) kits: Vec<KitView>,
    pub(crate) worlds: Vec<WorldView>,
}

pub(crate) fn report(vault: &oneiron::Vault) -> oneiron::Result<KitStatusView> {
    let status = vault.world_kit_status()?;
    Ok(KitStatusView {
        vault_id: status.vault_id.map(|id| hex(&id)),
        pinned_root: status.pinned.map(|root| hex(&root.0)),
        current: status.current.map(kit_id),
        kits: status.kits.into_iter().map(KitView::from).collect(),
        worlds: status
            .worlds
            .into_iter()
            .map(|(world, state)| WorldView {
                world: world.to_hex(),
                state,
            })
            .collect(),
    })
}

pub(crate) fn kit_id(id: KitId) -> String {
    hex(&id.0)
}
