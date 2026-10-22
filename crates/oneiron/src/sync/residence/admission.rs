//! One residence request's admission for the machine at the other end of the
//! connection (OF-534 G6). L02's read context judges the credential, the
//! selector's live grant and each row's world for the proved machine. The
//! same snapshot names the worlds kept off that machine, and the selector's
//! filter withholds exactly those at its source, in place of the
//! unknown-destination set an unproved peer gets.

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{Destination, PeerMachine, VerifiedSlip, WorldPrivacyView};
use crate::claim::ResidenceReadContext;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::FederationGrantScope;
use crate::sync::SyncSelector;
use crate::sync::types::WindowKey;
use crate::sync::window::Withhold;
use crate::world_keys::PromotedWorldPad;

/// A residence read admitted for one credential, selector and destination.
/// Load it once per request, and again at each release; never keep it on a
/// connection or in a cache.
pub struct ResidenceAdmission<'v> {
    vault: &'v Vault,
    context: ResidenceReadContext<'v>,
    /// Every world whose read setting keeps it off the destination.
    withheld: BTreeSet<EntityId>,
}

impl<'v> ResidenceAdmission<'v> {
    /// Admits the read `proof` makes through `selector` over `scope`, for the
    /// machine `peer` proved on this connection. A peer whose proof no longer
    /// stands is an unknown destination.
    ///
    /// # Errors
    ///
    /// A credential, grant or member the context refuses; storage errors.
    pub fn load(
        vault: &'v Vault,
        proof: &VerifiedSlip,
        peer: PeerMachine,
        scope: FederationGrantScope,
        selector: &SyncSelector,
    ) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        let context = ResidenceReadContext::load_in(vault, &txn, proof, peer, scope, selector)?;
        let withheld =
            WorldPrivacyView::load_in(vault, &txn)?.withheld_for(context.destination())?;
        Ok(Self {
            vault,
            context,
            withheld,
        })
    }

    /// The machine this read serves, or `Unknown`.
    #[must_use]
    pub fn destination(&self) -> Destination {
        self.context.destination()
    }

    /// The worlds the selector's filter withholds for this destination. An
    /// unknown destination gets the device's own unknown-destination set.
    #[must_use]
    pub fn withhold(&self) -> Withhold<'_> {
        match self.destination() {
            Destination::Machine(_) => Withhold::Worlds(&self.withheld),
            Destination::Unknown => Withhold::Unknown,
        }
    }

    /// Whether the credential reads `id` and its world may be read on the
    /// destination.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn allows_item(&self, id: EntityId) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        // FIX 7608 slice 4: a marked repo item's copy id is judged as its source.
        let id =
            crate::sync::selector::secret_projection::stored_item_in_txn(&self.vault, &txn, id)?;
        self.context.allows_item(&txn, &id)
    }

    /// Whether every row of `rows` may go to the destination.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn rows_may_leave(&self, rows: &[EntityId]) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        self.context.rows_may_leave(&txn, rows)
    }

    /// The pads of `window`'s world a promotion of it carries (FIX 3789):
    /// every pad row of the world held here
    /// ([`Vault::promoted_world_pads`]), for a proved machine they may reach.
    /// None for a base window or any other destination. Ask it only once the
    /// promotion was admitted.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn promoted_pads(&self, window: &WindowKey) -> Result<Vec<PromotedWorldPad>> {
        let Some(world) = window.world() else {
            return Ok(Vec::new());
        };
        if !matches!(self.destination(), Destination::Machine(_)) {
            return Ok(Vec::new());
        }
        let pads = self.vault.promoted_world_pads(world)?;
        let ids: Vec<EntityId> = pads.iter().map(|pad| pad.id).collect();
        Ok(if self.rows_may_leave(&ids)? {
            pads
        } else {
            Vec::new()
        })
    }
}

/// Whether every row of `rows` may go to the machine `peer` proved, by each
/// row's world read setting for that machine now. A queued body's last door
/// asks it: the request admitted the credential and grant, and this judges
/// the destination again at release. A peer whose proof no longer stands is
/// an unknown destination; a row whose world cannot be placed stays.
///
/// # Errors
///
/// Storage errors.
pub fn rows_may_reach(vault: &Vault, peer: PeerMachine, rows: &[EntityId]) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let (_, withheld) = destination_withheld_in(vault, &txn, peer)?;
    for row in rows {
        match crate::settings::device_only_withholds(&vault.store, &txn, &withheld, row) {
            Ok(false) => {}
            Ok(true) | Err(crate::error::Error::CorruptedIndex(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// The worlds kept off the machine `peer` proved, read now, or `None` when no
/// proof stands: an unknown destination gets the device's own set
/// ([`Withhold::Unknown`]).
///
/// # Errors
///
/// Storage errors.
pub fn withheld_from_peer(vault: &Vault, peer: PeerMachine) -> Result<Option<BTreeSet<EntityId>>> {
    let txn = vault.store.env.read_txn()?;
    Ok(match destination_withheld_in(vault, &txn, peer)? {
        (Destination::Machine(_), withheld) => Some(withheld),
        (Destination::Unknown, _) => None,
    })
}

/// The destination `peer` names in `txn`, and the worlds kept off it. The
/// machine's proof must still stand on the key it proved.
fn destination_withheld_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    peer: PeerMachine,
) -> Result<(Destination, BTreeSet<EntityId>)> {
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    let destination = match peer {
        PeerMachine::Proven { machine, key } if fold.machine_proof_key(machine) == Some(key) => {
            Destination::Machine(machine)
        }
        _ => Destination::Unknown,
    };
    let withheld = WorldPrivacyView::load_in(vault, txn)?.withheld_for(destination)?;
    Ok((destination, withheld))
}
