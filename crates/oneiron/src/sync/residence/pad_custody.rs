//! Pad hydration through the home (KS-5, FIX 6706): one world's current
//! pads, sealed for the one machine of the owner's that asks, as capsules it
//! opens with its own machine key and installs into its own custody
//! (`store::world_pad_custody::current`). It is how a pad reaches a machine
//! whose rows do not carry it: a promotion or a retain asks for every pad of
//! the promoted window's world, and a first open or an exact repair asks for
//! the keys it lacks. Pads still ride their rows as before; a capsule only
//! adds to them.
//!
//! Each page is one whole capsule: a seal is fresh on every call, so a set
//! larger than one page goes on from the last pad a page held (`after`),
//! never from a byte offset into a capsule. A capsule is bound to the
//! source's custody position and its digest, which the reply names; the
//! receiver opens it against those.

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{Destination, PeerMachine};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::PadRecipients;
use crate::sync::types::WindowKey;
use crate::world_keys::{
    WrapRecipient, row_pad_in_txn, world_pad_recipients_in_txn, world_pad_row_items_in_txn,
};

use super::admission::ResidenceAdmission;
use super::bundle::denied;

/// The most pads one capsule of a hydration holds (CALLS:
/// PAD_FETCH_PAGE_KEYS): a page of a larger set, the rest asked for from the
/// last pad it held, never refused. At about 150 bytes a pad, a page stays
/// near 150 KiB.
pub const PAD_FETCH_PAGE_KEYS: usize = 1024;

/// The pads a hydration asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorldPadSelection {
    /// These pads, by full id (world (16) ‖ generation (8, big-endian) ‖
    /// mint (16)), each of the window's world: a first open, or an exact
    /// repair.
    Keys(BTreeSet<[u8; 40]>),
    /// Every pad of the window's world the home holds, live and retired: a
    /// promotion or a retain, admitted as one.
    PromotedWorld,
}

/// One page of a hydration a machine asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldPadFetch {
    /// A window of the world whose pads it asks for.
    pub window: WindowKey,
    pub selection: WorldPadSelection,
    /// The machine the capsule is sealed to: the one asking, and none other.
    pub recipient: EntityId,
    /// The custody position the asker's earlier page was bound to, if any:
    /// a reply says whether the home's moved since. A page stands alone, so
    /// a move refuses nothing.
    pub known_position: Option<[u8; 96]>,
    /// The last pad an earlier page held; none for the first page.
    pub after: Option<[u8; 40]>,
}

/// One capsule of a hydration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldPadCapsule {
    /// The home's custody position the capsule is bound to.
    pub position: [u8; 96],
    /// Every pad it holds, live and retired, ascending.
    pub required_keys: Vec<[u8; 40]>,
    /// Those retired at the home: retirement evidence, never installed.
    pub retired: Vec<[u8; 40]>,
    /// BLAKE3 of [`Self::bytes`].
    pub digest: [u8; 32],
    pub bytes: Vec<u8>,
    /// Whether the position moved from the one the fetch knew.
    pub position_moved: bool,
}

/// One page of a hydration's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldPadPage {
    pub world: EntityId,
    pub recipient: EntityId,
    /// `None` when the home holds none of the page's pads, or keeps no
    /// custody to seal them under.
    pub capsule: Option<WorldPadCapsule>,
    /// The last pad this page covered, when more follow.
    pub next: Option<[u8; 40]>,
}

/// A pad's full id, a custody position or a capsule digest in lower-case
/// hex, as a hydration's wire spells it.
#[must_use]
pub fn pad_wire_hex(bytes: &[u8]) -> String {
    super::bundle::hex(bytes)
}

/// `N` bytes a hydration's wire spells in lower-case hex, and nothing else.
#[must_use]
pub fn pad_wire_from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    super::bundle::unhex(text)
}

/// One page of `fetch`'s pads, sealed for the machine `peer` proved on this
/// connection (FIX 6706). That machine must be the fetch's recipient, its
/// proof must stand here, and the world's current pad recipients must name
/// it (`world_pad_recipients_in_txn`): a machine of the owner's the world's
/// read setting admits. Exact keys need nothing more. Every pad of the
/// world needs `promoted`, the promotion's own admission of the window for
/// that machine, which the caller judged as a promotion is judged (selector,
/// item and whole-window coverage), and the pad rows must be ones that may
/// reach it; else the page is empty, as a promotion's pad set is. Pads come
/// from current custody here, else from the rows that hold them, and an
/// erase standing here sends a pad as retired.
///
/// # Errors
///
/// A refused peer or recipient; a window of no world, or a key of another
/// world; storage, custody and sealing faults.
pub fn world_pad_capsule(
    vault: &Vault,
    peer: PeerMachine,
    fetch: &WorldPadFetch,
    promoted: Option<&ResidenceAdmission<'_>>,
) -> Result<WorldPadPage> {
    let world = fetch.window.world().ok_or_else(denied)?;
    let PeerMachine::Proven { machine, key } = peer else {
        return Err(denied());
    };
    if machine != fetch.recipient {
        return Err(denied());
    }
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    if fold.machine_proof_key(machine) != Some(key) {
        return Err(denied());
    }
    let recipient = WrapRecipient::Machine(machine);
    let mut to = PadRecipients::new();
    let public = world_pad_recipients_in_txn(vault, &txn, world)?
        .remove(&recipient)
        .ok_or_else(denied)?;
    to.insert(recipient, public);
    let candidates = match &fetch.selection {
        WorldPadSelection::Keys(keys) => {
            if keys.iter().any(|key| key[..16] != world.as_bytes()[..]) {
                return Err(denied());
            }
            keys.clone()
        }
        WorldPadSelection::PromotedWorld => {
            let admission = promoted.ok_or_else(denied)?;
            if admission.destination() != Destination::Machine(machine) {
                return Err(denied());
            }
            let mut all = vault.store.world_pad_items(&world)?;
            all.extend(world_pad_row_items_in_txn(&vault.store, &txn, world)?);
            let rows = all
                .iter()
                .filter_map(|item| crate::world_keys::pad_row_of_item(item).ok().flatten())
                .collect::<Vec<_>>();
            if admission.rows_may_leave(&rows)? {
                all
            } else {
                BTreeSet::new()
            }
        }
    };
    let mut rest = candidates
        .into_iter()
        .filter(|item| fetch.after.is_none_or(|after| *item > after));
    let page: BTreeSet<[u8; 40]> = rest.by_ref().take(PAD_FETCH_PAGE_KEYS).collect();
    let next = if rest.next().is_some() {
        page.last().copied()
    } else {
        None
    };
    let row_pad = |item: &[u8; 40]| row_pad_in_txn(&vault.store, &txn, item);
    let exported = vault
        .store
        .export_current_world_pads(&txn, world, &page, &row_pad, &to)?;
    let capsule = exported.map(|exported| {
        let position = exported.sealed.position.to_bytes();
        WorldPadCapsule {
            position,
            required_keys: exported
                .sealed
                .required_keys
                .iter()
                .map(crate::world_keys::WorldKeyId::envelope_key_id)
                .collect(),
            retired: exported.retired.into_iter().collect(),
            digest: exported.sealed.digest,
            bytes: exported.sealed.bytes,
            position_moved: fetch.known_position.is_some_and(|known| known != position),
        }
    });
    Ok(WorldPadPage {
        world,
        recipient: machine,
        capsule,
        next,
    })
}
