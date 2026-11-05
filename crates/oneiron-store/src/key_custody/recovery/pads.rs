//! A restored vault's world pads, admitted again from the custody head beside
//! its backup (PAD-2, FIX 10470): the head a restore landed leaves a world
//! Locked when it did not open that world's compartment, and the recovery kit
//! or an admitted machine opens it later.
//!
//! The head is admitted as a restore admits it ([`admit_recovery`]): its
//! seal, lineage and chain, the anchor's reconciliation when one is
//! configured, and every retirement after the head. It is asked for the
//! image's position alone, never the claim keys the image required, which
//! the restore already landed. Nothing lands here: the caller installs the
//! pads into the vault's current custody, and no binding, writer epoch,
//! recipient or control secret moves.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::key_custody::head::scope::CustodyOpener;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySubject;
use crate::restore_admission::Rejected;
use crate::restore_admission::RestoreAdmissionReason as R;
use crate::restore_admission::because;
use oneiron_contracts::entity_id::EntityId;

/// A world pad's full id: world (16) | generation (8, big-endian) | mint (16).
type PadItem = [u8; 40];

/// One lineage's world pads as the head admitted gives them: each live pad of
/// a compartment the opener opened, by world and full id, and every pad the
/// lineage retired. Never the lineage's control secret, and no other kind's
/// key.
pub struct AdmittedWorldPads {
    pub live: BTreeMap<EntityId, BTreeMap<PadItem, Zeroizing<[u8; 32]>>>,
    pub retired: BTreeSet<PadItem>,
    pub note: Option<&'static str>,
}

impl AdmittedWorldPads {
    /// The live pads of `world` among `items` the head gave: none when its
    /// compartment did not open, or holds none of them.
    pub fn live_among(
        &self,
        world: EntityId,
        items: &BTreeSet<PadItem>,
    ) -> BTreeMap<PadItem, Zeroizing<[u8; 32]>> {
        self.live
            .get(&world)
            .map(|pads| {
                pads.iter()
                    .filter(|(item, _)| items.contains(*item))
                    .map(|(item, pad)| (*item, pad.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Each of `items` the lineage retired: its erase stands.
    pub fn retired_among(&self, items: &BTreeSet<PadItem>) -> BTreeSet<PadItem> {
        self.retired.intersection(items).copied().collect()
    }

    /// What the reopen says about the head it used: rollback is not proven
    /// when no anchor was configured.
    pub fn note(&self) -> Option<&'static str> {
        self.note
    }
}

/// The full id of the world pad `subject` names; `None` for another kind.
pub fn pad_item(subject: &CustodySubject) -> Option<PadItem> {
    if subject.kind() != CustodyKind::WorldPad {
        return None;
    }
    PadItem::try_from(subject.item()).ok()
}

pub fn pads_corrupt() -> Rejected {
    Rejected::new(R::CodecInvalid, CustodyKind::WorldPad.corrupt())
}
