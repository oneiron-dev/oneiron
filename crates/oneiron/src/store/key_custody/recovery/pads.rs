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

use super::{CustodyRequirement, CustodySourceAt, admit_recovery, refused};
use crate::entity_id::EntityId;
use crate::recovery::checkpoint::{Rejected, RestoreAdmissionReason as R, because};
use crate::store::Store;
use crate::store::key_custody::folder::FolderTarget;
use crate::store::key_custody::head::CustodyOpener;
use crate::store::key_custody::identity::{CustodyKind, CustodySubject};

/// A world pad's full id: world (16) | generation (8, big-endian) | mint (16).
type PadItem = [u8; 40];

/// One lineage's world pads as the head admitted gives them: each live pad of
/// a compartment the opener opened, by world and full id, and every pad the
/// lineage retired. Never the lineage's control secret, and no other kind's
/// key.
pub(crate) struct AdmittedWorldPads {
    live: BTreeMap<EntityId, BTreeMap<PadItem, Zeroizing<[u8; 32]>>>,
    retired: BTreeSet<PadItem>,
    note: Option<&'static str>,
}

impl AdmittedWorldPads {
    /// The live pads of `world` among `items` the head gave: none when its
    /// compartment did not open, or holds none of them.
    pub(crate) fn live_among(
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
    pub(crate) fn retired_among(&self, items: &BTreeSet<PadItem>) -> BTreeSet<PadItem> {
        self.retired.intersection(items).copied().collect()
    }

    /// What the reopen says about the head it used: rollback is not proven
    /// when no anchor was configured.
    pub(crate) fn note(&self) -> Option<&'static str> {
        self.note
    }
}

/// The full id of the world pad `subject` names; `None` for another kind.
fn pad_item(subject: &CustodySubject) -> Option<PadItem> {
    if subject.kind() != CustodyKind::WorldPad {
        return None;
    }
    PadItem::try_from(subject.item()).ok()
}

fn pads_corrupt() -> Rejected {
    Rejected::new(R::CodecInvalid, CustodyKind::WorldPad.corrupt())
}

impl Store {
    /// Admits the head beside the backup `source` names for the custody
    /// position `required` names, opened with `data_key` (the backup's) and
    /// the kit's root or a machine's key `source` carries. The head must be
    /// this vault's current custody lineage. Refuses as a restore's admission
    /// refuses: a missing head, a missing or stale anchor record with one
    /// configured, a bad seal, lineage or chain, or a head older than the
    /// backup.
    pub(crate) fn admit_restore_pads(
        &self,
        required: &CustodyRequirement,
        source: &CustodySourceAt<'_>,
        data_key: Zeroizing<[u8; 32]>,
    ) -> std::result::Result<AdmittedWorldPads, Rejected> {
        let wanted = required
            .position()
            .map_err(because(R::CustodyRequirementInvalid))?;
        let current = self.core.key_custody.local();
        if !current.is_some_and(|custody| {
            custody.binding().vault() == wanted.vault
                && custody.binding().namespace() == wanted.namespace
        }) {
            return Err(Rejected::new(
                R::CustodyLineageMismatch,
                refused("the backup's custody is not this vault's current custody lineage".into()),
            ));
        }
        // The image's position alone: the claim keys it required landed
        // with the restore.
        let position = CustodyRequirement {
            position: required.position.clone(),
            required: Vec::new(),
        };
        let opener = CustodyOpener {
            root: source.root,
            data_key: Some(data_key),
            machine: source.machine,
        };
        let target = FolderTarget::at(source.folder.to_path_buf());
        let admitted = admit_recovery(&position, &target, &opener, source.anchor)?;
        let mut pads = AdmittedWorldPads {
            live: BTreeMap::new(),
            retired: BTreeSet::new(),
            note: admitted.note(),
        };
        for id in &admitted.retired {
            if let Some(item) = pad_item(id.subject()) {
                pads.retired.insert(item);
            }
        }
        for subject in admitted.retired_through.keys() {
            if let Some(item) = pad_item(subject) {
                pads.retired.insert(item);
            }
        }
        for (id, secret) in &admitted.live {
            let Some(item) = pad_item(id.subject()) else {
                continue;
            };
            if admitted.retires(id) {
                pads.retired.insert(item);
                continue;
            }
            let world = <[u8; 16]>::try_from(&item[..16])
                .ok()
                .and_then(|world| EntityId::from_bytes(world).ok())
                .ok_or_else(pads_corrupt)?;
            // Straight into guarded storage, never through a plain array.
            let mut pad = Zeroizing::new([0u8; 32]);
            if secret.expose().len() != pad.len() {
                return Err(pads_corrupt());
            }
            pad.copy_from_slice(secret.expose());
            pads.live.entry(world).or_default().insert(item, pad);
        }
        Ok(pads)
    }
}
