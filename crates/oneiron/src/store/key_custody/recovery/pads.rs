//! Core half of `store::key_custody::recovery::pads`: its store-layer items live in `oneiron_store::key_custody::recovery::pads` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::recovery::pads::*;

use super::{CustodyRequirement, CustodySourceAt, admit_recovery, refused};
use crate::entity_id::EntityId;
use crate::store::Store;
use crate::store::key_custody::head::CustodyOpener;
use crate::store::key_custody::identity::{CustodyKind, CustodySubject};
use crate::store::restore_admission::Rejected;
use crate::store::restore_admission::RestoreAdmissionReason as R;
use crate::store::restore_admission::because;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

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
        let target = source.reader();
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
