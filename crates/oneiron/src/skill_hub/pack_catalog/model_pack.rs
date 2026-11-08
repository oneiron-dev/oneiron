//! Model packs at the hub door (FIX 5365, MODEL PACKS = A). A pack of kind
//! `model` carries data only: its roles, variants, changelog and bench
//! evidence in [`MODEL_PACK_FILE`]. Its authority is the install receipt's
//! content hash and that hash's scan evidence, the checks the first-party
//! model catalog's rows meet (`CatalogSeed::from_installed_pack`); no new
//! key signs it. Packs from any admitted hub publisher install the same way.
//!
//! A same-name update keeps the version it replaced, receipt and source, one
//! per pack name, for the owner's one-tap revert (FIX 20192). The kept
//! version is never followed by itself: only a revert installs it again,
//! after its bytes pass an install's checks once more.
//!
//! Each installed model pack's full check is kept in memory, per vault
//! handle, beside what it read that can move (FIX 20043): the install
//! receipt, the pin a frozen hub ref holds and the source's liveness. A role
//! call reads those in its own transaction and reuses the kept check while
//! they match the store; an install, update, revert or removal, or a moved
//! freeze, changes them and the pack is checked in full again.
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use heed::{RoTxn, RwTxn};
use oneiron_store::settings::model_pack::{ModelPack, ModelPackId};

use super::{
    PackCandidateReason, PackInstallReceipt, PackInstallStatus, PackKind, PackManifest, PackSource,
    admission, invalid,
};
use crate::error::{Error, ErrorKind, Result};
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::{
    HubFile, HubPin, HubSyncPolicy, skill_scan_verdicts_for_content_hash_in_store,
};
use crate::{EntityId, Vault};

/// Where a model pack keeps its data.
pub const MODEL_PACK_FILE: &str = "knowledge/model-pack.json";

/// The PACK.md fields that declare runtime powers. An engine call (CALLS,
/// FIX 5365): a model pack is data, so it declares none of them and no
/// adapter, and its files are PACK.md and `knowledge/` data alone.
pub(super) const MODEL_PACK_RUNTIME_FIELDS: [&str; 10] = [
    "predicates",
    "kinds",
    "grants",
    "effects",
    "wakes",
    "hooks",
    "organs",
    "lenses",
    "migrations",
    "setup",
];

/// Each model pack's version a same-name update replaced, as its install
/// receipt named it: the version that update's change notice names as
/// `previous` (FIX 20192). Key: string(pack name).
const REPLACED: SideTable<String, PackInstallReceipt, Named> =
    SideTable::new(&side_table::LLM_MODEL_PACK_REPLACED);

/// An installed model pack: the receipt it installed under and its data,
/// read from the exact source that receipt names.
#[derive(Debug, Clone, PartialEq)]
pub struct InstalledModelPack {
    pub receipt: PackInstallReceipt,
    pub pack: ModelPack,
}

/// What a model pack's full check reads that can move while the store holds
/// its receipt (FIX 20043): the receipt itself, the owner's lift of a hold
/// included, the pin its hub ref is frozen to, and whether the source it
/// names is live. A source's bytes are fixed by its id, and the scan
/// evidence on them is kept, a newer scan replacing an older one, so a
/// kept check reads neither again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelPackAdmissionKey {
    receipt: PackInstallReceipt,
    /// The pin the receipt's hub ref is frozen to; `None` when the ref holds
    /// no freeze.
    frozen_pin: Option<HubPin>,
    source_live: bool,
}

/// One model pack's last full check: what it read, and the pack it
/// admitted, `None` when a check refused it.
#[derive(Debug, Clone)]
struct KeptModelPackCheck {
    key: ModelPackAdmissionKey,
    admitted: Option<ModelPack>,
}

/// Each installed model pack's last full check, by pack name (FIX 20043).
/// In memory only, one per vault handle: a reopened vault checks each pack
/// in full on its first read. A check is reused only while its key matches
/// the store, so a check kept from any transaction is never followed past a
/// change; no timer drops one.
#[derive(Debug, Default)]
pub(crate) struct AdmittedModelPacks {
    kept: Mutex<BTreeMap<String, KeptModelPackCheck>>,
}

impl AdmittedModelPacks {
    /// Pack `name`'s kept check when it read `key`: the pack it admitted,
    /// or `None` when it refused it.
    fn reuse(&self, name: &str, key: &ModelPackAdmissionKey) -> Option<Option<ModelPack>> {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .filter(|kept| kept.key == *key)
            .map(|kept| kept.admitted.clone())
    }

    /// Keeps pack `name`'s full check of `key`, in place of the one before.
    fn keep(&self, name: &str, key: &ModelPackAdmissionKey, admitted: Option<&ModelPack>) {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                name.to_owned(),
                KeptModelPackCheck {
                    key: key.clone(),
                    admitted: admitted.cloned(),
                },
            );
    }

    /// Drops the checks of every pack `names` leaves out: no longer an
    /// Active model pack.
    fn retain(&self, names: &[String]) {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|name, _| names.contains(name));
    }
}

/// The source's model pack: its data file, read under its manifest's name
/// and version. A source of kind `model` without one, or whose data does not
/// read, is refused.
pub(super) fn read_source_model_pack(
    manifest: &PackManifest,
    files: &[HubFile],
) -> Result<ModelPack> {
    let file = files
        .iter()
        .find(|file| file.path == MODEL_PACK_FILE)
        .ok_or_else(|| invalid("a model pack requires knowledge/model-pack.json"))?;
    let id = ModelPackId::new(manifest.name.clone())
        .map_err(|_| invalid("a model pack's name is not a pack id"))?;
    ModelPack::parse(id, manifest.version.clone(), &file.content)
        .map_err(|error| Error::InvalidConfig(format!("pack source: model pack: {error}")))
}

impl Vault {
    /// Every Active model pack installed, in pack name order, each read
    /// from the source its receipt names. A pack that fails a check its
    /// receipt binds (a frozen ref's drift, the source's name, kind or
    /// content hash, its scan evidence, its data) is not admitted and is
    /// left out, so no route follows it. A pack whose receipt, frozen pin
    /// and source liveness read in `txn` match its kept check is that
    /// check's outcome; any other is checked in full and kept (FIX 20043).
    pub(crate) fn installed_model_packs_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Vec<InstalledModelPack>> {
        let mut packs = Vec::new();
        let mut names = Vec::new();
        for entry in admission::PACK_INSTALL.iter_from(&self.store, txn, &[])? {
            let (name, receipt) = entry.map_err(|error| {
                if error.kind() == ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
            if receipt.kind != PackKind::Model || receipt.status != PackInstallStatus::Active {
                continue;
            }
            let key = self.model_pack_admission_key_in_txn(txn, receipt)?;
            let admitted = match self.admitted_model_packs.reuse(&name, &key) {
                Some(admitted) => admitted,
                None => {
                    let admitted = self
                        .admitted_model_pack_source_in_txn(txn, &name, &key.receipt)?
                        .map(|(_, pack)| pack);
                    self.admitted_model_packs
                        .keep(&name, &key, admitted.as_ref());
                    admitted
                }
            };
            if let Some(pack) = admitted {
                packs.push(InstalledModelPack {
                    receipt: key.receipt,
                    pack,
                });
            }
            names.push(name);
        }
        self.admitted_model_packs.retain(&names);
        Ok(packs)
    }

    /// What `receipt`'s full check reads that can move while it stands,
    /// read in `txn` (FIX 20043): its hub ref's row and its source's
    /// liveness, never the source's bytes or scan evidence.
    fn model_pack_admission_key_in_txn(
        &self,
        txn: &RoTxn<'_>,
        receipt: PackInstallReceipt,
    ) -> Result<ModelPackAdmissionKey> {
        let frozen_pin = self.model_pack_frozen_pin_in_txn(txn, &receipt)?;
        let source_live = match EntityId::from_hex(&receipt.source_id) {
            Ok(source_id) => self.pack_source_live_in_txn(txn, &source_id)?,
            Err(_) => false,
        };
        Ok(ModelPackAdmissionKey {
            receipt,
            frozen_pin,
            source_live,
        })
    }

    /// The pin `receipt`'s hub ref is frozen to, when the ref's policy
    /// accepts one content hash; `None` when it holds no freeze.
    fn model_pack_frozen_pin_in_txn(
        &self,
        txn: &RoTxn<'_>,
        receipt: &PackInstallReceipt,
    ) -> Result<Option<HubPin>> {
        let Ok(hub) = EntityId::from_hex(&receipt.hub_id) else {
            return Ok(None);
        };
        Ok(self
            .hub_ref_sync_in_txn(txn, &hub, &receipt.hub_ref)?
            .filter(|tracked| tracked.sync_policy == HubSyncPolicy::ContentHashFrozen)
            .map(|tracked| tracked.hub_ref.pin))
    }

    /// Whether `receipt`'s hub ref is frozen to other bytes: the ref's own
    /// policy judges drift, and a frozen ref accepts one hash.
    fn model_pack_drifted_in_txn(
        &self,
        txn: &RoTxn<'_>,
        receipt: &PackInstallReceipt,
    ) -> Result<bool> {
        Ok(self
            .model_pack_frozen_pin_in_txn(txn, receipt)?
            .is_some_and(|pin| pin != HubPin::ContentHash(receipt.content_hash.clone())))
    }

    /// The source `receipt` names and its model pack, when they meet every
    /// check the first-party model catalog meets; `None` when one fails.
    fn admitted_model_pack_source_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
        receipt: &PackInstallReceipt,
    ) -> Result<Option<(PackSource, ModelPack)>> {
        if receipt.pack_name != name {
            return Ok(None);
        }
        let (Ok(_), Ok(source_id)) = (
            EntityId::from_hex(&receipt.hub_id),
            EntityId::from_hex(&receipt.source_id),
        ) else {
            return Ok(None);
        };
        if self.model_pack_drifted_in_txn(txn, receipt)? {
            return Ok(None);
        }
        let Some(source) = self.pack_source_in_txn(txn, &source_id)? else {
            return Ok(None);
        };
        if source.manifest().name != name
            || source.manifest().kind != PackKind::Model
            || source.content_hash().to_hex() != receipt.content_hash
        {
            return Ok(None);
        }
        // Bytes that never reached the hub door's scan ledger are refused.
        if skill_scan_verdicts_for_content_hash_in_store(&self.store, txn, source.content_hash())?
            .is_empty()
        {
            return Ok(None);
        }
        let Ok(pack) = read_source_model_pack(source.manifest(), source.files()) else {
            return Ok(None);
        };
        Ok(Some((source, pack)))
    }

    /// Keeps the model pack an install replaced, in the install's
    /// transaction (FIX 20192): when `installed` replaces `replaced` under
    /// the same name at other bytes, both of kind `model`, `replaced` is
    /// kept as the pack's replaced version, in place of any kept before.
    /// When either is of another kind, the name keeps no model pack version.
    /// The same bytes installed again keep what was kept.
    pub(super) fn keep_replaced_model_pack_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        replaced: Option<&PackInstallReceipt>,
        installed: &PackInstallReceipt,
    ) -> Result<()> {
        let Some(replaced) = replaced else {
            return Ok(());
        };
        if replaced.content_hash == installed.content_hash {
            return Ok(());
        }
        let name = installed.pack_name.clone();
        if replaced.kind == PackKind::Model && installed.kind == PackKind::Model {
            REPLACED.put(&self.store, txn, &name, replaced)
        } else {
            REPLACED.delete(&self.store, txn, &name)?;
            Ok(())
        }
    }

    /// Drops model pack `name`'s replaced version with the pack, in its
    /// removal's transaction (FIX 20192).
    pub(super) fn drop_replaced_model_pack_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        name: &str,
    ) -> Result<()> {
        REPLACED.delete(&self.store, txn, &name.to_owned())?;
        Ok(())
    }

    /// Model pack `name`'s replaced version (FIX 20192), read as an install
    /// admits its bytes now: an Active `model` receipt meeting every check
    /// an installed model pack is followed on (a frozen ref's drift, the
    /// source's name, kind and content hash, its scan evidence, its data),
    /// then the install door's screen under the vault's install rules now
    /// and, unless the owner lifted it on these bytes, its advisory hold.
    /// Kept bytes are never trusted as they were kept. `None` when no
    /// version is kept, it fails a check, or the name now holds a pack of
    /// another kind, whose powers a revert does not undo.
    pub(crate) fn replaced_model_pack_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
    ) -> Result<Option<InstalledModelPack>> {
        let key = name.to_owned();
        let Some(receipt) = REPLACED.get(&self.store, txn, &key)? else {
            return Ok(None);
        };
        let holds_model_pack = admission::PACK_INSTALL
            .get(&self.store, txn, &key)?
            .is_some_and(|installed| installed.kind == PackKind::Model);
        if !holds_model_pack
            || receipt.kind != PackKind::Model
            || receipt.status != PackInstallStatus::Active
        {
            return Ok(None);
        }
        let Some((source, pack)) = self.admitted_model_pack_source_in_txn(txn, name, &receipt)?
        else {
            return Ok(None);
        };
        let lifted = receipt
            .owner_activated
            .contains(&PackCandidateReason::Advisories);
        if self
            .screen_pack_in_txn(txn, &source, &[], &receipt.publisher)?
            .is_some()
            || (!lifted && self.pack_advisory_hold_in_txn(txn, source.content_hash())?)
        {
            return Ok(None);
        }
        Ok(Some(InstalledModelPack { receipt, pack }))
    }

    /// Whether pack `name` is held at `content_hash`, installed or kept as
    /// its replaced version, under a hub ref frozen to other bytes (FIX
    /// 22058): the frozen ref's drift check refuses that version, as a
    /// freeze on the version a same-name update installed refuses the one
    /// it replaced, until the owner lifts the freeze or moves it.
    pub(crate) fn model_pack_frozen_out_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
        content_hash: &str,
    ) -> Result<bool> {
        let key = name.to_owned();
        let held = [
            admission::PACK_INSTALL.get(&self.store, txn, &key)?,
            REPLACED.get(&self.store, txn, &key)?,
        ];
        for receipt in held.into_iter().flatten() {
            if receipt.kind == PackKind::Model
                && receipt.content_hash == content_hash
                && self.model_pack_drifted_in_txn(txn, &receipt)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Installs model pack `name`'s replaced version again, in a revert's
    /// transaction (FIX 20192): its kept receipt becomes the pack's install
    /// receipt, and the receipt it replaces is kept in its place, so a
    /// revert of the revert returns forward the same way. The caller judged
    /// it in this transaction first ([`Self::replaced_model_pack_in_txn`]).
    /// A model pack declares no predicates, kinds, skills, adapter or setup,
    /// so its receipt is all an install of it writes. A revert is a new
    /// install of the kept version: its receipt carries the time of the
    /// revert, on the vault's clock, as its install time (FIX 22058).
    pub(crate) fn restore_replaced_model_pack_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        name: &str,
    ) -> Result<()> {
        let key = name.to_owned();
        let mut replaced = REPLACED
            .get(&self.store, txn, &key)?
            .ok_or_else(|| invalid("no replaced model pack version is kept"))?;
        let installed = admission::PACK_INSTALL
            .get(&self.store, txn, &key)?
            .ok_or_else(|| invalid("the model pack is not installed"))?;
        replaced.installed_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        admission::PACK_INSTALL.put(&self.store, txn, &key, &replaced)?;
        REPLACED.put(&self.store, txn, &key, &installed)
    }
}
