//! The owner's notice of each change of the pack the vault follows, and its
//! one-tap revert (FIX 5369, MODEL PACKS = A: "each update comes with a
//! notice and a one-tap way back to the previous pack", the ruled settings
//! pattern of DEC-0005 #agent-world-settings).
//!
//! Every change [`Vault::note_active_model_pack_in_txn`] records (an install
//! or removal that moves the active pack, the owner's setting, a
//! retirement's move, a revert) tells each owner once, naming the packs
//! before and after with their changelog headlines. The notice's tap names
//! the change; [`Vault::revert_model_pack_change_as_owner`] judges it again
//! when called. A revert pins the pack before the change and is itself a
//! change, so its own notice reverts it. When a same-name update replaced
//! that pack, the revert installs the version the update kept again, after
//! its bytes pass an install's checks once more (FIX 20192).

use serde::{Deserialize, Serialize};

use super::{ACTIVE, ModelPackChange, ModelPackReceipt, ModelPackSetting, PREFERENCE, invalid};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::settings::model_pack::ModelPackPreference;
use crate::skill_hub::pack_catalog::InstalledModelPack;

/// Producer of the owner's notice of a pack change.
pub const MODEL_PACK_CHANGE_NOTIFICATION_PRODUCER: &str = "llm.model_pack.change";

/// The verb a change notice's tap calls.
pub const MODEL_PACK_REVERT_VERB: &str = "vault.model_pack.revert";

/// Domain separator for a pack change's id.
const MODEL_PACK_CHANGE_ID_DOMAIN: &[u8] = b"oneiron:model-pack-change:v1";

/// What moved the pack the vault follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPackChangeCause {
    /// A model pack's install.
    Install,
    /// A model pack's removal.
    Removal,
    /// The owner's own preference.
    Preference,
    /// The active pack, or the pack a pin named, retired (FIX 5368).
    Retirement,
    /// The owner's revert of the change before (FIX 5369).
    Revert,
    /// The owner moved a hub ref's pin or policy, which changes the model
    /// packs it admits (review #6390).
    HubRefPin,
}

impl ModelPackChangeCause {
    /// The cause in the owner's notice.
    fn text(self) -> &'static str {
        match self {
            Self::Install => "a model pack install",
            Self::Removal => "a model pack removal",
            Self::Preference => "the owner's model pack setting",
            Self::Retirement => "a model pack retirement",
            Self::Revert => "a revert",
            Self::HubRefPin => "a hub ref pin change",
        }
    }
}

/// The owner's revert: the change its notice names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelPackRevertRequest {
    pub change_ref: String,
}

/// Why a revert cannot run now. Nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelPackRevertBlock {
    /// A later pack change replaced this one; its own notice reverts it.
    Superseded,
    /// The change had no pack before it: the vault's first pack.
    NoPreviousPack,
    /// The pack before the change is neither installed nor kept as the
    /// version a same-name update replaced at the bytes the change recorded,
    /// or its kept bytes no longer pass an install's checks.
    NotInstalled,
    /// The pack before the change has retired: it is no longer served.
    Retired,
    /// The hub ref the pack before the change came from is frozen to other
    /// bytes, the newer version's, so its drift check refuses the version
    /// the change recorded. The owner lifts the freeze, then reverts: the
    /// newer version stays in effect while the freeze is lifted, so the
    /// change still stands. Moving the freeze to the older bytes instead
    /// ends the newer version first, a change of its own that supersedes
    /// this one (review #6755).
    FrozenRefPinsNewer,
}

/// What a revert did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelPackRevert {
    /// `None` when the revert ran: the pack before the change is pinned and
    /// followed. Otherwise why it cannot run now, and nothing changed.
    pub blocked: Option<ModelPackRevertBlock>,
    /// The owner's model pack setting after the call.
    pub setting: ModelPackSetting,
}

/// The pack a revert returns to, and where it is now.
enum RevertTarget {
    /// Installed at the bytes the change recorded: the revert pins it.
    Installed(InstalledModelPack),
    /// The version a same-name update replaced, kept at those bytes and
    /// admitted again (FIX 20192): the revert installs it again and pins it.
    Replaced(InstalledModelPack),
}

impl RevertTarget {
    fn pack(&self) -> &InstalledModelPack {
        match self {
            Self::Installed(pack) | Self::Replaced(pack) => pack,
        }
    }
}

/// The preference a revert to `previous` stores. An engine call (CALLS, FIX
/// 5369): a revert pins the pack it restores by its id, so a newer pack does
/// not move the vault off it again; following the latest pack again is the
/// owner's own setting (`vault.settings.model_pack.replace`), and a revert
/// of the revert pins the pack it left.
#[must_use]
pub fn model_pack_revert_preference(previous: &InstalledModelPack) -> ModelPackPreference {
    ModelPackPreference::PinnedPack {
        pack: previous.pack.id.clone(),
    }
}

/// A new change's id, from the change before it, the pack it moves to and
/// its time, so no two changes share one.
pub(super) fn model_pack_change_ref(
    prior: Option<&ModelPackChange>,
    active: Option<&ModelPackReceipt>,
    changed_at: u64,
) -> Result<String> {
    let prior_ref = prior.map_or("", |change| change.change_ref.as_str());
    let active_hash = active.map_or("", |receipt| receipt.content_hash.as_str());
    let active_pack = active.map_or("", |receipt| receipt.pack.as_str());
    Ok(crate::store::code_snapshot::entity_id_from_hash_material(
        MODEL_PACK_CHANGE_ID_DOMAIN,
        &[
            prior_ref.as_bytes(),
            active_pack.as_bytes(),
            active_hash.as_bytes(),
            &changed_at.to_be_bytes(),
        ],
    )?
    .to_hex())
}

/// One side of a change, as the notice names it.
fn receipt_text(receipt: Option<&ModelPackReceipt>) -> String {
    receipt.map_or_else(
        || "no model pack".to_owned(),
        |receipt| {
            format!(
                "{} {} (season {})",
                receipt.pack, receipt.version, receipt.season
            )
        },
    )
}

/// The change notice's words: the packs before and after, what moved it,
/// and each pack's changelog headline on a line of its own.
fn model_pack_change_text(change: &ModelPackChange) -> String {
    let mut text = format!(
        "The vault's model pack moved from {} to {}, by {}.",
        receipt_text(change.previous.as_ref()),
        receipt_text(change.active.as_ref()),
        change.cause.text(),
    );
    for receipt in [change.active.as_ref(), change.previous.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(headline) = &receipt.changelog_headline {
            text.push_str(&format!(
                "\n{} {}: {headline}",
                receipt.pack, receipt.version
            ));
        }
    }
    text
}

impl Vault {
    /// Tells every owner of `change`, once each, in the caller's
    /// transaction: a replay finds the row it wrote first. An engine call
    /// (CALLS, FIX 5369): every recorded change is told, the vault's first
    /// pack and a move to no pack included; the revert tap is offered only
    /// where [`Self::model_pack_revert_runs_in_txn`] finds it can run.
    pub(super) fn notify_model_pack_change_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        change: &ModelPackChange,
    ) -> Result<()> {
        let detail = model_pack_change_text(change);
        for owner in crate::policy_model::owners_in_txn(self, txn)? {
            self.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::ModelPackChanged,
                    source: NotificationSource {
                        producer: MODEL_PACK_CHANGE_NOTIFICATION_PRODUCER.to_owned(),
                        event: format!("{}:{}", change.change_ref, owner.to_hex()),
                        result: Some(change.change_ref.clone()),
                        detail: Some(detail.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient: Some(owner),
                    created_at: change.changed_at,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    }

    /// The pack a revert of `change_ref` restores, read in `txn`, or why it
    /// cannot run now. An engine call (CALLS, FIX 5369, 20192): the change
    /// must be the vault's last, as a later change's own notice carries the
    /// way back from it, and the pack before it must be at the bytes the
    /// change recorded, never another version of the same pack, and served
    /// today: installed, or else kept as the version a same-name update
    /// replaced, whose bytes pass an install's checks again
    /// ([`Vault::replaced_model_pack_in_txn`]). A version held at those bytes
    /// under a hub ref frozen to other bytes answers that freeze (FIX 22058).
    fn model_pack_revert_target_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        change_ref: &str,
    ) -> Result<std::result::Result<RevertTarget, ModelPackRevertBlock>> {
        let Some(change) = ACTIVE
            .get(&self.store, txn, &())?
            .filter(|change| change.change_ref == change_ref)
        else {
            return Ok(Err(ModelPackRevertBlock::Superseded));
        };
        let Some(previous) = change.previous else {
            return Ok(Err(ModelPackRevertBlock::NoPreviousPack));
        };
        let installed = self
            .installed_model_packs_in_txn(txn)?
            .into_iter()
            .find(|installed| previous.names(installed));
        let target = match installed {
            Some(installed) => RevertTarget::Installed(installed),
            None => match self.replaced_model_pack_in_txn(txn, &previous.pack)? {
                Some(replaced) if previous.names(&replaced) => RevertTarget::Replaced(replaced),
                _ => {
                    let block = if self.model_pack_frozen_out_in_txn(
                        txn,
                        &previous.pack,
                        &previous.content_hash,
                    )? {
                        ModelPackRevertBlock::FrozenRefPinsNewer
                    } else {
                        ModelPackRevertBlock::NotInstalled
                    };
                    return Ok(Err(block));
                }
            },
        };
        if !target.pack().pack.is_served_on(self.model_pack_today()) {
            return Ok(Err(ModelPackRevertBlock::Retired));
        }
        Ok(Ok(target))
    }

    /// Whether a change notice offers its revert now (FIX 5369): the change
    /// is the vault's last and its previous pack can run. A read: the revert
    /// door judges again when tapped.
    pub(crate) fn model_pack_revert_runs_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        change_ref: &str,
    ) -> Result<bool> {
        Ok(self
            .model_pack_revert_target_in_txn(txn, change_ref)?
            .is_ok())
    }

    /// The owner's one-tap revert of the pack change `request` names, under
    /// the owner proof (FIX 5369): the pack the vault followed before it is
    /// pinned ([`model_pack_revert_preference`]) and followed, recorded as a
    /// change of its own with its own notice. When a same-name update
    /// replaced that pack, its kept version is installed again first, and
    /// the version it replaces is kept in turn, so the revert's own notice
    /// reverts it the same way (FIX 20192). A change a later one replaced,
    /// with no pack before it, or whose pack before it is neither installed
    /// nor kept at its bytes, fails an install's checks (a frozen hub ref
    /// that pins other bytes named apart) or is not served, answers why it
    /// cannot run now and changes nothing.
    ///
    /// # Errors
    /// The owner proof; [`crate::Error::InvalidConfig`] for a blank change id.
    pub fn revert_model_pack_change_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &ModelPackRevertRequest,
    ) -> Result<ModelPackRevert> {
        if request.change_ref.trim().is_empty() {
            return Err(invalid("a revert names a change"));
        }
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let blocked = match self.model_pack_revert_target_in_txn(txn, &request.change_ref)? {
                Ok(target) => {
                    let before = self.model_pack_in_effect_in_txn(txn)?;
                    if let RevertTarget::Replaced(replaced) = &target {
                        self.restore_replaced_model_pack_in_txn(txn, &replaced.receipt.pack_name)?;
                    }
                    PREFERENCE.put(
                        &self.store,
                        txn,
                        &(),
                        &model_pack_revert_preference(target.pack()),
                    )?;
                    self.note_active_model_pack_in_txn(txn, before, ModelPackChangeCause::Revert)?;
                    None
                }
                Err(block) => Some(block),
            };
            Ok(ModelPackRevert {
                blocked,
                setting: self.model_pack_setting_in_txn(txn)?,
            })
        })
    }
}
