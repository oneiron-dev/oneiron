//! Model packs at inference (FIX 5365-5367, MODEL PACKS = A): the access a
//! host can run now, the pack a vault follows, each role's pick from it, and
//! the owner's follow-or-pin setting.
//!
//! Precedence for a role's model: an agent's own model list wins on the
//! seats and raw calls it binds (#agent-models), then the owner's manifest,
//! then the active pack's pick, then today's defaults (the host's seat for
//! the role). A vault with no model pack installed routes as before.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::manifest::{ModelManifest, ModelRole};
use super::run_admission::{OfferBinding, Payer};
use super::{ModelId, ModelLocality};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::settings::model_pack::{
    ModelPack, ModelPackAccess, ModelPackId, ModelPackVariant, model_pack_recency,
    select_model_pack,
};
use crate::settings::{ModelStackDeprecationStatus, ModelStackId, ModelStackPreference};
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::InstalledModelPack;

/// The owner's model pack preference: follow the latest pack, or pin a
/// season. Key: (). Absent follows the latest pack.
const PREFERENCE: SideTable<(), ModelStackPreference, Named> =
    SideTable::new(&side_table::LLM_MODEL_PACK_PREFERENCE);
/// The pack the vault followed when its pack last changed, and the one it
/// followed before. Key: ().
const ACTIVE: SideTable<(), ModelPackChange, Named> =
    SideTable::new(&side_table::LLM_MODEL_PACK_ACTIVE);

/// Seconds in a day, for the epoch day a pack's release and retirement name.
const SECONDS_PER_DAY: u64 = 86_400;

/// The kinds of access a host can run now, each with the models its offers
/// serve on it (FIX 5366). Built from the offers the host bound: nothing is
/// probed and nothing is fetched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessSnapshot {
    access: BTreeMap<ModelPackAccess, BTreeSet<ModelId>>,
}

impl AccessSnapshot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The access each of `offers` runs on, with the model it serves.
    pub fn from_offers(offers: impl IntoIterator<Item = &OfferBinding>) -> Self {
        let mut snapshot = Self::new();
        for offer in offers {
            snapshot.insert_offer(offer);
        }
        snapshot
    }

    /// Adds the access `offer` runs on, serving its model. An offer that
    /// holds no pack access ([`model_pack_access_for`]) adds nothing.
    pub fn insert_offer(&mut self, offer: &OfferBinding) {
        if let Some(access) = model_pack_access_for(offer) {
            self.insert(access, offer.model.clone());
        }
    }

    /// Adds `access`, serving `model`.
    pub fn insert(&mut self, access: ModelPackAccess, model: ModelId) {
        self.access.entry(access).or_default().insert(model);
    }

    /// Every kind of access held, in order.
    pub fn kinds(&self) -> impl Iterator<Item = &ModelPackAccess> {
        self.access.keys()
    }

    /// Whether any offer runs on `access`.
    #[must_use]
    pub fn holds(&self, access: &ModelPackAccess) -> bool {
        self.access.contains_key(access)
    }

    /// Whether `variant` runs here. An engine call (CALLS, FIX 5366): an
    /// offer must serve the variant's model on the variant's access; holding
    /// the access alone does not run a model no offer serves. A local-GPU
    /// variant runs only where an on-device offer serves its model.
    #[must_use]
    pub fn runs(&self, variant: &ModelPackVariant) -> bool {
        self.access
            .get(&variant.access)
            .is_some_and(|models| models.contains(&variant.model))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.access.is_empty()
    }
}

/// The access an offer runs on. An engine call (CALLS, FIX 5366): the
/// host's payer names it. Host-paid is our hosted credits; the customer's
/// key or cloud account is their own keys; a signed-in vendor CLI or plan
/// is a seat; a local-payer offer on this device or on the owner's own
/// model server is a local GPU. A local-payer offer at a third party (a
/// keyless remote) holds no pack access: a local-GPU pick never sends input
/// to a third party. The provider is the model id's provider segment.
#[must_use]
pub fn model_pack_access_for(offer: &OfferBinding) -> Option<ModelPackAccess> {
    let provider = || offer.model.provider().to_owned();
    match offer.payer {
        Payer::Host => Some(ModelPackAccess::Hosted {
            provider: provider(),
        }),
        Payer::CustomerKey | Payer::CustomerAccount => Some(ModelPackAccess::OwnKey {
            provider: provider(),
        }),
        Payer::CustomerSeat => Some(ModelPackAccess::Seat {
            provider: provider(),
        }),
        Payer::Local => {
            (offer.locality != ModelLocality::ThirdParty).then_some(ModelPackAccess::LocalGpu)
        }
    }
}

/// The key a pack fills `role` under. An engine call (CALLS, FIX 5365): a
/// pack's role keys are the engine's role names (`generative_reasoner`,
/// `dreamer_current`, `retrieval_embedder`, `extraction_encoder`, ...). A
/// key no role reads (`coding`, `compaction`) is kept with the pack and
/// binds nothing yet.
#[must_use]
pub fn model_pack_role_key(role: ModelRole) -> String {
    serde_json::to_value(role)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{role:?}"))
}

/// The pack's pick for `role` (FIX 5366): the first variant, in the pack's
/// order, that runs on the access the host holds.
#[must_use]
pub fn resolve_model_pack_role<'p>(
    pack: &'p ModelPack,
    role: &str,
    access: &AccessSnapshot,
) -> Option<&'p ModelPackVariant> {
    pack.variants(role)
        .iter()
        .find(|variant| access.runs(variant))
}

/// Whether the owner's manifest outranks the pack. An engine call (CALLS,
/// FIX 5366, 5367): a vault whose owner pinned a manifest has chosen its
/// models, so it follows no pack ("a person who does not choose models
/// follows the latest pack"). Per-agent lists outrank both on the seats and
/// raw calls they bind, which never reach a role's pick.
#[must_use]
pub fn manifest_outranks_model_pack(manifest: Option<&ModelManifest>) -> bool {
    manifest.is_some()
}

/// Whether the owner may pin `season`. An engine call (CALLS, FIX 5367): a
/// season is pinnable while an installed pack of it is still served, as a
/// person "may pin an older season until its support ends".
#[must_use]
pub fn season_is_pinnable(
    packs: &[InstalledModelPack],
    season: &ModelStackId,
    as_of_epoch_day: u32,
) -> bool {
    packs.iter().any(|installed| {
        installed.pack.season == *season && installed.pack.is_served_on(as_of_epoch_day)
    })
}

/// A role's model from the active pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelPackRoleChoice {
    pub pack: ModelPackId,
    pub season: ModelStackId,
    pub variant: ModelPackVariant,
}

impl ModelPackRoleChoice {
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.variant.model
    }
}

/// A followed pack, as its install receipt named it: the exact bytes and the
/// ref they came from, all a way back to them needs (FIX 5369).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelPackReceipt {
    pub pack: String,
    pub version: String,
    pub season: ModelStackId,
    pub source_id: String,
    pub content_hash: String,
    pub hub_id: String,
    pub hub_ref: String,
    pub pin_type: String,
    pub pin_value: String,
    pub publisher: String,
}

impl ModelPackReceipt {
    fn of(installed: &InstalledModelPack) -> Self {
        let receipt = &installed.receipt;
        Self {
            pack: receipt.pack_name.clone(),
            version: installed.pack.version.clone(),
            season: installed.pack.season.clone(),
            source_id: receipt.source_id.clone(),
            content_hash: receipt.content_hash.clone(),
            hub_id: receipt.hub_id.clone(),
            hub_ref: receipt.hub_ref.clone(),
            pin_type: receipt.pin_type.clone(),
            pin_value: receipt.pin_value.clone(),
            publisher: receipt.publisher.clone(),
        }
    }

    /// The same pack at the same bytes.
    fn same_pack(&self, other: &Self) -> bool {
        self.pack == other.pack && self.content_hash == other.content_hash
    }
}

/// The vault's last pack change: the pack it follows since, and the one it
/// followed before, which a one-tap way back returns to (FIX 5369).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPackChange {
    pub active: Option<ModelPackReceipt>,
    pub previous: Option<ModelPackReceipt>,
    /// Unix seconds.
    pub changed_at: u64,
}

/// One installed model pack, for the owner's view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelPackView {
    pub receipt: ModelPackReceipt,
    /// Days since the Unix epoch.
    pub released_epoch_day: u32,
    /// The role keys the pack fills.
    pub roles: Vec<String>,
    pub successor: Option<String>,
    pub retirement: Option<ModelStackDeprecationStatus>,
}

impl ModelPackView {
    fn of(installed: &InstalledModelPack, as_of_epoch_day: u32) -> Self {
        let pack = &installed.pack;
        Self {
            receipt: ModelPackReceipt::of(installed),
            released_epoch_day: pack.released_epoch_day,
            roles: pack.roles.keys().cloned().collect(),
            successor: pack.successor.as_ref().map(|id| id.as_str().to_owned()),
            retirement: pack
                .retirement
                .map(|retirement| retirement.status(as_of_epoch_day)),
        }
    }
}

/// The owner's model pack setting and what it selects now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelPackSetting {
    /// Follow the latest pack (the default), or pin a season.
    pub preference: ModelStackPreference,
    /// The pack the preference selects now; none with no model pack installed.
    pub active: Option<ModelPackView>,
    /// The pack the vault followed before its last pack change.
    pub previous: Option<ModelPackReceipt>,
    /// Every installed model pack, newest first.
    pub installed: Vec<ModelPackView>,
}

/// Today, in days since the Unix epoch.
fn today_epoch_day() -> u32 {
    u32::try_from(crate::unix_seconds_now() / SECONDS_PER_DAY).unwrap_or(u32::MAX)
}

/// The pack the vault followed before the one it follows now, for the
/// owner's view, from the last recorded change. When the effective active
/// pack is the recorded one, that change's `previous`. When it differs, the
/// vault moved off the recorded pack with no change recorded (the followed
/// pack retired, and a read writes nothing), so the recorded pack is the one
/// it followed before. Recording that retirement migration as a change, with
/// its notice, is FIX 5368, slice 2's day-clock pass.
fn previous_model_pack(
    recorded: Option<ModelPackChange>,
    active: Option<&ModelPackReceipt>,
) -> Option<ModelPackReceipt> {
    let change = recorded?;
    let followed = match (change.active.as_ref(), active) {
        (Some(was), Some(now)) => was.same_pack(now),
        (None, None) => true,
        _ => false,
    };
    if followed {
        change.previous
    } else {
        change.active
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("model pack: {reason}"))
}

impl Vault {
    /// The owner's model pack preference; following the latest pack when
    /// the owner set none.
    pub fn model_pack_preference(&self) -> Result<ModelStackPreference> {
        let txn = self.store.env.read_txn()?;
        Ok(PREFERENCE.get(&self.store, &txn, &())?.unwrap_or_default())
    }

    /// The pack the vault follows now, read with its receipt; `None` with
    /// no model pack installed.
    pub fn active_model_pack(&self) -> Result<Option<InstalledModelPack>> {
        let txn = self.store.env.read_txn()?;
        self.active_model_pack_in_txn(&txn)
    }

    pub(crate) fn active_model_pack_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<InstalledModelPack>> {
        let packs = self.installed_model_packs_in_txn(txn)?;
        if packs.is_empty() {
            return Ok(None);
        }
        let preference = PREFERENCE.get(&self.store, txn, &())?.unwrap_or_default();
        Ok(select_model_pack(
            &packs,
            |installed| &installed.pack,
            &preference,
            today_epoch_day(),
        )
        .cloned())
    }

    /// The active pack's model for `role` on the access the host holds
    /// (FIX 5366): `None` when the owner's manifest outranks the pack, no
    /// model pack is installed, or no variant for the role runs here. Then
    /// today's defaults name the role's model.
    pub fn model_pack_role_choice(
        &self,
        role: ModelRole,
        access: &AccessSnapshot,
    ) -> Result<Option<ModelPackRoleChoice>> {
        let txn = self.store.env.read_txn()?;
        let manifest = super::manifest::read_manifest(&self.store, &txn)?;
        if manifest_outranks_model_pack(manifest.as_ref()) {
            return Ok(None);
        }
        let Some(active) = self.active_model_pack_in_txn(&txn)? else {
            return Ok(None);
        };
        let key = model_pack_role_key(role);
        let choice = resolve_model_pack_role(&active.pack, &key, access).map(|variant| {
            ModelPackRoleChoice {
                pack: active.pack.id.clone(),
                season: active.pack.season.clone(),
                variant: variant.clone(),
            }
        });
        Ok(choice)
    }

    /// The owner's model pack setting, the pack it selects and every
    /// installed model pack.
    pub fn model_pack_setting_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<ModelPackSetting> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        self.model_pack_setting_in_txn(&txn)
    }

    fn model_pack_setting_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<ModelPackSetting> {
        let today = today_epoch_day();
        let preference = PREFERENCE.get(&self.store, txn, &())?.unwrap_or_default();
        let mut packs = self.installed_model_packs_in_txn(txn)?;
        let active = select_model_pack(&packs, |installed| &installed.pack, &preference, today)
            .map(|installed| ModelPackView::of(installed, today));
        packs.sort_by(|left, right| {
            model_pack_recency(&right.pack).cmp(&model_pack_recency(&left.pack))
        });
        let previous = previous_model_pack(
            ACTIVE.get(&self.store, txn, &())?,
            active.as_ref().map(|view| &view.receipt),
        );
        Ok(ModelPackSetting {
            preference,
            active,
            previous,
            installed: packs
                .iter()
                .map(|installed| ModelPackView::of(installed, today))
                .collect(),
        })
    }

    /// Replaces the owner's model pack preference under the owner proof. A
    /// pin names a season an installed, still-served pack carries
    /// ([`season_is_pinnable`]). The returned setting is the one this
    /// transaction stored.
    pub fn replace_model_pack_preference_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        preference: ModelStackPreference,
    ) -> Result<ModelPackSetting> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        if let ModelStackPreference::Pinned { stack } = &preference {
            let packs = self.installed_model_packs_in_txn(&txn)?;
            if !season_is_pinnable(&packs, stack, today_epoch_day()) {
                return Err(invalid(
                    "a pin names a season an installed, still-served pack carries",
                ));
            }
        }
        let before = self.model_pack_in_effect_in_txn(&txn)?;
        PREFERENCE.put(&self.store, &mut txn, &(), &preference)?;
        self.note_active_model_pack_in_txn(&mut txn, before)?;
        let setting = self.model_pack_setting_in_txn(&txn)?;
        txn.commit()?;
        Ok(setting)
    }

    /// The receipt of the pack in effect now, as routing selects it: what a
    /// change's caller reads before it installs, removes or re-prefers, so
    /// the change it records keeps the pack the vault really followed.
    pub(crate) fn model_pack_in_effect_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<ModelPackReceipt>> {
        Ok(self
            .active_model_pack_in_txn(txn)?
            .map(|installed| ModelPackReceipt::of(&installed)))
    }

    /// Records a change of the pack the vault follows, in the caller's
    /// transaction (FIX 5367; FIX 5369's way back reads `previous`).
    /// `before` is the pack in effect just before the caller's change
    /// ([`Self::model_pack_in_effect_in_txn`]). When the change moves the
    /// pack in effect, `previous` is `before`. When it does not, but a
    /// retirement had already moved the selection off the recorded pack
    /// (FIX 5368's day pass records that on the day itself), the record
    /// catches up with `previous` the recorded pack. The install, removal
    /// and preference doors call it.
    pub(crate) fn note_active_model_pack_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: Option<ModelPackReceipt>,
    ) -> Result<()> {
        let active = self.model_pack_in_effect_in_txn(txn)?;
        let recorded = ACTIVE
            .get(&self.store, txn, &())?
            .and_then(|change| change.active);
        let same =
            |left: Option<&ModelPackReceipt>, right: Option<&ModelPackReceipt>| match (left, right)
            {
                (Some(left), Some(right)) => left.same_pack(right),
                (None, None) => true,
                _ => false,
            };
        let previous = if same(before.as_ref(), active.as_ref()) {
            if same(recorded.as_ref(), active.as_ref()) {
                return Ok(());
            }
            recorded
        } else {
            before
        };
        let change = ModelPackChange {
            previous,
            active,
            changed_at: crate::unix_seconds_now(),
        };
        ACTIVE.put(&self.store, txn, &(), &change)
    }
}
