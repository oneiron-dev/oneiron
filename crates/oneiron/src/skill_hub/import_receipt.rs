//! Source receipts and admitted-publisher ingress beside content dedup, never in place of it.
use super::{
    ForeignSkillPublisher, HubPackage, HubRef, SkillCapabilitySurface, SkillHubAdapter,
    install_transition::{
        InstallBinding, InstallDisposition, InstallHoldReason, InstallLifecycle, InstallPlan,
        InstallResult,
    },
    package_codec::invalid,
};
use crate::claim::ClaimApprovalStatus;
use crate::consent::{AuthenticatedOwner, ComposedEffect, ConsentReceipt, EffectFacts};
use crate::side_table::{self, CodecError, LegacyJson, Raw, RawValue, SideTable};
use crate::skill::{SkillContentHash, SkillLifecycle};
use crate::{Vault, entity_id::EntityId, error::Result, temporal::TimeRange};

mod fitted;
mod rule_fit;
pub use rule_fit::{CallerPermissions, HoldsNothing, RuleSkillFit, SkillFitSetting};

/// Hub-import receipt for one entity, keyed by (entity, source hub id, hash
/// of the source ref string).
const IMPORT_RECEIPT: SideTable<(EntityId, EntityId, [u8; 32]), HubImportReceipt, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_IMPORT_RECEIPT);
/// Owner switch for auto-installing code-bearing marketplace folders; an
/// absent row is off. `pub(super)` for the transport tests' read-back.
pub(super) const CODE_AUTO_INSTALL: SideTable<(), MarketplaceSwitch, Raw> =
    SideTable::new(&side_table::SKILL_HUB_MARKETPLACE_CODE_AUTO_INSTALL);
/// Revision of the code auto-install switch, bound into each change's consent.
const CODE_AUTO_INSTALL_REVISION: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::SKILL_HUB_MARKETPLACE_CODE_AUTO_INSTALL_REVISION);
/// Owner blocking rule on one canonical content hash; an absent row is off.
const BLOCKED_HASH: SideTable<[u8; 32], MarketplaceSwitch, Raw> =
    SideTable::new(&side_table::SKILL_HUB_MARKETPLACE_BLOCKED_HASH);

/// One owner-set marketplace switch byte: `0` off, `1` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MarketplaceSwitch(bool);

impl RawValue for MarketplaceSwitch {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![u8::from(self.0)])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [0] => Ok(Self(false)),
            [1] => Ok(Self(true)),
            _ => Err(crate::error::Error::CorruptedIndex("marketplace switch").into()),
        }
    }
}

/// A host-side fit rung over the exact fetched folder and its source-derived
/// requested permissions. The hub cannot declare its own fit result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketplaceFit {
    /// Content suits the use and requested capabilities fit the host's grant.
    Ready,
    /// A permission or content judgment needs a bounded owner ask.
    Ask,
    /// Content or requested permissions do not fit this context.
    NoFit,
}

/// Host's decision binds the fetched content, source and source-derived grants.
/// A stale or mismatched evaluation cannot authorize an import.
#[derive(Debug, Clone)]
pub struct MarketplaceFitDecision {
    source: HubRef,
    hash: SkillContentHash,
    capabilities: SkillCapabilitySurface,
    outcome: MarketplaceFit,
    analysis: String,
    static_scan: crate::skill_hub::SkillScanReceipt,
}
impl MarketplaceFitDecision {
    pub fn new(
        source: &HubRef,
        package: &HubPackage,
        outcome: MarketplaceFit,
        analysis: impl Into<String>,
        static_scan: &crate::skill_hub::SkillScanReceipt,
    ) -> Result<Self> {
        let analysis = analysis.into();
        if analysis.len() > 512 || (outcome != MarketplaceFit::Ready && analysis.trim().is_empty())
        {
            return Err(invalid("marketplace fit analysis is missing or too long"));
        }
        Ok(Self {
            source: source.clone(),
            hash: package.content_hash()?,
            capabilities: package.capabilities.clone(),
            outcome,
            analysis,
            static_scan: static_scan.clone(),
        })
    }
}

pub trait MarketplaceFitEvaluator {
    fn evaluate(
        &self,
        source: &HubRef,
        package: &HubPackage,
        static_scan: &crate::skill_hub::SkillScanReceipt,
    ) -> Result<MarketplaceFitDecision>;
}

/// Read the owner rule at the same write frontier as every imported activation.
/// Scanner risk and provider governance remain independent advisory signals.
pub(crate) fn marketplace_hash_blocked_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    hash: SkillContentHash,
) -> Result<bool> {
    Ok(BLOCKED_HASH
        .get(store, txn, hash.as_bytes())?
        .is_some_and(|MarketplaceSwitch(blocked)| blocked))
}

/// A source receipt for a marketplace install. One content holder can have many source receipts.
/// The publisher field is engine-stamped only by the admitted-publisher adapter door.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct HubImportReceipt {
    pub entity: String,
    pub content_hash: String,
    pub hub_id: String,
    pub ref_string: String,
    pub pin_type: String,
    pub pin_value: Option<String>,
    pub publisher: Option<String>,
    pub publisher_grant: Option<String>,
    /// Typed lifecycle and result at this transaction's committed frontier.
    pub installed_as: InstallLifecycle,
    pub disposition: InstallDisposition,
    /// Host fit analysis and exact source-derived permission requests.
    #[serde(default)]
    pub fit_analysis: Option<String>,
    #[serde(default)]
    pub requested_permissions: Vec<String>,
    pub at: u64,
}
impl Vault {
    /// Owner-controlled code policy. Disabled by default. Hosts should enable it
    /// only after sandbox install tests pass; this flag does not run those tests.
    /// Importing a code-bearing folder while disabled leaves it Candidate.
    pub fn set_marketplace_code_auto_install(
        &self,
        owner: &AuthenticatedOwner,
        enabled: bool,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let revision = CODE_AUTO_INSTALL_REVISION
                .get(&self.store, txn, &())?
                .unwrap_or(0);
            let next = revision
                .checked_add(1)
                .ok_or(crate::error::Error::IndexOverflow(
                    "marketplace code policy revision",
                ))?;
            let effect = ComposedEffect::new(EffectFacts::new(format!(
                "skill.marketplace.code-auto-install:{revision}:{enabled}"
            ))?)
            .digest();
            let receipt = self.approve_once_in_txn(txn, owner, effect)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &effect)?
                    .ok_or_else(|| invalid("code auto-install consent missing"))?;
            CODE_AUTO_INSTALL.put(&self.store, txn, &(), &MarketplaceSwitch(enabled))?;
            CODE_AUTO_INSTALL_REVISION.put(&self.store, txn, &(), &next)?;
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            Ok(receipt)
        })
    }

    /// An owner-maintained blocking rule on canonical content, independent of
    /// advisory scanner risk or a hub's declared governance value.
    pub fn set_marketplace_blocked_hash(
        &self,
        owner: &AuthenticatedOwner,
        hash: SkillContentHash,
        blocked: bool,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let nonce = self.store.clock.entity_id()?;
            let effect = ComposedEffect::new(EffectFacts::new(format!(
                "skill.marketplace.blocked-hash:{}:{blocked}:{}",
                hash.to_hex(),
                nonce.to_hex()
            ))?)
            .digest();
            let receipt = self.approve_once_in_txn(txn, owner, effect)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &effect)?
                    .ok_or_else(|| invalid("marketplace rule consent missing"))?;
            BLOCKED_HASH.put(
                &self.store,
                txn,
                hash.as_bytes(),
                &MarketplaceSwitch(blocked),
            )?;
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            Ok(receipt)
        })
    }

    /// Fetches from a configured source and checks the publisher again at commit.
    /// Import, scan, activation and source receipt share one transaction.
    pub fn import_marketplace_skill_from_adapter<A: SkillHubAdapter>(
        &self,
        adapter: &A,
        source: &HubRef,
        publisher: &ForeignSkillPublisher,
        fit: &dyn MarketplaceFitEvaluator,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.import_marketplace_skill_with_query(
            adapter, source, publisher, fit, None, occurred, learned_at,
        )
    }

    /// The same import; with `advisories`, the bytes' OSV receipts are queried
    /// before the writer and co-commit with the import, so the activation
    /// consult reads them.
    #[expect(
        clippy::too_many_arguments,
        reason = "the marketplace import plus an optional dependency advisory transport"
    )]
    pub(super) fn import_marketplace_skill_with_query<A: SkillHubAdapter>(
        &self,
        adapter: &A,
        source: &HubRef,
        publisher: &ForeignSkillPublisher,
        fit: &dyn MarketplaceFitEvaluator,
        advisories: Option<&dyn super::osv::OsvQuery>,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let fitted = self.fit_marketplace_skill(
            adapter, source, publisher, fit, advisories, occurred, learned_at,
        )?;
        self.with_write_txn_grouped(|txn| self.commit_fitted_skill_in_txn(txn, &fitted, None))
    }
    pub(super) fn write_hub_import_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        hash: SkillContentHash,
        source: &HubRef,
        publisher_and_result: Option<(&ForeignSkillPublisher, InstallResult, &str)>,
        at: u64,
    ) -> Result<()> {
        let result = publisher_and_result.map_or_else(
            || {
                self.read_skill_record_in_txn(txn, entity)
                    .and_then(|record| {
                        InstallResult::finalized(
                            &record,
                            InstallDisposition::NotInstalled(InstallHoldReason::SourceOnly),
                        )
                    })
            },
            |(_, result, _)| Ok(result),
        )?;
        let receipt = HubImportReceipt {
            entity: entity.to_hex(),
            content_hash: hash.to_hex(),
            hub_id: source.hub_id.to_hex(),
            ref_string: source.ref_string.clone(),
            pin_type: source.pin.pin_type().to_owned(),
            pin_value: pin_value(&source.pin),
            publisher: publisher_and_result.map(|(p, _, _)| p.identity.clone()),
            publisher_grant: publisher_and_result.map(|(p, _, _)| p.grant_ref.clone()),
            installed_as: result.lifecycle,
            disposition: result.disposition,
            fit_analysis: publisher_and_result.map(|(_, _, analysis)| analysis.to_owned()),
            requested_permissions: self
                .read_admitted_capability_surface_in_txn(txn, entity)?
                .map(|surface| permission_labels(&surface))
                .unwrap_or_default(),
            at,
        };
        let key = import_receipt_key(entity, source);
        if publisher_and_result.is_none() && IMPORT_RECEIPT.contains(&self.store, txn, &key)? {
            return Ok(());
        }
        IMPORT_RECEIPT.put(&self.store, txn, &key, &receipt)
    }
    /// Resolves an exact fit-rung permission ask by a current owner, without
    /// requiring held-out improvement of imported content. A changed package,
    /// rule, code policy or local decision invalidates the old ask.
    pub fn approve_marketplace_permission_ask(
        &self,
        owner: &AuthenticatedOwner,
        entity: &EntityId,
        source: &HubRef,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let key = import_receipt_key(entity, source);
            let mut receipt = IMPORT_RECEIPT
                .get(&self.store, txn, &key)?
                .ok_or_else(|| invalid("marketplace permission ask missing"))?;
            if receipt.disposition != InstallDisposition::PendingPermission
                || receipt.hub_id != source.hub_id.to_hex()
                || receipt.ref_string != source.ref_string
                || receipt.pin_type != source.pin.pin_type()
                || receipt.pin_value != pin_value(&source.pin)
            {
                return Err(invalid("marketplace permission ask is stale"));
            }
            let grant = receipt
                .publisher_grant
                .as_deref()
                .ok_or_else(|| invalid("marketplace permission ask has no publisher"))?;
            if !crate::consent::standing_grant_is_active_in_txn(&self.store, txn, grant)? {
                return Err(invalid("marketplace publisher grant was revoked"));
            }
            let record = self.read_skill_record_in_txn(txn, entity)?;
            let hash = SkillContentHash::parse_hex(&receipt.content_hash)?;
            let package = self.stored_hub_package_in_txn(txn, entity)?;
            if record.lifecycle_status != SkillLifecycle::Candidate
                || record.approval_status != ClaimApprovalStatus::Auto
                || record.content_hash != Some(hash)
                || package.content_hash()? != hash
                || permission_labels(&package.capabilities) != receipt.requested_permissions
            {
                return Err(invalid(
                    "marketplace permission ask no longer matches content",
                ));
            }
            self.check_hub_source_alias(txn, entity, source, hash)?;
            if marketplace_hash_blocked_in_txn(&self.store, txn, hash)? {
                return Err(invalid("marketplace hash rule blocks activation"));
            }
            let has_code = package
                .files
                .iter()
                .any(|file| file.path.starts_with("scripts/"));
            if has_code
                && !CODE_AUTO_INSTALL
                    .get(&self.store, txn, &())?
                    .is_some_and(|MarketplaceSwitch(enabled)| enabled)
            {
                return Err(invalid("code auto-install is disabled"));
            }
            let effect = ComposedEffect::new(EffectFacts::new(format!(
                "skill.marketplace.permission:{}:{}:{}:{}",
                entity.to_hex(),
                source.hub_id.to_hex(),
                receipt.content_hash,
                blake3::hash(receipt.requested_permissions.join("\0").as_bytes()).to_hex()
            ))?)
            .digest();
            let approval = self.approve_once_in_txn(txn, owner, effect)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &effect)?
                    .ok_or_else(|| invalid("marketplace permission consent missing"))?;
            let plan = InstallPlan::owner_answer(
                &record,
                InstallBinding::new(source, hash, &package.capabilities),
            );
            if !plan.is_owner_answerable() {
                return Err(invalid("marketplace permission ask no longer answerable"));
            }
            let result = self.execute_hub_install_plan_in_txn(
                txn,
                entity,
                &plan,
                occurred,
                learned_at,
                Some(&authorization),
            )?;
            receipt.disposition = result.disposition;
            receipt.installed_as = result.lifecycle;
            receipt.at = learned_at;
            IMPORT_RECEIPT.put(&self.store, txn, &key, &receipt)?;
            Ok(approval)
        })
    }

    /// Bounded durable marketplace install rows. Projection applies the reader's
    /// own scope before rendering; this method never grants read authority.
    pub(crate) fn marketplace_install_receipts(&self) -> Result<Vec<HubImportReceipt>> {
        let txn = self.store.env.read_txn()?;
        let mut recent = std::collections::BTreeMap::new();
        for row in IMPORT_RECEIPT.iter_from(&self.store, &txn, &[])? {
            let (_, receipt) = row?;
            if receipt.publisher.is_some() {
                let order = (
                    receipt.at,
                    receipt.entity.clone(),
                    receipt.hub_id.clone(),
                    receipt.ref_string.clone(),
                );
                recent.insert(order, receipt);
                if recent.len() > 4096 {
                    recent.pop_first();
                }
            }
        }
        Ok(recent.into_values().rev().collect())
    }

    pub fn hub_import_receipt(
        &self,
        entity: &EntityId,
        source: &HubRef,
    ) -> Result<Option<HubImportReceipt>> {
        let txn = self.store.env.read_txn()?;
        IMPORT_RECEIPT.get(&self.store, &txn, &import_receipt_key(entity, source))
    }

    /// Source receipts for this skill's current content, with its actual loader
    /// disposition in the same read snapshot. The source identity and hash stay
    /// those of the import; a later activation or retirement is not a new import.
    /// Like `hub_import_receipt`, this door grants no read authority.
    pub fn current_hub_import_receipts(&self, entity: &EntityId) -> Result<Vec<HubImportReceipt>> {
        let txn = self.store.env.read_txn()?;
        let Some(record) = self.get_skill_record_in_txn(&txn, entity)? else {
            return Ok(Vec::new());
        };
        let mut receipts = Vec::new();
        for row in IMPORT_RECEIPT.iter_from(&self.store, &txn, entity.as_bytes())? {
            let (_, mut receipt) = row?;
            if !record
                .content_hash
                .is_some_and(|hash| hash.to_hex() == receipt.content_hash)
            {
                continue;
            }
            let disposition = match record.lifecycle_status {
                SkillLifecycle::Active if crate::skill::skill_loadable(&record) => {
                    InstallDisposition::AlreadyInstalled
                }
                SkillLifecycle::Active => {
                    InstallDisposition::NotInstalled(InstallHoldReason::UnloadableApproval)
                }
                SkillLifecycle::Candidate
                    if record.approval_status != ClaimApprovalStatus::Auto =>
                {
                    InstallDisposition::NotInstalled(InstallHoldReason::LocalApproval)
                }
                SkillLifecycle::Candidate => match receipt.disposition {
                    InstallDisposition::Installed | InstallDisposition::AlreadyInstalled => {
                        InstallDisposition::NotInstalled(InstallHoldReason::SourceOnly)
                    }
                    disposition => disposition,
                },
                SkillLifecycle::Stale => InstallDisposition::NotInstalled(InstallHoldReason::Stale),
                SkillLifecycle::Quarantined => {
                    InstallDisposition::NotInstalled(InstallHoldReason::Quarantined)
                }
                SkillLifecycle::Superseded => {
                    InstallDisposition::NotInstalled(InstallHoldReason::Superseded)
                }
            };
            let result = InstallResult::finalized(&record, disposition)?;
            receipt.installed_as = result.lifecycle;
            receipt.disposition = result.disposition;
            receipts.push(receipt);
        }
        Ok(receipts)
    }
}
fn permission_labels(surface: &SkillCapabilitySurface) -> Vec<String> {
    [
        ("bin", &surface.bins),
        ("env", &surface.env),
        ("mcp", &surface.mcp),
        ("tool", &surface.allowed_tools),
    ]
    .into_iter()
    .flat_map(|(kind, values)| values.iter().map(move |value| format!("{kind}:{value}")))
    .collect()
}

fn import_receipt_key(entity: &EntityId, source: &HubRef) -> (EntityId, EntityId, [u8; 32]) {
    (
        *entity,
        source.hub_id,
        *blake3::hash(source.ref_string.as_bytes()).as_bytes(),
    )
}

fn pin_value(pin: &super::HubPin) -> Option<String> {
    match pin {
        super::HubPin::Semver(value)
        | super::HubPin::Tag(value)
        | super::HubPin::Commit(value)
        | super::HubPin::ContentHash(value) => Some(value.clone()),
        super::HubPin::None => None,
    }
}
