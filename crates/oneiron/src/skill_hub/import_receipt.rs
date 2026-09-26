//! Source receipts and admitted-publisher ingress beside content dedup, never in place of it.
use super::{ForeignSkillPublisher, HubRef, SkillHubAdapter, package_codec::invalid};
use crate::claim::ClaimApprovalStatus;
use crate::consent::{AuthenticatedOwner, ComposedEffect, ConsentReceipt, EffectFacts};
use crate::skill::{SkillContentHash, SkillLifecycle};
use crate::{Vault, entity_id::EntityId, error::Result, temporal::TimeRange};

const CODE_AUTO_INSTALL_KEY: &[u8] = b"skill_hub/marketplace-code-auto-install/v1";

/// A source receipt for a marketplace install. One content holder can have many source receipts.
/// The publisher field is engine-stamped only by the admitted-publisher adapter door.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// Lifecycle on this source's install line, not a promise about later updates.
    #[serde(default)]
    pub installed_as: Option<String>,
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
        let effect = ComposedEffect::new(EffectFacts::new(format!(
            "skill.marketplace.code-auto-install:{enabled}"
        ))?)
        .digest();
        self.with_write_txn(|txn| {
            let receipt = self.approve_once_in_txn(txn, owner, effect)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &effect)?
                    .ok_or_else(|| invalid("code auto-install consent missing"))?;
            self.store
                .vault_meta
                .put(txn, CODE_AUTO_INSTALL_KEY, &[u8::from(enabled)])?;
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
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let configured = {
            let txn = self.store.env.read_txn()?;
            self.check_publisher_in_txn(&txn, publisher)?;
            let hub = self.hub_record_in_txn(&txn, &source.hub_id)?;
            if publisher.hub != source.hub_id
                || adapter.hub_id() != source.hub_id
                || adapter.kind() != hub.kind
                || adapter.endpoint() != Some(hub.endpoint.as_str())
            {
                return Err(invalid(
                    "marketplace adapter is not the configured publisher source",
                ));
            }
            hub
        };
        let package = adapter.fetch_package(source)?;
        let parsed = super::folder::package_from_files(package.files)?;
        self.with_write_txn(|txn| {
            self.check_publisher_in_txn(txn, publisher)?;
            if self.hub_record_in_txn(txn, &source.hub_id)? != configured {
                return Err(invalid("configured hub moved while fetching"));
            }
            let hash = parsed.content_hash()?;
            let entity = self.import_skill_from_hub_in_txn(
                txn,
                source,
                &parsed,
                self.store.clock.entity_id()?,
                occurred,
                learned_at,
            )?;
            let posture =
                crate::skill_scan::scan_gate_for_activation_in_txn(&self.store, txn, hash)?;
            let code_bearing = parsed
                .files
                .iter()
                .any(|file| file.path.starts_with("scripts/"));
            let code_enabled = match self
                .store
                .vault_meta
                .get(txn, CODE_AUTO_INSTALL_KEY)?
                .as_deref()
            {
                None | Some([0]) => false,
                Some([1]) => true,
                Some(_) => {
                    return Err(crate::error::Error::CorruptedIndex(
                        "marketplace code auto-install flag",
                    ));
                }
            };
            let mut record = self.read_skill_record_in_txn(txn, &entity)?;
            if record.lifecycle_status == SkillLifecycle::Candidate
                && matches!(posture, crate::skill_scan::ActivationPosture::AutoEligible)
                && (!code_bearing || code_enabled)
            {
                record.lifecycle_status = SkillLifecycle::Active;
                record.approval_status = ClaimApprovalStatus::Auto;
                let data = crate::skill::encode_skill_record(&record)?;
                let proof = super::HubAdmissionProof::marketplace(entity, &data);
                self.admit_hub_skill_record_in_txn(txn, occurred, learned_at, data, proof)?;
            }
            self.write_hub_import_receipt_in_txn(
                txn,
                &entity,
                hash,
                source,
                Some(publisher),
                learned_at,
            )?;
            Ok(entity)
        })
    }
    pub(super) fn write_hub_import_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        hash: SkillContentHash,
        source: &HubRef,
        publisher: Option<&ForeignSkillPublisher>,
        at: u64,
    ) -> Result<()> {
        let receipt = HubImportReceipt {
            entity: entity.to_hex(),
            content_hash: hash.to_hex(),
            hub_id: source.hub_id.to_hex(),
            ref_string: source.ref_string.clone(),
            pin_type: source.pin.pin_type().to_owned(),
            pin_value: pin_value(&source.pin),
            publisher: publisher.map(|p| p.identity.clone()),
            publisher_grant: publisher.map(|p| p.grant_ref.clone()),
            installed_as: Some(
                self.read_skill_record_in_txn(txn, entity)?
                    .lifecycle_status
                    .as_str()
                    .to_owned(),
            ),
            at,
        };
        let key = import_receipt_key(entity, source);
        if publisher.is_none() && self.store.vault_meta.get(txn, &key)?.is_some() {
            return Ok(());
        }
        self.store.vault_meta.put(
            txn,
            &key,
            &serde_json::to_vec(&receipt).map_err(|_| invalid("import receipt encode failed"))?,
        )?;
        Ok(())
    }
    pub fn hub_import_receipt(
        &self,
        entity: &EntityId,
        source: &HubRef,
    ) -> Result<Option<HubImportReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &import_receipt_key(entity, source))?
            .map(|raw| {
                serde_json::from_slice(&raw).map_err(|_| invalid("invalid hub import receipt"))
            })
            .transpose()
    }
}
fn import_receipt_key(entity: &EntityId, source: &HubRef) -> Vec<u8> {
    let mut key = b"skill_hub/import-receipt/v1\0".to_vec();
    key.extend_from_slice(entity.as_bytes());
    key.extend_from_slice(source.hub_id.as_bytes());
    key.extend_from_slice(blake3::hash(source.ref_string.as_bytes()).as_bytes());
    key
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
