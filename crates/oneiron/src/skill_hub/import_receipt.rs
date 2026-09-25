//! Source receipts and admitted-publisher ingress beside content dedup, never in place of it.
use super::{ForeignSkillPublisher, HubRef, SkillHubAdapter, package_codec::invalid};
use crate::skill::SkillContentHash;
use crate::{Vault, entity_id::EntityId, error::Result, temporal::TimeRange};

/// A source receipt for a Candidate import. One content holder can have many source receipts.
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
    pub at: u64,
}
impl Vault {
    /// Fetches from the configured source and admits its publisher only as an offerer.
    /// Candidate import is inert. If the publisher is revoked during fetching or receipt
    /// attachment this errors; any already-created Candidate remains unable to activate.
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
        let entity = self.import_skill_from_hub(source, &parsed, occurred, learned_at)?;
        self.with_write_txn(|txn| {
            self.check_publisher_in_txn(txn, publisher)?;
            if self.hub_record_in_txn(txn, &source.hub_id)? != configured {
                return Err(invalid("configured hub moved while fetching"));
            }
            self.write_hub_import_receipt_in_txn(
                txn,
                &entity,
                parsed.content_hash()?,
                source,
                Some(publisher),
                learned_at,
            )
        })?;
        Ok(entity)
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
