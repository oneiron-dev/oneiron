//! Generic Git/HTTP source fetch composes with the post-fit pack install door.
use super::{PackFitPolicy, PackInstallDisposition, PackSource, invalid};
use crate::{
    Vault,
    entity_id::EntityId,
    error::Result,
    skill_hub::{ForeignSkillPublisher, HubPin, HubRef, SkillHubAdapter},
    temporal::TimeRange,
};
pub trait PackSourceAdapter: SkillHubAdapter {
    fn fetch_pack_source(&self, reference: &HubRef) -> Result<PackSource>;
}
impl Vault {
    /// The returned byte-pinned reference is ready for the post-fit install.
    /// A fetch neither activates the adapter nor issues its requested grants.
    pub fn fetch_pack_from_adapter<A: PackSourceAdapter>(
        &self,
        adapter: &A,
        reference: &HubRef,
        publisher: &ForeignSkillPublisher,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<(EntityId, HubRef)> {
        let configuration = {
            let txn = self.store.env.read_txn()?;
            self.check_publisher_in_txn(&txn, publisher)?;
            self.hub_record_in_txn(&txn, &reference.hub_id)?
        };
        if adapter.hub_id() != reference.hub_id
            || publisher.hub != reference.hub_id
            || adapter.kind() != configuration.kind
            || adapter.endpoint() != Some(configuration.endpoint.as_str())
        {
            return Err(invalid(
                "pack adapter does not match configured publisher source",
            ));
        }
        let source = adapter.fetch_pack_source(reference)?;
        let pinned = HubRef::new(
            reference.hub_id,
            reference.ref_string.clone(),
            HubPin::ContentHash(source.content_hash().to_hex()),
        )?;
        self.with_write_txn(|txn| {
            self.check_publisher_in_txn(txn, publisher)?;
            if self.hub_record_in_txn(txn, &reference.hub_id)? != configuration {
                return Err(invalid("hub changed during pack fetch"));
            }
            let id = self.stage_pack_source_in_txn(txn, &source, occurred, learned_at)?;
            self.record_pack_fetch_in_txn(txn, &id, &pinned, publisher)?;
            Ok((id, pinned))
        })
    }
    /// Only this configured-adapter fetch door records a source/publisher alias.
    pub(super) fn record_pack_fetch_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source_id: &EntityId,
        pinned: &HubRef,
        publisher: &ForeignSkillPublisher,
    ) -> Result<()> {
        let key = source_hub_alias_key(source_id, pinned)?;
        let value = serde_json::to_vec(&(publisher.identity(), publisher.grant_ref()))
            .map_err(|_| invalid("pack publisher receipt encoding"))?;
        self.store.vault_meta.put(txn, &key, &value)?;
        Ok(())
    }
    /// Fetch, pin, evaluate fit and install by the same immutable source hash.
    /// Source staging may remain as inert evidence if the fit policy refuses.
    pub fn install_pack_from_adapter<A: PackSourceAdapter>(
        &self,
        adapter: &A,
        reference: &HubRef,
        publisher: &ForeignSkillPublisher,
        policy: &dyn PackFitPolicy,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<PackInstallDisposition> {
        let (source_id, pinned) =
            self.fetch_pack_from_adapter(adapter, reference, publisher, occurred, learned_at)?;
        let ask = self.prepare_pack_install(source_id, &pinned, publisher, policy)?;
        self.install_pack(&ask)
    }
}

/// A source can carry multiple pinned hub aliases; no alias is minted by local staging.
pub(super) fn source_hub_alias_key(source_id: &EntityId, pinned: &HubRef) -> Result<Vec<u8>> {
    let bytes =
        serde_json::to_vec(&pinned.to_value()?).map_err(|_| invalid("pack hub source encoding"))?;
    let mut key = b"pack.source-alias.v1/".to_vec();
    key.extend_from_slice(source_id.as_bytes());
    key.extend_from_slice(blake3::hash(&bytes).as_bytes());
    Ok(key)
}
