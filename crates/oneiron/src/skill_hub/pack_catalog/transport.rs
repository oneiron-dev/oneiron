//! Generic Git/HTTP source fetch composes with inert pack staging, never install.
use super::{PackSource, invalid};
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
    /// The returned byte-pinned reference is ready for the human install ask.
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
            Ok((id, pinned))
        })
    }
}
