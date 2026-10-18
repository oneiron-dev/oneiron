//! The served-form receipts a read writes (OF-329): what it served of each
//! asset, recorded under the holder it read as, before it answers.
use super::ScopedRead;
use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::receipt::ServedForm;

impl ScopedRead<'_> {
    /// Records `served`, what this read served, as one served-form receipt
    /// per asset and form, each naming this lane's holder and, when the lane
    /// knows one, its class. All of them share one grouped write, and the
    /// door answers only once it commits: a failed write fails the read with
    /// the store's own error. The write first rechecks the holder in its own
    /// snapshot as the read admitted it (`holder_live_in`). It asks for no
    /// write authority and keeps nothing but the receipts and the id and
    /// clock floors they take. Nothing served writes nothing.
    pub fn commit_served_forms(&self, served: &[ServedForm]) -> Result<()> {
        self.commit_served_forms_listing(served).map(|_| ())
    }

    /// Records the same forms and returns their durable receipt refs.
    pub fn commit_served_forms_listing(&self, served: &[ServedForm]) -> Result<Vec<String>> {
        let mut served = served.to_vec();
        served.sort_unstable();
        served.dedup();
        if served.is_empty() {
            return Ok(Vec::new());
        }
        let vault = self.vault;
        vault.store.write_in_group(|txn| {
            self.holder_live_in(txn)?;
            // Ids first: the floor `recorded_at_in_txn` persists covers them.
            let ids = served
                .iter()
                .map(|_| vault.store.clock.entity_id())
                .collect::<Result<Vec<_>>>()?;
            let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let refs = ids
                .iter()
                .map(|id| format!("served_form:{}", id.to_hex()))
                .collect();
            for (id, served) in ids.into_iter().zip(&served) {
                crate::receipt::put_served_form_in_txn(
                    vault,
                    txn,
                    id,
                    served,
                    &self.actor_key,
                    at,
                )?;
            }
            Ok(refs)
        })
    }

    /// This lane's holder, rechecked in `txn` as its read admitted it: a
    /// credential still live in this vault, its pact too, and still naming
    /// the lane's holder and class; the owner key's binding; a proofless
    /// key's actor still a row its class may act as. A key with no
    /// credential and no class proved nothing to recheck.
    fn holder_live_in(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        let key = &self.actor_key;
        if let Some(proof) = &key.proof {
            let claims = proof.claims();
            let class = claims
                .actor_class
                .as_deref()
                .map(str::trim)
                .filter(|class| !class.is_empty());
            if claims.holder_ref.trim() != key.actor_ref()
                || class != key.actor_class()
                || !self.vault.capability_slip_is_live_in_txn(txn, proof)?
            {
                return Err(Error::InvalidClaimBody(
                    "scoped read credential no longer live",
                ));
            }
        }
        self.owner_live_in(txn)?;
        let class = match key.actor_class() {
            Some("human") => Some(EdgeActorClass::Human),
            Some("agent") => Some(EdgeActorClass::Agent),
            Some("system") => Some(EdgeActorClass::System),
            _ => None,
        };
        if key.proof.is_none()
            && key.vault_owner_ref().is_none()
            && let Some(class) = class
            && let Ok(actor) = EntityId::from_hex(key.actor_ref())
        {
            let raw = self
                .vault
                .store
                .port_entity_raw(txn, &actor)?
                .ok_or(Error::EntityNotFound)?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            crate::provenance::validate_actor_class(header.entity_type, class)?;
        }
        Ok(())
    }
}
