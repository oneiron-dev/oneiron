//! The quiet receipt of a disclosure under standing clearance (OF-365,
//! DEC-0006: "the owner sees a post-hoc receipt without another ask"). When a
//! host hands out a context pack, each contact present whose active standing
//! clearance admits a delivered non-public record gets one `Used` receipt
//! over the contact, the channels and those records. It authorizes nothing:
//! the disclosable set already decided what the pack holds.

use std::collections::{BTreeMap, BTreeSet};

use super::{DisclosureScopeStatus, contact_clearance_in_txn};
use crate::Vault;
use crate::consent::EffectDigest;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{Scope, Sensitivity, SensitivityCeiling};
use crate::interlocutor::InterlocutorSet;

const USE_DIGEST_DOMAIN: &[u8] = b"oneiron.consent.contact_clearance_use.v1\0";

/// The digest one use receipt names: the contact, every channel the
/// delivery went to, and the delivered non-public records it covered.
fn use_digest(contact: &EntityId, channels: &BTreeSet<String>, ids: &[EntityId]) -> EffectDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(USE_DIGEST_DOMAIN);
    hasher.update(contact.as_bytes());
    hasher.update(&(channels.len() as u64).to_be_bytes());
    for channel in channels {
        hasher.update(&(channel.len() as u64).to_be_bytes());
        hasher.update(channel.as_bytes());
    }
    hasher.update(&(ids.len() as u64).to_be_bytes());
    for id in ids {
        hasher.update(id.as_bytes());
    }
    EffectDigest::from_bytes(*hasher.finalize().as_bytes())
}

impl Vault {
    /// Writes the quiet receipts of one delivery: for each contact among
    /// `parties` whose active standing clearance admits at least one of the
    /// delivered records `ids` that is not public, one receipt
    /// ([`Vault::record_contact_clearance_use`]) over the contact, `channels`
    /// and those records. A contact an approve-once in `once` admitted used
    /// that answer, not its standing clearance, and gets none; so do public
    /// records and the owner alone. It reads first and writes after, so call
    /// it outside any writer. Answers how many receipts it wrote.
    pub fn record_standing_disclosure_uses(
        &self,
        ids: &[EntityId],
        parties: Option<&InterlocutorSet>,
        once: &BTreeMap<EntityId, Scope>,
        channels: &BTreeSet<String>,
    ) -> Result<usize> {
        let contacts: BTreeSet<EntityId> = parties
            .into_iter()
            .flat_map(InterlocutorSet::non_owner)
            .filter_map(|party| party.contact_ref())
            .filter_map(|contact| EntityId::from_hex(contact).ok())
            .filter(|contact| !once.contains_key(contact))
            .collect();
        if contacts.is_empty() || ids.is_empty() {
            return Ok(0);
        }
        let uses = {
            let txn = self.store.env.read_txn()?;
            let mut delivered = BTreeMap::new();
            for id in ids {
                let Some(row) =
                    crate::ports::EntityStoreRead::port_entity_record(&self.store, &txn, id)?
                else {
                    continue;
                };
                let scope = crate::federation::record_scope::scope_for_blob(
                    &self.store,
                    &txn,
                    *id,
                    &row.encode(),
                )?;
                if let Some(scope) = scope
                    && scope.sensitivity != SensitivityCeiling::AtMost(Sensitivity::Public)
                {
                    delivered.insert(*id, scope);
                }
            }
            let mut uses = Vec::new();
            for contact in contacts {
                let Some(clearance) = contact_clearance_in_txn(&self.store, &txn, &contact)? else {
                    continue;
                };
                if clearance.status != DisclosureScopeStatus::Active {
                    continue;
                }
                let covered: Vec<EntityId> = delivered
                    .iter()
                    .filter(|(_, scope)| clearance.scope.admits("read", scope, &Scope::top()))
                    .map(|(id, _)| *id)
                    .collect();
                if !covered.is_empty() {
                    uses.push((contact, covered));
                }
            }
            uses
        };
        for (contact, covered) in &uses {
            self.record_contact_clearance_use(contact, use_digest(contact, channels, covered))?;
        }
        Ok(uses.len())
    }
}
