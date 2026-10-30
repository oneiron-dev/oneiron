//! PERSON handles use the reveal consent machine, not custody or a T1 lease.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{HandleReveal, RevealAsker, RevealRow};
use crate::Vault;
use crate::claim::{ClaimBody, ScopedReadActorKey, claim_surfaceable};
use crate::disclosure::{DisclosureBand, DisclosureDataClass};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;

/// The exact claim revision the owner is asked to disclose. A changed value
/// needs a new ask; a grant never authorizes an unrelated successor value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PersonRevealTarget {
    pub(super) claim: EntityId,
    pub(super) digest: [u8; 32],
}

#[derive(Debug)]
pub(crate) struct PersonHandleCard {
    pub handle: String,
    pub band: DisclosureBand,
    pub claim: EntityId,
    pub learned_at: u64,
    pub reveal: HandleReveal,
}

fn admitted_claim_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: &ScopedReadActorKey,
    person: EntityId,
    claim: EntityId,
) -> Result<ClaimBody> {
    let lane = vault.scoped_read(reader.clone());
    let policy = lane.live_policy_manifest_in(txn)?;
    if !lane.is_entity_readable_with_policy_in(txn, &policy, &person)?
        || !lane.is_entity_readable_with_policy_in(txn, &policy, &claim)?
        || crate::vault::live_entity_row_in_txn(&vault.store, txn, &person)?.live_type()
            != Some(crate::registry::ENTITY_TYPE_PERSON)
    {
        return Err(Error::EntityNotFound);
    }
    vault
        .get_claim_in_txn(txn, &claim)?
        .filter(|body| {
            body.subject == crate::claim::ClaimSubject::Entity(person)
                && crate::disclosure::claim_data_class(body) == Some(DisclosureDataClass::Names)
                && claim_surfaceable(body)
        })
        .ok_or(Error::EntityNotFound)
}

pub(super) fn resolve_person_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    asker: &RevealAsker,
    handle: &str,
) -> Result<(String, EntityId, PersonRevealTarget)> {
    let (handle, person) = super::resolve_typed_handle_in_txn(
        &vault.store,
        txn,
        handle,
        crate::registry::ENTITY_TYPE_PERSON,
    )?;
    let reader = asker.reader.as_ref().ok_or(Error::EntityNotFound)?;
    let lane = vault.scoped_read(reader.clone());
    let policy = lane.live_policy_manifest_in(txn)?;
    if !lane.is_entity_readable_with_policy_in(txn, &policy, &person)? {
        return Err(Error::EntityNotFound);
    }
    let (claim, _) = crate::disclosure::person_name_claim_in(vault, txn, person)?
        .ok_or(Error::EntityNotFound)?;
    let body = admitted_claim_in(vault, txn, reader, person, claim)?;
    if !crate::claim::has_live_support_in_txn(&vault.store, txn, &body)? {
        return Err(Error::EntityNotFound);
    }
    let digest = *blake3::hash(&crate::claim::encode_claim_body(&body)?).as_bytes();
    Ok((handle, person, PersonRevealTarget { claim, digest }))
}

/// Rechecks authority, support and exact value in the writer that spends the
/// grant. No returned value is read before that writer has admitted it.
pub(super) fn value_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    asker: &RevealAsker,
    row: &RevealRow,
) -> Result<Zeroizing<Vec<u8>>> {
    let target = row.person.as_ref().ok_or(Error::EntityNotFound)?;
    let reader = asker.reader.as_ref().ok_or(Error::EntityNotFound)?;
    let body = admitted_claim_in(vault, txn, reader, row.secret, target.claim)?;
    if !crate::claim::has_live_support_in_txn(&vault.store, txn, &body)?
        || *blake3::hash(&crate::claim::encode_claim_body(&body)?).as_bytes() != target.digest
    {
        return Err(Error::EntityNotFound);
    }
    let text = match &body.value {
        rmpv::Value::String(text) => text.as_str().ok_or(Error::EntityNotFound)?.to_owned(),
        value => crate::serialize::msgpack_value_to_json(value).to_string(),
    };
    Ok(Zeroizing::new(text.into_bytes()))
}

impl Vault {
    pub(crate) fn describe_person_handle(
        &self,
        asker: &RevealAsker,
        handle: &str,
    ) -> Result<PersonHandleCard> {
        let txn = self.store.env.read_txn()?;
        let (handle, _, target) = resolve_person_in(self, &txn, asker, handle)?;
        let body = self
            .get_claim_in_txn(&txn, &target.claim)?
            .ok_or(Error::EntityNotFound)?;
        let grants = crate::consent::load_active_standing_grants(&self.store, &txn)?;
        // A grant of any reach covers it (FIX 2354).
        let reveal = asker
            .reach()
            .covering_grant(&asker.connection(), "names", &grants)?
            .map_or(HandleReveal::Asks, |(_, grant_ref)| HandleReveal::Hydrates {
                grant_ref,
            });
        let learned_at = self
            .store
            .port_entity_record(&txn, &target.claim)?
            .map(|row| row.learned_at)
            .unwrap_or_default();
        Ok(PersonHandleCard {
            handle,
            band: DisclosureBand::of_claim(&body),
            claim: target.claim,
            learned_at,
            reveal,
        })
    }
}
