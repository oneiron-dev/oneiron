//! The ILDF2 room rule (ONE-1592, ratified 2026-09-23):
//! `disclosable_set = public ∪ (∩ clearances of all non-owner present)`.
//! A clearance is the contact's Scope, so ∩ is the meet of Scopes. The meet
//! itself is `room_scope` (R17: one function, one implementation).

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::federation::{Scope, Sensitivity, SensitivityCeiling};
use crate::interlocutor::{InterlocutorClass, InterlocutorSet};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::Store;

pub use crate::context_board::room_scope as disclosable_set;

/// What one audience may be shown. The clearance half is a Scope; the
/// public half is a property of the record (P7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosableSet(Scope);

impl DisclosableSet {
    /// An unknown party's set: the empty clearance, so public-only.
    #[must_use]
    pub fn unknown_reader() -> Self {
        Self(Scope::default())
    }

    /// The set for `roster`. The owner's entry contributes no clearance
    /// term, so with no non-owner present the fold is the top of the Scope
    /// lattice (P1), never bottom. An unknown party, a missing or revoked
    /// clearance, or a row that does not decode contributes bottom, so that
    /// party narrows the set to public-only. An empty roster names no one
    /// and is public-only too. `reader` adds the proven owner reading the
    /// assembly as one more party with no term. Only storage I/O errors
    /// surface.
    pub fn resolve(vault: &Vault, roster: &InterlocutorSet, reader: bool) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        let mut terms = roster
            .entries()
            .iter()
            .map(|party| match (party.class(), party.contact_ref()) {
                (InterlocutorClass::Owner, _) => Ok(None),
                (_, Some(hex)) => {
                    contact_clearance_in(vault, &txn, EntityId::from_hex(hex)?).map(Some)
                }
                (_, None) => Ok(Some(Scope::default())),
            })
            .collect::<Result<Vec<_>>>()?;
        if reader {
            terms.push(None);
        }
        Ok(Self(disclosable_set(&terms)?))
    }

    /// The met clearance of every non-owner present.
    #[must_use]
    pub fn clearance(&self) -> &Scope {
        &self.0
    }

    /// P7: a record is disclosed iff it is positively public, or its Scope
    /// sits at or under the met clearance. Relevance never bypasses this,
    /// and a missing sensitivity stamp is never public.
    #[must_use]
    pub fn admits(&self, record: &Scope) -> bool {
        admits(&self.0, record)
    }
}

fn admits(clearance: &Scope, record: &Scope) -> bool {
    record.sensitivity == SensitivityCeiling::AtMost(Sensitivity::Public)
        || clearance.admits("read", record, &Scope::top())
}

/// P7 for the stored revision `raw` of `id` under a [`disclosable_set`]
/// Scope: [`DisclosableSet::admits`] over the revision's own stamp. A
/// revision with no stamp is never public. A TURN's text and vector are its
/// messages' (`embed::turn_text_in_txn`), so a turn is disclosed only with
/// each live message `PartOf` it.
pub(crate) fn discloses_raw(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &Scope,
    id: EntityId,
    raw: &[u8],
) -> Result<bool> {
    if !crate::federation::record_scope::scope_for_blob(store, txn, id, raw)?
        .is_some_and(|record| admits(scope, &record))
    {
        return Ok(false);
    }
    if EntityMetadataHeader::parse(raw).is_none_or(|header| header.entity_type != ENTITY_TYPE_TURN)
    {
        return Ok(true);
    }
    for part in store.port_edges(txn, &id, EdgeDirection::In, Some(EdgeKind::PartOf), None)? {
        let message = part?.target;
        let Some(row) = store.port_entity_record(txn, &message)? else {
            continue;
        };
        if row.entity_type != ENTITY_TYPE_MESSAGE || row.body.is_empty() {
            continue;
        }
        if !discloses_raw(store, txn, scope, message, &row.encode())? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `contact`'s clearance as `txn` reads it: bottom when the contact has
/// none, or its row does not decode. Only storage I/O errors surface.
pub(crate) fn contact_clearance_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    contact: EntityId,
) -> Result<Scope> {
    match super::vault_context::DISCLOSURE_SCOPES.get(&vault.store, txn, &contact) {
        Ok(Some(clearance)) => Ok(clearance.effective_scope()),
        Ok(None) => Ok(Scope::default()),
        Err(error) if error.kind() == ErrorKind::InvalidDisclosureScope => Ok(Scope::default()),
        Err(error) => Err(error),
    }
}
