//! The one blessed Plugin contract, installed by a verified person.

use crate::error::Result;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EdgeActorClass, EntityId};
use serde::{Deserialize, Serialize};

/// The one blessed, person-stamped brief-kind policy contract.
const BRIEF_KIND_CONTRACT: SideTable<(), BriefKindContract, LegacyJson> =
    SideTable::new(&side_table::NOTE_BRIEF_KIND_CONTRACT);

#[doc(hidden)]
use oneiron_verb_wire::note::kind_contract::invalid_contract;
#[doc(hidden)]
pub use oneiron_verb_wire::note::kind_contract::{
    NoteContextDefault, NoteExtractionDefault, NoteRetentionDefault,
};

/// Policy seed shipped by the brief pack. These defaults do not grant sharing
/// or extraction authority; those doors still require their ordinary grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefKindContract {
    version: u8,
    #[serde(with = "super::id_codec")]
    person: EntityId,
    pub extraction: NoteExtractionDefault,
    pub context: NoteContextDefault,
    pub retention: NoteRetentionDefault,
}

impl BriefKindContract {
    pub fn person(&self) -> EntityId {
        self.person
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.version != 1 {
            return Err(invalid_contract());
        }
        serde_json::to_vec(self).map_err(|_| invalid_contract())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid_contract())?;
        if value.version != 1 {
            return Err(invalid_contract());
        }
        Ok(value)
    }
}

impl Memory<'_> {
    /// Install the pack's pinned policy seed. Only a store-verified person can
    /// stamp it; an agent cannot bless its own namespace or change defaults.
    pub fn bless_brief_kind(&self) -> MemoryResult<BriefKindContract> {
        let value = BriefKindContract {
            version: 1,
            person: self.actor(),
            extraction: NoteExtractionDefault::Disabled,
            context: NoteContextDefault::RelationshipScoped,
            retention: NoteRetentionDefault::Durable,
        };
        self.with_verified_actor_write_txn(|txn| {
            if self.actor_class() != EdgeActorClass::Human {
                return Err(MemoryError::bad_request_with(
                    "brief policy must be person-stamped",
                    &[],
                ));
            }
            if let Some(contract) = BRIEF_KIND_CONTRACT.get(&self.vault().store, txn, &())? {
                if contract.version != 1 {
                    return Err(invalid_contract().into());
                }
                return Ok(contract);
            }
            BRIEF_KIND_CONTRACT.put(&self.vault().store, txn, &(), &value)?;
            Ok(value.clone())
        })
    }
}

impl crate::Vault {
    pub fn brief_kind_contract(&self) -> Result<Option<BriefKindContract>> {
        let txn = self.store.env.read_txn()?;
        self.brief_kind_contract_in_txn(&txn)
    }

    pub(super) fn brief_kind_contract_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<BriefKindContract>> {
        BRIEF_KIND_CONTRACT
            .get(&self.store, txn, &())?
            .map(|contract| {
                if contract.version != 1
                    || self.get_entity_type_in_txn(txn, &contract.person)?
                        != Some(crate::registry::ENTITY_TYPE_PERSON)
                {
                    return Err(invalid_contract());
                }
                Ok(contract)
            })
            .transpose()
    }
}
