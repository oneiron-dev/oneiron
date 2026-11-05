//! The source-custody index of a skill holder: the live, dead or unseen
//! state of each (holder, content hash) pair. The skill hub
//! (`skill_hub::source_custody`) stages and retires these rows; the store's
//! erase, replay and deletion-receipt paths test a holder and list its
//! carriers.
use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use crate::write_envelope::skill_record::SkillContentHash;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// Source-custody state for one (holder, content hash) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyState {
    Live,
    Dead,
    Unseen,
}

impl RawValue for CustodyState {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![match self {
            Self::Live => 0,
            Self::Dead => 1,
            Self::Unseen => 2,
        }])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [0] => Ok(Self::Live),
            [1] => Ok(Self::Dead),
            [2] => Ok(Self::Unseen),
            _ => Err(Error::CorruptedIndex("source custody index value").into()),
        }
    }
}
