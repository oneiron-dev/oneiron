//! The custody index of a skill candidate's refinement carriers: which
//! carriers a candidate owns, the holder each carrier binds to, the latest
//! ruling pointer and the retired carrier fence. The skill hub
//! (`skill_hub::refinement_custody`) stages, retires and erases these rows;
//! the store's erase, deindex and replay paths test and remove them.
use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// Latest-ruling pointer: the ruling id, then the carrier id (32 bytes).
pub struct LatestRuling {
    pub ruling: [u8; 16],
    pub carrier: [u8; 16],
}

impl RawValue for LatestRuling {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok([self.ruling, self.carrier].concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.len() != 32 {
            return Err(Error::CorruptedIndex("refinement latest pointer").into());
        }
        let mut ruling = [0; 16];
        let mut carrier = [0; 16];
        ruling.copy_from_slice(&bytes[..16]);
        carrier.copy_from_slice(&bytes[16..]);
        Ok(Self { ruling, carrier })
    }
}
