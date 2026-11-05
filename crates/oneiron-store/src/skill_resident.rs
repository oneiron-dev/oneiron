//! Resident ownership of skill forks: an immutable birth mark, not a claim on the shared base.

use rmpv::Value;

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use crate::side_table::key::SideKey;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_MACHINE;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::EntityMetadataHeader;

use crate::write_envelope::skill_record::SkillRecord;

pub use crate::write_envelope::skill_record::resident::RESIDENT_PROVENANCE_KEY;
use crate::write_envelope::skill_record::resident::invalid_owner;
pub use crate::write_envelope::skill_record::resident::resident_of;

/// [`OWNER_MARKER`]'s row: a version byte (1), a has-owner byte, then the owner id when there
/// is one.
#[derive(PartialEq, Eq)]
pub struct OwnerMarker(pub Option<EntityId>);

impl RawValue for OwnerMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut encoded = vec![1_u8, u8::from(self.0.is_some())];
        if let Some(owner) = self.0 {
            encoded.extend_from_slice(owner.as_bytes());
        }
        Ok(encoded)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let owner = match bytes {
            [1, 0] => None,
            [1, 1, owner @ ..] => Some(EntityId::decode_key(owner).ok_or_else(invalid_owner)?),
            _ => return Err(invalid_owner().into()),
        };
        Ok(Self(owner))
    }
}

/// [`RECEIPT_OWNER`]'s row: the bound actor's 16-byte id.
pub struct ReceiptOwner(pub EntityId);

impl RawValue for ReceiptOwner {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let raw: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("resident receipt owner"))?;
        Ok(Self(EntityId::from_bytes(raw)?))
    }
}

/// The marker [`LOADED_SKILL`] rows carry.
pub const LOADED: [u8; 1] = [1];

/// [`LOADED_SKILL`]'s key: the receipt id framed by its big-endian `u64` byte length, then the
/// skill id.
pub struct LoadedSkillKey {
    pub receipt: String,
    pub skill: EntityId,
}

impl LoadedSkillKey {
    pub fn new(receipt: &str, skill: &EntityId) -> Self {
        Self {
            receipt: receipt.to_owned(),
            skill: *skill,
        }
    }
}

impl SideKey for LoadedSkillKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        (self.receipt.len() as u64).encode_into(out);
        out.extend_from_slice(self.receipt.as_bytes());
        self.skill.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (length, rest) = bytes.split_at_checked(8)?;
        let length = usize::try_from(u64::decode_key(length)?).ok()?;
        let (receipt, skill) = rest.split_at_checked(length)?;
        Some(Self {
            receipt: std::str::from_utf8(receipt).ok()?.to_owned(),
            skill: EntityId::decode_key(skill)?,
        })
    }
}
