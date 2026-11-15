//! Moved from `crates/oneiron/src/embed/locality.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::embedding::EmbedderLocality;
use oneiron_base::error::Error;
use oneiron_store::side_table::codec::RawValue;

impl RawValue for EmbedderLocality {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, oneiron_store::side_table::codec::CodecError> {
        Ok(vec![match self {
            EmbedderLocality::OnDevice => 0,
            EmbedderLocality::OwnerServer => 1,
            EmbedderLocality::ThirdParty => 2,
        }])
    }

    fn from_raw(
        bytes: &[u8],
    ) -> std::result::Result<Self, oneiron_store::side_table::codec::CodecError> {
        match bytes {
            [0] => Ok(EmbedderLocality::OnDevice),
            [1] => Ok(EmbedderLocality::OwnerServer),
            [2] => Ok(EmbedderLocality::ThirdParty),
            _ => Err(Error::CorruptedIndex("embedding locality receipt").into()),
        }
    }
}
