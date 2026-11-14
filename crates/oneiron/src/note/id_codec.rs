//! Hex entity references in the NOTE document and blessed-kind wire formats.
use crate::EntityId;
use serde::{Deserialize, Deserializer, Serializer};

#[doc(hidden)]
pub(super) use oneiron_records::note::id_codec::{deserialize, serialize};
