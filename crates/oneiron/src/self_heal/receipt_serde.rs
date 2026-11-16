//! Strict serde adapters for ids and provenance in local healer receipts.
use crate::{EntityId, claim::ClaimSource};
#[doc(hidden)]
pub(super) use oneiron_verb_wire::self_heal::receipt_serde::id;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

#[doc(hidden)]
pub(super) use oneiron_records::self_heal::receipt_serde::{ids, source, value};
