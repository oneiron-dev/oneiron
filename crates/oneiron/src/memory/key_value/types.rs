//! Typed actor-owned, worldless keyed-memory requests and results.

#[doc(hidden)]
pub use oneiron_verb_wire::memory::key_value::types::{
    KeyValueAddress, KeyValueNamespaces, KeyValuePut, KeyValueSearch,
};

#[doc(hidden)]
pub use oneiron_records::memory::key_value::types::{
    KeyValueDeleteReceipt, KeyValueItem, KeyValuePutReceipt,
};
