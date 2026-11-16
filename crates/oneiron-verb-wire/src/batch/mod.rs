#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use oneiron_contracts::record_layout::ENTITY_BODY_OFFSET;
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use oneiron_contracts::record_layout::ENTITY_LEARNED_AT_OFFSET;
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use oneiron_contracts::record_layout::ENTITY_OCCURRED_END_OFFSET;
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use oneiron_contracts::record_layout::ENTITY_OCCURRED_START_OFFSET;
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use oneiron_contracts::record_layout::ENTITY_TYPE_OFFSET;
pub use oneiron_store::batch::phonetic_codes::generate_phonetic_codes;

pub mod secret_scan;
