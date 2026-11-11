//! The verb table's rows core reads by name (untangle slice 5.0a, S5-2 = A; S50A-1, S50A-2): the
//! names core calls or records, the two count defaults it applies, the rows a context board section
//! may advertise, and the custody rows with the input member that carries each secret.
//!
//! The SDK generator (`crates/oneiron-sdk-generator`) writes this table at build time from the verb
//! table (`scripts/sdk/verbs/`), and fails when a name it lists is not a row. The runtime's catalog
//! (`crate::verbs`) asserts at compile time that every entry is its own row, so core reads verb
//! names here and never through the catalog's types.

include!(concat!(env!("OUT_DIR"), "/core_verb_names.rs"));
