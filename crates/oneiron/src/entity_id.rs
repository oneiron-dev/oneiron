//! Entity ids, world ids and the presentation-id grammar. Defined in
//! `oneiron-contracts`; every `oneiron::entity_id` path is unchanged.
//!
//! A [`ForeignWorldId`] (a WORLD id received from a foreign vault) never converts into a
//! [`LocalWorldId`], which keeps A->B->C re-share out of outbound selector construction:
//!
//! ```compile_fail
//! use oneiron::sync::SyncSelectorWorld;
//! use oneiron::entity_id::{EntityId, ForeignWorldId};
//!
//! let foreign = ForeignWorldId::from_entity_id(
//!     EntityId::from_bytes([0xF1; 16]).unwrap(),
//! )
//! .unwrap();
//! let _cannot_reshare = SyncSelectorWorld::World(foreign);
//! ```

pub(crate) use oneiron_contracts::entity_id::{
    ENTITY_ID_LEN, bytes_to_hex_lower, derived_domains, parse_entity_id, serde_hex,
};
pub use oneiron_contracts::entity_id::{
    EntityId, FOREIGN_WORLD_ID_RANGE_START_BYTE, ForeignWorldId, LocalWorldId,
    MIN_PRESENTATION_PREFIX_LEN, ParsedPresentationId, is_foreign_world_id_range,
    parse_presentation_id, parse_short_ref_syntax,
};

#[cfg(test)]
mod tests {
    #[test]
    fn no_nibble_stamp_remains_outside_entity_id() {
        // The engine's sources span this crate and `oneiron-contracts`, where
        // `EntityId::derive` now lives.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut offenders = Vec::new();
        for src in [
            manifest.join("src"),
            manifest.join("../oneiron-contracts/src"),
        ] {
            let tree = crate::test_util::source_scan::SourceTree::read(&src);
            offenders.extend(
                tree.production_sources()
                    .filter(|(_, text)| text.contains("[6] = ("))
                    .map(|(path, _)| tree.relative(path))
                    .filter(|path| path != "entity_id.rs" && !path.starts_with("entity_id/")),
            );
        }
        assert!(
            offenders.is_empty(),
            "derive ids through EntityId::derive, not a version stamp: {offenders:?}"
        );
    }
}
