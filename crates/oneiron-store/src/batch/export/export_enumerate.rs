//! Snapshot enumeration for whole-vault exports, independent of type whitelists.
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::EntityMetadataHeader;

/// A row selected for export. Serialization owns credential nulling; this
/// enumerator returns identities, never raw credentials or unredacted bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WholeVaultExportRow {
    pub entity_id: EntityId,
    pub entity_type: u8,
}
