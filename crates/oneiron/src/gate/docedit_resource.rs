//! Vault-wide document resource ceilings, decoded from policy manifest data.
use super::decode::decode_docedit_resource::parse_docedit_resource_policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gate) struct DoceditResourcePolicy {
    pub archive_bytes: usize,
    pub entries: usize,
    pub part_bytes: usize,
    pub expanded_bytes: usize,
    pub xml_depth: usize,
    pub xml_nodes: usize,
}

impl DoceditResourcePolicy {
    /// Values are authored once in the shipped manifest row, not in the organ
    /// parser. Malformed shipped data is a broken invariant, never a fallback.
    pub(in crate::gate) fn shipped() -> Self {
        parse_docedit_resource_policy(&super::default_manifest::default_docedit_resource_row())
            .expect("shipped document resource policy must decode")
    }
    pub(in crate::gate) fn restrict(self, other: Self) -> Self {
        Self {
            archive_bytes: self.archive_bytes.min(other.archive_bytes),
            entries: self.entries.min(other.entries),
            part_bytes: self.part_bytes.min(other.part_bytes),
            expanded_bytes: self.expanded_bytes.min(other.expanded_bytes),
            xml_depth: self.xml_depth.min(other.xml_depth),
            xml_nodes: self.xml_nodes.min(other.xml_nodes),
        }
    }
    pub(in crate::gate) fn organ_limits(self) -> oneiron_docedit::retained_opc::Limits {
        oneiron_docedit::retained_opc::Limits {
            archive_bytes: self.archive_bytes,
            entries: self.entries,
            part_bytes: self.part_bytes,
            expanded_bytes: self.expanded_bytes,
            xml: oneiron_docedit::retained_opc::XmlLimits {
                max_depth: self.xml_depth,
                max_nodes: self.xml_nodes,
            },
        }
    }
}

/// The shipped ceilings, for a document entry with no vault to resolve them
/// (the raw xlsx edit round trip).
pub(crate) fn shipped_docedit_package_limits() -> oneiron_docedit::retained_opc::Limits {
    DoceditResourcePolicy::shipped().organ_limits()
}

pub(in crate::gate) fn row_values(row: DoceditResourcePolicy) -> [u64; 6] {
    [
        row.archive_bytes as u64,
        row.entries as u64,
        row.part_bytes as u64,
        row.expanded_bytes as u64,
        row.xml_depth as u64,
        row.xml_nodes as u64,
    ]
}
