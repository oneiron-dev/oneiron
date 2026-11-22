//! Two consent structures compared field by field, so a test door shows
//! that the structure a kept door view grew equals one built afresh (FIX
//! [OWNER-RESERVE-PROJECTION-COST]). Compiled only under
//! `--cfg oneiron_test_support`.

use super::AuthorityStructure;

impl AuthorityStructure {
    /// The first field in which `self` and `other` differ, or None. The
    /// genesis rows compare as a set: rows pushed in another order list them
    /// in another order, and a log with more than one reads each the same.
    pub(in crate::authority) fn differs_from(&self, other: &Self) -> Option<&'static str> {
        if self.roots.len() != other.roots.len()
            || self.roots.iter().any(|root| !other.roots.contains(root))
        {
            return Some("roots");
        }
        [
            ("admitters", self.admitters == other.admitters),
            ("issuers", self.issuers == other.issuers),
            ("machine_keys", self.machine_keys == other.machine_keys),
            ("stranger_keys", self.stranger_keys == other.stranger_keys),
            ("removed", self.removed == other.removed),
            ("anchors", self.anchors == other.anchors),
            ("own_anchors", self.own_anchors == other.own_anchors),
            (
                "awaited_anchors",
                self.awaited_anchors == other.awaited_anchors,
            ),
            ("local", self.local == other.local),
        ]
        .into_iter()
        .find_map(|(field, same)| (!same).then_some(field))
    }
}
