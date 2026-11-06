//! The shipped `policy_values` rows as fallbacks in the manifest fold (Engine
//! 10-22 C1; FIX 9802, 9809 for the edit-distance thresholds, FIX 11346 for
//! every key): a seeded manifest's rows are set aside while the fold reads
//! every trusted manifest, and each one stays only where no row an
//! authenticated owner or holder door authored names the same key and scope.
//! An authored row that differs from the seed thus replaces it, never sits
//! beside it as a second row in one slot, which would fail the manifest
//! closed. Other trusted rows meet that selected baseline by the key's own
//! narrowing order; they cannot replace an authored parent override.

use std::collections::BTreeSet;

use super::manifest_authenticity::{PolicyRowOrigin, policy_row_origin};
use super::policy_values::{PolicyRowScope, PolicyValueKey, PolicyValueRow};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The manifest fold's hold on the seeded `policy_values` rows.
#[derive(Debug, Default)]
pub(in crate::gate) struct SeededPolicyValueRows {
    seeded: Vec<PolicyValueRow>,
    authored: BTreeSet<(PolicyValueKey, PolicyRowScope)>,
    narrowing: Vec<PolicyValueRow>,
}

impl SeededPolicyValueRows {
    /// Folds one trusted manifest's value rows into `folded`, setting a
    /// seeded manifest's rows aside and noting an authored one's slots.
    pub(in crate::gate) fn fold(
        &mut self,
        store: &impl crate::store::ManifestDbs,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &[u8],
        rows: Vec<PolicyValueRow>,
        folded: &mut Vec<PolicyValueRow>,
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        match policy_row_origin(store, txn, id, body)? {
            PolicyRowOrigin::Seeded => self.seeded.extend(rows),
            PolicyRowOrigin::Authored => {
                self.authored
                    .extend(rows.iter().map(|row| (row.key, row.scope)));
                folded.extend(rows);
            }
            PolicyRowOrigin::Narrowing => self.narrowing.extend(rows),
        }
        Ok(())
    }

    /// Selects the authored-or-seeded baseline, then applies trusted narrowing.
    pub(in crate::gate) fn finish(self, folded: &mut Vec<PolicyValueRow>) {
        let authored = self.authored;
        folded.extend(
            self.seeded
                .into_iter()
                .filter(|row| !authored.contains(&(row.key, row.scope))),
        );
        for mut narrowing in self.narrowing {
            // Precedence has no meet: retain its existing conflict handling.
            if narrowing.key == PolicyValueKey::ScopePrecedence {
                folded.push(narrowing);
                continue;
            }
            let slot = (narrowing.key, narrowing.scope);
            let Some(index) = folded.iter().position(|row| (row.key, row.scope) == slot) else {
                // Only an authored baseline can release a parent's bound.
                narrowing.override_parent = false;
                folded.push(narrowing);
                continue;
            };
            let baseline = &folded[index];
            // A meet must not conceal a conflict among authored or seeded rows.
            if folded
                .iter()
                .any(|row| (row.key, row.scope) == slot && row != baseline)
            {
                folded.push(narrowing);
                continue;
            }
            let value = baseline.value.restrict(narrowing.value);
            if value != baseline.value {
                narrowing.value = value;
                narrowing.override_parent = baseline.override_parent;
                // Retain the actual deciding row's reference and explanation.
                for row in folded.iter_mut().filter(|row| (row.key, row.scope) == slot) {
                    *row = narrowing.clone();
                }
            }
        }
    }
}
