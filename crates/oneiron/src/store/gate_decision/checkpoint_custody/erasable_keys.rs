//! The erasable custody keys (FIX 8875) a side restore or an activation
//! carries into its fork (FIX 11205). Each key whose ref a
//! `key_custody:erasable_ref:v1:` row of the image, or of the archive, names
//! is an optional subject of the plan: the fork copies a live one byte for
//! byte, so the copy opens the handoff content it kept, and keeps a retired
//! one retired, never revived. A key its source no longer holds is not
//! planned; a fault reading the source's custody is warned by the error's
//! kind, and the restore goes on without that key, as it did.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::side_table::{self, SideKey};
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, ErasableItem, LocalCustody,
};

/// Plans the key in `bound`, the custody the rows bind, of each erasable
/// ref `rows` name, through `plan` as optional. Never a requirement.
pub(super) fn plan_erasable_keys(
    plan: &mut CustodyPlan,
    bound: &CustodyBinding,
    rows: &[(Vec<u8>, Vec<u8>)],
) {
    let refs: BTreeSet<[u8; 32]> = rows
        .iter()
        .filter_map(|(key, _)| {
            key.strip_prefix(side_table::KEY_CUSTODY_ERASABLE_REF.prefix)
                .and_then(<[u8; 32]>::decode_key)
        })
        .collect();
    if refs.is_empty() {
        return;
    }
    if let Err(error) = plan_held_keys(plan, bound, &refs) {
        tracing::warn!(
            kind = ?error.kind(),
            "the erasable keys' custody did not list for this restore's plan; \
             the copy carries none of them"
        );
    }
}

/// Plans each key of `refs` that `bound`'s custody holds a directory for,
/// live or retired, by its directory name, as a handoff's read finds it.
/// A key whose state does not read is planned all the same: the fork copies
/// it if it reads then, and warns if not.
fn plan_held_keys(
    plan: &mut CustodyPlan,
    bound: &CustodyBinding,
    refs: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    let custody = LocalCustody::at(bound);
    for subject in custody.subjects_with_prefix(CustodyKind::ErasableKey, &[])? {
        let named =
            ErasableItem::of_item(subject.item()).is_some_and(|item| refs.contains(&item.key_ref));
        if !named {
            continue;
        }
        if let Err(error) = plan.require_present(&subject.at(0)) {
            tracing::warn!(
                kind = ?error.kind(),
                "an erasable key's state did not read for this restore's plan"
            );
        }
    }
    Ok(())
}
