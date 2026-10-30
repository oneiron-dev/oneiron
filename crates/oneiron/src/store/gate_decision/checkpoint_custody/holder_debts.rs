//! The holder debts (FIX 8875) a side restore or an activation carries
//! into its fork (FIX 12192). Every debt standing at the source custody is
//! planned, unfiltered: the fork already copies each retired marker, so
//! planning only the debts the image's rows name could drop a retired
//! key's pending debt while its marker is copied. The fork copies a
//! planned debt while it still stands at the source, so the copy reads
//! the same remote steps. A fault listing the source's debts is warned by
//! the error's kind, and the restore goes on without them, as it does for
//! the erasable keys (FIX 11205).

use crate::store::key_custody::{CustodyBinding, CustodyPlan, LocalCustody};

/// Plans every holder debt standing in `bound`, the custody the rows bind,
/// through `plan` for the copy to carry. Never a requirement.
pub(super) fn plan_holder_debts(plan: &mut CustodyPlan, bound: &CustodyBinding) {
    match LocalCustody::at(bound).holder_debts() {
        Ok(debts) => {
            for debt in debts {
                plan.plan_holder_debt(debt);
            }
        }
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            "the holder debts' custody did not list for this restore's plan; \
             the copy carries none of them"
        ),
    }
}
