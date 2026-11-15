//! The setting keys `drafter` declares (Setting stage 1): the crate's build script lists each row
//! in the setting catalogue.

use super::policy::{DrafterPolicyValue, drafter_policy_changed_in_txn};
use crate::setting::Kind;

crate::setting::setting_keys! {
    /// The owner's drafter policy (I5-DRAFTER = A, DRAFTER-DATA = A): whether nightly retraining
    /// runs and a version may serve, the worlds whose content never trains a drafter, and the
    /// recipe the nightly retrain runs. On by default, with no world excluded and no recipe. Off,
    /// or a newly excluded world, returns each affected target to stock in the write that changes
    /// it, and the serving host is told once that write commits.
    pub(crate) DRAFTER_POLICY: DrafterPolicyValue = "drafter.policy" {
        kind: Kind::new(DrafterPolicyValue::default),
        on_change: Some(drafter_policy_changed_in_txn),
        after_commit: Some(crate::Vault::notify_drafter_serving),
    };
}
