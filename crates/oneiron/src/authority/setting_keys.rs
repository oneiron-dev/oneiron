//! The authority module's catalogue keys (DESIGN 15-setting-primitive): this machine's
//! authority observation policy.

use super::AuthorityObservationPolicy;
use crate::setting::{Kind, SettingSync};

crate::setting::setting_keys! {
    /// This machine's authority observation bounds: the stale-roster window, the ingest
    /// window and its check threshold, the log's signer bound, the fold's headroom for rows,
    /// handoffs and ancestor pairs, and its memory floor. A choice about this machine; it never
    /// changes a signed entry.
    pub(crate) AUTHORITY_OBSERVATION_POLICY: AuthorityObservationPolicy = "authority.observation_policy" {
        kind: Kind::new(AuthorityObservationPolicy::default),
        sync: SettingSync::Install,
    };
}
