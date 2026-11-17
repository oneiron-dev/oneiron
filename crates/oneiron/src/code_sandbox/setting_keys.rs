//! The code sandbox's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::setting::{Kind, lower_is_tighter};

/// Off: a foreign `execute_code` run is lent no network.
fn no_foreign_egress() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let foreign `execute_code` programs reach the network through this host's egress proxy.
    /// Off by default: a foreign program is lent no network, so every connect, datagram and
    /// fetch it makes fails before any socket opens. On, each run is lent the host's egress
    /// proxy, the one a callable foreign-tier skill already runs under: public addresses only,
    /// the host's allowlist and raw endpoint grants, and a receipt for every request. No
    /// credential is lent either way. On is the looser value, so only the owner turns it on; an
    /// agent's change waits on the owner's answer (owner 16 Nov 00:44: a restriction that is
    /// not a correctness fix ships as a good default plus an owner opt-out).
    pub(crate) FOREIGN_EXECUTE_CODE_EGRESS: bool = "code_sandbox.foreign.execute_code_egress" {
        kind: Kind::new(no_foreign_egress)
            .strictest(no_foreign_egress)
            .tighter(lower_is_tighter::<bool>),
    };
}
