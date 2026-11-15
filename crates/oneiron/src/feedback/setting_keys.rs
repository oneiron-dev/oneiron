//! The feedback destination's owner Setting key (owner principle, 16 Nov 00:44: a restriction
//! that is not a correctness fix ships as a good default plus an owner opt-out). The default is
//! today's rule. The owner changes the value; an agent's change, either way, waits on the owner's
//! approval.
//!
//! Direction: plain HTTP carries the owner's approved feedback, and the destination's bearer,
//! readable on the network, so requiring HTTPS is tighter. A row that does not decode reads as
//! true, today's rule.

use crate::Vault;
use crate::error::Result;
use crate::setting::{Kind, higher_is_tighter};

/// HTTPS required: today's rule, and the strictest value.
fn required() -> bool {
    true
}

crate::setting::setting_keys! {
    /// Whether the server's `[feedback]` destination must be HTTPS (default true: plain HTTP
    /// only on loopback). False lets a send and the Coach's issue signatures go to a plain-HTTP
    /// endpoint anywhere, the owner accepting that the bundle and the bearer cross the network
    /// unencrypted; true is tighter. The endpoint never carries credentials, a query or a
    /// fragment whatever this says, and the peer routes (inquiry delivery, courtesy deletes)
    /// keep HTTPS (the server's feedback transport).
    pub(crate) FEEDBACK_DELIVERY_REQUIRE_HTTPS: bool = "feedback.delivery.require_https" {
        kind: Kind::new(required)
            .strictest(required)
            .tighter(higher_is_tighter::<bool>),
    };
}

/// Whether the vault's owner requires the feedback destination to be HTTPS, read now.
///
/// # Errors
///
/// Storage errors.
pub fn feedback_delivery_requires_https(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(FEEDBACK_DELIVERY_REQUIRE_HTTPS
        .read_in_txn(vault, &txn, &[], None)?
        .value)
}
