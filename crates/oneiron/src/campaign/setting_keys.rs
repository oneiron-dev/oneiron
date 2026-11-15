//! The campaign sticky sender's pack Setting key (owner ruling PACK-SETTINGS-ALL = B; Engine
//! RULING 23:20 15 Nov, PACK-KEYS-CAMPAIGN-PRESET-LOCKS = A, C06): whether a member-channel whose
//! stored sender is dead moves to the proposed sender, or waits for a human restart. The default
//! is today's: a human restarts it (`send_hygiene::StickySenderOutcome::RestartRequired`). The
//! owner changes the value; an agent's change waits on the owner's approval.
//!
//! Direction: false is tighter. With true a person is mailed from an address they have not had
//! mail from, so turning it on is a loosening and needs the owner's device yes. Each rotation then
//! writes the member's new head and a notice to every vault owner, so the identity change stays
//! visible. A row that does not decode reads as false.

use crate::Vault;
use crate::error::Result;
use crate::setting::{Kind, lower_is_tighter};

const fn restart_required() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Rotate a campaign member-channel off its dead sticky sender (default false: the binding
    /// returns a restart for a human and writes nothing). true: the binding moves the
    /// member-channel to the proposed sender, and every vault owner gets a notice naming the
    /// person, the dead sender and the new one. false is tighter. An unreadable row reads as
    /// false.
    pub(crate) CAMPAIGN_SENDER_ROTATE_ON_DEAD: bool = "campaign.sender.rotate_on_dead" {
        kind: Kind::new(restart_required)
            .strictest(restart_required)
            .tighter(lower_is_tighter::<bool>),
    };
}

/// Whether the owner lets a dead sticky sender rotate, in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn sender_rotates_on_dead_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(CAMPAIGN_SENDER_ROTATE_ON_DEAD
        .read_in_txn(vault, txn, &[], None)?
        .value)
}
