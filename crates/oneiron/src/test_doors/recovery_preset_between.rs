//! Door for changing the recovery preset between the owner's check and write.

use crate::Vault;
use crate::authority::ActAuthority;
use crate::error::Result;
use crate::store::recovery_kit::{KitIssue, KitPassphrase, KitPiece};
use crate::world_keys::{KitPasskey, RecoveryBoxHold, RecoveryPresetAnyTwoChange};

/// [`Vault::set_recovery_preset_any_two_with_kit_as`] with `between` run after the presence check
/// and before the kit is drawn or the write opens.
///
/// # Errors
/// As [`Vault::set_recovery_preset_any_two_with_kit_as`].
#[expect(
    clippy::too_many_arguments,
    reason = "the kit door arguments and the between hook"
)]
pub fn set_recovery_preset_any_two_with_kit_between(
    vault: &Vault,
    authority: &ActAuthority,
    issue: &KitIssue<'_>,
    passkey: Option<KitPasskey<'_>>,
    pieces: &[&KitPiece],
    passphrase: Option<&KitPassphrase>,
    keep_pieces: impl FnOnce(&[KitPiece]) -> Result<()>,
    box_hold: &dyn RecoveryBoxHold,
    between: impl FnOnce(),
) -> Result<RecoveryPresetAnyTwoChange> {
    vault.set_recovery_preset_any_two_with_kit_between(
        authority,
        issue,
        passkey,
        pieces,
        passphrase,
        keep_pieces,
        box_hold,
        between,
    )
}
