//! The adopted-fold door (FIX [ADOPTED-FOLD-GATE-TEST] and
//! [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY]): one vault's log folded past an
//! image of a prefix of it on a cold install, beside the vault's own whole
//! fold, live and image-grade, so a test shows where the fold past an image
//! answers and that its answer is the whole fold's. Compiled only under
//! `--cfg oneiron_test_support`; never API.

pub use crate::authority::adopted_door::{
    AdoptedFoldComparison, ImageGradeFold, PastImage, fold_past_prefix_image,
};

/// Records `root` as the root this install awaits for the root request signed
/// as entry `request`, as a carried pin request's pickup does (the request's
/// own wait, FIX 5582), so a test folds past an adopted image with such a wait
/// standing (FIX [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD], #9476 review round
/// 1).
///
/// # Errors
///
/// Storage errors.
pub fn await_root_for_request(
    vault: &crate::Vault,
    root: crate::authority::RecoveryRootId,
    request: crate::authority::AuthorityEntryHash,
) -> crate::Result<()> {
    vault.with_write_txn(|wtxn| {
        crate::authority::write_awaited_root_in_txn(&vault.store, wtxn, Some(root), Some(request))
    })
}
