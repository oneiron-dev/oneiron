//! The adopted-fold door (FIX [ADOPTED-FOLD-GATE-TEST] and
//! [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY]): one vault's log folded past an
//! image of a prefix of it on a cold install, beside the vault's own whole
//! fold, live and image-grade, so a test shows where the fold past an image
//! answers and that its answer is the whole fold's; past an image that
//! dropped its residence bodies too (FIX 11400); and a host-signed row
//! above a withheld parent for the fold past an adopted image to judge (FIX
//! [ADOPTED-PENDING-BATCH-BELIEF-RED-TEST]). Compiled only under
//! `--cfg oneiron_test_support`; never API.

pub use crate::authority::adopted_door::{
    AdoptedFoldComparison, ImageGradeFold, PastImage, fold_past_overflow_prefix_image,
    fold_past_prefix_image, host_signed_row,
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

// The adopted-fold gate's covered-row check over replaced summaries (FIX
// [ADOPTED-FOLD-GATE-SIGNER-COST]).
pub use crate::authority::adopted_door::covered_rows_unfloored;

// The adopted fold's tail checks over replaced summaries and tail rows (FIX
// [ADOPTED-FOLD-TAIL-WALK-SIGNER-COST]).
pub use crate::authority::adopted_door::tail_floored_rows;
