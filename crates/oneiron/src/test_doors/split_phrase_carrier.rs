//! Doors for the split-phrase carrier tests
//! (`tests/split_phrase_mask_on_write.rs`; REVIEW-7059): whether the door's
//! file rules place a carrier's stored text, and how a lifted text reads to
//! a reader other than the owner and back from a writer who keeps its
//! handles. Compiled only under `--cfg oneiron_test_support` (`test_doors`).
//! Hidden; never API. Every assertion stays in the test file: these return
//! plain values.

use crate::Result;
use crate::batch::secret_scan::{LiftedKeys, carrier_text_placeable};
use crate::vault::Vault;

/// Whether the door's file rules place each key in `text`, a carrier's
/// stored text with a hit (`carrier_text_placeable`).
///
/// # Errors
///
/// The door's.
#[doc(hidden)]
pub fn carrier_text_is_placeable(text: &[u8]) -> Result<bool> {
    carrier_text_placeable(text)
}

/// `text`, a carrier's stored text, as a reader other than the owner reads
/// it (`LiftedKeys::masked`), and that copy as a writer who kept every
/// handle writes it back (`LiftedKeys::resolved`). `None` where a step
/// changes nothing.
///
/// # Errors
///
/// The store's.
#[doc(hidden)]
pub fn lifted_text_round_trip(
    vault: &Vault,
    text: &str,
) -> Result<(Option<String>, Option<String>)> {
    let txn = vault.store.env.read_txn()?;
    let keys = LiftedKeys::of_in_txn(&vault.store, &txn, [text])?;
    let masked = keys.masked(text);
    let resolved = masked.as_deref().and_then(|copy| keys.resolved(copy));
    Ok((masked, resolved))
}
