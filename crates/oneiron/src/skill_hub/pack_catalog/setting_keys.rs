//! The pack install screen's Setting key (FIX SCREENING-PER-TOOL-SKIP, PR D;
//! Engine ANSWER SCREENING-SKIP-OVERRIDE-SCOPE, 16 Nov 13:20: the text bound
//! is a size limit, not a correctness rule, so it is an owner key rather than
//! a per-tool lift). The default is the bound the screen has always kept. The
//! owner sets it. An agent sets it only as the Setting primitive's one change
//! rule allows: with the key's own Grant line it tightens inside the owner's
//! value, and its widening waits on a check-in.
//!
//! Direction: a lower bound is tighter, since the screen keeps out every text
//! past it. A row that does not decode reads as one byte. Every other screen
//! rule still reads the whole text, whatever the bound. A bound above the
//! default does not widen a pack's observed tool manifest: pack prepare keeps
//! its own 16384-byte limit on an observed tool description, a manifest shape
//! bound and not a screen rule.

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// The bound on one screened text the screen has always kept, in bytes.
const DEFAULT_TEXT_MAX_BYTES: u32 = 16_384;

/// The largest text the pack install screen admits, in bytes: at least 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ScreenTextMaxBytes(pub(crate) u32);

impl SettingValue for ScreenTextMaxBytes {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "the pack install screen admits a text of at least 1 byte".to_owned(),
            ))
        }
    }
}

fn default_text_max_bytes() -> ScreenTextMaxBytes {
    ScreenTextMaxBytes(DEFAULT_TEXT_MAX_BYTES)
}

fn fewest_bytes() -> ScreenTextMaxBytes {
    ScreenTextMaxBytes(1)
}

crate::setting::setting_keys! {
    /// The largest text the pack install screen admits, in bytes (default 16384). Lower is
    /// tighter: a connector tool whose name, description or one schema text is longer is kept
    /// out, and a pack whose PACK.md or tool declaration text is longer is refused. Every other
    /// screen rule still reads the whole text. Pack prepare keeps its own 16384-byte limit on an
    /// observed tool description, whatever this bound.
    pub(crate) PACK_INSTALL_SCREEN_TEXT_MAX_BYTES: ScreenTextMaxBytes =
        "pack_install.screen.text_max_bytes" {
        kind: Kind::new(default_text_max_bytes)
            .strictest(fewest_bytes)
            .tighter(lower_is_tighter::<ScreenTextMaxBytes>),
    };
}

/// The largest text the pack install screen admits in `txn`, at the vault
/// scope, in bytes.
///
/// # Errors
///
/// Storage errors.
pub(super) fn text_max_bytes_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<usize> {
    let bound = PACK_INSTALL_SCREEN_TEXT_MAX_BYTES
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0;
    Ok(usize::try_from(bound).unwrap_or(usize::MAX))
}
