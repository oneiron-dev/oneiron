//! Door for `tests/federated_admission_rewrite_keeps_local_writes.rs`
//! (FEDERATED-ADMISSION-FRESH-DOC-LAMPORT-TIE): the write over a window an
//! admitted part makes once it imports, as `SyncClient` computes it, for a
//! window and parts the test authors itself.

use loro::{LoroDoc, VersionVector};

use crate::error::Result;

/// The update writing again over `window` each key `part` lost to an
/// earlier admission, `held` being the window's version before `part`
/// imported; `None` when it writes nothing.
///
/// # Errors
///
/// `part` does not decode.
pub fn admitted_rewrite(
    window: &LoroDoc,
    part: &[u8],
    held: &VersionVector,
) -> Result<Option<Vec<u8>>> {
    crate::sync::client::admitted_rewrite(window, part, held)
}
