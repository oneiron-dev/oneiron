//! Guarded key derivation, OS entropy, and the world-key refusal constructor.

use zeroize::Zeroizing;

use crate::error::{Error, Result, SecretError};

pub(crate) fn refused(reason: &'static str) -> Error {
    Error::Secret(SecretError::WorldKeyRefused(reason))
}

/// `BLAKE3-derive_key(context, parts…)`, the same 32 bytes, written straight
/// into guarded output (FIX 6334): the output is zero-filled first and the
/// XOF fills it in place, and the hasher's block buffer and the reader's
/// state, which still hold the input key's bytes, are wiped. A secret subkey
/// never passes through a plain array on its way to its guard.
pub(crate) fn derive_guarded(context: &str, parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out[..]);
    zeroize::Zeroize::zeroize(&mut hasher);
    zeroize::Zeroize::zeroize(&mut reader);
    out
}

/// Fills `buf` from the OS CSPRNG. A failure is an error, never a weaker key.
pub(crate) fn os_fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| refused("os entropy unavailable"))
}
