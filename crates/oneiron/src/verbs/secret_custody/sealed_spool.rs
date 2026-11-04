//! The sealed input `vault.secrets.custody.submit` carries, decoded onto a
//! spool file (FIX 11880). Its base64 is decoded piece by piece onto an
//! anonymous file the vault stages ([`Vault::archive_spool_file`]), as the
//! `POST /v1/owner/secrets/custody` door decodes its body's, so the custody
//! door reads the input where it lies and no decoded copy is held whole.
//! The input is ciphertext sealed to the holder, and the file is gone once
//! dropped.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use base64::Engine as _;

use crate::Vault;
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult};

/// Bytes of base64 text decoded at a time: whole quads, so only the last
/// piece may close with padding.
const BASE64_PIECE: usize = 64 * 1024;

/// Decodes `input_base64`, standard base64, onto a spool file of the
/// vault's own, piece by piece, and answers the file rewound to its start
/// with the decoded length.
///
/// # Errors
/// Text that is not standard base64, as decoding the whole string refuses
/// it; a spool file the vault cannot make, write or rewind.
pub(super) fn spool_sealed_input(vault: &Vault, input_base64: &str) -> MemoryResult<(File, u64)> {
    let mut file = vault.archive_spool_file()?;
    let mut len = 0u64;
    let mut pieces = input_base64.as_bytes().chunks(BASE64_PIECE).peekable();
    while let Some(piece) = pieces.next() {
        // Padding closes only the last piece.
        if pieces.peek().is_some() && piece.contains(&b'=') {
            return Err(not_base64());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(piece)
            .map_err(|_| not_base64())?;
        file.write_all(&bytes).map_err(Error::from)?;
        len = len.saturating_add(bytes.len() as u64);
    }
    file.seek(SeekFrom::Start(0)).map_err(Error::from)?;
    Ok((file, len))
}

/// What a sealed input that is not standard base64 says.
fn not_base64() -> MemoryError {
    MemoryError::bad_request("input_base64 must be standard base64")
}
