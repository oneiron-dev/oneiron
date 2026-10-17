//! ONEIRON FORK (OF-570): the page cipher of a sealed environment.
//!
//! mdb.master3 hands every page it writes to [`seal_page`] and every page it
//! reads back to the same function. The page's first bytes (its number and the
//! writing transaction's id) stay clear and are passed as the "IV"; the rest is
//! sealed with XChaCha20-Poly1305 under the environment's page key.
//!
//! - Every seal draws a fresh random 24-byte nonce. It is never derived from the
//!   page number or transaction id, so a page spilled and rewritten in one
//!   transaction, an aborted transaction's pages, or two files under one key
//!   never reuse a nonce.
//! - The nonce and the 16-byte tag sit in the per-page authentication area LMDB
//!   reserves at the tail of each page (or overflow run): [`AUTH`] bytes.
//! - The associated data is a format label and the clear page prefix, so a page
//!   moved to another page number or transaction fails to open.
//! - Meta pages 0 and 1 are not sealed by mdb.master3; they carry the
//!   environment's encrypted flag, and opening a sealed file without a key (or a
//!   plain one with a key) refuses.

use std::os::raw::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};

use crate::mdb::ffi;

const NONCE: usize = 24;
const TAG: usize = 16;
/// The per-page authentication area: the nonce, then the tag.
pub(crate) const AUTH: u32 = (NONCE + TAG) as u32;
/// The page key's length.
pub(crate) const KEY: usize = 32;
const LABEL: &[u8] = b"oneiron/lmdb-page/v1";
/// The clear page prefix LMDB passes as the IV: page number and txn id.
const PREFIX_MAX: usize = 16;

/// The `MDB_enc_func` a sealed environment registers. Returns 0 on success and
/// 1 on any failure, a refused tag included; it never unwinds into C.
pub(crate) unsafe extern "C" fn seal_page(
    src: *const ffi::MDB_val,
    dst: *mut ffi::MDB_val,
    key: *const ffi::MDB_val,
    encdec: c_int,
) -> c_int {
    let done = catch_unwind(AssertUnwindSafe(|| unsafe {
        transform(src, dst, key, encdec != 0)
    }));
    match done {
        Ok(Some(())) => 0,
        _ => 1,
    }
}

/// # Safety
///
/// LMDB's contract for `MDB_enc_func`: `src` and `dst` name disjoint buffers of
/// one length, and `key` points at three values: the key, the clear page
/// prefix, and the authentication area (in `dst` when sealing, in `src` when
/// opening).
unsafe fn transform(
    src: *const ffi::MDB_val,
    dst: *mut ffi::MDB_val,
    key: *const ffi::MDB_val,
    seal: bool,
) -> Option<()> {
    let (src, dst) = unsafe { (&*src, &*dst) };
    let keys = unsafe { slice::from_raw_parts(key, 3) };
    if src.mv_size != dst.mv_size
        || keys[0].mv_size != KEY
        || keys[1].mv_size > PREFIX_MAX
        || keys[2].mv_size != AUTH as usize
    {
        return None;
    }
    let page_key = unsafe { slice::from_raw_parts(keys[0].mv_data as *const u8, KEY) };
    let prefix = unsafe { slice::from_raw_parts(keys[1].mv_data as *const u8, keys[1].mv_size) };
    let input = unsafe { slice::from_raw_parts(src.mv_data as *const u8, src.mv_size) };
    let output = unsafe { slice::from_raw_parts_mut(dst.mv_data as *mut u8, dst.mv_size) };

    let mut aad = [0u8; LABEL.len() + PREFIX_MAX];
    aad[..LABEL.len()].copy_from_slice(LABEL);
    aad[LABEL.len()..LABEL.len() + prefix.len()].copy_from_slice(prefix);
    let aad = &aad[..LABEL.len() + prefix.len()];

    let cipher = XChaCha20Poly1305::new_from_slice(page_key).ok()?;
    let buffer = InOutBuf::new(input, output).ok()?;
    if seal {
        let auth = unsafe { slice::from_raw_parts_mut(keys[2].mv_data as *mut u8, AUTH as usize) };
        let (nonce, tag) = auth.split_at_mut(NONCE);
        getrandom::fill(nonce).ok()?;
        let nonce = <&XNonce>::try_from(&*nonce).ok()?;
        let sealed = cipher.encrypt_inout_detached(nonce, aad, buffer).ok()?;
        tag.copy_from_slice(&sealed);
    } else {
        let auth = unsafe { slice::from_raw_parts(keys[2].mv_data as *const u8, AUTH as usize) };
        let (nonce, tag) = auth.split_at(NONCE);
        let nonce = <&XNonce>::try_from(nonce).ok()?;
        let tag = <&Tag>::try_from(tag).ok()?;
        cipher
            .decrypt_inout_detached(nonce, aad, buffer, tag)
            .ok()?;
    }
    Some(())
}
