//! Panic guard and raw-pointer slice/out/vault helpers.

use std::{
    mem::size_of,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use super::types::{OneironStatus, OneironVault};

pub(super) fn ffi_guard(f: impl FnOnce() -> OneironStatus) -> OneironStatus {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(status) => status,
        Err(_) => OneironStatus::Panic,
    }
}

pub(super) fn checked_slice_len<T>(len: usize) -> Result<(), OneironStatus> {
    let elem = size_of::<T>().max(1);
    if len > isize::MAX as usize / elem {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(())
}

pub(super) fn with_required_slice<T, R>(
    ptr: *const T,
    len: usize,
    f: impl FnOnce(&[T]) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if ptr.is_null() {
        return Err(OneironStatus::NullArg);
    }
    checked_slice_len::<T>(len)?;
    // SAFETY: The caller supplies a non-null pointer to at least `len`
    // contiguous `T` values that stay alive for the duration of this call.
    let values = unsafe { slice::from_raw_parts(ptr, len) };
    f(values)
}

pub(super) fn with_optional_slice<T, R>(
    ptr: *const T,
    len: usize,
    f: impl FnOnce(Option<&[T]>) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if ptr.is_null() {
        if len == 0 {
            return f(None);
        }
        return Err(OneironStatus::NullArg);
    }
    checked_slice_len::<T>(len)?;
    // SAFETY: The caller supplies a non-null pointer to at least `len`
    // contiguous `T` values that stay alive for the duration of this call.
    let values = unsafe { slice::from_raw_parts(ptr, len) };
    f(Some(values))
}

pub(super) fn write_out<T>(out: *mut T, value: T) -> Result<(), OneironStatus> {
    if out.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `out` is non-null and the caller guarantees it points to
    // writable storage for one `T`. `ptr::write` avoids reading old contents.
    unsafe { ptr::write(out, value) };
    Ok(())
}

pub(super) fn with_vault<R>(
    vault: *mut OneironVault,
    f: impl FnOnce(&OneironVault) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if vault.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `vault` is a non-null handle previously returned by
    // `oneiron_vault_open` and not yet freed by `oneiron_vault_free`.
    let vault = unsafe { &*vault };
    f(vault)
}
