//! ONEIRON FORK: nonblocking admission for native heap buffers and sealed read copies.

use std::ffi::c_void;
use std::sync::Arc;

use crate::Result;
use crate::mdb::{error::mdb_result, ffi};

/// An account scoped to one root writer and retained by its accounted buffers.
///
/// These callbacks must not wait, re-enter LMDB, or panic. Admission happens
/// before entering the writer: `reserve` only consumes already admitted bytes.
/// Cached page buffers retain their account after commit/abort until physically
/// freed. This covers the native heap sites wired to these callbacks and sealed
/// read-copy payloads, not disk allocation, mmap or unaccounted metadata.
pub trait PageAccount: Send + Sync + 'static {
    /// Reserves `bytes` for one allocation, including any native heap-only prefix.
    /// False leaves the reservation unchanged; the writer then fails with ENOMEM.
    fn reserve(&self, bytes: usize) -> bool;

    /// The admitted allocation succeeded and now holds exactly `bytes`.
    fn materialized(&self, bytes: usize);

    /// Consumes one reservation: after physical free if `allocated`, otherwise
    /// after allocation failed without allocating. Called once per successful reserve.
    fn release(&self, bytes: usize, allocated: bool);
}

pub(crate) struct Registration(Arc<dyn PageAccount>);

impl Registration {
    pub(crate) fn attach(
        txn: *mut ffi::MDB_txn,
        account: Arc<dyn PageAccount>,
    ) -> Result<Arc<Self>> {
        let registration = Arc::new(Self(account));
        // SAFETY: the caller retains this Arc until the root transaction ends.
        // Each successful reserve retains another Arc, owned by that buffer.
        unsafe {
            mdb_result(ffi::mdb_txn_set_page_account(
                txn,
                Some(reserve),
                Some(materialized),
                Some(release),
                Arc::as_ptr(&registration).cast_mut().cast(),
            ))?;
        }
        Ok(registration)
    }
}

unsafe extern "C" fn reserve(
    context: *mut c_void,
    bytes: usize,
    ticket: *mut *mut c_void,
) -> libc::c_int {
    let pointer = context.cast::<Registration>();
    // SAFETY: the root transaction owns this registration throughout the call.
    let registration = unsafe { &*pointer };
    if !registration.0.reserve(bytes) {
        return libc::ENOMEM;
    }
    // SAFETY: the live root Arc backs pointer; its added strong reference moves
    // into the native buffer ticket without a per-buffer Rust allocation.
    unsafe {
        Arc::increment_strong_count(pointer);
        *ticket = context;
    }
    0
}

unsafe extern "C" fn materialized(ticket: *mut c_void, bytes: usize) {
    // SAFETY: successful reserve retained this Arc until release consumes it.
    unsafe { &*ticket.cast::<Registration>() }
        .0
        .materialized(bytes);
}

unsafe extern "C" fn release(ticket: *mut c_void, bytes: usize, allocated: libc::c_int) {
    // SAFETY: native code consumes exactly one ticket after physical free or
    // failed malloc, and never uses it again. Cached buffers have not released it.
    let registration = unsafe { Arc::from_raw(ticket.cast::<Registration>()) };
    registration.0.release(bytes, allocated != 0);
}
