use std::borrow::Cow;
use std::ops::Deref;
use std::ptr;
use std::sync::Mutex;

use zeroize::Zeroize;

use crate::mdb::error::mdb_result;
use crate::mdb::ffi;
use crate::{Env, Result};

/// A read-only transaction.
///
/// ## LMDB Limitations
///
/// It's a must to keep read transactions short-lived.
///
/// Active Read transactions prevent the reuse of pages freed
/// by newer write transactions, thus the database can grow quickly.
///
/// ## OSX/Darwin Limitation
///
/// At least 10 transactions can be active at the same time in the same process, since only 10 POSIX semaphores can
/// be active at the same time for a process. Threads are in the same process space.
///
/// If the process crashes in the POSIX semaphore locking section of the transaction, the semaphore will be kept locked.
///
/// Note: if your program already use POSIX semaphores, you will have less available for heed/LMDB!
///
/// You may increase the limit by editing it **at your own risk**: `/Library/LaunchDaemons/sysctl.plist`
pub struct RoTxn<'e> {
    pub(crate) txn: *mut ffi::MDB_txn,
    env: Cow<'e, Env>,
    /// ONEIRON FORK (OF-570): copies of what a sealed env returned.
    stash: Option<Stash>,
}

/// ONEIRON FORK (OF-570): the bytes a sealed environment returned, copied out
/// of mdb.master3's page cache. That cache may unmap a page while the
/// transaction lives, so a sealed env's values are copied here and live until
/// the transaction ends, as heed promises. Wiped when the transaction drops.
#[derive(Default)]
pub(crate) struct Stash(Mutex<Vec<Box<[u8]>>>);

impl Stash {
    fn for_env(env: &Env) -> Option<Stash> {
        env.is_sealed().then(Stash::default)
    }

    /// A copy of `bytes` that lives as long as this stash.
    ///
    /// # Safety
    ///
    /// The caller bounds `'s` by the stash's own life, as heed bounds every
    /// returned value by its transaction.
    pub(crate) unsafe fn keep<'s>(&self, bytes: &[u8]) -> &'s [u8] {
        let copy: Box<[u8]> = bytes.into();
        let (data, len) = (copy.as_ptr(), copy.len());
        // A boxed slice's buffer never moves; it frees only when the stash drops.
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(copy);
        unsafe { std::slice::from_raw_parts(data, len) }
    }
}

impl Drop for Stash {
    fn drop(&mut self) {
        let kept = self.0.get_mut().unwrap_or_else(|poisoned| poisoned.into_inner());
        for copy in kept.iter_mut() {
            copy.zeroize();
        }
    }
}

impl<'e> RoTxn<'e> {
    pub(crate) fn new(env: &'e Env) -> Result<RoTxn<'e>> {
        let mut txn: *mut ffi::MDB_txn = ptr::null_mut();

        unsafe {
            mdb_result(ffi::mdb_txn_begin(
                env.env_mut_ptr(),
                ptr::null_mut(),
                ffi::MDB_RDONLY,
                &mut txn,
            ))?
        };

        Ok(RoTxn {
            txn,
            stash: Stash::for_env(env),
            env: Cow::Borrowed(env),
        })
    }

    pub(crate) fn static_read_txn(env: Env) -> Result<RoTxn<'static>> {
        let mut txn: *mut ffi::MDB_txn = ptr::null_mut();

        unsafe {
            mdb_result(ffi::mdb_txn_begin(
                env.env_mut_ptr(),
                ptr::null_mut(),
                ffi::MDB_RDONLY,
                &mut txn,
            ))?
        };

        Ok(RoTxn {
            txn,
            stash: Stash::for_env(&env),
            env: Cow::Owned(env),
        })
    }

    pub(crate) fn env_mut_ptr(&self) -> *mut ffi::MDB_env {
        self.env.env_mut_ptr()
    }

    /// ONEIRON FORK (OF-570): `bytes` LMDB returned in this transaction, made
    /// to last as long as it: unchanged for a plain env, copied for a sealed one.
    ///
    /// # Safety
    ///
    /// `'s` must not outlive this transaction.
    pub(crate) unsafe fn stable<'s>(&self, bytes: &'s [u8]) -> &'s [u8] {
        match &self.stash {
            None => bytes,
            Some(stash) => unsafe { stash.keep(bytes) },
        }
    }

    pub(crate) fn stash(&self) -> Option<&Stash> {
        self.stash.as_ref()
    }

    /// Commit a read transaction.
    ///
    /// Synchronizing some [`Env`] metadata with the global handle.
    ///
    /// ## LMDB
    ///
    /// It's mandatory in a multi-process setup to call [`RoTxn::commit`] upon read-only database opening.
    /// After the transaction opening, the database is dropped. The next transaction might return
    /// `Io(Os { code: 22, kind: InvalidInput, message: "Invalid argument" })` known as `EINVAL`.
    pub fn commit(mut self) -> Result<()> {
        let result = unsafe { mdb_result(ffi::mdb_txn_commit(self.txn)) };
        self.txn = ptr::null_mut();
        result.map_err(Into::into)
    }
}

impl Drop for RoTxn<'_> {
    fn drop(&mut self) {
        if !self.txn.is_null() {
            abort_txn(self.txn);
        }
    }
}

#[cfg(feature = "read-txn-no-tls")]
unsafe impl Send for RoTxn<'_> {}

fn abort_txn(txn: *mut ffi::MDB_txn) {
    // Asserts that the transaction hasn't been already committed.
    assert!(!txn.is_null());
    unsafe { ffi::mdb_txn_abort(txn) }
}

/// A read-write transaction.
///
/// ## LMDB Limitations
///
/// Only one [`RwTxn`] may exist in the same environment at the same time.
/// If two exist, the new one may wait on a mutex for [`RwTxn::commit`] or [`RwTxn::abort`] to
/// be called for the first one.
///
/// ## OSX/Darwin Limitation
///
/// At least 10 transactions can be active at the same time in the same process, since only 10 POSIX semaphores can
/// be active at the same time for a process. Threads are in the same process space.
///
/// If the process crashes in the POSIX semaphore locking section of the transaction, the semaphore will be kept locked.
///
/// Note: if your program already use POSIX semaphores, you will have less available for heed/LMDB!
///
/// You may increase the limit by editing it **at your own risk**: `/Library/LaunchDaemons/sysctl.plist`
pub struct RwTxn<'p> {
    pub(crate) txn: RoTxn<'p>,
}

impl<'p> RwTxn<'p> {
    pub(crate) fn new(env: &'p Env) -> Result<RwTxn<'p>> {
        let mut txn: *mut ffi::MDB_txn = ptr::null_mut();

        unsafe {
            mdb_result(ffi::mdb_txn_begin(
                env.env_mut_ptr(),
                ptr::null_mut(),
                0,
                &mut txn,
            ))?
        };

        Ok(RwTxn {
            txn: RoTxn {
                txn,
                stash: Stash::for_env(env),
                env: Cow::Borrowed(env),
            },
        })
    }

    pub(crate) fn nested(env: &'p Env, parent: &'p mut RwTxn) -> Result<RwTxn<'p>> {
        let mut txn: *mut ffi::MDB_txn = ptr::null_mut();
        let parent_ptr: *mut ffi::MDB_txn = parent.txn.txn;

        unsafe {
            mdb_result(ffi::mdb_txn_begin(
                env.env_mut_ptr(),
                parent_ptr,
                0,
                &mut txn,
            ))?
        };

        Ok(RwTxn {
            txn: RoTxn {
                txn,
                stash: Stash::for_env(env),
                env: Cow::Borrowed(env),
            },
        })
    }

    pub(crate) fn env_mut_ptr(&self) -> *mut ffi::MDB_env {
        self.txn.env.env_mut_ptr()
    }

    /// Commit all the operations of a transaction into the database.
    /// The transaction is reset.
    pub fn commit(mut self) -> Result<()> {
        let result = unsafe { mdb_result(ffi::mdb_txn_commit(self.txn.txn)) };
        self.txn.txn = ptr::null_mut();
        result.map_err(Into::into)
    }

    /// Abandon all the operations of the transaction instead of saving them.
    /// The transaction is reset.
    pub fn abort(mut self) {
        abort_txn(self.txn.txn);
        self.txn.txn = ptr::null_mut();
    }
}

impl<'p> Deref for RwTxn<'p> {
    type Target = RoTxn<'p>;

    fn deref(&self) -> &Self::Target {
        &self.txn
    }
}
