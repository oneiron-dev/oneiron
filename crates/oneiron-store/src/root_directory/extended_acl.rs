//! A macOS directory's extended access-control list, read without following a
//! final link (ARCH-0038 #restore-path-open): whether one of its allow entries
//! lets anyone but this user or root change what a path through it names.
//!
//! The declarations follow the SDK's `sys/acl.h` and `membership.h`; libc
//! declares neither. Every call is in libSystem, which every macOS binary
//! links.

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::NonNull;

use oneiron_base::error::{Error, Result};

/// `struct _acl`, read only through the calls below.
type Acl = c_void;
/// `struct _acl_entry`, read only through the calls below; it lives inside
/// the ACL it came from.
type AclEntry = c_void;

/// `acl_type_t` ACL_TYPE_EXTENDED.
const ACL_TYPE_EXTENDED: c_int = 0x100;
/// `acl_tag_t` ACL_EXTENDED_ALLOW.
const ACL_EXTENDED_ALLOW: c_int = 1;
/// `acl_entry_id_t` ACL_FIRST_ENTRY.
const ACL_FIRST_ENTRY: c_int = 0;
/// `acl_entry_id_t` ACL_NEXT_ENTRY.
const ACL_NEXT_ENTRY: c_int = -1;

/// The rights that let their holder change what a path through the directory
/// names: add a file or a subdirectory (`ACL_ADD_FILE` 1<<2,
/// `ACL_ADD_SUBDIRECTORY` 1<<5), remove or rename an entry
/// (`ACL_DELETE_CHILD` 1<<6), remove or rename the directory itself
/// (`ACL_DELETE` 1<<4), or give themselves any of these by rewriting the list
/// or taking the directory over (`ACL_WRITE_SECURITY` 1<<12,
/// `ACL_CHANGE_OWNER` 1<<13).
const CHANGING_RIGHTS: u64 = (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 12) | (1 << 13);

unsafe extern "C" {
    fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut Acl;
    fn acl_get_entry(acl: *mut Acl, entry_id: c_int, entry: *mut *mut AclEntry) -> c_int;
    fn acl_get_tag_type(entry: *mut AclEntry, tag: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: *mut AclEntry, mask: *mut u64) -> c_int;
    fn acl_get_qualifier(entry: *mut AclEntry) -> *mut c_void;
    fn acl_free(object: *mut c_void) -> c_int;
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> c_int;
}

/// The principals whose entries never share a directory: this user and root,
/// by the UUIDs an access-control list names them with.
pub(super) struct OwnPrincipals {
    user: [u8; 16],
    root: [u8; 16],
}

impl OwnPrincipals {
    pub(super) fn of(euid: u32) -> Result<Self> {
        Ok(Self {
            user: principal_of(euid)?,
            root: principal_of(0)?,
        })
    }
}

fn principal_of(uid: u32) -> Result<[u8; 16]> {
    let mut uuid = [0_u8; 16];
    // SAFETY: `uuid` is a live 16-byte buffer, the size of `uuid_t`, that
    // mbr_uid_to_uuid only writes; no pointer outlives the call.
    let code = unsafe { mbr_uid_to_uuid(uid, uuid.as_mut_ptr()) };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code).into());
    }
    Ok(uuid)
}

/// An ACL `acl_get_link_np` handed this caller, freed once on drop.
struct HeldAcl(NonNull<Acl>);

impl Drop for HeldAcl {
    fn drop(&mut self) {
        // SAFETY: the pointer is the caller-owned copy acl_get_link_np
        // returned; no entry taken from it outlives this value, and it is
        // freed here exactly once.
        unsafe { acl_free(self.0.as_ptr()) };
    }
}

/// Whether an allow entry in the extended ACL of the directory `path` names
/// (no final link followed) gives any group, or a user other than `own`, one
/// of [`CHANGING_RIGHTS`]. Deny entries never count; an allow entry counts
/// whatever its inheritance flags, and whatever the sticky bit. No ACL, or a
/// file system without ACLs, is no such entry.
pub(super) fn lets_another_user_change(path: &Path, own: &OwnPrincipals) -> Result<bool> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::InvalidConfig("a path on the way contains a NUL byte".to_owned()))?;
    // SAFETY: `name` is a live NUL-terminated string for the whole call;
    // acl_get_link_np returns a fresh caller-owned ACL or NULL, and HeldAcl
    // takes only a non-NULL one.
    let acl = unsafe { acl_get_link_np(name.as_ptr(), ACL_TYPE_EXTENDED) };
    let Some(acl) = NonNull::new(acl).map(HeldAcl) else {
        let error = std::io::Error::last_os_error();
        // libSystem answers ENOENT for a directory that has no extended ACL.
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTSUP | libc::EOPNOTSUPP) => Ok(false),
            _ => Err(error.into()),
        };
    };
    let mut entry_id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl` holds a live ACL and `entry` is a live out pointer;
        // the entry it sets lives inside that ACL, which outlives the loop.
        if unsafe { acl_get_entry(acl.0.as_ptr(), entry_id, &raw mut entry) } != 0 {
            // EINVAL after the last entry.
            return Ok(false);
        }
        entry_id = ACL_NEXT_ENTRY;
        if allows_another_user_change(entry, own)? {
            return Ok(true);
        }
    }
}

/// Whether `entry`, live inside a held ACL, is an allow entry giving
/// [`CHANGING_RIGHTS`] to anyone but `own`.
fn allows_another_user_change(entry: *mut AclEntry, own: &OwnPrincipals) -> Result<bool> {
    let mut tag: c_int = 0;
    // SAFETY: `entry` lives inside a held ACL; `tag` is a live c_int, the size
    // of the `acl_tag_t` enum the call writes.
    if unsafe { acl_get_tag_type(entry, &raw mut tag) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if tag != ACL_EXTENDED_ALLOW {
        return Ok(false);
    }
    let mut rights: u64 = 0;
    // SAFETY: `entry` lives inside a held ACL; `rights` is a live u64, the
    // `acl_permset_mask_t` the call writes.
    if unsafe { acl_get_permset_mask_np(entry, &raw mut rights) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if rights & CHANGING_RIGHTS == 0 {
        return Ok(false);
    }
    // SAFETY: `entry` lives inside a held ACL; the call returns a fresh
    // caller-owned copy of the entry's 16-byte `guid_t`, or NULL.
    let qualifier = unsafe { acl_get_qualifier(entry) };
    if qualifier.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut principal = [0_u8; 16];
    // SAFETY: `qualifier` points at the 16 bytes of a `guid_t` that live until
    // the acl_free below, and `principal` is a separate live 16-byte buffer.
    unsafe { std::ptr::copy_nonoverlapping(qualifier.cast::<u8>(), principal.as_mut_ptr(), 16) };
    // SAFETY: `qualifier` is the copy acl_get_qualifier made for this call; it
    // is freed here once and not read again.
    unsafe { acl_free(qualifier) };
    Ok(principal != own.user && principal != own.root)
}
