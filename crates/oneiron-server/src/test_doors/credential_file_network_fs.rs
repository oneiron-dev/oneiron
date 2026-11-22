//! Door for `tests/credential_file_network_fs.rs`: the judge that admits a
//! credential file on a Linux network file system (FIX
//! CREDENTIAL-FILE-NETWORK-FS-ACL-UNCHECKED). The fleet has no NFS or SMB
//! mount, so the test hands the judge mount types and the list bytes a mount
//! would report, and the mount table reader table text in the kernel's
//! format, and reads the mount of real local files as the control.

use std::fs::File;

use crate::commands::credential_file::network_fs::{self, MountKind, Principals};

/// The environment variable by which the host owner trusts a network file
/// system server's list that is not read here.
pub const TRUST_NETWORK_FS_ACL_VARIABLE: &str = network_fs::TRUST_NETWORK_FS_ACL_VARIABLE;

/// The NFSv4 list `list` (XDR, as `system.nfs4_acl` holds it) judged for a
/// credential file its owner alone may reach: `Ok(None)` admits it,
/// `Ok(Some(text))` refuses it with that text.
///
/// # Errors
///
/// The reason a list that does not read as an NFSv4 list is refused.
pub fn judge_nfs4_list_for_owner(list: &[u8]) -> Result<Option<String>, String> {
    text_of(network_fs::judge_nfs4_list(list, Principals::Owner))
}

/// The NFSv4 list `list` judged for a credential its host shares with the
/// file's group, as [`judge_nfs4_list_for_owner`] answers.
///
/// # Errors
///
/// The reason a list that does not read as an NFSv4 list is refused.
pub fn judge_nfs4_list_for_owner_and_group(list: &[u8]) -> Result<Option<String>, String> {
    text_of(network_fs::judge_nfs4_list(list, Principals::OwnerAndGroup))
}

/// The open `file` judged for a credential file its owner alone may reach,
/// as [`judge_nfs4_list_for_owner`] answers.
///
/// # Errors
///
/// The reason the file system or the list could not be read.
pub fn judge_file_for_owner(file: &File) -> Result<Option<String>, String> {
    text_of(network_fs::judge(file, Principals::Owner))
}

/// A credential file its owner alone may reach, on a mount of the
/// `mountinfo` type `file_system_type`, whose NFSv4 list read as `list`
/// (`None` when the mount reports none), judged with the host owner's trust
/// in a server's list that is not read here given as `server_list_trusted`;
/// answered as [`judge_nfs4_list_for_owner`] answers.
///
/// # Errors
///
/// The reason a list that does not read as an NFSv4 list is refused.
pub fn judge_mount_for_owner(
    file_system_type: &str,
    list: Option<&[u8]>,
    server_list_trusted: bool,
) -> Result<Option<String>, String> {
    text_of(network_fs::judge_mount(
        MountKind::of_file_system_type(file_system_type),
        list,
        Principals::Owner,
        server_list_trusted,
    ))
}

/// The type of the mount the open `file` is on, as the judge reads it from
/// the kernel's mount table.
///
/// # Errors
///
/// The reason the table could not be read or does not list the mount.
pub fn file_system_type_of_file(file: &File) -> Result<String, String> {
    network_fs::file_system_type(file).map_err(|error| error.to_string())
}

/// The type of the mount whose ID the `/proc/<pid>/fdinfo/<fd>` text
/// `fdinfo` gives, as the `/proc/<pid>/mountinfo` text `mountinfo` lists it;
/// `None` when `fdinfo` gives no mount ID or `mountinfo` lists no mount by it.
#[must_use]
pub fn file_system_type_in<'a>(fdinfo: &str, mountinfo: &'a str) -> Option<&'a str> {
    network_fs::file_system_type_in(fdinfo, mountinfo)
}

/// The judge's answer as text.
fn text_of(
    judged: std::io::Result<Option<network_fs::NetworkFsRefusal>>,
) -> Result<Option<String>, String> {
    judged
        .map(|refusal| refusal.map(|refusal| refusal.to_string()))
        .map_err(|error| error.to_string())
}
