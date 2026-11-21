//! Door for `tests/credential_file_network_fs.rs`: the judge that admits a
//! credential file on a Linux network file system (FIX
//! CREDENTIAL-FILE-NETWORK-FS-ACL-UNCHECKED). The fleet has no NFSv4 or SMB
//! mount, so the test hands the NFSv4 judge list bytes and the SMB check
//! `statfs` magic numbers, and judges one local file as the control.

use std::fs::File;

use crate::commands::credential_file::network_fs::{self, Principals};

/// The environment variable by which the host owner trusts an SMB server's
/// list.
pub const TRUST_SMB_ACL_VARIABLE: &str = network_fs::TRUST_SMB_ACL_VARIABLE;

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

/// Whether the `statfs` magic number `kind` names an SMB mount.
#[must_use]
pub fn is_smb_magic(kind: u64) -> bool {
    network_fs::is_smb_magic(kind)
}

/// The refusal of a credential file on an SMB mount whose list is not
/// trusted.
#[must_use]
pub fn smb_refusal_text() -> String {
    network_fs::smb_refusal().to_string()
}

/// The judge's answer as text.
fn text_of(
    judged: std::io::Result<Option<network_fs::NetworkFsRefusal>>,
) -> Result<Option<String>, String> {
    judged
        .map(|refusal| refusal.map(|refusal| refusal.to_string()))
        .map_err(|error| error.to_string())
}
