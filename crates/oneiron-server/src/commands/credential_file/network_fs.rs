//! Who a credential file on a network file system lets in beyond its mode
//! (FIX CREDENTIAL-FILE-NETWORK-FS-ACL-UNCHECKED; Engine ANSWER
//! CREDENTIAL-FILE-NETWORK-FS-RULE = B, 21 Nov 10:16).
//!
//! A local file system's POSIX list is masked by the group bits, so there
//! the mode says who can read a file. A network file system's server decides
//! by its own list, whatever mode the mount reports:
//! - An NFSv4 mount reports that list in `system.nfs4_acl` (RFC 7530 section
//!   6.2.1, in XDR), and the list is judged: a file is admitted when no ALLOW
//!   entry that applies to it grants a principal outside the admitted ones
//!   read or write of its data, or a change of its list or owner, which
//!   grants the rest. A DENY entry is not counted in the file's favour, so
//!   the verdict never rests on the order of the entries.
//! - An SMB (CIFS) mount reports a mode built from its mount options, while
//!   the server's Windows security descriptor decides who reads the file.
//!   That descriptor is not read here, so a file there is refused unless the
//!   host owner trusts the server's own list
//!   ([`TRUST_NETWORK_FS_ACL_VARIABLE`]).
//! - An NFSv4 mount that reports no list (its server does not hand the list
//!   to this host) may still decide by a list of its own, so a file there is
//!   refused on the same terms (REVIEW-10143).
//!
//! On any other file system the mode decides alone, unless it reports an
//! NFSv4 list, which is then judged. That includes an NFSv2 or NFSv3 mount:
//! it carries no NFSv4 list, and its server enforces the mode bits for
//! AUTH_SYS clients, so it is judged as a local file system is (Engine ANSWER
//! 21 Nov 11:29; FIX CREDENTIAL-FILE-NFSV3-REFUSED-NOT-MODE-JUDGED).
//!
//! The kind of mount is read from the kernel's own mount table, and reading
//! it sends no request to a server. `fstatfs` would send an NFS server an
//! FSSTAT call, which a hard mount retries without end while the server does
//! not answer, so the credential would wait forever (REVIEW-10143 round 2).

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// The environment variable by which the host owner trusts a network file
/// system server's own access list, where this host does not read it, for
/// the credential files on its mounts, so that every user that list admits
/// can read them: an SMB mount, and an NFSv4 mount that reports no list.
/// `1`, `true`, `yes` or `on` (any case) trusts it; any other value, or
/// none, refuses such a file. A list this host reads is judged either way.
pub(crate) const TRUST_NETWORK_FS_ACL_VARIABLE: &str =
    "ONEIRON_CREDENTIAL_FILES_TRUST_NETWORK_FS_ACL";

/// The extended attribute a Linux NFSv4 mount reports a file's list in.
const NFS4_ACL_ATTRIBUTE: &str = "system.nfs4_acl";

/// The mount table of this process's mount namespace
/// (`proc_pid_mountinfo(5)`).
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

/// The types `mountinfo` gives an SMB mount: `cifs` (CIFS, SMB2 and SMB3),
/// `smb3` (the same client mounted by that name) and `smbfs` (the SMB1
/// client that Linux 2.6.37 removed).
const SMB_FILE_SYSTEM_TYPES: [&str; 3] = ["cifs", "smb3", "smbfs"];

/// The type `mountinfo` gives an NFSv4 mount (NFSv4.0, 4.1 or 4.2). Linux
/// gives every NFSv4 mount this type, also one mounted as `-t nfs`
/// (fs/nfs/fs_context.c, `nfs_fs_context_validate`, takes the version's own
/// type), so the type `nfs` names an NFSv2 or NFSv3 mount.
const NFS4_FILE_SYSTEM_TYPE: &str = "nfs4";

/// Why a file on an SMB mount is refused, to follow its path.
const SMB_UNREAD_LIST_REASON: &str = "is on an SMB (CIFS) mount, where the server's own access \
     list, which this host does not read, decides who can read it whatever its mode shows";

/// Why a file on an NFSv4 mount that reports no list is refused, to follow
/// its path.
const NFS4_UNREAD_LIST_REASON: &str = "is on an NFSv4 mount that reports no access control \
     list (its server does not hand the list to this host), where the server may decide who \
     can read it by a list this host does not read, whatever its mode shows";

/// `acetype4` of an entry that grants access (RFC 7530 section 6.2.1.1).
const ACE4_ACCESS_ALLOWED_ACE_TYPE: u32 = 0;

/// `aceflag4` of an entry that only a directory's new children take, which
/// does not apply to the file that carries it (RFC 7530 section 6.2.1.4).
const ACE4_INHERIT_ONLY_ACE: u32 = 0x0000_0008;

/// The `acemask4` bits an entry may not grant outside the admitted
/// principals, by their RFC 7530 names (section 6.2.1.3.1): reading or
/// changing the data, and changing the list or the owner.
const REFUSED_GRANTS: [(u32, &str); 5] = [
    (0x0000_0001, "READ_DATA"),
    (0x0000_0002, "WRITE_DATA"),
    (0x0000_0004, "APPEND_DATA"),
    (0x0004_0000, "WRITE_ACL"),
    (0x0008_0000, "WRITE_OWNER"),
];

/// The longest principal name a refusal repeats, in characters.
const PRINCIPAL_TEXT_LIMIT: usize = 64;

/// The kind of file system a mount's type in `mountinfo` names, as the judge
/// tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountKind {
    /// CIFS, SMB2 or SMB3: the server's list is never read here.
    Smb,
    /// NFSv4: the server's list is read when the mount reports one.
    Nfs4,
    /// Any other file system, local or network, NFSv2 and NFSv3 among them.
    Other,
}

impl MountKind {
    /// The kind the `mountinfo` file system type `file_system_type` names.
    pub(crate) fn of_file_system_type(file_system_type: &str) -> Self {
        if SMB_FILE_SYSTEM_TYPES.contains(&file_system_type) {
            Self::Smb
        } else if file_system_type == NFS4_FILE_SYSTEM_TYPE {
            Self::Nfs4
        } else {
            Self::Other
        }
    }
}

/// The principals an NFSv4 list may grant a file to.
#[derive(Clone, Copy)]
pub(crate) enum Principals {
    /// Its owner alone (`OWNER@`): a credential file.
    Owner,
    /// Its owner and its group (`OWNER@`, `GROUP@`): a credential its host
    /// shares with one group.
    OwnerAndGroup,
}

impl Principals {
    /// Whether an entry for the principal `who` may grant the file.
    fn admits(self, who: &[u8]) -> bool {
        who == b"OWNER@" || (matches!(self, Self::OwnerAndGroup) && who == b"GROUP@")
    }

    /// Whom a refused entry lets in, as a refusal says it.
    fn outside(self) -> &'static str {
        match self {
            Self::Owner => "a user other than its owner",
            Self::OwnerAndGroup => "a user outside its owner and group",
        }
    }
}

/// Why a file on a network file system is refused: what lets others in,
/// which follows the file's path in a refusal, and what mends it.
#[derive(Debug)]
pub(crate) struct NetworkFsRefusal {
    reason: String,
    mend: String,
}

impl NetworkFsRefusal {
    /// What lets others in, to follow the file's path.
    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }

    /// What the owner does about it.
    pub(crate) fn mend(&self) -> &str {
        &self.mend
    }
}

impl std::fmt::Display for NetworkFsRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; {}", self.reason, self.mend)
    }
}

/// Judges the open `file` by the list of the network file system it is on:
/// a refusal when that list may let in a principal outside `principals`,
/// `None` when the mode alone decides. An error when the file system or the
/// list cannot be read, which refuses the file too.
pub(crate) fn judge(file: &File, principals: Principals) -> io::Result<Option<NetworkFsRefusal>> {
    let mount = MountKind::of_file_system_type(&file_system_type(file)?);
    let list = match mount {
        MountKind::Smb => None,
        MountKind::Nfs4 | MountKind::Other => nfs4_list(file)?,
    };
    judge_mount(mount, list.as_deref(), principals, server_list_trusted())
}

/// Judges a file on a mount of kind `mount` whose NFSv4 list read as `list`
/// (`None` when the mount reports none), for `principals`. A list that is
/// read is judged ([`judge_nfs4_list`]). A server's list that is not read
/// here refuses the file unless the host owner trusts it
/// (`server_list_trusted`): always on an SMB mount, and on an NFSv4 mount
/// that reports no list. On any other file system with no list, NFSv2 and
/// NFSv3 among them, the mode decides.
pub(crate) fn judge_mount(
    mount: MountKind,
    list: Option<&[u8]>,
    principals: Principals,
    server_list_trusted: bool,
) -> io::Result<Option<NetworkFsRefusal>> {
    let reason = match (mount, list) {
        (MountKind::Nfs4 | MountKind::Other, Some(list)) => {
            return judge_nfs4_list(list, principals);
        }
        (MountKind::Other, None) => return Ok(None),
        _ if server_list_trusted => return Ok(None),
        (MountKind::Smb, _) => SMB_UNREAD_LIST_REASON,
        (MountKind::Nfs4, None) => NFS4_UNREAD_LIST_REASON,
    };
    Ok(Some(NetworkFsRefusal {
        reason: reason.to_owned(),
        mend: format!(
            "place it on a local file system, or set {TRUST_NETWORK_FS_ACL_VARIABLE}=1 to trust \
             that server's list: every user the list admits can then read this credential"
        ),
    }))
}

/// The type of the mount the open `file` is on, from the kernel's mount
/// table: its descriptor's mount ID in `/proc/self/fdinfo`, looked up in
/// [`MOUNTINFO_PATH`]. Neither read reaches a network file system's server.
/// An error when a table cannot be read or does not list the mount.
pub(crate) fn file_system_type(file: &File) -> io::Result<String> {
    let fdinfo_path = format!("/proc/self/fdinfo/{}", file.as_raw_fd());
    let fdinfo = read_table(&fdinfo_path)?;
    let mountinfo = read_table(MOUNTINFO_PATH)?;
    file_system_type_in(&fdinfo, &mountinfo)
        .map(str::to_owned)
        .ok_or_else(|| {
            io::Error::other(format!(
                "{fdinfo_path} names no mount that {MOUNTINFO_PATH} lists"
            ))
        })
}

/// The text of the kernel table at `path`, or an error that names it.
fn read_table(path: &str) -> io::Result<String> {
    std::fs::read_to_string(path)
        .map_err(|error| io::Error::new(error.kind(), format!("read {path}: {error}")))
}

/// The type of the mount whose ID the `fdinfo` text gives on its `mnt_id:`
/// line, as the `mountinfo` text lists it: the first field after the ` - `
/// that ends a line's optional fields (`proc_pid_mountinfo(5)`; a space in a
/// path is written `\040`, so ` - ` occurs in a line only as that
/// separator). `None` when `fdinfo` gives no mount ID or `mountinfo` lists
/// no mount by it.
pub(crate) fn file_system_type_in<'a>(fdinfo: &str, mountinfo: &'a str) -> Option<&'a str> {
    let mount_id: u64 = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))?
        .trim()
        .parse()
        .ok()?;
    mountinfo.lines().find_map(|line| {
        let (location, file_system) = line.split_once(" - ")?;
        let listed: u64 = location.split(' ').next()?.parse().ok()?;
        if listed != mount_id {
            return None;
        }
        file_system.split(' ').next()
    })
}

/// Whether the host owner trusts a server's list that is not read here
/// ([`TRUST_NETWORK_FS_ACL_VARIABLE`]).
fn server_list_trusted() -> bool {
    std::env::var(TRUST_NETWORK_FS_ACL_VARIABLE).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// The open `file`'s NFSv4 list, as the mount reports it; `None` when it
/// reports none, as a file system that is not NFSv4 does, and as an NFSv4
/// mount does whose server hands it no list. A list that changes size
/// between the reads of its size and its bytes is read again.
fn nfs4_list(file: &File) -> io::Result<Option<Vec<u8>>> {
    use rustix::io::Errno;
    for _ in 0..3 {
        let size = match rustix::fs::fgetxattr(file, NFS4_ACL_ATTRIBUTE, &mut [0u8; 0]) {
            Ok(size) => size,
            Err(error) if error == Errno::NODATA || error == Errno::NOTSUP => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut list = vec![0u8; size];
        match rustix::fs::fgetxattr(file, NFS4_ACL_ATTRIBUTE, &mut list[..]) {
            Ok(read) => {
                list.truncate(read);
                return Ok(Some(list));
            }
            Err(error) if error == Errno::RANGE => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::other(
        "its NFSv4 access control list changed size on each of three reads",
    ))
}

/// Judges the NFSv4 list `list`, in XDR as `system.nfs4_acl` holds it: a
/// `u32` count, then per entry its `u32` type, flags and access mask, and its
/// principal as a `u32` length and that many bytes padded to four. The first
/// ALLOW entry that applies to the file and grants a principal outside
/// `principals` a [`REFUSED_GRANTS`] bit refuses it, naming the entry. A list
/// that does not read to its end in that form is an error.
pub(crate) fn judge_nfs4_list(
    list: &[u8],
    principals: Principals,
) -> io::Result<Option<NetworkFsRefusal>> {
    let mut reader = XdrReader(list);
    let count = reader.word()?;
    for position in 1..=count {
        let kind = reader.word()?;
        let flags = reader.word()?;
        let mask = reader.word()?;
        let who = reader.opaque()?;
        if kind != ACE4_ACCESS_ALLOWED_ACE_TYPE
            || flags & ACE4_INHERIT_ONLY_ACE != 0
            || principals.admits(who)
        {
            continue;
        }
        let grants: Vec<&str> = REFUSED_GRANTS
            .iter()
            .filter(|(bit, _)| mask & bit != 0)
            .map(|&(_, name)| name)
            .collect();
        if !grants.is_empty() {
            return Ok(Some(NetworkFsRefusal {
                reason: format!(
                    "is on an NFSv4 mount whose access control list lets in {} where its mode \
                     does not show: entry {position} of {count} grants `{}` {}",
                    principals.outside(),
                    principal_text(who),
                    grants.join(", ")
                ),
                mend: "remove that entry (`nfs4_getfacl` lists the entries, `nfs4_setfacl -x` \
                       removes one), or place the file on a local file system"
                    .to_owned(),
            }));
        }
    }
    if reader.0.is_empty() {
        Ok(None)
    } else {
        Err(malformed("bytes follow its last entry"))
    }
}

/// The principal `who` as a refusal repeats it: escaped, and cut at
/// [`PRINCIPAL_TEXT_LIMIT`] characters, since the server chose it.
fn principal_text(who: &[u8]) -> String {
    let name = String::from_utf8_lossy(who);
    let mut text: String = name
        .chars()
        .take(PRINCIPAL_TEXT_LIMIT)
        .flat_map(char::escape_debug)
        .collect();
    if name.chars().nth(PRINCIPAL_TEXT_LIMIT).is_some() {
        text.push('…');
    }
    text
}

/// The error of a list that does not read as an NFSv4 list.
fn malformed(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("its NFSv4 access control list is malformed: {what}"),
    )
}

/// A reader of XDR's big-endian four-byte words and padded opaque fields.
struct XdrReader<'a>(&'a [u8]);

impl<'a> XdrReader<'a> {
    /// The next word.
    fn word(&mut self) -> io::Result<u32> {
        let bytes: &'a [u8] = self.0;
        let (word, rest) = bytes
            .split_first_chunk::<4>()
            .ok_or_else(|| malformed("it ends inside an entry"))?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*word))
    }

    /// The next opaque field: its length, then its bytes padded to four.
    fn opaque(&mut self) -> io::Result<&'a [u8]> {
        let length = usize::try_from(self.word()?)
            .map_err(|_| malformed("a principal is longer than the list"))?;
        let bytes: &'a [u8] = self.0;
        let padded = length
            .checked_next_multiple_of(4)
            .filter(|&padded| padded <= bytes.len())
            .ok_or_else(|| malformed("a principal runs past its end"))?;
        let (field, rest) = bytes.split_at(padded);
        self.0 = rest;
        Ok(field.split_at(length).0)
    }
}
