//! A credential file on a Linux network file system is judged by the
//! server's own list (FIX CREDENTIAL-FILE-NETWORK-FS-ACL-UNCHECKED; Engine
//! ANSWER CREDENTIAL-FILE-NETWORK-FS-RULE = B, 21 Nov 10:16). An NFSv4 list
//! is admitted when no ALLOW entry that applies to the file grants anyone
//! but its owner (and, for a group-shared relay token, its group) read or
//! write of its data or a change of its list or owner; the refusal names the
//! entry. A file on an SMB mount is refused by its `statfs` magic unless the
//! host owner trusts the server's list.
//!
//! The fleet has no NFSv4 or SMB mount, so the lists are handed to the judge
//! as the bytes a mount reports in `system.nfs4_acl` (RFC 7530 section
//! 6.2.1, in XDR), and the SMB check gets the magic numbers.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test credential_file_network_fs`.
#![cfg(all(oneiron_test_support, target_os = "linux"))]

use oneiron_server::test_doors::credential_file_network_fs as door;

/// `acetype4` values (RFC 7530 section 6.2.1.1).
const ALLOW: u32 = 0;
const DENY: u32 = 1;
const AUDIT: u32 = 2;

/// `aceflag4` bits (RFC 7530 section 6.2.1.4).
const FILE_INHERIT: u32 = 0x0000_0001;
const INHERIT_ONLY: u32 = 0x0000_0008;
const IDENTIFIER_GROUP: u32 = 0x0000_0040;

/// `acemask4` bits (RFC 7530 section 6.2.1.3.1).
const READ_DATA: u32 = 0x0000_0001;
const WRITE_DATA: u32 = 0x0000_0002;
const APPEND_DATA: u32 = 0x0000_0004;
const READ_NAMED_ATTRS: u32 = 0x0000_0008;
const EXECUTE: u32 = 0x0000_0020;
const READ_ATTRIBUTES: u32 = 0x0000_0080;
const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const READ_ACL: u32 = 0x0002_0000;
const WRITE_ACL: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// What a server that mirrors the mode grants every principal
/// (knfsd's `NFS4_ANYONE_MODE`, fs/nfsd/nfs4acl.c).
const ANYONE: u32 = READ_ATTRIBUTES | READ_ACL | SYNCHRONIZE;

/// What it grants the owner of a file it may read and write
/// (`NFS4_OWNER_MODE` plus the read and write bits).
const OWNER_READ_WRITE: u32 =
    ANYONE | WRITE_ATTRIBUTES | WRITE_ACL | READ_DATA | WRITE_DATA | APPEND_DATA;

/// The list knfsd reports for a file of mode 0600 that has no POSIX ACL,
/// byte for byte: OWNER@ may read and write, GROUP@ (flagged as a group)
/// and EVERYONE@ get [`ANYONE`] alone.
#[rustfmt::skip]
const KNFSD_LIST_MODE_0600: [u8; 80] = [
    0, 0, 0, 3, // three entries
    0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x16, 0x01, 0x87, // ALLOW, no flag, OWNER_READ_WRITE
    0, 0, 0, 6, b'O', b'W', b'N', b'E', b'R', b'@', 0, 0, // "OWNER@", padded to 8
    0, 0, 0, 0, 0, 0, 0, 0x40, 0x00, 0x12, 0x00, 0x80, // ALLOW, IDENTIFIER_GROUP, ANYONE
    0, 0, 0, 6, b'G', b'R', b'O', b'U', b'P', b'@', 0, 0, // "GROUP@", padded to 8
    0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x12, 0x00, 0x80, // ALLOW, no flag, ANYONE
    0, 0, 0, 9, // a principal of nine bytes
    b'E', b'V', b'E', b'R', b'Y', b'O', b'N', b'E', b'@', 0, 0, 0, // "EVERYONE@", padded to 12
];

/// An NFSv4 list of `entries` (type, flags, access mask, principal) in XDR,
/// as `system.nfs4_acl` holds it.
fn nfs4_list(entries: &[(u32, u32, u32, &str)]) -> Vec<u8> {
    let count = u32::try_from(entries.len()).expect("a short list");
    let mut list = count.to_be_bytes().to_vec();
    for &(kind, flags, mask, who) in entries {
        let length = u32::try_from(who.len()).expect("a short principal");
        for word in [kind, flags, mask, length] {
            list.extend(word.to_be_bytes());
        }
        list.extend(who.as_bytes());
        list.resize(list.len().next_multiple_of(4), 0);
    }
    list
}

/// The refusal of `list` for an owner-alone credential file; fails when the
/// list is admitted or does not read.
fn refusal_for_owner(list: &[u8]) -> String {
    door::judge_nfs4_list_for_owner(list)
        .expect("the list reads")
        .expect("the list is refused")
}

/// A server that mirrors mode 0600 lets no one but the owner near the data,
/// so an NFS home keeps working, for an owner-alone credential and for a
/// group-shared one.
#[test]
fn the_list_a_server_mirrors_from_mode_0600_is_admitted() {
    let built = nfs4_list(&[
        (ALLOW, 0, OWNER_READ_WRITE, "OWNER@"),
        (ALLOW, IDENTIFIER_GROUP, ANYONE, "GROUP@"),
        (ALLOW, 0, ANYONE, "EVERYONE@"),
    ]);
    assert_eq!(
        built, KNFSD_LIST_MODE_0600,
        "the encoder writes knfsd's bytes"
    );
    assert_eq!(
        door::judge_nfs4_list_for_owner(&KNFSD_LIST_MODE_0600),
        Ok(None)
    );
    assert_eq!(
        door::judge_nfs4_list_for_owner_and_group(&KNFSD_LIST_MODE_0600),
        Ok(None)
    );
}

/// An ALLOW entry that grants a principal other than the owner the data, the
/// list or the owner refuses an owner-alone credential, and the refusal names
/// the entry, the principal and the bits.
#[test]
fn an_entry_that_grants_another_principal_the_file_is_refused_by_name() {
    for (who, flags, mask, grants) in [
        ("EVERYONE@", 0, ANYONE | READ_DATA, "READ_DATA"),
        ("GROUP@", IDENTIFIER_GROUP, ANYONE | READ_DATA, "READ_DATA"),
        ("alice@example.org", 0, READ_DATA, "READ_DATA"),
        (
            "staff@example.org",
            IDENTIFIER_GROUP,
            WRITE_DATA,
            "WRITE_DATA",
        ),
        ("AUTHENTICATED@", 0, APPEND_DATA, "APPEND_DATA"),
        ("EVERYONE@", 0, ANYONE | WRITE_ACL, "WRITE_ACL"),
        ("1001", 0, WRITE_OWNER, "WRITE_OWNER"),
        (
            "EVERYONE@",
            FILE_INHERIT,
            READ_DATA | WRITE_DATA,
            "READ_DATA, WRITE_DATA",
        ),
    ] {
        let list = nfs4_list(&[
            (ALLOW, 0, OWNER_READ_WRITE, "OWNER@"),
            (ALLOW, flags, mask, who),
            (ALLOW, 0, ANYONE, "EVERYONE@"),
        ]);
        let refusal = refusal_for_owner(&list);
        assert!(
            refusal.contains(&format!("entry 2 of 3 grants `{who}` {grants}")),
            "{who}: {refusal}"
        );
        assert!(
            refusal.contains("lets in a user other than its owner"),
            "{refusal}"
        );
        assert!(refusal.contains("`nfs4_setfacl -x`"), "{refusal}");
    }
}

/// A DENY or AUDIT entry, an entry only a directory's children take, and an
/// entry that grants only attributes, execution or named attributes leave
/// the data with the owner.
#[test]
fn entries_that_do_not_grant_the_file_away_are_admitted() {
    let list = nfs4_list(&[
        (ALLOW, 0, OWNER_READ_WRITE, "OWNER@"),
        (DENY, 0, READ_DATA | WRITE_DATA | WRITE_ACL, "EVERYONE@"),
        (AUDIT, 0, READ_DATA, "EVERYONE@"),
        (
            ALLOW,
            FILE_INHERIT | INHERIT_ONLY,
            READ_DATA | WRITE_DATA,
            "EVERYONE@",
        ),
        (
            ALLOW,
            0,
            ANYONE | WRITE_ATTRIBUTES | EXECUTE | READ_NAMED_ATTRS,
            "EVERYONE@",
        ),
    ]);
    assert_eq!(door::judge_nfs4_list_for_owner(&list), Ok(None));
}

/// A DENY entry before a grant is not counted in the file's favour: the
/// verdict never rests on the order of the entries.
#[test]
fn a_deny_entry_before_a_grant_does_not_admit_it() {
    let list = nfs4_list(&[
        (DENY, 0, READ_DATA, "EVERYONE@"),
        (ALLOW, 0, OWNER_READ_WRITE, "OWNER@"),
        (ALLOW, 0, READ_DATA, "EVERYONE@"),
    ]);
    let refusal = refusal_for_owner(&list);
    assert!(
        refusal.contains("entry 3 of 3 grants `EVERYONE@` READ_DATA"),
        "{refusal}"
    );
}

/// A relay token its host shares with one group may grant that group
/// (GROUP@), as its mode 0440 does, and nobody else.
#[test]
fn a_group_shared_credential_admits_its_group_alone() {
    let mirrored_0440 = nfs4_list(&[
        (
            ALLOW,
            0,
            ANYONE | WRITE_ATTRIBUTES | WRITE_ACL | READ_DATA,
            "OWNER@",
        ),
        (ALLOW, IDENTIFIER_GROUP, ANYONE | READ_DATA, "GROUP@"),
        (ALLOW, 0, ANYONE, "EVERYONE@"),
    ]);
    assert_eq!(
        door::judge_nfs4_list_for_owner_and_group(&mirrored_0440),
        Ok(None)
    );
    let refusal = refusal_for_owner(&mirrored_0440);
    assert!(
        refusal.contains("entry 2 of 3 grants `GROUP@` READ_DATA"),
        "an owner-alone credential refuses the group: {refusal}"
    );

    let shared = nfs4_list(&[
        (ALLOW, 0, ANYONE | READ_DATA, "OWNER@"),
        (ALLOW, IDENTIFIER_GROUP, ANYONE | READ_DATA, "GROUP@"),
        (ALLOW, IDENTIFIER_GROUP, READ_DATA, "staff@example.org"),
    ]);
    let refusal = door::judge_nfs4_list_for_owner_and_group(&shared)
        .expect("the list reads")
        .expect("a named group outside the file's own is refused");
    assert!(
        refusal.contains("lets in a user outside its owner and group"),
        "{refusal}"
    );
    assert!(
        refusal.contains("entry 3 of 3 grants `staff@example.org` READ_DATA"),
        "{refusal}"
    );
}

/// The server chose the principal's name, so a refusal repeats it escaped
/// and cut short.
#[test]
fn a_principal_name_is_escaped_and_cut_in_the_refusal() {
    let who = format!("evil\nname{}", "x".repeat(100));
    let list = nfs4_list(&[(ALLOW, 0, READ_DATA, who.as_str())]);
    let refusal = refusal_for_owner(&list);
    assert!(!refusal.contains('\n'), "{refusal}");
    assert!(refusal.contains("`evil\\nname"), "{refusal}");
    assert!(refusal.contains("…` READ_DATA"), "{refusal}");
    assert!(!refusal.contains(&"x".repeat(60)), "{refusal}");
}

/// A list that does not read to its end as an NFSv4 list is refused: what
/// cannot be read counts as a grant.
#[test]
fn a_list_that_does_not_read_to_its_end_is_refused() {
    let one_entry = nfs4_list(&[(ALLOW, 0, OWNER_READ_WRITE, "OWNER@")]);
    let mut two_counted = one_entry.clone();
    two_counted[3] = 2;
    let mut trailing = one_entry.clone();
    trailing.extend([0u8; 4]);
    let mut long_principal = one_entry.clone();
    long_principal[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
    let cut_principal = &one_entry[..one_entry.len() - 4];
    for (case, list) in [
        ("empty", &[0u8; 0][..]),
        ("count alone", &[0u8, 0, 0, 1][..]),
        ("cut inside an entry", &one_entry[..10]),
        ("principal cut short", cut_principal),
        ("principal longer than the list", &long_principal[..]),
        ("fewer entries than counted", &two_counted[..]),
        ("bytes after the last entry", &trailing[..]),
    ] {
        let error = door::judge_nfs4_list_for_owner(list).expect_err(case);
        assert!(error.contains("malformed"), "{case}: {error}");
    }
    assert_eq!(door::judge_nfs4_list_for_owner(&one_entry), Ok(None));
}

/// The SMB mounts (CIFS, SMB2 and SMB3) are known by their `statfs` magic,
/// also as a 32-bit host's signed field carries it; every other file system,
/// network or local, is not one.
#[test]
fn the_smb_magic_numbers_name_smb_mounts_alone() {
    for smb in [
        0xFF53_4D42,
        0xFE53_4D42,
        0xFFFF_FFFF_FF53_4D42,
        0xFFFF_FFFF_FE53_4D42,
    ] {
        assert!(door::is_smb_magic(smb), "{smb:#x}");
    }
    for other in [
        0x6969,      // NFS
        0xEF53,      // ext4
        0x0102_1994, // tmpfs
        0x9123_683E, // btrfs
        0x5846_5342, // XFS
        0x794C_7630, // overlayfs
        0x6573_5546, // FUSE
        0,
    ] {
        assert!(!door::is_smb_magic(other), "{other:#x}");
    }
}

/// The refusal of a file on an SMB mount names the one opt-out and the risk
/// it takes.
#[test]
fn the_smb_refusal_names_the_opt_out_and_its_risk() {
    let refusal = door::smb_refusal_text();
    assert!(
        refusal.contains(&format!("set {}=1", door::TRUST_SMB_ACL_VARIABLE)),
        "{refusal}"
    );
    assert!(
        refusal.contains("every user the list admits can then read this credential"),
        "{refusal}"
    );
    assert!(
        refusal.contains("place it on a local file system"),
        "{refusal}"
    );
}

/// The control: a file on the test host's own file system has no network
/// list, so its mode decides alone.
#[test]
fn a_file_on_a_local_file_system_is_left_to_its_mode() {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("agent.cred");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("create the file");
    assert_eq!(door::judge_file_for_owner(&file), Ok(None));
}
