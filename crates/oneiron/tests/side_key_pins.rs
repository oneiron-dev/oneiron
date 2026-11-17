//! UC-06 PR 2 K-proof: the nine roster and origin side-table keys that PR 2 derives spell the
//! same bytes and read the same inputs as their hand-written impls (M-1 STORED-CHANGE-RULE = A: a
//! key a vault already holds keeps its meaning).
//!
//! The test builds one table: for every fixture key, the bytes it spells, and the verdict
//! (refused, or the bytes of the key read back) on those bytes and on malformed copies of them
//! (one byte short, the first byte dropped, a trailing digit, NUL or `:`, a leading `:`, upper
//! case, a `+` in the first, last and hex-tail places, the separator swapped, a byte that is not
//! UTF-8), plus some raw inputs per key (a reserved id, a missing or doubled separator, an empty
//! key). The table's sha256 is the one a model of the hand-written decoders gives
//! (`lanes/kimi/OPUS-UC06-SIDEKEYS/check/pins/pin_table_model_pr2.py`), and each run prints the
//! table so a base run and a head run can be compared line by line.
//!
//! `ProjectRevisionHash` is public; the other eight keys are crate-private and are reached
//! through `test_doors::side_key_pins`. Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test side_key_pins -- --nocapture`.
#![cfg(oneiron_test_support)]

use std::fmt::Write as _;

use oneiron::EntityId;
use oneiron::test_doors::side_key_pins::{
    Pin, fact_key, lfs_ref_key, member_intent_key, provenance_ref_key, receive_pack_intent_key,
    receive_pack_progress_key, repo_revision_key, roster_member_key,
};
use oneiron_verb_wire::workspace_roster::ProjectRevisionHash;
use sha2::{Digest, Sha256};

const TABLE_SHA256: &str = "0a89c3d563672feba0da1737e18176ecda7557e1a1d154cf3a81860cf206d821";

const ID_A: &str = "0123456789abcdef0123456789abcdef";
const ID_B: &str = "fedcba9876543210fedcba9876543210";
/// An id whose raw bytes hold NUL bytes.
const ID_NUL: &str = "01000200030004000500060007000800";
/// An id whose raw bytes are all `:`.
const ID_COLON: &str = "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a";

fn id(hex: &str) -> EntityId {
    EntityId::from_hex(hex).expect("fixture id is not a reserved id")
}

fn id_a() -> EntityId {
    id(ID_A)
}

fn id_b() -> EntityId {
    id(ID_B)
}

fn hex(bytes: &[u8]) -> String {
    oneiron_hex::encode(bytes)
}

fn joined(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn replaced(bytes: &[u8], at: usize, byte: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] = byte;
    out
}

/// The inputs a fixture's bytes are read as: the bytes themselves, then malformed copies.
fn mutations(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let len = bytes.len();
    let mut out = vec![("exact", bytes.to_vec())];
    if len > 0 {
        out.push(("short", bytes[..len - 1].to_vec()));
        out.push(("drop_first", bytes[1..].to_vec()));
    }
    out.push(("trailing_digit", joined(&[bytes, b"0"])));
    out.push(("trailing_nul", joined(&[bytes, b"\0"])));
    out.push(("trailing_colon", joined(&[bytes, b":"])));
    out.push(("leading_colon", joined(&[b":", bytes])));
    out.push(("upper", bytes.to_ascii_uppercase()));
    if len > 0 {
        out.push((
            "upper_last",
            replaced(bytes, len - 1, bytes[len - 1].to_ascii_uppercase()),
        ));
        out.push(("plus_first", replaced(bytes, 0, b'+')));
        out.push(("plus_last", replaced(bytes, len - 1, b'+')));
    }
    for (label, from_end) in [("plus_tail16", 16), ("plus_tail32", 32)] {
        if len >= from_end {
            out.push((label, replaced(bytes, len - from_end, b'+')));
        }
    }
    let swap = |from: u8, to: u8| -> Vec<u8> {
        bytes
            .iter()
            .map(|&byte| if byte == from { to } else { byte })
            .collect()
    };
    out.push(("colon_to_semicolon", swap(b':', b';')));
    out.push(("nul_to_soh", swap(0, 1)));
    out.push(("bad_utf8", joined(&[bytes, &[0xff]])));
    out
}

fn verdict(read: fn(&[u8]) -> Option<Vec<u8>>, input: &[u8]) -> String {
    read(input).map_or_else(|| "none".to_owned(), |key| format!("some {}", hex(&key)))
}

fn pin(table: &mut String, name: &str, fixtures: Vec<(&str, Pin)>, raw: &[(&str, Vec<u8>)]) {
    let read = fixtures.first().expect("each key has a fixture").1.read;
    for (label, fixture) in &fixtures {
        for (mutation, input) in mutations(&fixture.spelled) {
            writeln!(
                table,
                "{name} {label} {mutation} {} -> {}",
                hex(&input),
                verdict(fixture.read, &input)
            )
            .expect("a String takes every write");
        }
    }
    for (label, input) in raw {
        writeln!(
            table,
            "{name} raw {label} {} -> {}",
            hex(input),
            verdict(read, input)
        )
        .expect("a String takes every write");
    }
}

#[test]
fn roster_and_origin_keys_spell_and_read_as_the_hand_impls() {
    let mut hash = [0_u8; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::try_from(index % 16).expect("below 16") * 0x11;
    }
    let mut digest_16 = [0_u8; 16];
    digest_16.copy_from_slice(&hash[..16]);
    let one_32 = [1_u8; 32];
    let repo_hex = "ab".repeat(32);
    let a = *id_a().as_bytes();
    let b = *id_b().as_bytes();
    let empty: (&str, Vec<u8>) = ("empty", Vec::new());
    let mut table = String::new();

    pin(
        &mut table,
        "ProjectRevisionHash",
        [
            ("zero", [0_u8; 32]),
            ("max", [0xff; 32]),
            ("hash", hash),
            ("colons", [b':'; 32]),
        ]
        .into_iter()
        .map(|(label, bytes)| (label, Pin::of(&ProjectRevisionHash(bytes))))
        .collect(),
        std::slice::from_ref(&empty),
    );
    pin(
        &mut table,
        "MemberIntentKey",
        vec![
            ("empty_ref", member_intent_key("", id_a())),
            ("workspace", member_intent_key("ws-1", id_a())),
            ("ref_with_nul", member_intent_key("a\0b", id_b())),
            ("person_with_nul", member_intent_key("ws", id(ID_NUL))),
            ("multibyte", member_intent_key("\u{fc}", id_a())),
        ],
        &[
            ("id_only", a.to_vec()),
            ("nil_person", joined(&[b"ws\0", &[0; 16]])),
            ("max_person", joined(&[b"ws\0", &[0xff; 16]])),
            ("two_nuls", joined(&[b"ws\0\0", &a])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "RosterMemberKey",
        vec![
            ("empty_ref", roster_member_key("", id_a())),
            ("workspace", roster_member_key("ws-1", id_a())),
            ("ref_with_nul", roster_member_key("a\0b", id_b())),
            ("multibyte", roster_member_key("\u{fc}", id_a())),
        ],
        &[
            ("nil_person", joined(&[b"ws\0", "00".repeat(16).as_bytes()])),
            ("two_nuls", joined(&[b"ws\0\0", ID_A.as_bytes()])),
            ("no_sep", joined(&[b"ws", ID_A.as_bytes()])),
            empty.clone(),
        ],
    );
    let cause = [7_u8; 16];
    pin(
        &mut table,
        "FactKey",
        vec![
            ("person", fact_key(id_a(), [0; 16], (1, b), (3, cause))),
            ("agent_thread", fact_key(id_b(), a, (2, a), (0, [0; 16]))),
            (
                "erased",
                fact_key(id_a(), [0xff; 16], (0, digest_16), (0xff, [0xff; 16])),
            ),
        ],
        &[
            (
                "nil_room",
                joined(&[&[0; 16], &[0; 16], &[1], &b, &[3], &cause]),
            ),
            (
                "unknown_kind",
                joined(&[&a, &[0; 16], &[3], &b, &[3], &cause]),
            ),
            (
                "nil_person",
                joined(&[&a, &[0; 16], &[1], &[0; 16], &[3], &cause]),
            ),
            (
                "erased_nil",
                joined(&[&a, &[0; 16], &[0], &[0; 16], &[3], &cause]),
            ),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "ProvenanceRefKey",
        vec![
            ("hash", provenance_ref_key(id_a(), hash)),
            ("zero_hash", provenance_ref_key(id_b(), [0; 32])),
            ("colon_hash", provenance_ref_key(id_a(), [b':'; 32])),
        ],
        &[
            ("nil_provenance", joined(&[&[0; 16], b":", &one_32])),
            ("semicolon", joined(&[&a, b";", &one_32])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "RepoRevisionKey",
        vec![
            ("empty_repo", repo_revision_key("", id_a())),
            ("repo", repo_revision_key(&repo_hex, id_b())),
            ("repo_with_colon", repo_revision_key("r:1", id_a())),
            ("revision_with_colon", repo_revision_key("r", id(ID_COLON))),
            ("multibyte", repo_revision_key("\u{fc}", id_a())),
        ],
        &[
            ("id_only", a.to_vec()),
            ("sep_id", joined(&[b":", &a])),
            ("nil_revision", joined(&[b"r:", &[0; 16]])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "LfsRefKey",
        vec![
            ("main", lfs_ref_key(id_a(), "refs/heads/main", hash)),
            ("empty_ref", lfs_ref_key(id_b(), "", [0; 32])),
            ("ref_with_nul", lfs_ref_key(id_a(), "a\0b", [0xff; 32])),
            ("multibyte", lfs_ref_key(id_a(), "\u{fc}", one_32)),
        ],
        &[
            ("one_sep", joined(&[&a, b"\0", &one_32])),
            ("nil_repo", joined(&[&[0; 16], b"\0x\0", &one_32])),
            ("bad_utf8_ref", joined(&[&a, b"\0\xff\0", &one_32])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "ReceivePackIntentKey",
        vec![
            ("empty_repo", receive_pack_intent_key("", id_a())),
            ("repo", receive_pack_intent_key(&repo_hex, id_b())),
            ("multibyte", receive_pack_intent_key("\u{fc}", id_a())),
        ],
        &[
            ("id_only", a.to_vec()),
            ("nil_operation", joined(&[b"x", &[0; 16]])),
            ("fifteen", a[..15].to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "ReceivePackProgressKey",
        vec![
            ("zero", receive_pack_progress_key(&repo_hex, id_a(), 0)),
            ("max", receive_pack_progress_key("", id_b(), u64::MAX)),
            ("one", receive_pack_progress_key("\u{fc}", id_a(), 1)),
        ],
        &[
            ("batch_only", vec![0; 8]),
            ("id_and_batch", joined(&[&a, &[0, 0, 0, 0, 0, 0, 0, 5]])),
            empty,
        ],
    );

    let digest = hex(&Sha256::digest(table.as_bytes()));
    for line in table.lines() {
        println!("PIN {line}");
    }
    println!(
        "PIN-TABLE roster-origin lines={} sha256={digest}",
        table.lines().count()
    );
    assert_eq!(
        digest, TABLE_SHA256,
        "the roster and origin key table differs from the hand-written decoders' table"
    );
}
