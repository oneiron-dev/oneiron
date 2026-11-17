//! UC-06 PR 1 K-proof: the ten `oneiron-store` side-table keys that PR 1 derives spell the same
//! bytes and read the same inputs as their hand-written impls (M-1 STORED-CHANGE-RULE = A: a key
//! a vault already holds keeps its meaning).
//!
//! Each test builds one table: for every fixture key, the bytes it spells, and the verdict
//! (refused, or the bytes of the key read back) on those bytes and on malformed copies of them
//! (one byte short, the first byte dropped, a trailing digit, NUL or `:`, a leading `:`, upper
//! case, a `+` in the first, last and hex-tail places, the separator swapped, a byte that is not
//! UTF-8), plus some raw inputs per key (a reserved id, a missing separator, an empty key). The
//! table's sha256 is the one a model of the hand-written decoders gives
//! (`lanes/kimi/OPUS-UC06-SIDEKEYS/check/pins/pin_table_model.py`), and each run prints the table
//! so a base run and a head run can be compared line by line.
//!
//! The window keys are compiled with the `sync` feature, as `window_rows` is. UC-06 PR 6 merged
//! `WindowEntityKey` into `WindowEntityHexKey`; the table's `WindowEntityKey` rows keep their name
//! and now spell `WindowEntityHexKey`, so the same table pins the merged type.
//!
//! UC-06 PR 7 derives `LfsOid`'s key (its one 32-byte part); its own table pins it
//! (`pin_table_model_pr7.py`).
//!
//! Run: `cargo test --locked -p oneiron-store --all-features --features oneiron-base/sync
//! --test side_key_pins -- --nocapture`.

use std::fmt::Write as _;

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::batch::export::foreign_stage::export_foreign_receipt::Hex64;
use oneiron_store::entity_doc::side_keys::HexPair;
use oneiron_store::gate_decision::types::GateDecisionId;
use oneiron_store::origin::lfs::oid::LfsOid;
use oneiron_store::origin::publication::publication_codec::VisibleRefKey;
use oneiron_store::query_memos::VerdictMemoKey;
use oneiron_store::side_table::key::{HexId, SideKey};
use sha2::{Digest, Sha256};

const STORE_TABLE_SHA256: &str = "9477a35642d244f6a5e9550d95504bad5a6fca31a6fc2163a72ba949195d5783";
const LFS_OID_TABLE_SHA256: &str =
    "42a6fbfde898acd001ff52c69fb988df2218efa3f27de57f192fbb1ccd0f71c1";

const ID_A: &str = "0123456789abcdef0123456789abcdef";
const ID_B: &str = "fedcba9876543210fedcba9876543210";

fn id_a() -> EntityId {
    EntityId::from_hex(ID_A).expect("fixture id is not a reserved id")
}

fn id_b() -> EntityId {
    EntityId::from_hex(ID_B).expect("fixture id is not a reserved id")
}

fn hex(bytes: &[u8]) -> String {
    oneiron_hex::encode(bytes)
}

fn spelled<K: SideKey>(key: &K) -> Vec<u8> {
    let mut out = Vec::new();
    key.encode_into(&mut out);
    out
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

fn verdict<K: SideKey>(input: &[u8]) -> String {
    K::decode_key(input).map_or_else(
        || "none".to_owned(),
        |key| format!("some {}", hex(&spelled(&key))),
    )
}

fn pin<K: SideKey>(
    table: &mut String,
    name: &str,
    fixtures: Vec<(&str, K)>,
    raw: &[(&str, Vec<u8>)],
) {
    for (label, key) in fixtures {
        for (mutation, input) in mutations(&spelled(&key)) {
            writeln!(
                table,
                "{name} {label} {mutation} {} -> {}",
                hex(&input),
                verdict::<K>(&input)
            )
            .expect("a String takes every write");
        }
    }
    for (label, input) in raw {
        writeln!(
            table,
            "{name} raw {label} {} -> {}",
            hex(input),
            verdict::<K>(input)
        )
        .expect("a String takes every write");
    }
}

/// Prints the table as `PIN` lines with its sha256, and checks the sha256.
fn check_table(part: &str, table: &str, expected: &str) {
    let digest = hex(&Sha256::digest(table.as_bytes()));
    for line in table.lines() {
        println!("PIN {line}");
    }
    println!(
        "PIN-TABLE {part} lines={} sha256={digest}",
        table.lines().count()
    );
    assert_eq!(
        digest, expected,
        "the {part} key table differs from the hand-written decoders' table"
    );
}

#[test]
fn store_keys_spell_and_read_as_the_hand_impls() {
    let fixed_16 = [
        ("zero", [0_u8; 16]),
        ("max", [0xff; 16]),
        ("text", *b"0123456789abcdef"),
        ("colons", [b':'; 16]),
    ];
    let mut evidence = [0_u8; 32];
    for (index, byte) in evidence.iter_mut().enumerate() {
        *byte = u8::try_from(index % 16).expect("below 16") * 0x11;
    }
    let one_32 = [1_u8; 32];
    let empty: (&str, Vec<u8>) = ("empty", Vec::new());
    let mut table = String::new();

    pin(
        &mut table,
        "AttemptId",
        fixed_16
            .iter()
            .map(|(label, bytes)| {
                (
                    *label,
                    AttemptId::from_bytes(bytes).expect("16 bytes are an attempt id"),
                )
            })
            .collect(),
        std::slice::from_ref(&empty),
    );
    pin(
        &mut table,
        "GateDecisionId",
        fixed_16
            .iter()
            .map(|(label, bytes)| (*label, GateDecisionId::from_bytes(*bytes)))
            .collect(),
        std::slice::from_ref(&empty),
    );
    // `[type byte, 0xff x 15]` is a reserved id only when the type byte is registered with a short
    // id prefix: 1 (TURN) is, 7 is not, so the second id reads.
    let mut reserved_entity = [0xff_u8; 16];
    reserved_entity[0] = 1;
    let mut unregistered_type_entity = [0xff_u8; 16];
    unregistered_type_entity[0] = 7;
    pin(
        &mut table,
        "VerdictMemoKey",
        vec![
            (
                "ab",
                VerdictMemoKey {
                    query_ref: id_a(),
                    entity_ref: id_b(),
                    evidence_hash: evidence,
                },
            ),
            (
                "ba_zero",
                VerdictMemoKey {
                    query_ref: id_b(),
                    entity_ref: id_a(),
                    evidence_hash: [0; 32],
                },
            ),
            (
                "aa_max",
                VerdictMemoKey {
                    query_ref: id_a(),
                    entity_ref: id_a(),
                    evidence_hash: [0xff; 32],
                },
            ),
        ],
        &[
            ("nil_query", joined(&[&[0; 16], id_a().as_bytes(), &one_32])),
            (
                "max_entity",
                joined(&[id_a().as_bytes(), &[0xff; 16], &one_32]),
            ),
            (
                "reserved_entity",
                joined(&[id_a().as_bytes(), &reserved_entity, &one_32]),
            ),
            (
                "unregistered_type_entity",
                joined(&[id_a().as_bytes(), &unregistered_type_entity, &one_32]),
            ),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "Hex64",
        vec![
            ("zero", Hex64([0; 32])),
            ("max", Hex64([0xff; 32])),
            ("hash", Hex64(evidence)),
        ],
        std::slice::from_ref(&empty),
    );
    pin(
        &mut table,
        "HexPair",
        vec![
            ("ab", HexPair(HexId(id_a()), HexId(id_b()))),
            ("ba", HexPair(HexId(id_b()), HexId(id_a()))),
        ],
        &[
            (
                "nil_first",
                joined(&["00".repeat(16).as_bytes(), b":", ID_A.as_bytes()]),
            ),
            (
                "max_second",
                joined(&[ID_A.as_bytes(), b":", "ff".repeat(16).as_bytes()]),
            ),
            ("no_sep", joined(&[ID_A.as_bytes(), ID_B.as_bytes()])),
            empty.clone(),
        ],
    );
    let visible = |repo_id: EntityId, ref_name: &str| VisibleRefKey {
        repo_id,
        ref_name: ref_name.to_owned(),
    };
    pin(
        &mut table,
        "VisibleRefKey",
        vec![
            ("empty_ref", visible(id_a(), "")),
            ("main", visible(id_a(), "refs/heads/main")),
            ("ref_with_nul", visible(id_b(), "a\0b")),
            ("multibyte", visible(id_a(), "\u{fc}")),
        ],
        &[
            ("id_only", id_a().as_bytes().to_vec()),
            ("nil_id", joined(&[&[0; 16], b"\0x"])),
            ("bad_utf8_ref", joined(&[id_a().as_bytes(), b"\0\xff"])),
            empty,
        ],
    );

    check_table("store", &table, STORE_TABLE_SHA256);
}

#[test]
fn lfs_oid_spells_and_reads_as_the_hand_impl() {
    let mut table = String::new();
    pin(
        &mut table,
        "LfsOid",
        vec![
            ("zero", LfsOid::from_bytes([0; 32])),
            ("max", LfsOid::from_bytes([0xff; 32])),
            (
                "text",
                LfsOid::from_bytes(*b"0123456789abcdef0123456789abcdef"),
            ),
            ("digest", LfsOid::digest(b"lfs object")),
        ],
        &[
            ("empty", Vec::new()),
            ("short", vec![0x07; 31]),
            ("long", vec![0x07; 33]),
        ],
    );
    check_table("lfs-oid", &table, LFS_OID_TABLE_SHA256);
}

#[cfg(feature = "sync")]
mod window_rows {
    use super::{ID_A, check_table, id_a, id_b, joined, pin};
    use oneiron_contracts::entity_id::EntityId;
    use oneiron_store::window_rows::{HexSeqKey, WindowEntityHexKey, WindowUpdateKey};

    const WINDOW_TABLE_SHA256: &str =
        "11d88051c49c2ed00b3c2f5d8f18f8b2ffe5725b2febb4797f3f95ab22641cef";

    #[test]
    fn window_keys_spell_and_read_as_the_hand_impls() {
        let empty: (&str, Vec<u8>) = ("empty", Vec::new());
        let mut table = String::new();

        pin(
            &mut table,
            "HexSeqKey",
            vec![
                ("zero", HexSeqKey(0)),
                ("one", HexSeqKey(1)),
                ("abcdef", HexSeqKey(0x00ab_cdef)),
                ("max", HexSeqKey(u32::MAX)),
            ],
            &[
                ("short_digits", b"abcdef".to_vec()),
                ("minus", b"-0000001".to_vec()),
                ("plus", b"+0000001".to_vec()),
                empty.clone(),
            ],
        );
        let windows: [(&str, &str, EntityId); 4] = [
            ("empty_window", "", id_a()),
            ("month", "2026-11", id_a()),
            ("window_with_colon", "w:1", id_b()),
            ("multibyte_colon", "\u{fc}:", id_a()),
        ];
        let window_raw = [
            ("nil_id", joined(&[b"w:", "00".repeat(16).as_bytes()])),
            ("no_sep", joined(&[b"w", ID_A.as_bytes()])),
            ("id_only", ID_A.as_bytes().to_vec()),
            empty.clone(),
        ];
        pin(
            &mut table,
            "WindowEntityHexKey",
            windows
                .iter()
                .map(|(label, window, id)| {
                    (
                        *label,
                        WindowEntityHexKey {
                            window: (*window).to_owned(),
                            id: *id,
                        },
                    )
                })
                .collect(),
            &window_raw,
        );
        pin(
            &mut table,
            "WindowEntityKey",
            windows
                .iter()
                .map(|(label, window, id)| {
                    (
                        *label,
                        WindowEntityHexKey {
                            window: (*window).to_owned(),
                            id: *id,
                        },
                    )
                })
                .collect(),
            &window_raw,
        );
        let update = |window: &str, seq: u64| WindowUpdateKey {
            window: window.to_owned(),
            seq,
        };
        pin(
            &mut table,
            "WindowUpdateKey",
            vec![
                ("empty_window", update("", 0)),
                ("month", update("2026-11", 7)),
                ("window_with_colon", update("w:1", u64::MAX)),
                ("multibyte", update("\u{fc}", 0x0123_4567_89ab_cdef)),
            ],
            &[
                (
                    "seventeen_digits",
                    joined(&[b"w:", "0".repeat(16).as_bytes(), b"7"]),
                ),
                ("short_digits", b"w:0007".to_vec()),
                ("no_sep", joined(&[b"w", "0".repeat(15).as_bytes(), b"7"])),
                empty,
            ],
        );

        check_table("window", &table, WINDOW_TABLE_SHA256);
    }
}
