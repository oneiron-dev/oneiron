//! UC-06 K-proofs of PRs 2 and 3: the side-table keys those PRs derive spell the same bytes and
//! read the same inputs as their hand-written impls (M-1 STORED-CHANGE-RULE = A: a key a vault
//! already holds keeps its meaning). PR 2 derives nine roster and origin keys, PR 3 five
//! question, step and document keys.
//!
//! Each test builds one table: for every fixture key, the bytes it spells, and the verdict
//! (refused, or the bytes of the key read back) on those bytes and on malformed copies of them
//! (one byte short, the first byte dropped, a trailing digit, NUL or `:`, a leading `:`, upper
//! case, a `+` in the first, last and hex-tail places, the separator swapped, a byte that is not
//! UTF-8), plus some raw inputs per key (a reserved id, a missing or doubled separator, an empty
//! key). A table's sha256 is the one a model of the hand-written decoders gives
//! (`lanes/kimi/OPUS-UC06-SIDEKEYS/check/pins/pin_table_model_pr2.py` and
//! `pin_table_model_pr3.py`), and each run prints the table so a base run and a head run can be
//! compared line by line.
//!
//! `ProjectRevisionHash` is public; the other keys are crate-private and are reached through
//! `test_doors::side_key_pins`. Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test side_key_pins -- --nocapture`.
#![cfg(oneiron_test_support)]

use std::fmt::Write as _;

use oneiron::EntityId;
use oneiron::test_doors::side_key_pins::{
    Pin, ask_history_key, document_slot, document_update_key_of_generation,
    document_update_key_of_sequence, fact_key, lfs_ref_key, member_intent_key, provenance_ref_key,
    receive_pack_intent_key, receive_pack_progress_key, repo_revision_key, roster_member_key,
    step_index_claim_key, step_index_key,
};
use oneiron_verb_wire::workspace_roster::ProjectRevisionHash;
use sha2::{Digest, Sha256};

const ROSTER_ORIGIN_TABLE_SHA256: &str =
    "0a89c3d563672feba0da1737e18176ecda7557e1a1d154cf3a81860cf206d821";
const QUESTION_STEP_DOCUMENT_TABLE_SHA256: &str =
    "881290dbcb9d8eddaa4f2327a34bce50e899abbda1135d7b745fbab584855bcf";

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

/// A 32-byte hash whose bytes run 0x00, 0x11, .. 0xff twice.
fn pattern_hash() -> [u8; 32] {
    let mut hash = [0_u8; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::try_from(index % 16).expect("below 16") * 0x11;
    }
    hash
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

/// Prints `table` under `name`, line by line, and checks its sha256 against `expected`, the one
/// the model of the hand-written decoders gives.
fn assert_table(name: &str, table: &str, expected: &str) {
    let digest = hex(&Sha256::digest(table.as_bytes()));
    for line in table.lines() {
        println!("PIN {name} {line}");
    }
    println!(
        "PIN-TABLE {name} lines={} sha256={digest}",
        table.lines().count()
    );
    assert_eq!(
        digest, expected,
        "the {name} key table differs from the hand-written decoders' table"
    );
}

#[test]
fn roster_and_origin_keys_spell_and_read_as_the_hand_impls() {
    let hash = pattern_hash();
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

    assert_table("roster-origin", &table, ROSTER_ORIGIN_TABLE_SHA256);
}

#[test]
fn question_step_and_document_keys_spell_and_read_as_the_hand_impls() {
    let hash = pattern_hash();
    let a = *id_a().as_bytes();
    let slot_a = ID_A.as_bytes();
    let after_slot_a = |rest: &[u8]| joined(&[slot_a, rest]);
    let empty: (&str, Vec<u8>) = ("empty", Vec::new());
    let mut table = String::new();

    pin(
        &mut table,
        "AskHistoryKey",
        vec![
            ("zero", ask_history_key(id_a(), 0)),
            ("max", ask_history_key(id_b(), u64::MAX)),
            (
                "colons",
                ask_history_key(id(ID_COLON), u64::from_be_bytes([b':'; 8])),
            ),
            ("question_with_nul", ask_history_key(id(ID_NUL), 1)),
        ],
        &[
            ("nil_question", vec![0; 24]),
            ("max_question", joined(&[&[0xff; 16], &[0; 8]])),
            ("question_only", a.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "StepIndexKey",
        vec![
            ("nil_attempt", step_index_key([0; 16], hash)),
            ("max", step_index_key([0xff; 16], [0xff; 32])),
            ("colons", step_index_key([b':'; 16], [b':'; 32])),
        ],
        &[
            ("attempt_only", a.to_vec()),
            ("claim_shape", joined(&[b"i:", &a])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "StepIndexClaimKey",
        vec![
            ("claim", step_index_claim_key(id_a())),
            ("colons", step_index_claim_key(id(ID_COLON))),
            ("claim_with_nul", step_index_claim_key(id(ID_NUL))),
        ],
        &[
            ("nil_claim", joined(&[b"i:", &[0; 16]])),
            ("no_tag", a.to_vec()),
            ("upper_tag", joined(&[b"I:", &a])),
            ("tag_only", b"i:".to_vec()),
            ("forward_shape", joined(&[&a, &hash])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "DocumentSlot",
        vec![
            ("a", document_slot(id_a())),
            ("b", document_slot(id_b())),
            ("colons", document_slot(id(ID_COLON))),
        ],
        &[
            ("nil", "00".repeat(16).into_bytes()),
            ("max", "ff".repeat(16).into_bytes()),
            ("upper", ID_A.to_ascii_uppercase().into_bytes()),
            ("raw_id", a.to_vec()),
            ("two_ids", joined(&[ID_A.as_bytes(), ID_B.as_bytes()])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "DocumentUpdateKey",
        vec![
            ("sequence_zero", document_update_key_of_sequence(id_a(), 0)),
            (
                "sequence_max",
                document_update_key_of_sequence(id_b(), u32::MAX),
            ),
            (
                "sequence_hex",
                document_update_key_of_sequence(id_a(), 0x0a0b_0c0d),
            ),
            (
                "generation_zero",
                document_update_key_of_generation(id_a(), 0),
            ),
            (
                "generation_max",
                document_update_key_of_generation(id_b(), u64::MAX),
            ),
        ],
        &[
            ("sequence_upper", after_slot_a(b":0000000A")),
            ("sequence_plus", after_slot_a(b":+0000001")),
            ("sequence_seven", after_slot_a(b":0000001")),
            ("sequence_nine", after_slot_a(b":000000001")),
            ("sequence_digits", after_slot_a(b":12345678")),
            ("generation_nineteen", after_slot_a(b":0000000000000000001")),
            (
                "generation_overflow",
                after_slot_a(b":18446744073709551616"),
            ),
            ("generation_plus", after_slot_a(b":+0000000000000000001")),
            ("generation_hex", after_slot_a(b":0000000000000000000a")),
            ("no_sequence", after_slot_a(b":")),
            ("slot_only", slot_a.to_vec()),
            ("no_sep", after_slot_a(b"00000000")),
            ("double_sep", after_slot_a(b"::0000000")),
            (
                "nil_slot",
                joined(&["00".repeat(16).as_bytes(), b":00000000"]),
            ),
            (
                "upper_slot",
                joined(&[ID_A.to_ascii_uppercase().as_bytes(), b":00000000"]),
            ),
            empty,
        ],
    );

    assert_table(
        "question-step-document",
        &table,
        QUESTION_STEP_DOCUMENT_TABLE_SHA256,
    );
}
