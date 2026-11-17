//! UC-06 K-proofs of PRs 2 to 6: the side-table keys those PRs derive or merge spell the same
//! bytes and read the same inputs as their hand-written impls (M-1 STORED-CHANGE-RULE = A: a key a
//! vault already holds keeps its meaning). PR 2 derives nine roster and origin keys, PR 3 five
//! question, step and document keys, PR 4 seventeen keys of the library's modules `a` to `g`,
//! PR 5 seventeen keys of its modules `n` to `v`. PR 6 merges the key types that spell one layout
//! (the earlier tables keep their key names and doors, so they pin the merged types too) and adds
//! the voice bank's two keys.
//!
//! Each test builds one table: for every fixture key, the bytes it spells, and the verdict
//! (refused, or the bytes of the key read back) on those bytes and on malformed copies of them
//! (one byte short, the first byte dropped, a trailing digit, NUL or `:`, a leading `:`, upper
//! case, a `+` in the first, last and hex-tail places, the separator swapped, a byte that is not
//! UTF-8), plus some raw inputs per key (a reserved id, a missing or doubled separator, an empty
//! key). A table's sha256 is the one a model of the hand-written decoders gives
//! (`lanes/kimi/OPUS-UC06-SIDEKEYS/check/pins/pin_table_model_pr2.py` to
//! `pin_table_model_pr6.py`), and each run prints the table so a base run and a head run can be
//! compared line by line. A decoder that panics reads as `panic`.
//!
//! `ProjectRevisionHash` is public; the other keys are crate-private and are reached through
//! `test_doors::side_key_pins`. Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test side_key_pins -- --nocapture`.
#![cfg(oneiron_test_support)]

use std::fmt::Write as _;

use oneiron::EntityId;
use oneiron::artifact_hosting::ArtifactPointerChannel;
use oneiron::dreamer_tournament::DreamerTournamentBranchVerdict;
use oneiron::test_doors::side_key_pins::{
    Pin, artifact_pointer_row_key, ask_history_key, attempt_call_key, band_key, block_key,
    branch_gap_key, budget_reservation_key, channel_identity_lifecycle_receipt_id,
    connector_index_key, critique_artifact_key, dispatch_observation_key, doc_key, document_slot,
    document_update_key_of_generation, document_update_key_of_sequence, epoch_scope, fact_key,
    hash_index_key, hex_hex_hash, hex_pair, hex_triple, history_key, lease_key, lfs_ref_key,
    listing_pin, loaded_skill_key, marker_key, member_intent_key, member_key,
    milestone_candidate_key, note_fork_key, op_key, pending_tombstone_key, proposal_key,
    provenance_ref_key, receive_pack_intent_key, receive_pack_progress_key, render_event_key,
    repo_revision_key, retrieval_run_id, roster_member_key, rule_key, step_index_claim_key,
    step_index_key, task_attempt_key, task_follow_up_key, text_index_key, tournament_evidence_key,
    vad_annotation_meta_key, voice_target_key,
};
use oneiron_verb_wire::workspace_roster::ProjectRevisionHash;
use sha2::{Digest, Sha256};

const ROSTER_ORIGIN_TABLE_SHA256: &str =
    "0a89c3d563672feba0da1737e18176ecda7557e1a1d154cf3a81860cf206d821";
const QUESTION_STEP_DOCUMENT_TABLE_SHA256: &str =
    "881290dbcb9d8eddaa4f2327a34bce50e899abbda1135d7b745fbab584855bcf";
/// The derived decoders' table (`pin_table_model_pr4.py --derived`). It differs from the hand
/// impls' table (sha256 `33d4e969349931b2ad6448a11f5ad73f76802a15d29dffe8160c142146c97bcb`) in
/// three `HistoryKey` lines only: the hand decoder panicked on a key shorter than 17 bytes (its
/// `then_some` argument sliced the bytes before the length check), and the derived one refuses it.
const LIB_KEYS_A_TO_G_TABLE_SHA256: &str =
    "55a7fb7dc2498bacb49def7594181e8a0d1ef603291e13aec5d0b427c92c1955";
const LIB_KEYS_N_TO_V_TABLE_SHA256: &str =
    "eeb0defe7c051bb21832b7fa5c2d38bc23788bf4430fb84f16dbc5593bd6eb5d";
const VOICE_KEYS_TABLE_SHA256: &str =
    "2be37d91b0f093a696af38cb63902fbdaddc4d5c86075edca33e1127e5501fa8";

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
    match std::panic::catch_unwind(|| read(input)) {
        Ok(read) => read.map_or_else(|| "none".to_owned(), |key| format!("some {}", hex(&key))),
        Err(_) => "panic".to_owned(),
    }
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

fn u16_be(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

fn u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

#[test]
fn lib_keys_a_to_g_spell_and_read_as_the_hand_impls() {
    let hash = pattern_hash();
    let a = *id_a().as_bytes();
    let b = *id_b().as_bytes();
    let empty: (&str, Vec<u8>) = ("empty", Vec::new());
    let mut table = String::new();

    pin(
        &mut table,
        "ArtifactPointerRowKey",
        vec![
            (
                "published",
                artifact_pointer_row_key(ArtifactPointerChannel::Published, "artifact-1"),
            ),
            (
                "preview_empty",
                artifact_pointer_row_key(ArtifactPointerChannel::Preview, ""),
            ),
            (
                "separators",
                artifact_pointer_row_key(ArtifactPointerChannel::Published, "a:b\0c"),
            ),
            (
                "multibyte",
                artifact_pointer_row_key(ArtifactPointerChannel::Preview, "\u{e9}"),
            ),
        ],
        &[
            ("channel_two", joined(&[&[2], &u16_be(1), b"a"])),
            ("channel_ff", joined(&[&[0xff], &u16_be(0)])),
            ("channel_only", vec![0]),
            ("short_length", vec![0, 0]),
            ("length_over", joined(&[&[0], &u16_be(2), b"a"])),
            ("length_under", joined(&[&[0], &u16_be(0), b"a"])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "TextIndexKey",
        vec![
            ("repo_ref", text_index_key("github.com/a/b", id_a())),
            ("empty_text", text_index_key("", id_b())),
            ("nul_in_text", text_index_key("a\0b", id_a())),
            ("id_with_nul", text_index_key("\u{e9}", id(ID_NUL))),
        ],
        &[
            ("nil_id", joined(&[b"x\0", &[0; 16]])),
            ("no_sep", joined(&[b"x", &a])),
            ("id_only", a.to_vec()),
            ("bad_utf8_text", joined(&[&[0xff, 0], &a])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "HashIndexKey",
        vec![
            ("pattern", hash_index_key(hash, id_a())),
            ("zero_hash", hash_index_key([0; 32], id_b())),
            ("colon_hash", hash_index_key([b':'; 32], id(ID_COLON))),
            ("id_with_nul", hash_index_key([0xff; 32], id(ID_NUL))),
        ],
        &[
            ("nil_id", joined(&[&hash, &[0], &[0; 16]])),
            ("short_hash", joined(&[&hash[..31], &[0], &a])),
            ("long_hash", joined(&[&hash, &[7, 0], &a])),
            ("sep_one", joined(&[&hash, &[1], &a])),
            ("id_only", a.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "EpochScope",
        vec![
            ("session", epoch_scope(id_a(), None)),
            ("conversation", epoch_scope(id_a(), Some(id_b()))),
            ("nul_colon", epoch_scope(id(ID_NUL), Some(id(ID_COLON)))),
        ],
        &[
            ("nil_session", vec![0; 16]),
            ("nil_conversation", joined(&[&a, &[0; 16]])),
            ("conversation_short", joined(&[&a, &b[..15]])),
            ("conversation_long", joined(&[&a, &b, &[0]])),
            ("session_short", a[..15].to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "ConnectorIndexKey",
        vec![
            ("connector", connector_index_key("github", id_a())),
            ("empty_connector", connector_index_key("", id_b())),
            (
                "nul_in_connector",
                connector_index_key("a\0b", id(ID_COLON)),
            ),
        ],
        &[
            ("nil_id", joined(&[b"github\0", &[0; 16]])),
            ("no_sep", joined(&[b"github", &a])),
            ("id_only", a.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "RuleKey",
        vec![
            ("grant", rule_key("grant-ref-1", [0x11; 16])),
            ("empty_ref", rule_key("", [0; 16])),
            ("colon_ref", rule_key("a:b", [b':'; 16])),
        ],
        &[
            ("no_sep", joined(&[b"g", &[0x11; 16]])),
            ("decision_only", vec![0x11; 16]),
            ("bad_utf8_ref", joined(&[&[0xff], b":", &[0x11; 16]])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "BlockKey",
        vec![
            ("section", block_key(id_a(), "notes", [1; 16])),
            ("empty_section", block_key(id_b(), "", [0; 16])),
            ("separators", block_key(id(ID_COLON), "a\0b:c", [b':'; 16])),
        ],
        &[
            ("nil_actor", joined(&[&[0; 16], &u64_be(0), &[1; 16]])),
            ("length_over", joined(&[&a, &u64_be(6), b"notes", &[1; 16]])),
            (
                "length_under",
                joined(&[&a, &u64_be(4), b"notes", &[1; 16]]),
            ),
            ("length_max", joined(&[&a, &u64_be(u64::MAX), &[1; 16]])),
            ("no_block", joined(&[&a, &u64_be(0)])),
            ("short_length", joined(&[&a, &[0; 7]])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "CritiqueArtifactKey",
        vec![
            ("artifact", critique_artifact_key([0; 16], "critique-1")),
            ("empty_id", critique_artifact_key([0xff; 16], "")),
            ("separators", critique_artifact_key([b':'; 16], "x\0y:z")),
        ],
        &[
            ("length_over", joined(&[&[0; 16], &u16_be(2), b"a"])),
            ("length_under", joined(&[&[0; 16], &u16_be(0), b"a"])),
            ("attempt_only", vec![0; 16]),
            ("short_attempt", vec![0; 15]),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "PendingTombstoneKey",
        vec![
            ("window", pending_tombstone_key("w1", id_a())),
            ("empty_window", pending_tombstone_key("", id_b())),
            ("colon_window", pending_tombstone_key("a:b", id(ID_COLON))),
        ],
        &[
            (
                "upper_id",
                joined(&[b"w:", ID_A.to_ascii_uppercase().as_bytes()]),
            ),
            ("nil_id", joined(&[b"w:", "00".repeat(16).as_bytes()])),
            ("plus_id", joined(&[b"w:+", &ID_A.as_bytes()[1..]])),
            ("no_sep", joined(&[b"w", ID_A.as_bytes()])),
            ("id_only", ID_A.as_bytes().to_vec()),
            ("raw_id", joined(&[b"w:", &a, &a])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "BranchGapKey",
        vec![
            ("scope", branch_gap_key("rel:proj", hash)),
            ("empty_scope", branch_gap_key("", [0; 32])),
            ("multibyte", branch_gap_key("\u{e9}\0", [0xff; 32])),
        ],
        &[
            ("short", vec![0; 31]),
            ("bad_utf8_scope", joined(&[&[0xff], &[0; 32]])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "ListingPin",
        vec![
            ("attempt", listing_pin([0; 16], None)),
            ("note", listing_pin([0xff; 16], Some(id_a()))),
            ("colon_nul", listing_pin([b':'; 16], Some(id(ID_NUL)))),
        ],
        &[
            ("nil_note", joined(&[&[0; 16], &[0; 16]])),
            ("note_short", joined(&[&[0; 16], &a[..15]])),
            ("note_long", joined(&[&[0; 16], &a, &[0]])),
            ("attempt_short", vec![0; 15]),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "MemberKey",
        vec![
            ("kind", member_key("dreamer_consolidation", id_a())),
            ("empty_kind", member_key("", id_b())),
            ("colon_kind", member_key("a:b", id(ID_COLON))),
        ],
        &[
            ("no_sep", joined(&[b"k", &a])),
            ("nil_turn", joined(&[b"k:", &[0; 16]])),
            ("turn_only", a.to_vec()),
            ("bad_utf8_kind", joined(&[&[0xff], b":", &a])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "BudgetReservationKey",
        vec![
            ("budget", budget_reservation_key("budget-1", [1; 16])),
            ("empty_budget", budget_reservation_key("", [0; 16])),
            ("separators", budget_reservation_key("a\0:b", [0xff; 16])),
        ],
        &[
            ("length_over", joined(&[&u16_be(2), b"b", &[1; 16]])),
            ("length_under", joined(&[&u16_be(0), b"b", &[1; 16]])),
            ("no_attempt", joined(&[&u16_be(1), b"b"])),
            ("one_byte", vec![0]),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "MilestoneCandidateKey",
        vec![
            ("zero", milestone_candidate_key([0; 16], 0, 0, id_a())),
            (
                "max",
                milestone_candidate_key([0xff; 16], u64::MAX, u64::MAX, id_b()),
            ),
            (
                "colons",
                milestone_candidate_key([b':'; 16], 0x3a3a_3a3a_3a3a_3a3a, 1, id(ID_NUL)),
            ),
        ],
        &[
            ("nil_claim", vec![0; 48]),
            ("short", vec![0; 47]),
            empty.clone(),
        ],
    );
    let evidence_head = joined(&[&u16_be(1), b"r", &[1; 16], &u16_be(0)]);
    pin(
        &mut table,
        "TournamentEvidenceKey",
        vec![
            (
                "survivor",
                tournament_evidence_key(
                    "run-1",
                    [1; 16],
                    0,
                    DreamerTournamentBranchVerdict::Survivor,
                    "cand-1",
                ),
            ),
            (
                "weaved_empty",
                tournament_evidence_key(
                    "",
                    [0; 16],
                    u16::MAX,
                    DreamerTournamentBranchVerdict::Weaved,
                    "",
                ),
            ),
            (
                "refined",
                tournament_evidence_key(
                    "r\0:",
                    [0xff; 16],
                    0x0102,
                    DreamerTournamentBranchVerdict::Refined,
                    "c:d",
                ),
            ),
            (
                "discarded",
                tournament_evidence_key(
                    "\u{e9}",
                    [b':'; 16],
                    7,
                    DreamerTournamentBranchVerdict::Discarded,
                    "x",
                ),
            ),
        ],
        &[
            ("verdict_zero", joined(&[&evidence_head, &[0], &u16_be(0)])),
            ("verdict_five", joined(&[&evidence_head, &[5], &u16_be(0)])),
            (
                "candidate_over",
                joined(&[&evidence_head, &[1], &u16_be(2), b"c"]),
            ),
            (
                "trailing",
                joined(&[&evidence_head, &[1], &u16_be(0), b"x"]),
            ),
            ("no_candidate_length", joined(&[&evidence_head, &[1]])),
            ("run_over", joined(&[&u16_be(40), b"r", &[1; 16]])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "ProposalKey",
        vec![
            ("proposal", proposal_key(id_a(), "proposal-1")),
            ("empty_ref", proposal_key(id_b(), "")),
            ("separators", proposal_key(id(ID_COLON), "a:b\0")),
        ],
        &[
            ("nil_actor", joined(&[&[0; 16], b":p"])),
            ("no_sep", joined(&[&a, b"p"])),
            ("wrong_sep", joined(&[&a, b";p"])),
            ("actor_only", a.to_vec()),
            ("bad_utf8_ref", joined(&[&a, b":", &[0xff]])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "HistoryKey",
        vec![
            ("zero", history_key(id_a(), 0)),
            ("max", history_key(id_b(), u64::MAX)),
            ("colons", history_key(id(ID_COLON), 0x3a3a_3a3a_3a3a_3a3a)),
        ],
        &[
            ("nil_actor", joined(&[&[0; 16], b":", &[0; 8]])),
            ("no_sep", joined(&[&a, &[0; 9]])),
            ("short_count", joined(&[&a, b":", &[0; 7]])),
            ("actor_sep", joined(&[&a, b":"])),
            ("actor_only", a.to_vec()),
            ("nil_actor_only", vec![0; 16]),
            ("short_actor", a[..15].to_vec()),
            empty,
        ],
    );

    assert_table("lib-keys-a-to-g", &table, LIB_KEYS_A_TO_G_TABLE_SHA256);
}

#[test]
fn lib_keys_n_to_v_spell_and_read_as_the_hand_impls() {
    let hash = pattern_hash();
    let hash_hex = hex(&hash);
    let a = *id_a().as_bytes();
    let b = *id_b().as_bytes();
    let hex_a = ID_A.as_bytes();
    let hex_b = ID_B.as_bytes();
    let nil_hex = [b'0'; 32];
    let zeros_16 = [b'0'; 16];
    let mut repo_hash = [0_u8; 64];
    repo_hash.copy_from_slice(hash_hex.as_bytes());
    let empty: (&str, Vec<u8>) = ("empty", Vec::new());
    let mut table = String::new();

    pin(
        &mut table,
        "HexPair",
        vec![
            ("ids", hex_pair(id_a(), id_b())),
            ("nul_colon", hex_pair(id(ID_NUL), id(ID_COLON))),
        ],
        &[
            ("nil_first", joined(&[&nil_hex, b":", hex_b])),
            ("nil_second", joined(&[hex_a, b":", &nil_hex])),
            ("no_sep", joined(&[hex_a, hex_b])),
            ("wrong_sep", joined(&[hex_a, b";", hex_b])),
            ("first_only", hex_a.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "HexTriple",
        vec![
            ("ids", hex_triple(id_a(), id_b(), id_a())),
            ("nul_colon", hex_triple(id(ID_NUL), id(ID_COLON), id_b())),
        ],
        &[
            ("nil_last", joined(&[hex_a, b":", hex_b, b":", &nil_hex])),
            ("no_second_sep", joined(&[hex_a, b":", hex_b, hex_a])),
            ("pair_only", joined(&[hex_a, b":", hex_b])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "HexHexHash",
        vec![
            ("hash", hex_hex_hash(id_a(), id_b(), &hash_hex)),
            ("zero_hash", hex_hex_hash(id_b(), id_a(), &"0".repeat(64))),
            (
                "text_hash",
                hex_hex_hash(id(ID_NUL), id(ID_COLON), "not-a-hash"),
            ),
        ],
        &[
            (
                "upper_hash",
                joined(&[
                    hex_a,
                    b":",
                    hex_b,
                    b":",
                    hash_hex.to_ascii_uppercase().as_bytes(),
                ]),
            ),
            (
                "short_hash",
                joined(&[hex_a, b":", hex_b, b":", &hash_hex.as_bytes()[..63]]),
            ),
            (
                "not_hex_hash",
                joined(&[hex_a, b":", hex_b, b":", &[b'g'; 64]]),
            ),
            (
                "nil_first",
                joined(&[&nil_hex, b":", hex_b, b":", hash_hex.as_bytes()]),
            ),
            ("pair_only", joined(&[hex_a, b":", hex_b])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "AttemptCallKey",
        vec![
            ("zero", attempt_call_key(a, 0)),
            ("max", attempt_call_key([0; 16], u64::MAX)),
            (
                "colons",
                attempt_call_key([b':'; 16], 0x3a3a_3a3a_3a3a_3a3a),
            ),
        ],
        &[
            ("short_seq", joined(&[&a, &[0; 7]])),
            ("attempt_only", a.to_vec()),
            ("short_attempt", a[..15].to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "DispatchObservationKey",
        vec![
            ("zero", dispatch_observation_key(a, 0)),
            ("max", dispatch_observation_key([0; 16], u32::MAX)),
            ("colons", dispatch_observation_key([b':'; 16], 0x3a3a_3a3a)),
        ],
        &[
            ("short_count", joined(&[&a, &[0; 3]])),
            ("call_key_shape", joined(&[&a, &[0; 8]])),
            ("attempt_only", a.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "DocKey",
        vec![
            ("ids", doc_key(id_a(), id_b())),
            ("nul_colon", doc_key(id(ID_NUL), id(ID_COLON))),
        ],
        &[
            ("nil_head", joined(&[hex_a, b":", &nil_hex])),
            ("no_sep", joined(&[hex_a, hex_b])),
            ("note_only", hex_a.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "OpKey",
        vec![
            ("hash", op_key(repo_hash, 0)),
            ("max", op_key([0; 64], u64::MAX)),
            ("colons", op_key([b':'; 64], 0x3a3a_3a3a_3a3a_3a3a)),
        ],
        &[
            ("wrong_sep", joined(&[&repo_hash, b";", &[0; 8]])),
            ("no_sep", joined(&[&repo_hash, &[0; 9]])),
            ("short_seq", joined(&[&repo_hash, b":", &[0; 7]])),
            ("hash_only", repo_hash.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "ChannelIdentityLifecycleReceiptId",
        vec![
            ("id", channel_identity_lifecycle_receipt_id(a)),
            ("zero", channel_identity_lifecycle_receipt_id([0; 16])),
            ("colons", channel_identity_lifecycle_receipt_id([b':'; 16])),
        ],
        &[("two_ids", joined(&[&a, &b])), empty.clone()],
    );
    pin(
        &mut table,
        "RetrievalRunId",
        vec![
            ("id", retrieval_run_id(a)),
            ("zero", retrieval_run_id([0; 16])),
            ("colons", retrieval_run_id([b':'; 16])),
        ],
        &[("two_ids", joined(&[&a, &b])), empty.clone()],
    );
    pin(
        &mut table,
        "LoadedSkillKey",
        vec![
            ("receipt", loaded_skill_key("receipt-1", id_a())),
            ("empty_receipt", loaded_skill_key("", id_b())),
            ("separators", loaded_skill_key("a:b\0c", id(ID_COLON))),
        ],
        &[
            ("nil_skill", joined(&[&u64_be(1), b"r", &[0; 16]])),
            ("length_over", joined(&[&u64_be(2), b"r", &a])),
            ("length_under", joined(&[&u64_be(0), b"r", &a])),
            ("length_max", joined(&[&u64_be(u64::MAX), &a])),
            ("no_skill", joined(&[&u64_be(1), b"r"])),
            ("short_length", vec![0; 7]),
            ("bad_utf8_receipt", joined(&[&u64_be(1), &[0xff], &a])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "VadAnnotationMetaKey",
        vec![
            ("zero_type", vad_annotation_meta_key(0, id_a())),
            ("max_type", vad_annotation_meta_key(u8::MAX, id_b())),
            ("colons", vad_annotation_meta_key(b':', id(ID_COLON))),
        ],
        &[
            ("nil_id", joined(&[&[1], &[0; 16]])),
            ("type_only", vec![1]),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "LeaseKey",
        vec![
            ("zero", lease_key(0, 0)),
            ("max", lease_key(u64::MAX, 1)),
            (
                "pattern",
                lease_key(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            ),
        ],
        &[
            ("no_sep", joined(&[&zeros_16, &zeros_16])),
            ("wrong_sep", joined(&[&zeros_16, b";", &zeros_16])),
            (
                "multibyte_at_split",
                joined(&[&zeros_16[..15], "\u{e9}".as_bytes(), &zeros_16]),
            ),
            (
                "signed_client",
                joined(&[&zeros_16, b":+", &zeros_16[..15]]),
            ),
            ("vault_only", zeros_16.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "NoteForkKey",
        vec![
            ("ids", note_fork_key(id_a(), id_b())),
            ("nul_colon", note_fork_key(id(ID_NUL), id(ID_COLON))),
        ],
        &[
            ("nil_fork", joined(&[hex_a, b":", &nil_hex])),
            ("no_sep", joined(&[hex_a, hex_b])),
            ("note_only", hex_a.to_vec()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "BandKey",
        vec![
            ("class", band_key(id_a(), "code-review")),
            ("empty_class", band_key(id_b(), "")),
            ("separators", band_key(id(ID_COLON), "a:b\0c")),
            ("multibyte", band_key(id_a(), "\u{e9}")),
        ],
        &[
            ("nil_owner", joined(&[&[0; 16], &u16_be(1), b"c"])),
            ("length_over", joined(&[&a, &u16_be(2), b"c"])),
            ("length_under", joined(&[&a, &u16_be(0), b"c"])),
            ("short_length", joined(&[&a, &[0]])),
            ("owner_only", a.to_vec()),
            ("bad_utf8_class", joined(&[&a, &u16_be(1), &[0xff]])),
            empty.clone(),
        ],
    );
    let band_a = joined(&[&a, &u16_be(1), b"c"]);
    pin(
        &mut table,
        "MarkerKey",
        vec![
            ("marker", marker_key(id_a(), "code-review", id_b())),
            ("empty_class", marker_key(id_b(), "", id_a())),
            ("colon_class", marker_key(id(ID_COLON), "a:b", id(ID_COLON))),
        ],
        &[
            ("nil_word", joined(&[&band_a, b":", &[0; 16]])),
            ("nil_owner", joined(&[&[0; 16], &u16_be(1), b"c:", &b])),
            ("wrong_sep", joined(&[&band_a, b";", &b])),
            ("length_over", joined(&[&a, &u16_be(2), b"c:", &b])),
            ("no_word", joined(&[&band_a, b":"])),
            ("band_only", band_a.clone()),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "TaskFollowUpKey",
        vec![
            ("stage", task_follow_up_key(id_a(), "review")),
            ("empty_stage", task_follow_up_key(id_b(), "")),
            ("nul_stage", task_follow_up_key(id(ID_COLON), "a\0b")),
        ],
        &[
            ("nil_task", joined(&[&[0; 16], b"\0s"])),
            ("wrong_sep", joined(&[&a, b"\x01s"])),
            ("task_only", a.to_vec()),
            ("bad_utf8_stage", joined(&[&a, b"\0", &[0xff]])),
            empty.clone(),
        ],
    );
    pin(
        &mut table,
        "TaskAttemptKey",
        vec![
            ("pattern", task_attempt_key(hash, [1; 16])),
            ("zero", task_attempt_key([0; 32], [0; 16])),
            ("colons", task_attempt_key([b':'; 32], [b':'; 16])),
        ],
        &[("digest_only", hash.to_vec()), empty],
    );

    assert_table("lib-keys-n-to-v", &table, LIB_KEYS_N_TO_V_TABLE_SHA256);
}

#[test]
fn voice_keys_spell_and_read_as_the_hand_impls() {
    let empty: (&str, Vec<u8>) = ("empty", Vec::new());
    let mut table = String::new();

    let doors: [(&str, fn(&str, &str) -> Pin, &str); 2] = [
        ("TargetKey", voice_target_key, "host"),
        ("RenderEventKey", render_event_key, "event-1"),
    ];
    for (name, door, second) in doors {
        pin(
            &mut table,
            name,
            vec![
                ("ids", door("voice-1", second)),
                ("empty_second", door("voice-1", "")),
                ("empty_voice", door("", second)),
                ("nul_in_second", door("v", "a\0b")),
                ("multibyte", door("\u{e9}", "\u{e9}:x")),
            ],
            &[
                ("no_sep", b"voice-1".to_vec()),
                ("sep_only", b"\0".to_vec()),
                ("bad_utf8_voice", joined(&[b"\xff\0", second.as_bytes()])),
                ("bad_utf8_second", b"v\0\xff".to_vec()),
                ("long_ids", joined(&[&[b'v'; 40], b"\0", &[b'w'; 40]])),
                empty.clone(),
            ],
        );
    }

    assert_table("voice-keys", &table, VOICE_KEYS_TABLE_SHA256);
}
