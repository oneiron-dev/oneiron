//! Kani model check of the tombstone wire decoder (FIX [KANI-TOMBSTONE-DECODER-PILOT]).
//!
//! Only `cargo kani` compiles this module (`--cfg kani`); no engine build sees it. The harnesses
//! call the unchanged production code in `super::tombstone`.
//!
//! The expected values come from [`WIRE_POLICY`] and the layout rules below, written from the
//! wire policy and never computed by the decoder or the encoder under check:
//! - the byte of each reason: the ONE-1132 owner decision (M4) that pins the tombstones-map
//!   value, with byte 5 from ONE-1931 (ARCH-0073) and byte 6 from #5509. Byte 0 and every byte
//!   the table does not name are unknown;
//! - the effect of each reason: the delete ladder (ARCH-0038; owner 2026-10-09 "archive is put
//!   in trash can restore. delete, fully delete. erase, meganuke"). `user_delete` keeps the
//!   shell and `archived_by_cleanup` is the soft reversible archive (ARCH-0073); every other
//!   reason purges;
//! - the layout: 25 bytes `[reason:1][deleted_at:8 LE][request_id:16]` (ARCH-0023b), or the
//!   legacy 8-byte bare `deleted_at` (u64 LE);
//! - fail closed: a legacy value, an unknown byte and any other length decode as hard
//!   (ARCH-0038 materialization gate: "a malformed tombstone pins the hard outcome").
//!
//! Bounds: one symbolic value of every length 0..=26 with every byte symbolic, so every one of
//! the 256 reason bytes, both layouts and their neighbours 7, 9, 24 and 26. Nothing here covers
//! a value longer than 26 bytes, nor erasure beyond this decoder (replicas, checkpoints, media).

use super::tombstone::{TombstoneReason, TombstoneValueV2, decode_tombstone_value};

/// What the wire policy says a reason does on the receiver.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WireEffect {
    /// The record stays as a shell (or in the archive) and can come back.
    Soft,
    /// The record's bytes are purged.
    Hard,
}

/// The known reason bytes, each with its reason and its effect.
const WIRE_POLICY: [(u8, TombstoneReason, WireEffect); 6] = [
    (1, TombstoneReason::UserDelete, WireEffect::Soft),
    (2, TombstoneReason::UserHardDelete, WireEffect::Hard),
    (3, TombstoneReason::GdprDelete, WireEffect::Hard),
    (4, TombstoneReason::PolicyDelete, WireEffect::Hard),
    (5, TombstoneReason::ArchivedByCleanup, WireEffect::Soft),
    (6, TombstoneReason::OwnerErase, WireEffect::Hard),
];

/// Length of the current layout.
const CURRENT_LEN: usize = 25;
/// Length of the legacy bare timestamp.
const LEGACY_LEN: usize = 8;
/// The longest value the decode harness builds.
const CHECKED_MAX_LEN: usize = 26;

/// The policy row of `byte`, or `None` where the policy names no reason for it.
fn policy_row(byte: u8) -> Option<(TombstoneReason, WireEffect)> {
    let mut index = 0;
    while index < WIRE_POLICY.len() {
        let (known, reason, effect) = WIRE_POLICY[index];
        if known == byte {
            return Some((reason, effect));
        }
        index += 1;
    }
    None
}

/// Little-endian u64 of the eight bytes at `start`, built by shifts.
fn little_endian_u64(bytes: &[u8], start: usize) -> u64 {
    let mut value = 0_u64;
    let mut index = 0;
    while index < 8 {
        value |= u64::from(bytes[start + index]) << (8 * index);
        index += 1;
    }
    value
}

/// Every value of 0..=26 bytes decodes as the policy says, without a panic or an
/// out-of-bounds read; only a 25-byte value whose first byte the policy names soft decodes soft.
#[kani::proof]
#[kani::unwind(17)]
fn decode_matches_the_wire_policy_up_to_26_bytes() {
    let bytes: [u8; CHECKED_MAX_LEN] = kani::any();
    let len: usize = kani::any_where(|len: &usize| *len <= CHECKED_MAX_LEN);
    let value = &bytes[..len];

    let decoded = decode_tombstone_value(value);

    if len == CURRENT_LEN {
        match policy_row(bytes[0]) {
            Some((reason, effect)) => {
                assert!(
                    decoded.reason == Some(reason),
                    "a known byte decodes as its reason"
                );
                assert!(
                    decoded.is_hard() == (effect == WireEffect::Hard),
                    "a known reason has the policy's effect"
                );
            }
            None => {
                assert!(
                    decoded.reason.is_none(),
                    "an unknown byte decodes as no reason"
                );
                assert!(decoded.is_hard(), "an unknown byte decodes as hard");
            }
        }
        assert!(
            decoded.deleted_at == little_endian_u64(value, 1),
            "deleted_at is bytes 1..9, little-endian"
        );
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&bytes[9..25]);
        assert!(
            decoded.request_id == Some(request_id),
            "request_id is bytes 9..25"
        );
    } else if len == LEGACY_LEN {
        assert!(decoded.reason.is_none(), "a legacy value has no reason");
        assert!(decoded.is_hard(), "a legacy value decodes as hard");
        assert!(
            decoded.deleted_at == little_endian_u64(value, 0),
            "a legacy value is its little-endian deleted_at"
        );
        assert!(
            decoded.request_id.is_none(),
            "a legacy value has no request_id"
        );
    } else {
        assert!(decoded.reason.is_none(), "a malformed value has no reason");
        assert!(decoded.is_hard(), "a malformed value decodes as hard");
        assert!(
            decoded.deleted_at == 0,
            "a malformed value has deleted_at 0"
        );
        assert!(
            decoded.request_id.is_none(),
            "a malformed value has no request_id"
        );
    }

    if !decoded.is_hard() {
        assert!(
            len == CURRENT_LEN && matches!(policy_row(bytes[0]), Some((_, WireEffect::Soft))),
            "only a 25-byte value with a soft reason byte decodes soft"
        );
    }

    kani::cover!(
        len == CURRENT_LEN && !decoded.is_hard(),
        "a soft record decodes soft"
    );
    kani::cover!(
        len == CURRENT_LEN && decoded.reason.is_some() && decoded.is_hard(),
        "a known hard record decodes hard"
    );
    kani::cover!(
        len == CURRENT_LEN && bytes[0] == 0,
        "the reserved byte 0 is reached"
    );
    kani::cover!(
        len == CURRENT_LEN && bytes[0] > 6,
        "a byte past the table is reached"
    );
    kani::cover!(len == LEGACY_LEN, "a legacy value is reached");
    kani::cover!(
        len == CURRENT_LEN - 1 || len == CURRENT_LEN + 1,
        "a length next to 25 is reached"
    );
    kani::cover!(
        len == LEGACY_LEN - 1 || len == LEGACY_LEN + 1,
        "a length next to 8 is reached"
    );
}

/// Every value the engine writes encodes as the pinned layout and decodes to its own fields.
#[kani::proof]
#[kani::unwind(17)]
fn encode_then_decode_keeps_the_fields() {
    let row: usize = kani::any_where(|row: &usize| *row < WIRE_POLICY.len());
    let (byte, reason, effect) = WIRE_POLICY[row];
    let written = TombstoneValueV2 {
        reason,
        deleted_at: kani::any(),
        request_id: kani::any(),
    };

    let wire = written.encode();

    assert!(wire.len() == CURRENT_LEN, "the encoder writes 25 bytes");
    assert!(
        wire[0] == byte,
        "byte 0 is the policy's byte for the reason"
    );
    assert!(
        little_endian_u64(&wire, 1) == written.deleted_at,
        "bytes 1..9 are deleted_at, little-endian"
    );
    assert!(
        wire[9..25] == written.request_id,
        "bytes 9..25 are the request_id"
    );

    let decoded = decode_tombstone_value(&wire);
    assert!(decoded.reason == Some(reason), "the reason comes back");
    assert!(
        decoded.deleted_at == written.deleted_at,
        "deleted_at comes back"
    );
    assert!(
        decoded.request_id == Some(written.request_id),
        "request_id comes back"
    );
    assert!(
        decoded.is_hard() == (effect == WireEffect::Hard),
        "the decoded value has the policy's effect"
    );
}
