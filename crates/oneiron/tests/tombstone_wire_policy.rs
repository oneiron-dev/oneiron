//! The tombstone wire decoder against the wire policy, for every reason byte and every length
//! 0..=26 (FIX [KANI-TOMBSTONE-DECODER-PILOT]). It is the cargo-test twin of the Kani harness in
//! crates/oneiron/src/deletion/tombstone_kani.rs: the same policy table, written from the wire
//! policy and never computed by the decoder, with concrete bytes in place of symbolic ones.
//!
//! - The byte of each reason: the ONE-1132 owner decision (M4), byte 5 from ONE-1931 (ARCH-0073),
//!   byte 6 from #5509. Byte 0 and every byte the table does not name are unknown.
//! - The effect: the delete ladder (ARCH-0038). `user_delete` keeps the shell and
//!   `archived_by_cleanup` is the soft reversible archive (ARCH-0073); every other reason purges.
//! - The layout: 25 bytes `[reason:1][deleted_at:8 LE][request_id:16]` (ARCH-0023b), or the
//!   legacy 8-byte bare `deleted_at`. A legacy value, an unknown byte and any other length decode
//!   as hard.
//!
//! Fleet only: `cargo test -p oneiron --all-features --test tombstone_wire_policy`.

use oneiron::deletion::{TombstoneReason, TombstoneValueV2, decode_tombstone_value};

/// What the wire policy says a reason does on the receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireEffect {
    Soft,
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

const CURRENT_LEN: usize = 25;
const LEGACY_LEN: usize = 8;
const CHECKED_MAX_LEN: usize = 26;

fn policy_row(byte: u8) -> Option<(TombstoneReason, WireEffect)> {
    WIRE_POLICY
        .iter()
        .find(|(known, _, _)| *known == byte)
        .map(|(_, reason, effect)| (*reason, *effect))
}

fn little_endian_u64(bytes: &[u8]) -> u64 {
    bytes.iter().enumerate().fold(0, |value, (index, byte)| {
        value | (u64::from(*byte) << (8 * index))
    })
}

/// Two fills for the bytes after the first: every byte different, and every byte 0xFF.
fn filled_value(first: u8, len: usize, ascending: bool) -> Vec<u8> {
    (0..len)
        .map(|index| match (index, ascending) {
            (0, _) => first,
            (_, true) => u8::try_from(index * 7 % 256).expect("below 256"),
            (_, false) => 0xFF,
        })
        .collect()
}

#[test]
fn every_reason_byte_at_every_length_decodes_as_the_wire_policy_says() {
    let mut soft_seen = 0;
    for len in 0..=CHECKED_MAX_LEN {
        for first in 0..=u8::MAX {
            for ascending in [true, false] {
                let value = filled_value(first, len, ascending);
                let decoded = decode_tombstone_value(&value);
                let at = format!("length {len}, first byte {first}, ascending fill {ascending}");

                if len == CURRENT_LEN {
                    match policy_row(first) {
                        Some((reason, effect)) => {
                            assert_eq!(decoded.reason, Some(reason), "{at}: the reason");
                            assert_eq!(
                                decoded.is_hard(),
                                effect == WireEffect::Hard,
                                "{at}: the policy's effect"
                            );
                        }
                        None => {
                            assert_eq!(decoded.reason, None, "{at}: an unknown byte has no reason");
                            assert!(decoded.is_hard(), "{at}: an unknown byte decodes as hard");
                        }
                    }
                    assert_eq!(
                        decoded.deleted_at,
                        little_endian_u64(&value[1..9]),
                        "{at}: deleted_at is bytes 1..9, little-endian"
                    );
                    assert_eq!(
                        decoded.request_id.map(Vec::from),
                        Some(value[9..25].to_vec()),
                        "{at}: request_id is bytes 9..25"
                    );
                } else if len == LEGACY_LEN {
                    assert_eq!(decoded.reason, None, "{at}: a legacy value has no reason");
                    assert!(decoded.is_hard(), "{at}: a legacy value decodes as hard");
                    assert_eq!(
                        decoded.deleted_at,
                        little_endian_u64(&value),
                        "{at}: a legacy value is its little-endian deleted_at"
                    );
                    assert_eq!(
                        decoded.request_id, None,
                        "{at}: a legacy value has no request_id"
                    );
                } else {
                    assert_eq!(
                        decoded.reason, None,
                        "{at}: a malformed value has no reason"
                    );
                    assert!(decoded.is_hard(), "{at}: a malformed value decodes as hard");
                    assert_eq!(
                        decoded.deleted_at, 0,
                        "{at}: a malformed value has deleted_at 0"
                    );
                    assert_eq!(
                        decoded.request_id, None,
                        "{at}: a malformed value has no request_id"
                    );
                }

                if !decoded.is_hard() {
                    assert!(
                        len == CURRENT_LEN
                            && matches!(policy_row(first), Some((_, WireEffect::Soft))),
                        "{at}: only a 25-byte value with a soft reason byte decodes soft"
                    );
                    soft_seen += 1;
                }
            }
        }
    }
    assert_eq!(
        soft_seen, 4,
        "bytes 1 and 5, each with both fills, decode soft"
    );
}

#[test]
fn every_written_reason_encodes_as_the_pinned_layout_and_decodes_to_its_fields() {
    for (byte, reason, effect) in WIRE_POLICY {
        let written = TombstoneValueV2 {
            reason,
            deleted_at: 0x0102_0304_0506_0708,
            request_id: *b"0123456789abcdef",
        };

        let wire = written.encode();

        assert_eq!(
            wire.len(),
            CURRENT_LEN,
            "{reason:?}: the encoder writes 25 bytes"
        );
        assert_eq!(wire[0], byte, "{reason:?}: byte 0 is the policy's byte");
        assert_eq!(
            wire[1..9],
            [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            "{reason:?}: bytes 1..9 are deleted_at, little-endian"
        );
        assert_eq!(
            &wire[9..25],
            b"0123456789abcdef",
            "{reason:?}: bytes 9..25 are the request_id"
        );

        let decoded = decode_tombstone_value(&wire);
        assert_eq!(
            decoded.reason,
            Some(reason),
            "{reason:?}: the reason comes back"
        );
        assert_eq!(
            decoded.deleted_at, written.deleted_at,
            "{reason:?}: deleted_at comes back"
        );
        assert_eq!(
            decoded.request_id,
            Some(written.request_id),
            "{reason:?}: request_id comes back"
        );
        assert_eq!(
            decoded.is_hard(),
            effect == WireEffect::Hard,
            "{reason:?}: the policy's effect"
        );
    }
}
