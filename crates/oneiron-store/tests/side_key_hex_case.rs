//! UC-06 PR 0a (HEX-CASE-POLICY = A, Engine RULING 14:31 Sun 15 Nov: "Stored and wire forms
//! stay lowercase-only"): each `oneiron-store` side-table key that spells a hex part decodes
//! only the lowercase digits its encoder writes. A side-table key is a stored form.
//!
//! On main `HexId`, the window keys and `Hex64` decode upper-case hex, and `HexSeqKey`,
//! `WindowUpdateKey` and `Hex64` also decode a `+` digit (`from_str_radix` takes a sign), so
//! the `*_refuses_*` tests fail there. The lowercase spelling each encoder writes decodes on
//! main and on the PR.
//!
//! The window keys are compiled with the `sync` feature, as `window_rows` is.
//!
//! Run: `cargo test --locked -p oneiron-store --all-features --test side_key_hex_case`.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::batch::export::foreign_stage::export_foreign_receipt::Hex64;
use oneiron_store::side_table::key::{HexId, SideKey};

const ID_LOWER: &str = "0123456789abcdef0123456789abcdef";
const ID_UPPER: &str = "0123456789ABCDEF0123456789ABCDEF";
/// One upper-case digit in the last place: a key that is otherwise the encoder's spelling.
const ID_ONE_UPPER: &str = "0123456789abcdef0123456789abcdeF";
const HASH_LOWER: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const HASH_UPPER: &str = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
/// The first byte spelled `+0`, which `u8::from_str_radix` reads as 0.
const HASH_SIGNED: &str = "+0112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn id() -> EntityId {
    EntityId::from_hex(ID_LOWER).expect("fixture id is not a sentinel")
}

fn encoded<K: SideKey>(key: &K) -> Vec<u8> {
    let mut out = Vec::new();
    key.encode_into(&mut out);
    out
}

fn hash() -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::try_from(index % 16).unwrap() * 0x11;
    }
    out
}

#[test]
fn hex_id_decodes_the_lowercase_it_writes() {
    assert_eq!(encoded(&HexId(id())), ID_LOWER.as_bytes());
    assert_eq!(HexId::decode_key(ID_LOWER.as_bytes()), Some(HexId(id())));
}

#[test]
fn hex_id_refuses_upper_case_hex() {
    assert_eq!(HexId::decode_key(ID_UPPER.as_bytes()), None);
    assert_eq!(HexId::decode_key(ID_ONE_UPPER.as_bytes()), None);
}

#[test]
fn hex_id_refuses_a_signed_digit() {
    assert_eq!(HexId::decode_key(b"+123456789abcdef0123456789abcdef"), None);
}

#[cfg(feature = "sync")]
mod window_rows {
    use super::{ID_LOWER, ID_ONE_UPPER, ID_UPPER, encoded, id};
    use oneiron_store::side_table::key::SideKey;
    use oneiron_store::window_rows::{HexSeqKey, WindowEntityHexKey, WindowUpdateKey};

    #[test]
    fn hex_seq_key_decodes_the_lowercase_it_writes() {
        assert_eq!(encoded(&HexSeqKey(0x00ab_cdef)), b"00abcdef");
        assert_eq!(
            HexSeqKey::decode_key(b"00abcdef"),
            Some(HexSeqKey(0x00ab_cdef))
        );
        assert_eq!(
            HexSeqKey::decode_key(b"ffffffff"),
            Some(HexSeqKey(u32::MAX))
        );
    }

    #[test]
    fn hex_seq_key_refuses_upper_case_hex() {
        assert_eq!(HexSeqKey::decode_key(b"00ABCDEF"), None);
    }

    #[test]
    fn hex_seq_key_refuses_a_signed_digit() {
        assert_eq!(HexSeqKey::decode_key(b"+0abcdef"), None);
    }

    #[test]
    fn window_update_key_decodes_the_lowercase_it_writes() {
        let key = WindowUpdateKey {
            window: "2026-11".to_owned(),
            seq: 0x00ab_cdef,
        };
        assert_eq!(encoded(&key), b"2026-11:0000000000abcdef");
        assert_eq!(
            WindowUpdateKey::decode_key(b"2026-11:0000000000abcdef"),
            Some(key)
        );
        assert_eq!(
            WindowUpdateKey::decode_key(b"2026-11:ffffffffffffffff").map(|key| key.seq),
            Some(u64::MAX)
        );
    }

    #[test]
    fn window_update_key_refuses_upper_case_hex() {
        assert_eq!(
            WindowUpdateKey::decode_key(b"2026-11:0000000000ABCDEF"),
            None
        );
    }

    #[test]
    fn window_update_key_refuses_a_signed_digit() {
        assert_eq!(
            WindowUpdateKey::decode_key(b"2026-11:+000000000abcdef"),
            None
        );
    }

    #[test]
    fn window_entity_keys_decode_the_lowercase_they_write() {
        let hex_key = WindowEntityHexKey {
            window: "2026-11".to_owned(),
            id: id(),
        };
        let spelled = format!("2026-11:{ID_LOWER}");
        assert_eq!(encoded(&hex_key), spelled.as_bytes());
        assert_eq!(
            WindowEntityHexKey::decode_key(spelled.as_bytes()),
            Some(hex_key)
        );
    }

    #[test]
    fn window_entity_keys_refuse_upper_case_hex() {
        for id_text in [ID_UPPER, ID_ONE_UPPER] {
            let spelled = format!("2026-11:{id_text}");
            assert_eq!(WindowEntityHexKey::decode_key(spelled.as_bytes()), None);
        }
    }
}

#[test]
fn hex64_decodes_the_lowercase_it_writes() {
    assert_eq!(encoded(&Hex64(hash())), HASH_LOWER.as_bytes());
    assert_eq!(
        Hex64::decode_key(HASH_LOWER.as_bytes()).map(|key| key.0),
        Some(hash())
    );
}

#[test]
fn hex64_refuses_upper_case_hex() {
    assert!(Hex64::decode_key(HASH_UPPER.as_bytes()).is_none());
}

#[test]
fn hex64_refuses_a_signed_digit() {
    assert!(Hex64::decode_key(HASH_SIGNED.as_bytes()).is_none());
}
