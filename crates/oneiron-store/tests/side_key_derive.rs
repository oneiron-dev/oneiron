//! UC-06 PR 0b: `#[derive(SideKey)]` spells and reads a key exactly as the hand-written impl it
//! will replace. One pair or more per shape class of the UC-06 plan (its re-measure REPORT §2):
//! separator-joined, fixed width, split from the end, length-prefixed and hex text, plus a key
//! with an inner prefix. Each pair is compared on the bytes of fixture keys (an empty variable
//! part, a variable part holding the separator, the largest integers) and on the verdict for
//! malformed inputs (one byte short, one trailing byte, the wrong separator, upper-case hex, a
//! `+` digit, a reserved id, text that is not UTF-8).
//!
//! The store's own public keys are compared with their impls on this branch. Three keys of the
//! `oneiron` crate (length-prefixed and prefixed) are private there, so their impls are copied
//! here verbatim from main ea1e495a6605, with the file and lines named at each copy.
//!
//! On main this file does not compile (no derive). The window keys are compiled with the `sync`
//! feature, as `window_rows` is.
//!
//! Run: `cargo test --locked -p oneiron-store --all-features --test side_key_derive`.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::batch::export::foreign_stage::export_foreign_receipt::Hex64;
use oneiron_store::entity_doc::side_keys::HexPair;
use oneiron_store::origin::publication::publication_codec::VisibleRefKey;
use oneiron_store::query_memos::VerdictMemoKey;
use oneiron_store::side_table::key::{FixedSideKey, HexId, HexLower, SideKey};

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("fixture id is not a reserved id")
}

fn spelled<K: SideKey>(key: &K) -> Vec<u8> {
    let mut out = Vec::new();
    key.encode_into(&mut out);
    out
}

/// The hand impl `H` and the derived `D` give one verdict on `input`: both refuse it, or both
/// read a key that spells the same bytes. Returns that verdict.
fn verdict<H: SideKey, D: SideKey>(input: &[u8]) -> Option<Vec<u8>> {
    let hand = H::decode_key(input).map(|key| spelled(&key));
    let derived = D::decode_key(input).map(|key| spelled(&key));
    let shown = String::from_utf8_lossy(input);
    assert_eq!(
        hand, derived,
        "hand and derived decodes differ on {shown:?}"
    );
    derived
}

fn accepts<H: SideKey, D: SideKey>(input: &[u8]) {
    let shown = String::from_utf8_lossy(input);
    assert_eq!(
        verdict::<H, D>(input),
        Some(input.to_vec()),
        "{shown:?} decodes and spells itself again"
    );
}

fn refuses<H: SideKey, D: SideKey>(input: &[u8]) {
    let shown = String::from_utf8_lossy(input);
    assert_eq!(verdict::<H, D>(input), None, "{shown:?} is refused");
}

fn joined(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

// Separator-joined, every part fixed width: `hex32(a) ":" hex32(b)`.
#[derive(SideKey)]
#[side_key(sep = b':')]
struct DerivedHexPair(HexId, HexId);

#[test]
fn hex_pair_spells_and_reads_as_the_hand_impl() {
    let hand = HexPair(HexId(id(0x11)), HexId(id(0x22)));
    let derived = DerivedHexPair(HexId(id(0x11)), HexId(id(0x22)));
    let bytes = format!("{}:{}", "11".repeat(16), "22".repeat(16)).into_bytes();
    assert_eq!(spelled(&hand), bytes);
    assert_eq!(spelled(&derived), bytes);
    assert_eq!(DerivedHexPair::WIDTH, 65);
    accepts::<HexPair, DerivedHexPair>(&bytes);
    refuses::<HexPair, DerivedHexPair>(&bytes[..64]);
    refuses::<HexPair, DerivedHexPair>(&joined(&[&bytes, b"2"]));
    refuses::<HexPair, DerivedHexPair>(
        format!("{}/{}", "11".repeat(16), "22".repeat(16)).as_bytes(),
    );
    refuses::<HexPair, DerivedHexPair>(
        format!("{}:{}", "AA".repeat(16), "22".repeat(16)).as_bytes(),
    );
    refuses::<HexPair, DerivedHexPair>(
        format!("+{}:{}", "1".repeat(31), "22".repeat(16)).as_bytes(),
    );
    refuses::<HexPair, DerivedHexPair>(
        format!("{}:{}", "00".repeat(16), "22".repeat(16)).as_bytes(),
    );
    refuses::<HexPair, DerivedHexPair>(b"");
}

// Separator-joined with a variable tail: repo id, NUL, ref name.
#[derive(SideKey)]
#[side_key(sep = b'\0')]
struct DerivedVisibleRefKey {
    repo_id: EntityId,
    #[side_key(rest)]
    ref_name: String,
}

#[test]
fn visible_ref_key_spells_and_reads_as_the_hand_impl() {
    let hand = VisibleRefKey {
        repo_id: id(0x11),
        ref_name: "refs/heads/main".to_owned(),
    };
    let derived = DerivedVisibleRefKey {
        repo_id: id(0x11),
        ref_name: "refs/heads/main".to_owned(),
    };
    let bytes = joined(&[&[0x11; 16], b"\0refs/heads/main"]);
    assert_eq!(spelled(&hand), bytes);
    assert_eq!(spelled(&derived), bytes);
    accepts::<VisibleRefKey, DerivedVisibleRefKey>(&bytes);
    accepts::<VisibleRefKey, DerivedVisibleRefKey>(&joined(&[&[0x11; 16], b"\0"]));
    accepts::<VisibleRefKey, DerivedVisibleRefKey>(&joined(&[&[0x11; 16], b"\0a\0b"]));
    refuses::<VisibleRefKey, DerivedVisibleRefKey>(&[0x11; 15]);
    refuses::<VisibleRefKey, DerivedVisibleRefKey>(&[0x11; 16]);
    refuses::<VisibleRefKey, DerivedVisibleRefKey>(&joined(&[&[0x11; 16], b":main"]));
    refuses::<VisibleRefKey, DerivedVisibleRefKey>(&joined(&[&[0; 16], b"\0main"]));
    refuses::<VisibleRefKey, DerivedVisibleRefKey>(&joined(&[&[0x11; 16], b"\0\xff"]));
}

// Fixed width, no separator: query id, entity id, evidence hash.
#[derive(SideKey)]
struct DerivedVerdictMemoKey {
    query_ref: EntityId,
    entity_ref: EntityId,
    evidence_hash: [u8; 32],
}

#[test]
fn verdict_memo_key_spells_and_reads_as_the_hand_impl() {
    let hand = VerdictMemoKey {
        query_ref: id(0x11),
        entity_ref: id(0x22),
        evidence_hash: [0x33; 32],
    };
    let derived = DerivedVerdictMemoKey {
        query_ref: id(0x11),
        entity_ref: id(0x22),
        evidence_hash: [0x33; 32],
    };
    let bytes = joined(&[&[0x11; 16], &[0x22; 16], &[0x33; 32]]);
    assert_eq!(spelled(&hand), bytes);
    assert_eq!(spelled(&derived), bytes);
    assert_eq!(DerivedVerdictMemoKey::WIDTH, 64);
    accepts::<VerdictMemoKey, DerivedVerdictMemoKey>(&bytes);
    refuses::<VerdictMemoKey, DerivedVerdictMemoKey>(&bytes[..63]);
    refuses::<VerdictMemoKey, DerivedVerdictMemoKey>(&joined(&[&bytes, &[0]]));
    refuses::<VerdictMemoKey, DerivedVerdictMemoKey>(&joined(&[
        &[0; 16],
        &[0x22; 16],
        &[0x33; 32],
    ]));
    refuses::<VerdictMemoKey, DerivedVerdictMemoKey>(&joined(&[
        &[0x11; 16],
        &[0xff; 16],
        &[0x33; 32],
    ]));
}

/// Split from the end, and hex text: the `window_rows` keys.
#[cfg(feature = "sync")]
mod window_rows {
    use super::{accepts, id, joined, refuses, spelled};
    use oneiron_contracts::entity_id::EntityId;
    use oneiron_store::side_table::key::{HexId, HexU32, HexU64, SideKey};
    use oneiron_store::window_rows::{HexSeqKey, WindowEntityHexKey, WindowUpdateKey};

    // A window that may hold `:`, then `:` and a fixed-width id read from the end.
    #[derive(SideKey)]
    #[side_key(sep = b':')]
    struct DerivedWindowEntityHexKey {
        #[side_key(rest)]
        window: String,
        #[side_key(with = HexId)]
        id: EntityId,
    }

    // A window, then `:` and a 16-hex-digit sequence number read from the end.
    #[derive(SideKey)]
    #[side_key(sep = b':')]
    struct DerivedWindowUpdateKey {
        #[side_key(rest)]
        window: String,
        #[side_key(with = HexU64)]
        seq: u64,
    }

    // Hex text: a u32 as 8 lower-case hex characters.
    #[derive(SideKey)]
    struct DerivedHexSeqKey(#[side_key(with = HexU32)] u32);

    #[test]
    fn window_entity_hex_key_spells_and_reads_as_the_hand_impl() {
        type Hand = WindowEntityHexKey;
        type Derived = DerivedWindowEntityHexKey;
        let hand = WindowEntityHexKey {
            window: "2026-11".to_owned(),
            id: id(0x11),
        };
        let derived = DerivedWindowEntityHexKey {
            window: "2026-11".to_owned(),
            id: id(0x11),
        };
        let hex = "11".repeat(16);
        let bytes = format!("2026-11:{hex}").into_bytes();
        assert_eq!(spelled(&hand), bytes);
        assert_eq!(spelled(&derived), bytes);
        accepts::<Hand, Derived>(&bytes);
        accepts::<Hand, Derived>(format!(":{hex}").as_bytes());
        accepts::<Hand, Derived>(format!("a:b:{hex}").as_bytes());
        refuses::<Hand, Derived>(format!("w:{}", &hex[..31]).as_bytes());
        refuses::<Hand, Derived>(format!("w:{hex}1").as_bytes());
        refuses::<Hand, Derived>(format!("w/{hex}").as_bytes());
        refuses::<Hand, Derived>(hex.as_bytes());
        refuses::<Hand, Derived>(format!("w:{}", "AA".repeat(16)).as_bytes());
        refuses::<Hand, Derived>(format!("w:+{}", &hex[..31]).as_bytes());
        refuses::<Hand, Derived>(format!("w:{}", "00".repeat(16)).as_bytes());
        refuses::<Hand, Derived>(&joined(&[b"\xff:", hex.as_bytes()]));
    }

    #[test]
    fn window_update_key_spells_and_reads_as_the_hand_impl() {
        type Hand = WindowUpdateKey;
        type Derived = DerivedWindowUpdateKey;
        for (seq, digits) in [(7, "0000000000000007"), (u64::MAX, "ffffffffffffffff")] {
            let hand = WindowUpdateKey {
                window: "2026-11".to_owned(),
                seq,
            };
            let derived = DerivedWindowUpdateKey {
                window: "2026-11".to_owned(),
                seq,
            };
            let bytes = format!("2026-11:{digits}").into_bytes();
            assert_eq!(spelled(&hand), bytes);
            assert_eq!(spelled(&derived), bytes);
        }
        accepts::<Hand, Derived>(b"2026-11:0000000000000007");
        accepts::<Hand, Derived>(b":ffffffffffffffff");
        accepts::<Hand, Derived>(b"a:b:0000000000000007");
        refuses::<Hand, Derived>(b"2026-11:000000000000007");
        refuses::<Hand, Derived>(b"2026-11:00000000000000007");
        refuses::<Hand, Derived>(b"2026-11/0000000000000007");
        refuses::<Hand, Derived>(b"0000000000000007");
        refuses::<Hand, Derived>(b"2026-11:000000000000000A");
        refuses::<Hand, Derived>(b"2026-11:+000000000000007");
        refuses::<Hand, Derived>(b"\xff:0000000000000007");
    }

    #[test]
    fn hex_seq_key_spells_and_reads_as_the_hand_impl() {
        type Hand = HexSeqKey;
        type Derived = DerivedHexSeqKey;
        for (seq, digits) in [(7, "00000007"), (u32::MAX, "ffffffff")] {
            assert_eq!(spelled(&HexSeqKey(seq)), digits.as_bytes());
            assert_eq!(spelled(&DerivedHexSeqKey(seq)), digits.as_bytes());
            accepts::<Hand, Derived>(digits.as_bytes());
        }
        refuses::<Hand, Derived>(b"0000007");
        refuses::<Hand, Derived>(b"000000007");
        refuses::<Hand, Derived>(b"0000000A");
        refuses::<Hand, Derived>(b"+0000007");
        refuses::<Hand, Derived>(b"-0000007");
    }
}

/// `BudgetReservationKey`, copied from `crates/oneiron/src/dreamer_runner/admission/mod.rs:72-94`
/// at main ea1e495a6605 (private there): a u16 length-prefixed budget id, then the attempt id.
struct HandBudgetReservationKey {
    budget_id: String,
    attempt_id: AttemptId,
}

impl SideKey for HandBudgetReservationKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        let budget_id_len = u16::try_from(self.budget_id.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&budget_id_len.to_be_bytes());
        out.extend_from_slice(self.budget_id.as_bytes());
        out.extend_from_slice(self.attempt_id.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (len_bytes, rest) = bytes.split_at_checked(2)?;
        let len = usize::from(u16::from_be_bytes(len_bytes.try_into().ok()?));
        let (id_bytes, attempt_bytes) = rest.split_at_checked(len)?;
        Some(Self {
            budget_id: String::from_utf8(id_bytes.to_vec()).ok()?,
            attempt_id: AttemptId::decode_key(attempt_bytes)?,
        })
    }
}

#[derive(SideKey)]
struct DerivedBudgetReservationKey {
    #[side_key(len = u16)]
    budget_id: String,
    attempt_id: AttemptId,
}

#[test]
fn length_prefixed_u16_key_spells_and_reads_as_the_hand_impl() {
    type Hand = HandBudgetReservationKey;
    type Derived = DerivedBudgetReservationKey;
    let attempt = || AttemptId::from_bytes(&[0x44; 16]).expect("16 bytes");
    for budget in ["night", ""] {
        let hand = HandBudgetReservationKey {
            budget_id: budget.to_owned(),
            attempt_id: attempt(),
        };
        let derived = DerivedBudgetReservationKey {
            budget_id: budget.to_owned(),
            attempt_id: attempt(),
        };
        let count = u16::try_from(budget.len()).expect("short").to_be_bytes();
        let bytes = joined(&[&count, budget.as_bytes(), &[0x44; 16]]);
        assert_eq!(spelled(&hand), bytes);
        assert_eq!(spelled(&derived), bytes);
        accepts::<Hand, Derived>(&bytes);
    }
    accepts::<Hand, Derived>(&joined(&[&[0, 3], b"a\0b", &[0x44; 16]]));
    refuses::<Hand, Derived>(&joined(&[&[0, 5], b"night", &[0x44; 15]]));
    refuses::<Hand, Derived>(&joined(&[&[0, 5], b"night", &[0x44; 17]]));
    refuses::<Hand, Derived>(&joined(&[&[0, 32], b"night", &[0x44; 16]]));
    refuses::<Hand, Derived>(&joined(&[&[0, 4], b"night", &[0x44; 16]]));
    refuses::<Hand, Derived>(&joined(&[&[0, 1], b"\xff", &[0x44; 16]]));
    refuses::<Hand, Derived>(&[0]);
}

/// `BlockKey`, copied from `crates/oneiron/src/context_board/plugin/state.rs:39-69` at main
/// ea1e495a6605 (private there; its `SectionId(String)` is a `String` here, the same bytes): the
/// actor id, a u64 length-prefixed section id, then the block ref.
struct HandBlockKey {
    actor: EntityId,
    section_id: String,
    block_ref: [u8; 16],
}

impl SideKey for HandBlockKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.actor.as_bytes());
        out.extend_from_slice(&(self.section_id.len() as u64).to_be_bytes());
        out.extend_from_slice(self.section_id.as_bytes());
        out.extend_from_slice(&self.block_ref);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (actor, rest) = bytes.split_at_checked(16)?;
        let actor = EntityId::from_bytes(actor.try_into().ok()?).ok()?;
        let (len, rest) = rest.split_at_checked(8)?;
        let len = u64::from_be_bytes(len.try_into().ok()?);
        let len = usize::try_from(len).ok()?;
        let (section, rest) = rest.split_at_checked(len)?;
        let section_id = std::str::from_utf8(section).ok()?.to_owned();
        let block_ref = rest.try_into().ok()?;
        Some(Self {
            actor,
            section_id,
            block_ref,
        })
    }
}

#[derive(SideKey)]
struct DerivedBlockKey {
    actor: EntityId,
    #[side_key(len = u64)]
    section_id: String,
    block_ref: [u8; 16],
}

#[test]
fn length_prefixed_u64_key_spells_and_reads_as_the_hand_impl() {
    type Hand = HandBlockKey;
    type Derived = DerivedBlockKey;
    let hand = HandBlockKey {
        actor: id(0x11),
        section_id: "notes".to_owned(),
        block_ref: [0x55; 16],
    };
    let derived = DerivedBlockKey {
        actor: id(0x11),
        section_id: "notes".to_owned(),
        block_ref: [0x55; 16],
    };
    let bytes = joined(&[&[0x11; 16], &5_u64.to_be_bytes(), b"notes", &[0x55; 16]]);
    assert_eq!(spelled(&hand), bytes);
    assert_eq!(spelled(&derived), bytes);
    accepts::<Hand, Derived>(&bytes);
    accepts::<Hand, Derived>(&joined(&[&[0x11; 16], &0_u64.to_be_bytes(), &[0x55; 16]]));
    refuses::<Hand, Derived>(&bytes[..bytes.len() - 1]);
    refuses::<Hand, Derived>(&joined(&[&bytes, &[0]]));
    refuses::<Hand, Derived>(&joined(&[
        &[0x11; 16],
        &u64::MAX.to_be_bytes(),
        b"notes",
        &[0x55; 16],
    ]));
    refuses::<Hand, Derived>(&joined(&[
        &[0x11; 16],
        &4_u64.to_be_bytes(),
        b"notes",
        &[0x55; 16],
    ]));
    refuses::<Hand, Derived>(&joined(&[
        &[0; 16],
        &5_u64.to_be_bytes(),
        b"notes",
        &[0x55; 16],
    ]));
    refuses::<Hand, Derived>(&joined(&[
        &[0x11; 16],
        &1_u64.to_be_bytes(),
        b"\xff",
        &[0x55; 16],
    ]));
}

/// `OutboxKey`, copied from `crates/oneiron/src/calendar/connectors/outbound.rs:42,64-75` at main
/// ea1e495a6605 (private there): the tag `row:`, then 32 bytes.
struct HandOutboxKey([u8; 32]);

const OUTBOX_ROW_TAG: &[u8] = b"row:";

impl SideKey for HandOutboxKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(OUTBOX_ROW_TAG);
        out.extend_from_slice(&self.0);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.strip_prefix(OUTBOX_ROW_TAG)?.try_into().ok()?))
    }
}

#[derive(SideKey)]
#[side_key(prefix = b"row:")]
struct DerivedOutboxKey([u8; 32]);

#[test]
fn prefixed_key_spells_and_reads_as_the_hand_impl() {
    let bytes = joined(&[b"row:", &[0x66; 32]]);
    assert_eq!(spelled(&HandOutboxKey([0x66; 32])), bytes);
    assert_eq!(spelled(&DerivedOutboxKey([0x66; 32])), bytes);
    assert_eq!(DerivedOutboxKey::WIDTH, 36);
    accepts::<HandOutboxKey, DerivedOutboxKey>(&bytes);
    refuses::<HandOutboxKey, DerivedOutboxKey>(&bytes[..35]);
    refuses::<HandOutboxKey, DerivedOutboxKey>(&joined(&[&bytes, &[0]]));
    refuses::<HandOutboxKey, DerivedOutboxKey>(&joined(&[b"rox:", &[0x66; 32]]));
    refuses::<HandOutboxKey, DerivedOutboxKey>(&[0x66; 32]);
}

#[test]
fn a_derived_fixed_key_leads_a_tuple_key() {
    let key = (DerivedOutboxKey([0x66; 32]), 9_u64);
    let bytes = joined(&[b"row:", &[0x66; 32], &9_u64.to_be_bytes()]);
    assert_eq!(spelled(&key), bytes);
    let (outbox, count) = <(DerivedOutboxKey, u64)>::decode_key(&bytes).expect("decodes");
    assert_eq!((outbox.0, count), ([0x66; 32], 9));
}

// Hex text: 32 bytes as 64 lower-case hex characters.
#[derive(SideKey)]
struct DerivedHex64(#[side_key(with = HexLower<32>)] [u8; 32]);

#[test]
fn hex64_spells_and_reads_as_the_hand_impl() {
    let bytes = "ab".repeat(32).into_bytes();
    assert_eq!(spelled(&Hex64([0xab; 32])), bytes);
    assert_eq!(spelled(&DerivedHex64([0xab; 32])), bytes);
    assert_eq!(DerivedHex64::WIDTH, 64);
    accepts::<Hex64, DerivedHex64>(&bytes);
    refuses::<Hex64, DerivedHex64>(&bytes[..63]);
    refuses::<Hex64, DerivedHex64>(&joined(&[&bytes, b"a"]));
    refuses::<Hex64, DerivedHex64>("AB".repeat(32).as_bytes());
    refuses::<Hex64, DerivedHex64>(format!("+{}", "b".repeat(63)).as_bytes());
    refuses::<Hex64, DerivedHex64>(&joined(&[b"\xff", &bytes[1..]]));
}
