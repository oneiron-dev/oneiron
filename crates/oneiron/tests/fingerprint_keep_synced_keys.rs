//! K-proof (oracle) for PLAN-UC-04 stage 5b: the index keys peers recompute keep their
//! bytes.
//!
//! A split custody input's part key (`purposes::secret::CUSTODY_INPUT_PART_KEY`), a custody
//! input witness's part key (`purposes::secret::CUSTODY_WITNESS_PART_KEY`) and a workplace
//! filing's intent key (`purposes::workspace_roster::WORKPLACE_JOIN_INTENT_KEY`) now start
//! their BLAKE3 through the fingerprint crate's K door. Each is a stored row's key that
//! leaves the machine: sync sends custody rows to peers under their part keys, and a peer
//! recomputes the key and refuses a row filed under another one; join receipts carry the
//! intent key to the house's other machines. So each must give main's bytes for every
//! value. The `base_*` modules hold main's lines at e8ab7831950c, copied by range (each range is
//! named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation. The few lines around the copies are a stand-in witness that holds the
//! three fields the part key reads, and wrappers and aliases that carry main's private fns
//! and tags to the tests.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_synced_keys`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::test_doors::fingerprint_keep_synced_keys as door;
use oneiron::workspace_roster::JoinSubject;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_input {
    /// Main's tag, which is private there.
    // main e8ab7831950c: crates/oneiron/src/secret_custody/control/input.rs:130-130
    const PART_KEY_DOMAIN: &[u8] = b"oneiron/custody-input-part-key/v1";

    // main e8ab7831950c: crates/oneiron/src/secret_custody/control/input.rs:317-325
    /// The key part `index` of the split input the request names `digest` of
    /// is kept and relayed under.
    fn part_key(digest: &[u8; 32], index: u32) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PART_KEY_DOMAIN);
        hasher.update(digest);
        hasher.update(&index.to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Main's input part key, which is private there.
    pub(crate) fn main_custody_input_part_key(digest: &[u8; 32], index: u32) -> [u8; 32] {
        part_key(digest, index)
    }

    /// The tag's bytes, for the tag test outside this module.
    pub(crate) const MAIN_PART_KEY_DOMAIN: &[u8] = PART_KEY_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_witness {
    /// Main's tag, which is private there.
    // main e8ab7831950c: crates/oneiron/src/secret_custody/control/input/witness.rs:56-56
    const KEY_DOMAIN: &[u8] = b"oneiron/custody-input-witness-part-key/v1";

    /// A stand-in for main's `WitnessGroup`: the three fields its part key reads, by main's
    /// names and types (`AuthorityEntryHash` is `[u8; 32]`).
    pub(crate) struct WitnessGroup {
        request: [u8; 32],
        input: [u8; 32],
        commitment: [u8; 32],
    }

    impl WitnessGroup {
        // main e8ab7831950c: crates/oneiron/src/secret_custody/control/input/witness.rs:137-146
            /// The key part `index` of this witness is kept and relayed under.
            fn part_key(&self, index: u32) -> [u8; 32] {
                let mut hasher = blake3::Hasher::new();
                hasher.update(KEY_DOMAIN);
                hasher.update(&self.request);
                hasher.update(&self.input);
                hasher.update(&self.commitment);
                hasher.update(&index.to_be_bytes());
                *hasher.finalize().as_bytes()
            }
    }

    /// Main's witness part key, which is private there.
    pub(crate) fn main_custody_witness_part_key(request: &[u8; 32], input: &[u8; 32], commitment: &[u8; 32], index: u32) -> [u8; 32] {
        WitnessGroup { request: *request, input: *input, commitment: *commitment }.part_key(index)
    }

    /// The tag's bytes, for the tag test outside this module.
    pub(crate) const MAIN_KEY_DOMAIN: &[u8] = KEY_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_workplace {
    use oneiron::EntityId;
    use oneiron::workspace_roster::JoinSubject;

    // main e8ab7831950c: crates/oneiron/src/workspace_roster/workplace_join.rs:26-45
    /// Why a workplace filing is made: the purpose its intent key names.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Purpose {
        /// The house mind joins a project home room whose roster seats it.
        House,
        /// A companion follows her principal into a room.
        Companion,
        /// A roster update newly seats a member in a project home room.
        Member,
    }

    impl Purpose {
        const fn as_str(self) -> &'static str {
            match self {
                Self::House => "workplace.house",
                Self::Companion => "workplace.companion",
                Self::Member => "workplace.member",
            }
        }
    }

    // main e8ab7831950c: crates/oneiron/src/workspace_roster/workplace_join.rs:47-62
    /// The filing's idempotency key: its purpose, then a digest of the purpose,
    /// room and subject, all printable bytes as OF-531 asks. The same
    /// filing replays its join; the decision is re-proved live on every use.
    fn intent_key(purpose: Purpose, room: EntityId, subject: &JoinSubject) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.workplace.join.v1");
        hasher.update(purpose.as_str().as_bytes());
        hasher.update(room.as_bytes());
        hasher.update(&[match subject {
            JoinSubject::Person(_) => 1,
            JoinSubject::Agent(_) => 2,
        }]);
        hasher.update(subject.id().as_bytes());
        let digest = hasher.finalize().to_hex();
        format!("{}:{}", purpose.as_str(), &digest[..32])
    }

    /// Main's three purposes' texts, and each one's intent key, which is private there.
    pub(crate) fn main_workplace_join_intent_keys(room: EntityId, subject: &JoinSubject) -> Vec<(&'static str, String)> {
        [Purpose::House, Purpose::Companion, Purpose::Member]
            .into_iter()
            .map(|purpose| (purpose.as_str(), intent_key(purpose, room, subject)))
            .collect()
    }
}

/// 32-byte values with the edge rows: all zero, all `0xFF`, a counting run and a constant.
fn digests() -> [[u8; 32]; 4] {
    let mut counting = [0_u8; 32];
    for (at, byte) in counting.iter_mut().enumerate() {
        *byte = u8::try_from(at).expect("32 fits a byte");
    }
    [[0; 32], [0xff; 32], counting, [0x5a; 32]]
}

/// Part indexes: the first, the second, a byte boundary, a high one and the largest.
const INDEXES: [u32; 6] = [0, 1, 255, 256, 65_536, u32::MAX];

/// Entity ids with the edge rows: all zero, all `0xFF` (reserved at the public layer, so
/// built unchecked) and two ordinary ids.
fn entity_ids() -> Vec<EntityId> {
    [[0_u8; 16], [0xff; 16], *b"0123456789abcdef", [7; 16]]
        .into_iter()
        .map(EntityId::from_bytes_unchecked)
        .collect()
}

fn purpose_shape(purpose: LegacyPurpose) -> (LegacyHash, TagMode) {
    (purpose.hash(), purpose.tag_mode())
}

#[test]
fn the_synced_key_purposes_keep_main_s_tags() {
    assert_eq!(
        purposes::secret::CUSTODY_INPUT_PART_KEY.tag().as_bytes(),
        base_input::MAIN_PART_KEY_DOMAIN
    );
    assert_eq!(
        purposes::secret::CUSTODY_WITNESS_PART_KEY.tag().as_bytes(),
        base_witness::MAIN_KEY_DOMAIN
    );
    for purpose in [
        purposes::secret::CUSTODY_INPUT_PART_KEY,
        purposes::secret::CUSTODY_WITNESS_PART_KEY,
        purposes::workspace_roster::WORKPLACE_JOIN_INTENT_KEY,
    ] {
        assert_eq!(
            purpose_shape(purpose),
            (LegacyHash::Blake3, TagMode::HashedFirst)
        );
    }
}

#[test]
fn the_custody_input_part_key_keeps_its_bytes() {
    let mut rows = 0;
    for digest in digests() {
        for index in INDEXES {
            assert_eq!(
                door::custody_input_part_key(&digest, index),
                base_input::main_custody_input_part_key(&digest, index),
                "digest {digest:?}, index {index}"
            );
            rows += 1;
        }
    }
    assert_eq!(rows, 24);
}

#[test]
fn the_custody_witness_part_key_keeps_its_bytes() {
    let values = digests();
    let mut rows = 0;
    for request in &values {
        for input in &values {
            for commitment in &values {
                for index in INDEXES {
                    assert_eq!(
                        door::custody_witness_part_key(request, input, commitment, index),
                        base_witness::main_custody_witness_part_key(
                            request, input, commitment, index
                        ),
                        "request {request:?}, input {input:?}, commitment {commitment:?}, index {index}"
                    );
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(rows, 384);
}

#[test]
fn the_workplace_join_intent_key_keeps_its_bytes() {
    let mut rows = 0;
    for room in entity_ids() {
        for id in entity_ids() {
            for subject in [JoinSubject::Person(id), JoinSubject::Agent(id)] {
                let main = base_workplace::main_workplace_join_intent_keys(room, &subject);
                assert_eq!(main.len(), 3);
                for (purpose, key) in main {
                    assert_eq!(
                        door::workplace_join_intent_key(purpose, room, &subject),
                        Some(key),
                        "purpose {purpose}, room {room:?}, subject {subject:?}"
                    );
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(rows, 96);
    assert_eq!(
        door::workplace_join_intent_key(
            "workplace.guest",
            entity_ids()[2],
            &JoinSubject::Person(entity_ids()[3])
        ),
        None
    );
}
