//! K-proof (oracle) for PLAN-UC-04 stage 6.1b: three custody digest helpers keep their bytes.
//!
//! A custody input witness's commitment, fragment and row digests
//! (`purposes::secret::{CUSTODY_WITNESS_COMMITMENT, CUSTODY_WITNESS_FRAGMENT,
//! CUSTODY_WITNESS_ROW}`), a subject restore review's digest of a stored raw row
//! (`purposes::subject_model::ARCHIVE_REVIEW`) and a key custody head's compartment and
//! carried compartment commitments (`purposes::key_custody::{COMPARTMENT_DIGEST,
//! CARRIED_DIGEST}`) now start their hash through the fingerprint crate's K door. Each is
//! signed, stored or compared against a stored value: the witness digests sit in signed
//! rows that peers relay and check, a restore review's digests are compared with the rows'
//! digests now and kept as the restored claim's evidence, and a head's control compartment
//! commits to its compartments' digests, which every check of the head recomputes. So each
//! must give main's bytes for every input. The `base_*` modules hold main's lines at
//! 1a9b49b8f1be, copied by range (each range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation. The few lines around the copies are wrappers that carry main's private
//! fns and tags to the tests, and stand-ins for the head's error type and its corrupt-head
//! error, which main's commitment returns when a wire does not encode.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_custody_digests`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::fingerprint_keep_custody_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_witness {
    /// Main's tags, which are private there.
    // main 1a9b49b8f1be: crates/oneiron/src/secret_custody/control/input/witness.rs:57-59
    const COMMIT_DOMAIN: &[u8] = b"oneiron/custody-input-witness-commitment/v1";
    const FRAGMENT_DOMAIN: &[u8] = b"oneiron/custody-input-witness-fragment/v1";
    const ROW_DOMAIN: &[u8] = b"oneiron/custody-input-witness-row/v1";

    // main 1a9b49b8f1be: crates/oneiron/src/secret_custody/control/input/witness.rs:90-96
    fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        *hasher.finalize().as_bytes()
    }

    /// Main's commitment, fragment and row digests of `bytes`, which are private there.
    pub(crate) fn main_witness_digests(bytes: &[u8]) -> [[u8; 32]; 3] {
        [digest(COMMIT_DOMAIN, bytes), digest(FRAGMENT_DOMAIN, bytes), digest(ROW_DOMAIN, bytes)]
    }

    /// The tags' bytes, in the same order, for the tag test outside this module.
    pub(crate) const MAIN_TAGS: [&[u8]; 3] = [COMMIT_DOMAIN, FRAGMENT_DOMAIN, ROW_DOMAIN];
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_archive {
    // main 1a9b49b8f1be: crates/oneiron/src/subject_model/archive.rs:177-180
    fn digest(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    /// Main's restore review digest of a stored raw row, which is private there.
    pub(crate) fn main_archive_review_digest(bytes: &[u8]) -> [u8; 32] {
        digest(bytes)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_carried_pads {
    use serde::Serialize;

    /// A stand-in for main's error.
    #[derive(Debug)]
    pub(crate) struct Corrupt;

    /// A stand-in for main's `Result`.
    type Result<T> = std::result::Result<T, Corrupt>;

    /// A stand-in for main's corrupt-head error.
    fn head_corrupt() -> Corrupt {
        Corrupt
    }

    /// Main's contexts, in the head's store half.
    // main 1a9b49b8f1be: crates/oneiron-store/src/key_custody/head/carried_pads.rs:34-34
    pub const COMPARTMENT_DIGEST_CONTEXT: &str = "oneiron/custody-head/compartment-digest/v2";
    // main 1a9b49b8f1be: crates/oneiron-store/src/key_custody/head/carried_pads.rs:36-36
    pub const CARRIED_DIGEST_CONTEXT: &str = "oneiron/custody-head/carried-digest/v2";

    // main 1a9b49b8f1be: crates/oneiron/src/store/key_custody/head/carried_pads.rs:70-76
    fn digest(context: &str, wire: &impl Serialize) -> Result<[u8; 32]> {
        let bytes = rmp_serde::to_vec_named(wire).map_err(|_| head_corrupt())?;
        Ok(*blake3::Hasher::new_derive_key(context)
            .update(&bytes)
            .finalize()
            .as_bytes())
    }

    /// Main's compartment and carried commitments over `wire`, which are private there.
    pub(crate) fn main_custody_head_digests(wire: &impl Serialize) -> ([u8; 32], [u8; 32]) {
        (
            digest(COMPARTMENT_DIGEST_CONTEXT, wire).expect("the stand-in wire encodes"),
            digest(CARRIED_DIGEST_CONTEXT, wire).expect("the stand-in wire encodes"),
        )
    }
}

/// A stand-in wire with named fields, as main's wires encode theirs: its bytes, a number,
/// an optional label and numbered parts.
#[derive(serde::Serialize)]
struct Wire {
    body: Vec<u8>,
    at: u64,
    label: Option<String>,
    parts: Vec<(u32, Vec<u8>)>,
}

/// Byte strings with the edge rows: empty, a NUL, one byte, an inner NUL, non-ASCII text,
/// a string and its extension, JSON, bytes that are not UTF-8, and a long run.
fn texts() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0],
        b"a".to_vec(),
        b"a\0b".to_vec(),
        "na\u{ef}ve \u{6f22}\u{5b57} \u{1f642}".as_bytes().to_vec(),
        b"part".to_vec(),
        b"part:1".to_vec(),
        br#"{"origins":["https://a.example"],"routes":[]}"#.to_vec(),
        vec![0xff; 255],
        vec![b'x'; 4096],
    ]
}

/// Two wires per text: the text as the body alone, and the text as the label and both
/// parts beside an empty body.
fn wires() -> Vec<Wire> {
    let mut wires = Vec::new();
    for (at, body) in (0_u64..).zip(texts()) {
        wires.push(Wire {
            body: body.clone(),
            at,
            label: None,
            parts: Vec::new(),
        });
        wires.push(Wire {
            body: Vec::new(),
            at: u64::MAX - at,
            label: Some(String::from_utf8_lossy(&body).into_owned()),
            parts: vec![(0, body.clone()), (u32::MAX, body)],
        });
    }
    wires
}

/// The witness purposes, in the order of `base_witness::MAIN_TAGS`.
fn witness_purposes() -> [LegacyPurpose; 3] {
    [
        purposes::secret::CUSTODY_WITNESS_COMMITMENT,
        purposes::secret::CUSTODY_WITNESS_FRAGMENT,
        purposes::secret::CUSTODY_WITNESS_ROW,
    ]
}

fn purpose_shape(purpose: LegacyPurpose) -> (LegacyHash, TagMode) {
    (purpose.hash(), purpose.tag_mode())
}

#[test]
fn the_custody_digest_purposes_keep_main_s_tags() {
    for (purpose, tag) in witness_purposes().into_iter().zip(base_witness::MAIN_TAGS) {
        assert_eq!(purpose.tag().as_bytes(), tag);
        assert_eq!(
            purpose_shape(purpose),
            (LegacyHash::Blake3, TagMode::HashedFirst)
        );
    }
    assert_eq!(
        purposes::key_custody::COMPARTMENT_DIGEST.tag(),
        base_carried_pads::COMPARTMENT_DIGEST_CONTEXT
    );
    assert_eq!(
        purposes::key_custody::CARRIED_DIGEST.tag(),
        base_carried_pads::CARRIED_DIGEST_CONTEXT
    );
    for purpose in [
        purposes::key_custody::COMPARTMENT_DIGEST,
        purposes::key_custody::CARRIED_DIGEST,
    ] {
        assert_eq!(
            purpose_shape(purpose),
            (LegacyHash::Blake3, TagMode::DeriveKeyContext)
        );
    }
    assert_eq!(
        purpose_shape(purposes::subject_model::ARCHIVE_REVIEW),
        (LegacyHash::Sha256, TagMode::NotHashed)
    );
}

#[test]
fn the_witness_digests_keep_their_bytes() {
    let mut rows = 0;
    for bytes in texts() {
        let main = base_witness::main_witness_digests(&bytes);
        for (purpose, main) in witness_purposes().into_iter().zip(main) {
            assert_eq!(door::custody_witness_digest(purpose, &bytes), main);
            rows += 1;
        }
    }
    assert_eq!(rows, 30);
}

#[test]
fn the_archive_review_digest_keeps_its_bytes() {
    for bytes in texts() {
        assert_eq!(
            door::archive_review_digest(&bytes),
            base_archive::main_archive_review_digest(&bytes)
        );
    }
}

#[test]
fn the_custody_head_digests_keep_their_bytes() {
    let wires = wires();
    assert_eq!(wires.len(), 20);
    for wire in &wires {
        let (compartment, carried) = base_carried_pads::main_custody_head_digests(wire);
        assert_eq!(
            door::custody_head_digest(purposes::key_custody::COMPARTMENT_DIGEST, wire)
                .expect("the stand-in wire encodes"),
            compartment
        );
        assert_eq!(
            door::custody_head_digest(purposes::key_custody::CARRIED_DIGEST, wire)
                .expect("the stand-in wire encodes"),
            carried
        );
    }
    for bytes in texts() {
        let (compartment, carried) = base_carried_pads::main_custody_head_digests(&bytes);
        assert_eq!(
            door::custody_head_digest(purposes::key_custody::COMPARTMENT_DIGEST, &bytes)
                .expect("bytes encode"),
            compartment
        );
        assert_eq!(
            door::custody_head_digest(purposes::key_custody::CARRIED_DIGEST, &bytes)
                .expect("bytes encode"),
            carried
        );
    }
}
