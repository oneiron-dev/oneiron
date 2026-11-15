//! PLAN-UC-04 stage 0: the rules of the fingerprint door, checked against hand-written
//! transcripts. (a) the framing laws, (b) the canonical record form, (c) each legacy
//! recipe kind. (d), two purposes with one string, is the `compile_fail` doc test on
//! `assert_distinct_contexts`.

use oneiron_fingerprint::purposes::testing::{
    ALPHA, BETA, BLAKE3_DERIVE_KEY, BLAKE3_NO_TAG, BLAKE3_TAG_FIRST, SHA256_NO_TAG,
    SHA256_TAG_FIRST,
};
use oneiron_fingerprint::{
    CanonicalBytesError, ContentHash, ContentHasher, Fingerprint, Fingerprinter, LegacyDigest,
    LegacyHash, Purpose, TagMode, canonical_bytes,
};
use serde::ser::{SerializeMap, Serializer};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::io::Write as _;

/// Part lists with the edge rows: no parts, empty parts, NULs, a long part, and two
/// lists whose concatenations are equal.
fn part_lists() -> Vec<Vec<Vec<u8>>> {
    vec![
        vec![],
        vec![vec![]],
        vec![vec![], vec![]],
        vec![b"a".to_vec()],
        vec![b"ab".to_vec()],
        vec![b"a".to_vec(), b"b".to_vec()],
        vec![b"ab".to_vec(), Vec::new()],
        vec![Vec::new(), b"ab".to_vec()],
        vec![vec![0; 32], vec![0xff; 16]],
        vec![b"a\0b".to_vec(), "\u{00e9}\u{6f22}".as_bytes().to_vec()],
        vec![u64::MAX.to_le_bytes().to_vec()],
        vec![vec![7; 4096]],
        (0..10_u8).map(|n| vec![n; usize::from(n)]).collect(),
    ]
}

/// The v1 rule by hand: derive-key with the context, each part as a u64-LE length and its bytes.
fn v1_by_hand(context: &str, parts: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn as_slices(parts: &[Vec<u8>]) -> Vec<&[u8]> {
    parts.iter().map(Vec::as_slice).collect()
}

// (a) The framing laws.

#[test]
fn of_parts_equals_a_fingerprinter_with_one_part_per_element() {
    for purpose in [ALPHA, BETA] {
        for parts in part_lists() {
            let slices = as_slices(&parts);
            let mut fingerprinter = Fingerprinter::new(purpose);
            for part in &slices {
                fingerprinter.part(part);
            }
            assert_eq!(
                Fingerprint::of_parts(purpose, &slices),
                fingerprinter.finish()
            );
        }
    }
}

#[test]
fn of_parts_is_the_v1_rule_by_hand() {
    for purpose in [ALPHA, BETA] {
        for parts in part_lists() {
            let fingerprint = Fingerprint::of_parts(purpose, &as_slices(&parts));
            assert_eq!(
                fingerprint.into_bytes(),
                v1_by_hand(purpose.context(), &parts)
            );
        }
    }
}

#[test]
fn framing_keeps_part_boundaries_and_purposes_apart() {
    let ab = Fingerprint::of_parts(ALPHA, &[b"ab"]);
    let a_b = Fingerprint::of_parts(ALPHA, &[b"a", b"b"]);
    let ab_empty = Fingerprint::of_parts(ALPHA, &[b"ab", b""]);
    assert_ne!(ab, a_b);
    assert_ne!(ab, ab_empty);
    assert_ne!(
        Fingerprint::of_parts(ALPHA, &[]),
        Fingerprint::of_parts(ALPHA, &[b""])
    );
    assert_ne!(ab, Fingerprint::of_parts(BETA, &[b"ab"]));
}

#[test]
fn number_and_flag_are_framed_parts() {
    let mut numbered = Fingerprinter::new(ALPHA);
    numbered.u64(u64::MAX).u64(0).flag(true).flag(false);
    let by_parts = Fingerprint::of_parts(
        ALPHA,
        &[&u64::MAX.to_le_bytes(), &0_u64.to_le_bytes(), &[1], &[0]],
    );
    assert_eq!(numbered.finish(), by_parts);
}

#[test]
fn fingerprint_accessors_agree() {
    let fingerprint = Fingerprint::of_parts(ALPHA, &[b"accessors"]);
    let bytes = fingerprint.into_bytes();
    assert_eq!(fingerprint.as_bytes(), &bytes);
    assert_eq!(fingerprint.prefix::<16>()[..], bytes[..16]);
    assert_eq!(fingerprint.prefix::<32>(), bytes);
    assert_eq!(fingerprint.prefix::<0>(), [0_u8; 0]);
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(fingerprint.to_hex(), hex);
    assert_eq!(format!("{fingerprint:?}"), format!("Fingerprint({hex})"));
}

#[test]
fn content_hash_is_plain_blake3_and_never_a_fingerprint() {
    for body in [&b""[..], &b"x"[..], &[0xff_u8; 1000][..]] {
        assert_eq!(
            ContentHash::of(body).into_bytes(),
            *blake3::hash(body).as_bytes()
        );
        let mut streamed = ContentHasher::new();
        for chunk in body.chunks(7) {
            streamed.update(chunk);
        }
        assert_eq!(streamed.finish(), ContentHash::of(body));
        let mut written = ContentHasher::default();
        written.write_all(body).expect("a hasher write cannot fail");
        written.flush().expect("a hasher flush cannot fail");
        assert_eq!(written.finish(), ContentHash::of(body));
        assert_ne!(
            ContentHash::of(body).into_bytes(),
            Fingerprint::of_parts(ALPHA, &[body]).into_bytes()
        );
    }
    let hash = ContentHash::of(b"hex");
    assert_eq!(hash.to_hex(), blake3::hash(b"hex").to_hex().as_str());
    assert_eq!(hash.as_bytes(), blake3::hash(b"hex").as_bytes());
}

#[test]
fn purposes_name_their_registry_strings() {
    assert_eq!(ALPHA.context(), "oneiron.testing.alpha.v1");
    assert_eq!(BETA.context(), "oneiron.testing.beta.v1");
    let all: &[Purpose] = oneiron_fingerprint::purposes::testing::ALL;
    assert_eq!(all, &[ALPHA, BETA]);
    assert_eq!(oneiron_fingerprint::purposes::testing::LEGACY.len(), 5);
}

// (b) The canonical record form.

#[derive(serde::Serialize)]
struct TwoFields {
    b: u8,
    a: bool,
}

#[test]
fn a_struct_is_a_map_sorted_by_encoded_key() {
    // {"a": true, "b": 1}: fixmap 2, "a", true, "b", 1, whatever the field order.
    let bytes = canonical_bytes(&TwoFields { b: 1, a: true }).expect("encodes");
    assert_eq!(bytes, [0x82, 0xa1, b'a', 0xc3, 0xa1, b'b', 0x01]);
}

#[test]
fn one_map_in_two_key_orders_has_one_form() {
    let forward: serde_json::Value =
        serde_json::from_str(r#"{"b": 1, "a": {"y": [1, 2], "x": null}, "ab": "s"}"#)
            .expect("json");
    let backward: serde_json::Value =
        serde_json::from_str(r#"{"ab": "s", "a": {"x": null, "y": [1, 2]}, "b": 1}"#)
            .expect("json");
    // The workspace builds serde_json with `preserve_order`, so these two differ as maps.
    assert_ne!(
        serde_json::to_string(&forward).expect("json"),
        serde_json::to_string(&backward).expect("json")
    );
    let forward_bytes = canonical_bytes(&forward).expect("encodes");
    assert_eq!(forward_bytes, canonical_bytes(&backward).expect("encodes"));
    let sorted: BTreeMap<&str, u8> = [("b", 1), ("a", 2)].into_iter().collect();
    let mut unsorted = serde_json::Map::new();
    unsorted.insert("b".to_owned(), 1.into());
    unsorted.insert("a".to_owned(), 2.into());
    assert_eq!(
        canonical_bytes(&sorted).expect("encodes"),
        canonical_bytes(&unsorted).expect("encodes")
    );
    // Keys sort by their encoded bytes: "a" (a1 61), then "b" (a1 62), then "ab"
    // (a2 61 62), because the length header is the first byte compared.
    let mut expected = vec![
        0x83, 0xa1, b'a', 0x82, 0xa1, b'x', 0xc0, 0xa1, b'y', 0x92, 1, 2,
    ];
    expected.extend_from_slice(&[0xa1, b'b', 1, 0xa2, b'a', b'b', 0xa1, b's']);
    assert_eq!(forward_bytes, expected);
}

#[test]
fn every_nan_has_one_spelling_and_negative_zero_stays() {
    let canonical_nan = [0xcb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0];
    for nan in [
        f64::NAN,
        -f64::NAN,
        f64::from_bits(0x7ff8_0000_0000_0001),
        f64::from_bits(0xfff0_0000_0000_0001),
    ] {
        assert_eq!(canonical_bytes(&nan).expect("encodes"), canonical_nan);
    }
    assert_eq!(canonical_bytes(&f32::NAN).expect("encodes"), canonical_nan);
    assert_eq!(
        canonical_bytes(&-0.0_f64).expect("encodes"),
        [0xcb, 0x80, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_ne!(
        canonical_bytes(&-0.0_f64).expect("encodes"),
        canonical_bytes(&0.0_f64).expect("encodes")
    );
    assert_eq!(
        canonical_bytes(&f64::INFINITY).expect("encodes"),
        [0xcb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        canonical_bytes(&f32::NEG_INFINITY).expect("encodes"),
        canonical_bytes(&f64::NEG_INFINITY).expect("encodes")
    );
    assert_eq!(
        canonical_bytes(&1.5_f32).expect("encodes"),
        canonical_bytes(&1.5_f64).expect("encodes")
    );
    // NaN is not null: the JSON forms alias them, this form does not.
    assert_ne!(
        canonical_bytes(&Some(f64::NAN)).expect("encodes"),
        canonical_bytes(&None::<f64>).expect("encodes")
    );
}

#[test]
fn integers_take_the_shortest_form_and_u64_max_is_exact() {
    assert_eq!(
        canonical_bytes(&u64::MAX).expect("encodes"),
        [0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    assert_eq!(
        canonical_bytes(&i64::MIN).expect("encodes"),
        [0xd3, 0x80, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(canonical_bytes(&5_i64).expect("encodes"), [0x05]);
    assert_eq!(canonical_bytes(&5_u64).expect("encodes"), [0x05]);
    assert_eq!(canonical_bytes(&200_i32).expect("encodes"), [0xcc, 200]);
    assert_eq!(canonical_bytes(&-1_i64).expect("encodes"), [0xff]);
    assert_eq!(
        canonical_bytes(&-200_i64).expect("encodes"),
        [0xd1, 0xff, 0x38]
    );
    assert_eq!(
        canonical_bytes(&(i64::MAX as u64)).expect("encodes"),
        canonical_bytes(&i64::MAX).expect("encodes")
    );
}

/// A map whose `Serialize` writes the given keys in order, each with the value 0.
struct KeysInOrder<K>(Vec<K>);

impl<K: serde::Serialize> serde::Serialize for KeysInOrder<K> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for key in &self.0 {
            map.serialize_entry(key, &0_u8)?;
        }
        map.end()
    }
}

/// Two map keys that differ only before canonicalization: 1.0 as f32 and as f64.
struct FloatKeys;

impl serde::Serialize for FloatKeys {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(&1.0_f32, &0_u8)?;
        map.serialize_entry(&1.0_f64, &1_u8)?;
        map.end()
    }
}

#[test]
fn a_duplicate_key_is_refused() {
    let duplicate = KeysInOrder(vec!["a", "b", "a"]);
    assert_eq!(
        canonical_bytes(&duplicate),
        Err(CanonicalBytesError::DuplicateKey)
    );
    assert_eq!(
        canonical_bytes(&FloatKeys),
        Err(CanonicalBytesError::DuplicateKey)
    );
    let nested = BTreeMap::from([("outer", KeysInOrder(vec!["k", "k"]))]);
    assert_eq!(
        canonical_bytes(&nested),
        Err(CanonicalBytesError::DuplicateKey)
    );
    assert_eq!(
        canonical_bytes(&KeysInOrder(vec!["b", "a"])).expect("encodes"),
        canonical_bytes(&KeysInOrder(vec!["a", "b"])).expect("encodes")
    );
}

/// A byte string serialized as bytes, not as a sequence of numbers.
struct Bytes(&'static [u8]);

impl serde::Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

#[test]
fn bytes_strings_and_arrays_keep_their_kinds() {
    assert_eq!(
        canonical_bytes(&Bytes(b"ab")).expect("encodes"),
        [0xc4, 2, b'a', b'b']
    );
    assert_eq!(canonical_bytes(&"ab").expect("encodes"), [0xa2, b'a', b'b']);
    assert_eq!(
        canonical_bytes(&vec![b'a', b'b']).expect("encodes"),
        [0x92, b'a', b'b']
    );
    assert_eq!(canonical_bytes(&Vec::<u8>::new()).expect("encodes"), [0x90]);
    assert_eq!(canonical_bytes(&"").expect("encodes"), [0xa0]);
    assert_eq!(canonical_bytes(&()).expect("encodes"), [0xc0]);
    assert_eq!(canonical_bytes(&None::<u8>).expect("encodes"), [0xc0]);
}

#[derive(serde::Serialize)]
enum Shape {
    Unit,
    Newtype(u8),
}

#[test]
fn a_unit_variant_is_its_name_and_others_are_one_entry_maps() {
    assert_eq!(
        canonical_bytes(&Shape::Unit).expect("encodes"),
        [0xa4, b'U', b'n', b'i', b't']
    );
    let mut newtype = vec![0x81, 0xa7];
    newtype.extend_from_slice(b"Newtype");
    newtype.push(0x07);
    assert_eq!(
        canonical_bytes(&Shape::Newtype(7)).expect("encodes"),
        newtype
    );
}

#[test]
fn of_record_is_of_parts_over_the_canonical_bytes() {
    let record = TwoFields { b: 9, a: false };
    let bytes = canonical_bytes(&record).expect("encodes");
    let by_record = Fingerprint::of_record(ALPHA, &record).expect("encodes");
    assert_eq!(by_record, Fingerprint::of_parts(ALPHA, &[&bytes]));
    let mut fingerprinter = Fingerprinter::new(ALPHA);
    fingerprinter.record(&record).expect("encodes");
    assert_eq!(fingerprinter.finish(), by_record);
    assert_eq!(
        Fingerprint::of_record(ALPHA, &KeysInOrder(vec!["x", "x"])),
        Err(CanonicalBytesError::DuplicateKey)
    );
}

// (c) The legacy recipes, each against its hand-written transcript.

/// The writes each legacy fixture makes, in order.
enum Step {
    Raw(&'static [u8]),
    LenU64Be(usize),
    LenU64Le(usize),
    LenU32BeSaturating(usize),
}

fn legacy_fixture() -> Vec<Step> {
    vec![
        Step::Raw(b""),
        Step::LenU64Be(0),
        Step::Raw(b"field"),
        Step::LenU64Le(5),
        Step::Raw(b"field"),
        Step::LenU32BeSaturating(3),
        Step::Raw(b"abc"),
        Step::LenU32BeSaturating(u32::MAX as usize + 7),
        Step::LenU64Be(usize::MAX),
        Step::Raw(&[0xff; 40]),
    ]
}

fn replay(digest: &mut LegacyDigest, steps: &[Step]) {
    for step in steps {
        match step {
            Step::Raw(bytes) => digest.raw(bytes),
            Step::LenU64Be(len) => digest.len_u64_be(*len),
            Step::LenU64Le(len) => digest.len_u64_le(*len),
            Step::LenU32BeSaturating(len) => digest.len_u32_be_saturating(*len),
        };
    }
}

/// The bytes the steps put into the hash, by hand.
fn transcript(steps: &[Step]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for step in steps {
        match step {
            Step::Raw(raw) => bytes.extend_from_slice(raw),
            Step::LenU64Be(len) => bytes.extend_from_slice(&(*len as u64).to_be_bytes()),
            Step::LenU64Le(len) => bytes.extend_from_slice(&(*len as u64).to_le_bytes()),
            Step::LenU32BeSaturating(len) => {
                bytes.extend_from_slice(&u32::try_from(*len).unwrap_or(u32::MAX).to_be_bytes());
            }
        }
    }
    bytes
}

#[test]
fn each_legacy_recipe_equals_its_hand_transcript() {
    let steps = legacy_fixture();
    let body = transcript(&steps);
    assert_eq!(&body[body.len() - 48..body.len() - 40], &[0xff; 8]);
    assert_eq!(
        &body[body.len() - 52..body.len() - 48],
        &[0xff; 4],
        "a length above u32::MAX saturates"
    );

    let digest_of = |purpose| {
        let mut digest = LegacyDigest::new(purpose);
        replay(&mut digest, &steps);
        digest.finish()
    };

    let mut derive_key = blake3::Hasher::new_derive_key(BLAKE3_DERIVE_KEY.tag());
    derive_key.update(&body);
    assert_eq!(
        digest_of(BLAKE3_DERIVE_KEY),
        *derive_key.finalize().as_bytes()
    );

    let mut tag_first = blake3::Hasher::new();
    tag_first.update(BLAKE3_TAG_FIRST.tag().as_bytes());
    tag_first.update(&body);
    assert_eq!(
        digest_of(BLAKE3_TAG_FIRST),
        *tag_first.finalize().as_bytes()
    );

    assert_eq!(digest_of(BLAKE3_NO_TAG), *blake3::hash(&body).as_bytes());

    let mut sha_tag_first = sha2::Sha256::new();
    sha_tag_first.update(SHA256_TAG_FIRST.tag().as_bytes());
    sha_tag_first.update(&body);
    let expected: [u8; 32] = sha_tag_first.finalize().into();
    assert_eq!(digest_of(SHA256_TAG_FIRST), expected);

    let expected: [u8; 32] = sha2::Sha256::digest(&body).into();
    assert_eq!(digest_of(SHA256_NO_TAG), expected);
}

#[test]
fn a_legacy_digest_can_finish_twice_and_continue() {
    let mut digest = LegacyDigest::new(SHA256_TAG_FIRST);
    digest.raw(b"first");
    let first = digest.finish();
    assert_eq!(first, digest.finish());
    digest.raw(b"second");
    assert_ne!(first, digest.finish());
}

#[test]
fn legacy_purposes_report_their_recipe() {
    assert_eq!(BLAKE3_DERIVE_KEY.hash(), LegacyHash::Blake3);
    assert_eq!(BLAKE3_DERIVE_KEY.tag_mode(), TagMode::DeriveKeyContext);
    assert_eq!(BLAKE3_TAG_FIRST.tag_mode(), TagMode::HashedFirst);
    assert!(BLAKE3_TAG_FIRST.tag().ends_with('\0'));
    assert_eq!(BLAKE3_NO_TAG.tag_mode(), TagMode::NotHashed);
    assert_eq!(SHA256_TAG_FIRST.hash(), LegacyHash::Sha256);
    assert_eq!(SHA256_NO_TAG.tag_mode(), TagMode::NotHashed);
    // A recipe that writes no tag: two such purposes give one digest for one input,
    // as today's untagged sites do. The registry name is the only difference.
    let mut plain = LegacyDigest::new(BLAKE3_NO_TAG);
    plain.raw(b"same");
    assert_eq!(plain.finish(), *blake3::hash(b"same").as_bytes());
}
