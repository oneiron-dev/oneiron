//! PLAN-UC-04 stage 0 and 2.1: the id rules against the fingerprint door.
//!
//! 1. `EntityId::derive` is the first 16 bytes of the fingerprint under the same purpose,
//!    stamped as RFC 9562 version 8 (DESIGN section 3.1), on 20 fixtures and two purposes;
//!    and it equals `EntityId::derive_unregistered` under the purpose's context, which keeps
//!    the body `derive` had before it took a `Purpose` (2.1).
//! 2. `EntityId::derive_legacy_material` gives the bytes of the store's
//!    `entity_id_from_hash_material` (oracle: a copy of its body at main eed5070979c,
//!    `crates/oneiron-store/src/code_snapshot/ids.rs:35-54` with `write_hash_len` from
//!    `crates/oneiron-store/src/code_snapshot/snapshot.rs:647-652`).

use oneiron_contracts::entity_id::{ENTITY_ID_LEN, EntityId};
use oneiron_contracts::error::{Error, Result};
use oneiron_contracts::fingerprint::Fingerprint;
use oneiron_contracts::fingerprint::purposes::testing::{
    ALPHA, BETA, BLAKE3_DERIVE_KEY, BLAKE3_NO_TAG, BLAKE3_TAG_FIRST, SHA256_TAG_FIRST,
};

/// 20 part lists: no parts, empty parts, boundaries that concatenate equal, NULs,
/// unicode, all-zero and all-0xff ids, `u64::MAX`, a long part and many parts.
fn fixtures() -> Vec<Vec<Vec<u8>>> {
    vec![
        vec![],
        vec![vec![]],
        vec![vec![], vec![]],
        vec![b"a".to_vec()],
        vec![b"ab".to_vec()],
        vec![b"a".to_vec(), b"b".to_vec()],
        vec![b"ab".to_vec(), Vec::new()],
        vec![Vec::new(), b"ab".to_vec()],
        vec![b"a\0b".to_vec()],
        vec![
            "\u{00e9}t\u{00e9}".as_bytes().to_vec(),
            "\u{6f22}\u{5b57}".as_bytes().to_vec(),
        ],
        vec![vec![0; ENTITY_ID_LEN]],
        vec![vec![0xff; ENTITY_ID_LEN]],
        vec![vec![0; 32], vec![0xff; 32]],
        vec![u64::MAX.to_le_bytes().to_vec()],
        vec![
            u64::MAX.to_be_bytes().to_vec(),
            0_u64.to_le_bytes().to_vec(),
        ],
        vec![
            b"actor".to_vec(),
            b"human".to_vec(),
            b"/a/b".to_vec(),
            b"req-1".to_vec(),
        ],
        vec![vec![0x5a; 4096]],
        (0..12_u8).map(|n| vec![n; usize::from(n)]).collect(),
        vec![b"oneiron.testing.alpha.v1".to_vec()],
        vec![vec![0x80], vec![0x3f], vec![0x0f]],
    ]
}

fn as_slices(parts: &[Vec<u8>]) -> Vec<&[u8]> {
    parts.iter().map(Vec::as_slice).collect()
}

/// The version-8 stamp `EntityId::derive` puts on its 16 bytes.
fn stamped(mut bytes: [u8; ENTITY_ID_LEN]) -> [u8; ENTITY_ID_LEN] {
    bytes[6] = (bytes[6] & 0x0F) | 0x80;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    bytes
}

#[test]
fn derive_is_the_stamped_prefix_of_the_fingerprint() {
    let fixtures = fixtures();
    assert_eq!(fixtures.len(), 20);
    for purpose in [ALPHA, BETA] {
        for parts in &fixtures {
            let slices = as_slices(parts);
            let id =
                EntityId::derive(purpose, &slices).expect("no fixture lands in the reserved range");
            let unregistered = EntityId::derive_unregistered(purpose.context().as_bytes(), &slices)
                .expect("no fixture lands in the reserved range");
            assert_eq!(id, unregistered, "{} {parts:?}", purpose.context());
            let prefix = Fingerprint::of_parts(purpose, &slices).prefix::<ENTITY_ID_LEN>();
            assert_eq!(
                id.as_bytes(),
                &stamped(prefix),
                "{} {parts:?}",
                purpose.context()
            );
            assert!(id.has_derived_stamp());
        }
    }
}

// The oracle: the store's body at main eed5070979c, copied; only the imports differ
// (`oneiron_base::error` re-exports `oneiron_contracts::error`).

fn entity_id_from_hash_material(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    for salt in 0_u64..=u64::MAX {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&salt.to_le_bytes());
        for part in parts {
            write_hash_len(&mut hasher, part.len())?;
            hasher.update(part);
        }
        let hash = hasher.finalize();
        let mut id = [0_u8; ENTITY_ID_LEN];
        id.copy_from_slice(&hash.as_bytes()[..ENTITY_ID_LEN]);
        if let Ok(id) = EntityId::from_bytes(id) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "codebase deterministic entity id exhausted salt space",
    ))
}

fn write_hash_len(hasher: &mut blake3::Hasher, value: usize) -> Result<()> {
    let value = u64::try_from(value)
        .map_err(|_| Error::ArithmeticOverflow("codebase hash length overflow"))?;
    hasher.update(&value.to_le_bytes());
    Ok(())
}

#[test]
fn derive_legacy_material_equals_the_store_rule() {
    let domain = BLAKE3_TAG_FIRST.tag().as_bytes();
    assert!(domain.ends_with(b"\0"));
    for parts in &fixtures() {
        let slices = as_slices(parts);
        let kept = EntityId::derive_legacy_material(BLAKE3_TAG_FIRST, &slices)
            .expect("a BLAKE3 tag-first purpose derives");
        let oracle = entity_id_from_hash_material(domain, &slices).expect("the oracle derives");
        assert_eq!(kept, oracle, "{parts:?}");
    }
}

#[test]
fn derive_legacy_material_refuses_another_recipe() {
    for purpose in [BLAKE3_DERIVE_KEY, BLAKE3_NO_TAG, SHA256_TAG_FIRST] {
        let refused = EntityId::derive_legacy_material(purpose, &[b"part"]);
        assert!(
            matches!(refused, Err(Error::InvariantViolation(_))),
            "{} must be refused",
            purpose.tag()
        );
    }
}
