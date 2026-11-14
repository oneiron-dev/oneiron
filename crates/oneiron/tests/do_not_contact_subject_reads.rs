#![cfg(all(oneiron_test_support, feature = "test-support"))]
//! L6-22 (ARCH-0057 H174: "A synced multi-valued party-key index is a
//! follow-up, so the scan reads every PERSON for each send"). The
//! do-not-contact leg names every PERSON whose synced body carries the
//! counterparty's party key, whatever its lifecycle, and the campaign
//! compliance gate reads the same list (FIX 11017). With the party-key index
//! a read decodes only the PERSONs that carry the key. The list stays the
//! full scan's: a same-key twin, a body with two `party_key` entries, a
//! deleted row and a re-keyed row answer as before.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test do_not_contact_subject_reads`.

use std::sync::Arc;

use oneiron::comm::resolve_or_create_comm_party;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::do_not_contact_subject_reads::{
    backfill_person_party_key_index, do_not_contact_subjects, forget_person_party_key_index,
    take_person_party_key_reads,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PARTY: &str = "owen@example.com";
const OTHER_PARTY: &str = "yuki@example.com";
/// PERSONs that carry no key for `PARTY`: rows the scan has no need to read.
const DECOYS: u8 = 64;

fn open_unseeded() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config)?;
    // Every delete signs as this install first.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    Ok((dir, vault))
}

fn person_id(n: u8) -> TestResult<EntityId> {
    let mut bytes = [0x5a; 16];
    bytes[15] = n;
    Ok(EntityId::from_bytes(bytes)?)
}

fn put_person(vault: &Vault, id: &EntityId, body: &[u8]) -> TestResult {
    vault.put_entity(
        id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        body,
    )?;
    Ok(())
}

/// A PERSON body: a map of `entries` in order, so a key may repeat.
fn person_body(entries: &[(&str, &str)]) -> TestResult<Vec<u8>> {
    let map = Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::from(*key), Value::from(*value)))
            .collect(),
    );
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &map)?;
    Ok(body)
}

fn sorted(mut ids: Vec<EntityId>) -> Vec<EntityId> {
    ids.sort_unstable();
    ids
}

/// The subjects the scan names for `counterparty`, and the PERSON rows it
/// read to name them.
fn subjects_and_reads(vault: &Vault, counterparty: &str) -> TestResult<(Vec<EntityId>, usize)> {
    take_person_party_key_reads();
    let subjects = do_not_contact_subjects(vault, counterparty)?;
    Ok((subjects, take_person_party_key_reads()))
}

#[test]
fn the_do_not_contact_scan_reads_only_the_persons_that_carry_the_key() -> TestResult {
    let (_dir, vault) = open_unseeded()?;
    for n in 0..DECOYS {
        let body = match n % 3 {
            0 => b"decoy".to_vec(),
            1 => person_body(&[("name", "decoy")])?,
            _ => {
                let key = format!("decoy{n}@example.com");
                person_body(&[("party_key", key.as_str())])?
            }
        };
        put_person(&vault, &person_id(n)?, &body)?;
    }
    let other = person_id(DECOYS)?;
    put_person(&vault, &other, &person_body(&[("party_key", OTHER_PARTY)])?)?;
    let party = resolve_or_create_comm_party(&vault, PARTY)?;
    // A same-key twin, as an offline mint on another device syncs in.
    let twin = person_id(DECOYS + 1)?;
    put_person(&vault, &twin, &person_body(&[("party_key", PARTY)])?)?;
    // Two `party_key` entries: the scan matches either one.
    let doubled = person_id(DECOYS + 2)?;
    put_person(
        &vault,
        &doubled,
        &person_body(&[("party_key", "nobody@example.com"), ("party_key", PARTY)])?,
    )?;

    // The counterparty string is trimmed; the stored key is matched exactly.
    let (subjects, reads) = subjects_and_reads(&vault, &format!("  {PARTY} "))?;
    let expected = sorted(vec![party, twin, doubled]);
    assert_eq!(
        subjects, expected,
        "every PERSON carrying the key, in id order"
    );
    assert!(
        reads <= expected.len(),
        "the scan read {reads} PERSON rows to name {} subjects",
        expected.len()
    );
    let (subjects, _) = subjects_and_reads(&vault, "nobody@example.com")?;
    assert_eq!(subjects, vec![doubled]);
    let (subjects, reads) = subjects_and_reads(&vault, "   ")?;
    assert!(subjects.is_empty());
    assert_eq!(reads, 0, "an empty key reads nothing");

    // A deleted twin leaves the list.
    assert!(vault.delete_entity(&twin)?, "the twin is deleted");
    let (subjects, reads) = subjects_and_reads(&vault, PARTY)?;
    let expected = sorted(vec![party, doubled]);
    assert_eq!(subjects, expected);
    assert!(reads <= expected.len(), "the scan read {reads} PERSON rows");

    // A re-keyed row leaves the old key's list and joins the new one.
    put_person(
        &vault,
        &doubled,
        &person_body(&[("party_key", OTHER_PARTY)])?,
    )?;
    let (subjects, reads) = subjects_and_reads(&vault, PARTY)?;
    assert_eq!(subjects, vec![party]);
    assert!(reads <= 1, "the scan read {reads} PERSON rows");
    let (subjects, _) = subjects_and_reads(&vault, OTHER_PARTY)?;
    assert_eq!(subjects, sorted(vec![other, doubled]));
    let (subjects, _) = subjects_and_reads(&vault, "nobody@example.com")?;
    assert!(subjects.is_empty());
    Ok(())
}

#[test]
fn a_vault_older_than_the_index_reads_every_person_until_the_open_rebuild() -> TestResult {
    let (_dir, vault) = open_unseeded()?;
    for n in 0..DECOYS {
        put_person(&vault, &person_id(n)?, &person_body(&[("name", "decoy")])?)?;
    }
    let party = resolve_or_create_comm_party(&vault, PARTY)?;
    let twin = person_id(DECOYS)?;
    put_person(&vault, &twin, &person_body(&[("party_key", PARTY)])?)?;
    let expected = sorted(vec![party, twin]);

    forget_person_party_key_index(&vault)?;
    let (subjects, reads) = subjects_and_reads(&vault, PARTY)?;
    assert_eq!(
        subjects, expected,
        "the walk of every PERSON gives the same list"
    );
    assert!(
        reads > usize::from(DECOYS),
        "with no complete index the scan reads every PERSON; it read {reads}"
    );

    backfill_person_party_key_index(&vault)?;
    let (subjects, reads) = subjects_and_reads(&vault, PARTY)?;
    assert_eq!(subjects, expected);
    assert!(
        reads <= expected.len(),
        "after the rebuild the scan read {reads} PERSON rows"
    );
    Ok(())
}
