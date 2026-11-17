#![cfg(all(oneiron_test_support, feature = "test-support"))]
//! FIX COMM-PARTY-LOOKUP-INDEX-CANDIDATES (after L6-22, ARCH-0057 H174). A
//! party lookup the node-local shortcut cannot answer (no shortcut, as for a
//! party another device minted, or a stale one) reads synced truth: the
//! active comm-owned PERSONs that carry exactly the key, smallest id first.
//! With the PERSON party-key index it reads only the PERSONs the index names
//! for the key, each under the same rule; the answer stays the walk's.
//! Until a whole index rebuild has committed, it reads every PERSON.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test comm_party_lookup_reads`.

use std::sync::Arc;

use oneiron::comm::resolve_or_create_comm_party;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::comm_party_lookup_reads::{
    resolve_comm_party_ref, take_comm_party_row_reads,
};
use oneiron::test_doors::do_not_contact_subject_reads::{
    backfill_person_party_key_index, forget_person_party_key_index,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PARTY: &str = "owen@example.com";
const OTHER_PARTY: &str = "yuki@example.com";
const ABSENT_PARTY: &str = "nobody@example.com";
/// PERSONs that carry no key for `PARTY`: rows a lookup of it has no need
/// to read.
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

/// A PERSON id above every decoy's when `n >= DECOYS`, below when `n` is
/// small: ids order by their bytes, so `person_id(1) < person_id(2)`.
fn person_id(n: u8) -> TestResult<EntityId> {
    let mut bytes = [0x5a; 16];
    bytes[15] = n;
    Ok(EntityId::from_bytes(bytes)?)
}

/// Writes `body` as the PERSON row `id`, as a row another device wrote
/// syncs in: no node-local shortcut names it.
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

/// PERSON rows that do not carry `PARTY`: an undecodable body, a map with no
/// key, and a comm party of its own key.
fn put_decoys(vault: &Vault) -> TestResult {
    for n in 0..DECOYS {
        let body = match n % 3 {
            0 => b"decoy".to_vec(),
            1 => person_body(&[("name", "decoy")])?,
            _ => {
                let key = decoy_key(n);
                person_body(&[("party_key", key.as_str())])?
            }
        };
        put_person(vault, &person_id(n.saturating_add(16))?, &body)?;
    }
    Ok(())
}

fn decoy_key(n: u8) -> String {
    format!("decoy{n}@example.com")
}

/// The party a read-only lookup resolves `party` to, and the PERSON rows it
/// read to resolve it.
fn lookup_and_reads(vault: &Vault, party: &str) -> TestResult<(Option<EntityId>, usize)> {
    take_comm_party_row_reads();
    let party_ref = resolve_comm_party_ref(vault, party)?;
    Ok((party_ref, take_comm_party_row_reads()))
}

/// Every key the vault's PERSONs carry, and two they do not.
fn probe_keys() -> Vec<String> {
    let mut keys = vec![
        PARTY.to_owned(),
        OTHER_PARTY.to_owned(),
        ABSENT_PARTY.to_owned(),
    ];
    keys.extend((0..DECOYS).filter(|n| n % 3 == 2).map(decoy_key));
    keys.push("decoy0@example.com".to_owned());
    keys
}

#[test]
fn a_lookup_past_the_shortcut_reads_only_the_persons_that_carry_the_key() -> TestResult {
    let (_dir, vault) = open_unseeded()?;
    put_decoys(&vault)?;
    let synced = person_id(DECOYS.saturating_add(32))?;
    put_person(&vault, &synced, &person_body(&[("party_key", PARTY)])?)?;

    // No shortcut names the synced party: the lookup reads synced truth.
    let (party_ref, reads) = lookup_and_reads(&vault, PARTY)?;
    assert_eq!(party_ref, Some(synced), "the synced PERSON is the party");
    assert!(
        reads <= 1,
        "the lookup read {reads} PERSON rows to find one party"
    );
    let (party_ref, reads) = lookup_and_reads(&vault, ABSENT_PARTY)?;
    assert_eq!(party_ref, None, "no PERSON carries the key");
    assert_eq!(reads, 0, "an absent key reads no PERSON row");
    let (party_ref, reads) = lookup_and_reads(&vault, &decoy_key(2))?;
    assert_eq!(
        party_ref,
        Some(person_id(18)?),
        "a decoy is its own key's party"
    );
    assert!(reads <= 1, "the lookup read {reads} PERSON rows");

    // The write path resolves to the same row, mints nothing, and points the
    // shortcut at it; a lookup then reads that one row.
    assert_eq!(resolve_or_create_comm_party(&vault, PARTY)?, synced);
    let (party_ref, reads) = lookup_and_reads(&vault, PARTY)?;
    assert_eq!(party_ref, Some(synced));
    assert_eq!(reads, 1, "a fresh shortcut reads its own row only");
    Ok(())
}

#[test]
fn a_stale_shortcut_resolves_to_the_smallest_active_row_that_carries_the_key() -> TestResult {
    let (_dir, vault) = open_unseeded()?;
    put_decoys(&vault)?;
    let minted = resolve_or_create_comm_party(&vault, PARTY)?;
    let (twin_a, twin_b) = (person_id(1)?, person_id(2)?);
    put_person(&vault, &twin_a, &person_body(&[("party_key", PARTY)])?)?;
    put_person(&vault, &twin_b, &person_body(&[("party_key", PARTY)])?)?;
    let (party_ref, _) = lookup_and_reads(&vault, PARTY)?;
    assert_eq!(party_ref, Some(minted), "a fresh shortcut wins over twins");

    // The shortcut's row is deleted: the smallest twin is the party.
    assert!(vault.delete_entity(&minted)?, "the minted party is deleted");
    let (party_ref, reads) = lookup_and_reads(&vault, PARTY)?;
    assert_eq!(party_ref, Some(twin_a));
    assert!(
        reads <= 3,
        "the stale shortcut and the two twins are all the lookup reads; it read {reads}"
    );

    // A body with two `party_key` entries is no comm party, even with the
    // smallest id: the lookup re-reads each row under the walk's rule.
    let doubled = person_id(0)?;
    put_person(
        &vault,
        &doubled,
        &person_body(&[("party_key", PARTY), ("party_key", PARTY)])?,
    )?;
    let (party_ref, _) = lookup_and_reads(&vault, PARTY)?;
    assert_eq!(party_ref, Some(twin_a), "the doubled row is skipped");

    // A re-keyed twin leaves the old key and answers for the new one.
    put_person(
        &vault,
        &twin_a,
        &person_body(&[("party_key", OTHER_PARTY)])?,
    )?;
    let (party_ref, reads) = lookup_and_reads(&vault, PARTY)?;
    assert_eq!(party_ref, Some(twin_b));
    assert!(
        reads <= 3,
        "the stale shortcut, the doubled row and the twin are all the lookup reads; it read {reads}"
    );
    let (party_ref, reads) = lookup_and_reads(&vault, OTHER_PARTY)?;
    assert_eq!(party_ref, Some(twin_a));
    assert!(reads <= 1, "the lookup read {reads} PERSON rows");
    Ok(())
}

#[test]
fn without_a_whole_index_rebuild_the_lookup_reads_every_person_and_answers_the_same() -> TestResult
{
    let (_dir, vault) = open_unseeded()?;
    put_decoys(&vault)?;
    let minted = resolve_or_create_comm_party(&vault, PARTY)?;
    put_person(
        &vault,
        &person_id(1)?,
        &person_body(&[("party_key", PARTY)])?,
    )?;
    put_person(
        &vault,
        &person_id(2)?,
        &person_body(&[("party_key", OTHER_PARTY)])?,
    )?;
    put_person(
        &vault,
        &person_id(0)?,
        &person_body(&[("party_key", OTHER_PARTY), ("party_key", OTHER_PARTY)])?,
    )?;
    assert!(vault.delete_entity(&minted)?, "the minted party is deleted");

    let mut indexed = Vec::new();
    for key in probe_keys() {
        indexed.push(lookup_and_reads(&vault, &key)?.0);
    }
    assert_eq!(indexed.first(), Some(&Some(person_id(1)?)));
    assert_eq!(indexed.get(1), Some(&Some(person_id(2)?)));

    forget_person_party_key_index(&vault)?;
    for (key, answer) in probe_keys().iter().zip(&indexed) {
        let (party_ref, reads) = lookup_and_reads(&vault, key)?;
        assert_eq!(
            &party_ref, answer,
            "the walk of every PERSON gives the index's answer for {key}"
        );
        assert!(
            reads > usize::from(DECOYS),
            "with no complete index the lookup of {key} reads every PERSON; it read {reads}"
        );
    }

    backfill_person_party_key_index(&vault)?;
    for (key, answer) in probe_keys().iter().zip(&indexed) {
        let (party_ref, reads) = lookup_and_reads(&vault, key)?;
        assert_eq!(&party_ref, answer, "after the rebuild, {key}");
        assert!(
            reads <= 2,
            "after the rebuild the lookup of {key} read {reads} PERSON rows"
        );
    }
    Ok(())
}
