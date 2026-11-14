//! L8-65 (census; PLAN-L8-65, Engine rulings 15 Nov 01:10): each external reader's lifetime
//! read exposure, the distinct records the engine has ever served a key bound to a credential
//! its caller presented. The reader is the seeded house (`sys.team_lead`) reading the owner's
//! CLAIMs through a verified read slip of its own, as tests/house_source_read.rs does; each wake
//! is a new lane on a newly minted slip.
//!
//! A read opens no writer: the records it served wait for the vault's next write, whose door
//! keeps them. The doors to the kept rows build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test actor_read_exposure`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::{ActorReadExposure, PointRead, ScopedReadActorKey};
use oneiron::deletion::DeleteReason;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::ScopeAxis;
use oneiron::limit_ask::{EngineLimit, LimitAsk};
use oneiron::test_doors::read_exposure::exposed_records;
use oneiron::{ClaimInput, EntityId, Vault, VaultConfig};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    house: EntityId,
    issuer: HostSlipIssuer,
}

fn open(config: VaultConfig) -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let house = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")?
        .expect("the fresh vault seeds sys.team_lead")
        .0;
    let issuer = HostSlipIssuer::from_secret(b"actor-read-exposure-test-host")?;
    Ok(Fixture {
        _dir: dir,
        vault,
        owner,
        house,
        issuer,
    })
}

impl Fixture {
    /// One owner CLAIM the house may read, each on a predicate of its own so no record
    /// supersedes another.
    fn owner_claim(&self, predicate: &str) -> TestResult<EntityId> {
        let id = EntityId::now();
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_upsert(&ClaimInput {
                id: Some(id.to_hex()),
                predicate: predicate.to_owned(),
                subject_ref: self.owner.to_hex(),
                value: serde_json::json!({ "choice": predicate }),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: None,
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
                confidence_details: None,
            })?;
        assert_eq!(
            receipt.claim.as_ref().map(|claim| claim.id.clone()),
            Some(id.to_hex()),
            "the owner's CLAIM lands with the requested id"
        );
        Ok(id)
    }

    /// Three owner CLAIMs: R1, R2 and R3.
    fn three_records(&self) -> TestResult<[EntityId; 3]> {
        Ok([
            self.owner_claim("preference.travel.seat")?,
            self.owner_claim("preference.travel.meal")?,
            self.owner_claim("preference.travel.airline")?,
        ])
    }

    /// The house's read key, bound to a verified read slip it presents.
    fn house_key(&self, slip: u8) -> TestResult<ScopedReadActorKey> {
        let mut claims = self.vault.ensure_host_root_slip(&self.issuer)?.claims;
        claims.slip_id = [slip; 32];
        claims.holder_ref = self.house.to_hex();
        claims.actor_class = Some("agent".to_owned());
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        claims.expires_at = claims.issued_at + 600;
        claims.ttl_secs = 600;
        let slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
        let challenge = b"actor-read-exposure";
        let signature = self.issuer.binding_proof(&slip, challenge)?;
        let proof = self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &slip,
            challenge,
            &signature,
        )?;
        assert_eq!(proof.claims().holder_ref, self.house.to_hex());
        Ok(ScopedReadActorKey::from_verified_slip(&proof).expect("the house's slip carries read"))
    }

    /// One wake: a new lane on a newly minted slip point-reads `records`. Returns the ids it
    /// was served.
    fn wake(&self, slip: u8, records: &[EntityId]) -> TestResult<Vec<EntityId>> {
        let reads: Vec<PointRead<'_>> = records.iter().map(|id| PointRead::id(*id)).collect();
        let read = self
            .vault
            .scoped_read(self.house_key(slip)?)
            .read(&reads, None)?;
        Ok(read.value.iter().flatten().map(|row| row.id).collect())
    }

    /// The vault's next write: its door keeps what the reads before it served.
    fn next_write(&self) -> TestResult {
        self.vault.with_write_txn_grouped(|_| Ok(()))?;
        Ok(())
    }

    fn house_exposure(&self) -> TestResult<ActorReadExposure> {
        Ok(self
            .vault
            .actor_read_exposure(&self.house)?
            .expect("the house was served records"))
    }
}

/// The limit port a host installs, recording each crossing of the read exposure row.
#[derive(Default)]
struct Asked(Mutex<Vec<(u64, u64)>>);

impl Asked {
    fn crossings(&self) -> Vec<(u64, u64)> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl LimitAsk for Asked {
    fn crossed(&self, row: EngineLimit, bound: u64, measured: u64) {
        if row == EngineLimit::ActorExposedRecords {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((bound, measured));
        }
    }
}

/// UNIT = A, the plan's case: two wakes read overlapping records, and the reader's lifetime
/// count is their union: three, both while the records wait for the next write and once it
/// kept one row for each.
#[test]
fn a_readers_exposure_is_the_union_of_its_wakes() -> TestResult {
    let fx = open(VaultConfig::default())?;
    let [r1, r2, r3] = fx.three_records()?;

    assert_eq!(
        fx.wake(0xb1, &[r1, r2])?,
        vec![r1, r2],
        "wake 1 is served R1 and R2"
    );
    assert_eq!(
        fx.wake(0xb2, &[r2, r3])?,
        vec![r2, r3],
        "wake 2 is served R2 and R3"
    );
    assert_eq!(
        fx.house_exposure()?.distinct_records,
        3,
        "the reads' records count while they wait for the next write"
    );

    fx.next_write()?;
    let kept = fx.house_exposure()?;
    assert_eq!(
        kept.distinct_records, 3,
        "the write keeps the union, R2 once"
    );
    assert!(kept.first_served_at <= kept.last_exposed_at);
    assert_eq!(
        exposed_records(&fx.vault, &fx.house)?,
        BTreeSet::from([r1, r2, r3]),
        "one kept row per record served"
    );
    assert_eq!(
        fx.vault.actor_read_exposures()?,
        vec![(fx.house, kept)],
        "the house is the only reader counted"
    );
    Ok(())
}

/// A record served again exposes nothing new: a third wake reading all three again leaves
/// the count and the rows as they were.
#[test]
fn a_record_served_again_is_not_counted_again() -> TestResult {
    let fx = open(VaultConfig::default())?;
    let [r1, r2, r3] = fx.three_records()?;
    fx.wake(0xb1, &[r1, r2, r3])?;
    fx.next_write()?;
    let before = fx.house_exposure()?;
    assert_eq!(before.distinct_records, 3);

    assert_eq!(
        fx.wake(0xb3, &[r3, r1, r2])?,
        vec![r3, r1, r2],
        "wake 3 is served all three again"
    );
    assert_eq!(
        fx.house_exposure()?.distinct_records,
        3,
        "nothing new waits"
    );
    fx.next_write()?;
    assert_eq!(
        fx.house_exposure()?,
        before,
        "no record new to the house was kept"
    );
    assert_eq!(
        exposed_records(&fx.vault, &fx.house)?,
        BTreeSet::from([r1, r2, r3])
    );
    Ok(())
}

/// ADOPT = A: past `limits.actor_exposed_records` the installed port is asked with the row's
/// bound and the reader's count when the write that keeps the new records commits, and every
/// record is still served. A write that keeps nothing new asks nothing.
#[test]
fn crossing_the_row_asks_the_port_and_serves_every_record() -> TestResult {
    let mut config = VaultConfig::default();
    config.limits.set(EngineLimit::ActorExposedRecords, 2);
    let fx = open(config)?;
    let asked = Arc::new(Asked::default());
    fx.vault.set_limit_ask(asked.clone());
    let [r1, r2, r3] = fx.three_records()?;

    fx.wake(0xb1, &[r1, r2])?;
    fx.next_write()?;
    assert!(
        asked.crossings().is_empty(),
        "two records are not past a bound of two"
    );

    assert_eq!(
        fx.wake(0xb2, &[r3])?,
        vec![r3],
        "the third record is served whole"
    );
    assert!(asked.crossings().is_empty(), "the read itself asks nothing");
    fx.next_write()?;
    assert_eq!(
        asked.crossings(),
        vec![(2, 3)],
        "the write that kept R3 asked once, at bound 2 with 3 records"
    );

    assert_eq!(
        fx.wake(0xb3, &[r1, r2, r3])?,
        vec![r1, r2, r3],
        "past the bound every record is still served"
    );
    fx.next_write()?;
    assert_eq!(
        asked.crossings(),
        vec![(2, 3)],
        "nothing new was kept, so nothing asked"
    );
    Ok(())
}

/// WHO = A: the owner's own reads are not counted. The owner reads all three records through
/// its own handle, which presents no credential, and no reader has an exposure.
#[test]
fn the_owners_own_reads_are_not_counted() -> TestResult {
    let fx = open(VaultConfig::default())?;
    let records = fx.three_records()?;
    let owner = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    for record in records {
        assert!(
            owner.get_entity(&record.to_hex())?.value.is_some(),
            "the owner reads its own CLAIM"
        );
    }
    fx.next_write()?;
    assert_eq!(fx.vault.actor_read_exposure(&fx.owner)?, None);
    assert!(fx.vault.actor_read_exposures()?.is_empty());
    Ok(())
}

/// RESET = A: an erased record leaves every reader's rows, and the reader's count stays.
#[test]
fn an_erased_record_leaves_its_rows_and_not_the_count() -> TestResult {
    let fx = open(VaultConfig::default())?;
    // A hard delete needs this install's keystore, as a host installs it after each open.
    fx.vault
        .install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    fx.vault.prepare_install_signing()?;
    let [r1, r2, r3] = fx.three_records()?;
    fx.wake(0xb1, &[r1, r2, r3])?;
    fx.next_write()?;
    assert_eq!(
        exposed_records(&fx.vault, &fx.house)?,
        BTreeSet::from([r1, r2, r3])
    );

    fx.vault
        .delete_entity_with_reason(&r1, DeleteReason::UserHardDelete)?;
    assert_eq!(
        exposed_records(&fx.vault, &fx.house)?,
        BTreeSet::from([r2, r3]),
        "the erased record's row is gone"
    );
    assert_eq!(
        fx.house_exposure()?.distinct_records,
        3,
        "the count never falls"
    );
    Ok(())
}
