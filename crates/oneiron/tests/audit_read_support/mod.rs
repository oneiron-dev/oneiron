//! The fixture every audit_read test file shares ([AUDIT-READ-POWER], RULING
//! AUDIT-READ-POWER-LIST = B): a device vault on a manual clock, its host
//! root and embedded owner, live PERSON readers bound to their own verified
//! credentials, the generated verb dispatch, and the owner's two audit_read
//! verbs. Public paths only. Not every test file uses every helper.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub const CHALLENGE: &[u8] = b"oneiron-request:audit-read-power";
pub const HOUR: u64 = 60 * 60;

pub struct Fixture {
    _dir: tempfile::TempDir,
    pub vault: Vault,
    pub clock: Arc<ManualClock>,
    pub issuer: HostSlipIssuer,
    pub owner: EntityId,
    pub start: u64,
}

/// A device vault on a manual clock set to the wall clock, with its host root
/// and embedded owner.
pub fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let clock = ManualClock::new(start);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-audit-read-power")?;
    vault.ensure_host_root_slip(&issuer)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(Fixture {
        _dir: dir,
        vault,
        clock,
        issuer,
        owner,
        start,
    })
}

pub fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A live PERSON, not the owner, with no power.
pub fn person(fixture: &Fixture, name: &str) -> Result<EntityId, Box<dyn std::error::Error>> {
    let person = EntityId::now();
    fixture.vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        name.as_bytes(),
    )?;
    Ok(person)
}

/// The live `human` credential this host mints `holder`, with the host root's
/// whole reach, verified as a transport verifies it.
pub fn credential(
    fixture: &Fixture,
    holder: EntityId,
) -> Result<VerifiedSlip, Box<dyn std::error::Error>> {
    let root = fixture.vault.ensure_host_root_slip(&fixture.issuer)?;
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = BTreeSet::new();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)?;
    let binding = fixture.issuer.binding_proof(&slip, CHALLENGE)?;
    Ok(fixture.vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &slip,
        CHALLENGE,
        &binding,
    )?)
}

/// The owner's own embedded handle.
pub fn owner(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// `person`'s handle, bound to its own live credential.
pub fn bound<'v>(fixture: &'v Fixture, person: EntityId, proof: &VerifiedSlip) -> Memory<'v> {
    fixture
        .vault
        .memory(person, EdgeActorClass::Human)
        .with_read_proof(proof)
}

pub fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

pub fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> MemoryError {
    match invoke(memory, verb, input) {
        Ok(answer) => panic!("{verb} is refused, but answered {answer}"),
        Err(error) => error,
    }
}

pub fn assert_forbidden(error: &MemoryError, what: &str) {
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "{what} is refused as forbidden: {error:?}"
    );
}

/// The owner grants `holder` the audit_read power, with no end unless
/// `expires_at` names one; answers the grant's answer.
pub fn grant(fixture: &Fixture, holder: EntityId, expires_at: Option<u64>) -> Value {
    let mut input = json!({ "holder": holder.to_hex() });
    if let Some(end) = expires_at {
        input["expires_at"] = json!(end);
    }
    call(&owner(fixture), "vault.audit_read.grant", input)
}

/// The owner revokes `holder`'s audit_read power; answers the revoke's answer.
pub fn revoke(fixture: &Fixture, holder: EntityId) -> Value {
    call(
        &owner(fixture),
        "vault.audit_read.revoke",
        json!({ "holder": holder.to_hex() }),
    )
}

/// The holders an owner verb's answer lists, by their hex.
pub fn listed_holders(answer: &Value) -> Vec<String> {
    answer["holders"]
        .as_array()
        .unwrap_or_else(|| panic!("the answer lists its holders: {answer}"))
        .iter()
        .map(|row| row["holder"].as_str().unwrap_or_default().to_owned())
        .collect()
}
