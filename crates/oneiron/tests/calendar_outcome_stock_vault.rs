//! CAL-07 outcome writes land live on a stock vault (ARCH-0060 [CAL-07]).
//!
//! The CAL-07 notes on main said the default policy manifest carries no
//! `calendar.` rule, so every calendar claim write on a default-seeded vault
//! would be gate-pending. The rule is there (`gate/default_manifest.rs`,
//! `calendar.` at normal criticality and sensitivity). This pins it at the
//! outcome door: on a stock vault an owner-attested and an observed outcome
//! each land live. It passes on main and on the head; it is a pin, not a fix.
#![cfg(feature = "test-support")]

use oneiron::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, read_event_outcome,
    record_event_outcome,
};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{ClaimSource, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

const EVENT_START: u64 = 1_800_000_000;
const EVENT_END: u64 = EVENT_START + 3_600;

/// Fixture ids under their own prefix, as in `tests/family_claim_facet.rs`.
fn entity(seed: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x7f;
    bytes[15] = seed;
    EntityId::from_bytes(bytes).expect("fixture id")
}

/// A stock vault: the default policy manifest is seeded, as a user's is.
fn stock_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    (dir, vault)
}

fn put_event(vault: &Vault, event_ref: EntityId) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from("intro call"))]),
    )
    .expect("encode event body");
    vault
        .put_entity(
            &event_ref,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: EVENT_START,
                end: EVENT_END,
            },
            EVENT_START,
            &body,
        )
        .expect("put event");
}

#[test]
fn outcome_writes_land_live_on_a_default_seeded_vault() {
    let (_dir, vault) = stock_vault();

    let answered = entity(0x43);
    put_event(&vault, answered);
    let owner_answer = EventOutcomeClaimValue {
        outcome: EventOutcome::NoShow,
        basis: EventOutcomeBasis::OwnerAttested,
        recorded_at: EVENT_END + 60,
    };
    record_event_outcome(&vault, answered, &owner_answer, ClaimSource::UserStated)
        .expect("an owner-attested outcome lands on a stock vault");
    assert_eq!(
        read_event_outcome(&vault, answered).expect("read"),
        Some(owner_answer),
        "the owner's answer is live, not gate-pending"
    );

    let observed = entity(0x44);
    put_event(&vault, observed);
    let machine = EventOutcomeClaimValue {
        outcome: EventOutcome::Held,
        basis: EventOutcomeBasis::Machine,
        recorded_at: EVENT_START + 300,
    };
    record_event_outcome(&vault, observed, &machine, ClaimSource::Observed)
        .expect("an observed outcome lands on a stock vault");
    assert_eq!(
        read_event_outcome(&vault, observed).expect("read"),
        Some(machine),
        "the observed outcome is live, not gate-pending"
    );
}
