//! A consolidation claim's evidence meet classes a TURN by the same
//! classifier the extraction path uses (FIX
//! DREAMER-TURN-TRUST-TWO-CLASSIFIERS): `evidence_chain_source` read only a
//! TURN's import stamp, while `turn_trust_class` also reads its role, so an
//! unstamped Counterparty TURN classed `Generated` on the meet path and
//! `Imported` on the extraction path. Now both read `Imported`; every other
//! TURN classes as before, and a stamped TURN stays `Imported` whatever its
//! role (review round 1: the classifier refuses a role it never classes
//! before it reads the stamp).
//!
//! Reds: the meet path's stamp-only read restored (the Counterparty case
//! reads `Generated`); the stamp read dropped from the meet path (the stamped
//! System case reads `Generated`).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test dreamer_counterparty_turn_evidence_class`.
#![cfg(oneiron_test_support)]

use oneiron::dreamer_consolidation::evidence_chain_source;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::temporal::TimeRange;
use oneiron::{ClaimSource, EntityId, Vault, VaultConfig};

/// The turn-body key an imported transcript's turn is stamped with
/// (`memory::IMPORTED_SOURCE_KEY`, crate-private).
const IMPORT_STAMP_KEY: &str = "import_source";

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// Stores one TURN whose body maps each of `fields` to its string value.
fn turn(vault: &Vault, fields: &[(&str, &str)]) -> EntityId {
    let body = rmpv::Value::Map(
        fields
            .iter()
            .map(|(key, value)| (rmpv::Value::from(*key), rmpv::Value::from(*value)))
            .collect(),
    );
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode turn body");
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: 5, end: 5 },
            5,
            &bytes,
        )
        .expect("store turn");
    id
}

fn meet(vault: &Vault, evidence: EntityId) -> ClaimSource {
    evidence_chain_source(vault, &[], &[evidence]).expect("evidence meet")
}

#[test]
fn an_unstamped_counterparty_turn_classes_the_meet_imported() {
    let (_dir, vault) = open_vault();
    let said = turn(
        &vault,
        &[
            ("speaker", "counterparty"),
            ("text", "I always pay on time"),
        ],
    );
    assert_eq!(
        meet(&vault, said),
        ClaimSource::Imported,
        "an unstamped Counterparty TURN classes Imported, as turn_trust_class classes it"
    );
}

#[test]
fn a_user_turn_keeps_the_dreamer_floor() {
    let (_dir, vault) = open_vault();
    let said = turn(&vault, &[("speaker", "user"), ("text", "I like tea")]);
    assert_eq!(
        meet(&vault, said),
        ClaimSource::Generated,
        "a native user TURN cannot lift the meet above the Dreamer's Generated floor"
    );
}

#[test]
fn a_stamped_user_turn_stays_imported() {
    let (_dir, vault) = open_vault();
    let said = turn(
        &vault,
        &[
            ("speaker", "user"),
            ("text", "I like tea"),
            (IMPORT_STAMP_KEY, "transcript"),
        ],
    );
    assert_eq!(
        meet(&vault, said),
        ClaimSource::Imported,
        "an imported transcript's TURN classes Imported whatever its role"
    );
}

#[test]
fn a_turn_whose_role_is_never_classed_keeps_the_dreamer_floor() {
    let (_dir, vault) = open_vault();
    let said = turn(&vault, &[("speaker", "system"), ("text", "be brief")]);
    assert_eq!(
        meet(&vault, said),
        ClaimSource::Generated,
        "a role turn_trust_class never classes contributes the floor, as before"
    );
}

#[test]
fn a_stamped_turn_whose_role_is_never_classed_stays_imported() {
    let (_dir, vault) = open_vault();
    let said = turn(
        &vault,
        &[
            ("speaker", "system"),
            ("text", "be brief"),
            (IMPORT_STAMP_KEY, "archive"),
        ],
    );
    assert_eq!(
        meet(&vault, said),
        ClaimSource::Imported,
        "an imported transcript's TURN classes Imported even in a role turn_trust_class never classes"
    );
}
