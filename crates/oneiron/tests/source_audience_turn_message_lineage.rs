//! FIX SOURCE-AUDIENCE-TURN-MESSAGE-LINEAGE: a witnessed TURN's words are
//! its MESSAGE rows', so the read judge (`readable_with_read_in`) holds the
//! TURN, and every row written from it, to the source-audience policies its
//! MESSAGE rows read under. On main the judge's walk went from a MESSAGE to
//! its TURN (`PartOf`) but never from a TURN to its MESSAGE rows, so a row
//! `DerivedFrom` a local TURN read to a person outside the policy of the
//! source its MESSAGE was written from.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test source_audience_turn_message_lineage`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::memory::{Memory, WitnessAssertions};
use oneiron::test_doors::source_audience::land_source_bound_artifact;
use oneiron::test_doors::source_audience_binding::reads;
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WitnessAuthor,
    WitnessMessage, WitnessTurn,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The owner witnesses one TURN of one MESSAGE row: the TURN and the
/// MESSAGE row its text is read from.
fn witnessed_turn_and_message(
    memory: &Memory<'_>,
) -> Result<(EntityId, EntityId), Box<dyn std::error::Error>> {
    let receipt = memory.witness(&WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: "the attachment says the lease ends in March".to_owned(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: 900,
        assertions: WitnessAssertions::default(),
    })?;
    let message = receipt
        .messages
        .first()
        .ok_or("the witness writes one MESSAGE row")?;
    Ok((receipt.turn_id, EntityId::from_hex(&message.id)?))
}

#[test]
fn a_row_written_from_a_turn_reads_under_the_policy_its_message_reads_under() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.memory(owner_actor, EdgeActorClass::Human);

    // A local TURN of one MESSAGE row, with no binding of its own.
    let (turn, message) = witnessed_turn_and_message(&owner)?;
    // A source's row under a policy one person reads; the MESSAGE row was
    // written from it.
    let insider = EntityId::now();
    let outsider = EntityId::now();
    let source =
        land_source_bound_artifact(&vault, BTreeSet::from([insider]), false, owner_actor, 1)?;
    vault.put_edge(&message, EdgeKind::DerivedFrom, &source.row, 1.0)?;
    // A local row written from the TURN.
    let derived = EntityId::now();
    vault.put_entity(
        &derived,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a row written from the turn",
    )?;
    vault.put_edge(&derived, EdgeKind::DerivedFrom, &turn, 1.0)?;

    // The policy's reader reads the source's row and the MESSAGE written
    // from it; the person outside the policy reads neither.
    assert!(
        reads(&vault, source.row, &[insider])?,
        "the policy's reader reads the source's row"
    );
    assert!(
        !reads(&vault, source.row, &[outsider])?,
        "a person outside the policy does not read the source's row"
    );
    assert!(
        reads(&vault, message, &[insider])?,
        "the policy's reader reads the MESSAGE"
    );
    assert!(
        !reads(&vault, message, &[outsider])?,
        "the MESSAGE reads under its source's policy"
    );

    // The TURN's words are its MESSAGE's, and the derived row's are the
    // TURN's: neither reads outside the policy, and both read inside it.
    assert!(
        !reads(&vault, derived, &[outsider])?,
        "a row written from the TURN read to a person outside its MESSAGE's source policy"
    );
    assert!(
        !reads(&vault, turn, &[outsider])?,
        "the TURN read to a person outside its MESSAGE's source policy"
    );
    assert!(
        reads(&vault, turn, &[insider])?,
        "the policy's reader reads the TURN"
    );
    assert!(
        reads(&vault, derived, &[insider])?,
        "the policy's reader reads the row written from the TURN"
    );
    Ok(())
}
