//! SIGNED-BIRTH-MESSAGE-SOURCES-UNREGISTERED T4: a CLAIM whose trusted pin
//! stands but whose signed birth does not resolve fails its verified write
//! with the history's typed error, and the write registers nothing: the
//! caller's transaction rolls back on the error, the CLAIM's own edges with
//! it.

use super::*;
use crate::dreamer_consolidation::evidence::{EvidenceLocator, VerifiedEvidenceSet};
use crate::error::{ClaimError, Error};

#[test]
fn a_pin_whose_birth_does_not_resolve_fails_the_write_and_registers_nothing() -> Result<()> {
    let (_dir, vault, _clock) = open_clocked_vault();
    let space = EntityId::now();
    vault.put_entity(
        &space,
        ENTITY_TYPE_RELATIONSHIP,
        occurred(1),
        1,
        b"relationship",
    )?;
    let said = WitnessMessage {
        metadata: Some(serde_json::json!({"rel": space.to_hex()})),
        ..message(0, WitnessAuthor::User, SAID, true)
    };
    let words = id_of(&said);
    let (turn, conversation) = witness(&vault, 0x5d, vec![said]);
    grant_messages(&vault, space, 100)?;
    let branch = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition_of(conversation),
        &[turn],
        AttemptId::now(),
        None,
    )?;
    let (start, end) = name_range();
    let evidence = VerifiedEvidenceSet::verify(
        &branch,
        &[EvidenceLocator::turn_range(turn, start, end)?],
        ClaimSource::UserStated,
    )?;

    // A CLAIM id whose trusted pin is stored, with no history behind it.
    let claim = EntityId::now();
    let pin = crate::claim::history_projection::pin_key(claim);
    let mut planted = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut planted, &pin, b"no handoff behind this pin".as_slice())?;
    planted.commit()?;

    let mut txn = vault.store.env.write_txn()?;
    let refused = evidence.record_message_dependencies_in_txn(&vault, &mut txn, &claim);
    let error = refused.expect_err("a pin whose birth does not resolve fails the write");
    assert!(
        matches!(
            error,
            Error::Claim(
                ClaimError::InvalidMachineClaimProof | ClaimError::MachineClaimHistoryIncomplete
            )
        ),
        "the refusal is the history's typed error: {error:?}"
    );
    // The caller's writer aborts on the error: nothing of it is stored.
    drop(txn);
    let read = vault.store.env.read_txn()?;
    assert!(
        crate::ports::dependency_sources_in(&vault.store, &read, &claim)?.is_empty(),
        "the CLAIM is left half-registered"
    );
    assert!(
        !crate::ports::dependency_sources_in(&vault.store, &read, &claim)?.contains(&words),
        "the refused CLAIM depends on the MESSAGE"
    );
    Ok(())
}
