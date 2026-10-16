//! The table's arms for readers of reserved heads and critic calibration. A
//! reserved predicate's own door attaches no confirm, so each arm lands its
//! head on a claim id whose owner-answer obligation is open: the same-id case.

use super::*;

/// A newer provider prior held on its claim id is no prior yet: the trust
/// multiplier stays the older settled one (review round 5, P1 on reserved
/// heads).
pub(super) fn provider_prior(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    let provider = "fixture-provider";
    let older = crate::provider_confidence::write_provider_prior(vault, provider, 0.5, "fixture")?;
    let mut body = stored_claim_body(vault, &older)?;
    body.value = Value::F32(0.25);
    body.valid_from = body.valid_from.map(|at| at + 100);
    let prior = test_id(0x4b);
    vault.with_write_txn(|wtxn| {
        vault.put_reserved_claim_in_txn(wtxn, &prior, &body, test_time(2), 2)
    })?;
    check_transition(vault, prior, reader, |v, _| {
        Ok(crate::provider_confidence::provider_prior_for_test(v, provider)? == Some(0.25))
    })
}

/// The owner's next outcome trains from a held calibration only once it is
/// answered: until then the writer neither folds nor supersedes it.
pub(super) fn critic_outcome(reader: ConsolidationReader) -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let mut session = crate::critic::review::tests::CalibratedSession::new(&vault)?;
    let [(held, _)] = <[_; 1]>::try_from(session.calibrations(&vault)?)
        .unwrap_or_else(|heads| panic!("{reader:?}: one calibration, found {}", heads.len()));
    check_transition(&vault, held, reader, |v, id| {
        session.train(v)?;
        Ok(session
            .calibrations(v)?
            .iter()
            .any(|(head, body)| head == id && body.lifecycle == ClaimLifecycleStatus::Superseded))
    })
}

/// A held calibration weights no review.
pub(super) fn critic_reliability(reader: ConsolidationReader) -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let session = crate::critic::review::tests::CalibratedSession::new(&vault)?;
    let [(held, _)] = <[_; 1]>::try_from(session.calibrations(&vault)?)
        .unwrap_or_else(|heads| panic!("{reader:?}: one calibration, found {}", heads.len()));
    check_transition(&vault, held, reader, |v, _| {
        Ok(session
            .reliabilities(v)?
            .iter()
            .any(|row| row.lens_id == "a"))
    })
}

/// A held provider-attributed claim has no confidence for the waterfall to
/// score.
pub(super) fn provider_confidence(
    vault: &Vault,
    claim: EntityId,
    reader: ConsolidationReader,
) -> Result<()> {
    let mut body = reader_body();
    body.value = Value::Map(vec![(
        Value::from("provider"),
        Value::from("fixture-provider"),
    )]);
    body.confidence = 0.8;
    put_claim_body(vault, &claim, &body)?;
    check_transition(vault, claim, reader, |v, id| {
        match crate::provider_confidence::effective_confidence(v, id) {
            Ok(score) => {
                assert_eq!(score, 0.8, "{reader:?}: reader output");
                Ok(true)
            }
            Err(Error::EntityNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    })
}

/// A held claim is no vertex of the community graph; the settled control is.
pub(super) fn ppr_community(
    vault: &Vault,
    claim: EntityId,
    control: EntityId,
    reader: ConsolidationReader,
) -> Result<()> {
    check_transition(vault, claim, reader, |v, id| {
        let txn = v.store.env.read_txn()?;
        let (snapshot, _) =
            v.store
                .compute_ppr_communities_in_txn(&txn, None, &[], 10, &v.config.ppr_community)?;
        assert!(
            snapshot.nodes.contains_key(&control),
            "{reader:?}: settled control missing"
        );
        Ok(snapshot.nodes.contains_key(id))
    })
}
