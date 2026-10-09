use super::*;
use crate::TimeRange;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

#[test]
fn maintenance_revalidates_owner_in_target_vault() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    crate::test_util::provision_engine_machines(&vault);
    let (_other_dir, other) = open_test_vault_with(embedding_test_config());
    let actor = entity(0x71);
    other.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let proof = other.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let cadence = digest::ProactivityCadence {
        period_secs: 100,
        group_by_facet: true,
        urgent_breakthrough: true,
    };
    let rubric: CuratorRubric =
        serde_json::from_str(include_str!("curator_defaults.json")).unwrap();
    let thresholds = RetuneThresholds {
        prompts_score_regression: 0.1,
        weights_score_regression: 0.1,
        manifest_thresholds_score_regression: 0.1,
    };
    let refuse = |target: &Vault| -> Result<()> {
        for result in [
            target.set_proactivity_cadence(&proof, &cadence),
            target.set_curator_rubric(&proof, &rubric),
            target.set_retune_thresholds(&proof, &thresholds),
            target.proactivity_digest(&proof, 10, None).map(|_| ()),
        ] {
            assert_eq!(
                result.unwrap_err().kind(),
                crate::ErrorKind::ConsentOwnerNotAuthenticated
            );
        }
        Ok(())
    };
    refuse(&vault)?;
    other.set_proactivity_cadence(&proof, &cadence)?;
    let mut invalid_rubric = rubric.clone();
    invalid_rubric.questions.freshness.clear();
    assert_eq!(
        other
            .set_curator_rubric(&proof, &invalid_rubric)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::InvalidConfig
    );
    other.set_curator_rubric(&proof, &rubric)?;
    other.set_retune_thresholds(&proof, &thresholds)?;
    other.with_write_txn(|txn| {
        let marker = crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
            deleted_at: 20,
            request_id: [0x72; 16],
        };
        other
            .store
            .sync_state
            .put(txn, &format!("ac:{}", actor.to_hex()), &marker.encode())?;
        Ok(())
    })?;
    refuse(&other)?;
    other.with_write_txn(|txn| {
        other
            .store
            .sync_state
            .delete(txn, &format!("ac:{}", actor.to_hex()))?;
        Ok(())
    })?;
    other.delete_entity_with_reason(&actor, crate::deletion::DeleteReason::UserDelete)?;
    refuse(&other)?;
    Ok(())
}
