//! Actor lifecycle counterexamples and controls. These are base-mode laws.

mod demotion_guards;
mod timestamp_guards;

use super::*;
use crate::claim::{ClaimDemotionAction, ClaimDemotionRung, claim_demotion_rung};
use crate::edge::EdgeKind;
use crate::error::ClaimError;
use crate::error::{GateError, RegistryError};
use crate::gate::gate_metric_emission_count_for_test;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_ORG};

fn authored_local_claim(vault: &Vault, actor: WriteActor, id: EntityId) -> Result<()> {
    // A normal predicate avoids pending critical-confirm consent. UserStated
    // allows demotion to succeed on the current unattributed local path, so
    // these tests reach binding invalidation rather than an earlier refusal.
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("host lifecycle fixture"))?,
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                "profile.lifecycle_actor",
                ClaimSubject::Entity(entity(0x62)),
                Value::from("fact"),
                1.0,
            ),
            &envelope,
            TimeRange { start: 10, end: 99 },
            10,
        )
        .commit()
}

fn binding_digest(vault: &Vault, id: EntityId) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&txn, &authored_key(&id))?
        .map(|bytes| bytes.to_vec()))
}

fn assert_current_actor(vault: &Vault, id: EntityId, actor: WriteActor) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let body = vault.get_claim_in_txn(&txn, &id)?.expect("claim");
    let envelope = lifecycle_envelope(&vault.store, &txn, &id, &body)?
        .expect("constrained lifecycle transforms must retain an authored binding");
    assert_eq!(envelope.actor(), actor);
    Ok(())
}

fn actor_only_policy(vault: &Vault, actor: WriteActor) -> Result<()> {
    let mut manifest =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().as_slice())
            .expect("manifest");
    let Value::Map(entries) = &mut manifest else {
        panic!("manifest map");
    };
    let (_, ceilings) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("actor_ceilings"))
        .expect("actor ceilings");
    // No first_party row, and not even a class-wide human row. Only this
    // exact actor can auto-write under the test policy.
    *ceilings = Value::Array(vec![Value::Map(vec![
        ("actor_class".into(), "human".into()),
        ("actor_ref".into(), actor.entity_ref().to_hex().into()),
        ("ceiling".into(), "auto".into()),
    ])]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).expect("manifest encode");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

fn retract_op(vault: &Vault, id: EntityId) -> Result<BatchOp> {
    let raw = vault.get_raw(&id)?.expect("claim");
    let header = EntityMetadataHeader::parse(&raw).expect("header");
    let mut body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
    body.lifecycle = ClaimLifecycleStatus::Retracted;
    body.valid_to = Some(30);
    Ok(BatchOp::Put {
        id,
        entity_type: ENTITY_TYPE_CLAIM,
        occurred: TimeRange {
            start: header.occurred_start,
            end: 30,
        },
        learned_at: header.learned_at,
        data: encode_claim_body(&body)?,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    })
}

#[test]
fn demotion_refreshes_binding_at_each_rung_and_stales_old_seal() -> Result<()> {
    for rung_count in 1..=3 {
        let (_dir, vault, actor) = fixture()?;
        let id = entity(0x64);
        authored_local_claim(&vault, actor, id)?;
        let original = vault.get_claim(&id)?.expect("authored claim");
        for (action, rung, now) in [
            (
                ClaimDemotionAction::Decay {
                    new_claim_of_weight: 0.1,
                },
                ClaimDemotionRung::Decayed,
                20,
            ),
            (
                ClaimDemotionAction::Weaken {
                    new_confidence: 0.5,
                },
                ClaimDemotionRung::Weakened,
                21,
            ),
            (ClaimDemotionAction::MarkStale, ClaimDemotionRung::Stale, 22),
        ]
        .into_iter()
        .take(rung_count)
        {
            let old_op = retract_op(&vault, id)?;
            let old_seal = {
                let txn = vault.store.env.read_txn()?;
                ClaimMaterialization::lifecycle(&vault.store, &txn, &old_op)?
                    .expect("seal before demotion")
            };
            assert_eq!(vault.apply_claim_demotion(&id, action, now)?, rung);
            let raw = vault.get_raw(&id)?.expect("demoted claim");
            let body = vault.get_claim(&id)?.expect("demoted body");
            assert_eq!(claim_demotion_rung(&body)?, Some(rung));
            assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
            assert_eq!(body.evidence, original.evidence);
            assert_eq!(body.source, original.source);
            assert_eq!(body.approval, original.approval);
            let error = vault
                .with_write_txn(|txn| {
                    apply_owner_bound_claim_puts(&vault, txn, vec![old_op], vec![old_seal], false)
                })
                .expect_err("demotion must invalidate the old exact-row seal");
            assert!(matches!(error, Error::InvalidClaimBody(_)));
            assert_eq!(vault.get_raw(&id)?.expect("unchanged"), raw);
        }
        actor_only_policy(&vault, actor)?;
        vault.retract_claim(&id, 30)?;
        let body = vault.get_claim(&id)?.expect("retracted claim");
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Retracted);
    }
    Ok(())
}

#[test]
fn demoted_claim_retracts_under_original_actor_only_policy() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let control = entity(0x64);
    let demoted = entity(0x65);
    for id in [control, demoted] {
        authored_local_claim(&vault, actor, id)?;
        assert_current_actor(&vault, id, actor)?;
    }
    assert_eq!(
        vault.apply_claim_demotion(
            &demoted,
            ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.1
            },
            20,
        )?,
        ClaimDemotionRung::Decayed,
    );
    let evidence = vault.get_claim(&demoted)?.expect("demoted").evidence;
    actor_only_policy(&vault, actor)?;
    // The same policy authorizes a non-demoted claim from this actor.
    vault.retract_claim(&control, 30)?;
    let before = vault.store.gate_decisions(128)?;
    let result = vault.retract_claim(&demoted, 30);
    assert!(
        result.is_ok(),
        "a successful constrained demotion must not turn its author's later retraction into an unattributed write: {result:?}"
    );
    let closed = vault.get_claim(&demoted)?.expect("closed");
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(closed.evidence, evidence);
    let after = vault.store.gate_decisions(128)?;
    let added: Vec<_> = after.iter().filter(|row| !before.contains(row)).collect();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].actor_class, "human");
    assert_eq!(added[0].actor_ref, Some(actor.entity_ref().to_hex()));
    assert_eq!(added[0].claim_id, Some(*demoted.as_bytes()));
    Ok(())
}

#[test]
fn rejected_demotion_keeps_original_binding_and_actor_rights() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    authored_local_claim(&vault, actor, id)?;
    let raw = vault.get_raw(&id)?.expect("claim");
    let error = vault
        .apply_claim_demotion(
            &id,
            ClaimDemotionAction::Weaken {
                new_confidence: 0.5,
            },
            20,
        )
        .expect_err("weaken before decay is not a constrained valid transition");
    assert!(matches!(error, Error::InvalidClaimBody(_)));
    assert_eq!(vault.get_raw(&id)?.expect("unchanged"), raw);
    actor_only_policy(&vault, actor)?;
    vault.retract_claim(&id, 30)?;
    let body = vault.get_claim(&id)?.expect("retracted claim");
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Retracted);
    Ok(())
}

fn failed_actor_retraction_emits_no_metrics(retype: bool) -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    authored_local_claim(&vault, actor, id)?;
    assert_current_actor(&vault, id, actor)?;
    if retype {
        // Deliberate corruption through the existing test-only storage seam.
        // A public Put cannot retype a live actor (EntityTypeImmutable).
        let mut actor_raw = vault.get_raw(&actor.entity_ref())?.expect("actor");
        actor_raw[0] = ENTITY_TYPE_ORG;
        vault.with_write_txn(|txn| {
            vault
                .store
                .entities
                .put(txn, actor.entity_ref().as_bytes(), &actor_raw)?;
            Ok(())
        })?;
    } else {
        assert!(vault.delete_entity(&actor.entity_ref())?);
        assert!(vault.get_raw(&actor.entity_ref())?.is_none());
    }
    let raw = vault.get_raw(&id)?.expect("active claim remains");
    let digest = binding_digest(&vault, id)?;
    let decisions = vault.store.gate_decisions(128)?;
    {
        let txn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .pending_gate_consent_in_txn(&txn, &id)?
                .is_none()
        );
    }
    // The existing thread-local hook counts actual metric emissions without
    // interference from other tests' process-wide counters.
    let before = gate_metric_emission_count_for_test();
    let error = vault
        .retract_claim(&id, 30)
        .expect_err("invalid persisted actor");
    if retype {
        assert!(matches!(
            error,
            Error::Claim(ClaimError::ActorClassMismatch {
                actor_entity_type: ENTITY_TYPE_ORG,
                actor_class: 0,
            })
        ));
    } else {
        assert!(matches!(error, Error::EntityNotFound));
    }
    assert_eq!(vault.get_raw(&id)?.expect("rolled back"), raw);
    assert_eq!(binding_digest(&vault, id)?, digest);
    assert_eq!(vault.store.gate_decisions(128)?, decisions);
    assert_eq!(
        vault.get_claim(&id)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        gate_metric_emission_count_for_test(),
        before,
        "actor validation failed and all receipt/body writes rolled back; no decision metric may escape"
    );
    Ok(())
}

#[test]
fn deleted_actor_retraction_rolls_back_without_metric_emission() -> Result<()> {
    failed_actor_retraction_emits_no_metrics(false)
}

#[test]
fn retyped_actor_retraction_rolls_back_without_metric_emission() -> Result<()> {
    failed_actor_retraction_emits_no_metrics(true)
}

#[test]
fn public_actor_retype_is_immutable_and_preserves_lifecycle_authority() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    authored_local_claim(&vault, actor, id)?;
    let raw = vault.get_raw(&actor.entity_ref())?.expect("actor");
    let digest = binding_digest(&vault, id)?;
    let before = gate_metric_emission_count_for_test();
    let error = vault
        .put_entity(
            &actor.entity_ref(),
            ENTITY_TYPE_ORG,
            TimeRange { start: 1, end: 1 },
            1,
            b"not an actor",
        )
        .expect_err("a public Put cannot corrupt the actor type");
    assert!(
        matches!(error, Error::Registry(RegistryError::EntityTypeImmutable {
        id: rejected,
        existing: crate::registry::ENTITY_TYPE_PERSON,
        attempted: ENTITY_TYPE_ORG,
    }) if rejected == actor.entity_ref())
    );
    assert_eq!(vault.get_raw(&actor.entity_ref())?.expect("actor"), raw);
    assert_eq!(binding_digest(&vault, id)?, digest);
    assert_eq!(gate_metric_emission_count_for_test(), before);
    actor_only_policy(&vault, actor)?;
    vault.retract_claim(&id, 30)?;
    Ok(())
}

#[test]
fn committed_actor_retraction_emits_one_metric_and_one_receipt() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    authored_local_claim(&vault, actor, id)?;
    let decisions = vault.store.gate_decisions(128)?;
    let before = gate_metric_emission_count_for_test();
    vault.retract_claim(&id, 30)?;
    assert_eq!(gate_metric_emission_count_for_test(), before + 1);
    let after = vault.store.gate_decisions(128)?;
    let added: Vec<_> = after
        .iter()
        .filter(|row| !decisions.contains(row))
        .collect();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].actor_ref, Some(actor.entity_ref().to_hex()));
    assert_eq!(added[0].outcome, "allow");
    assert_eq!(
        vault.get_claim(&id)?.expect("closed").lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    Ok(())
}

#[test]
fn unbound_source_less_claims_keep_default_local_lifecycle_contract() -> Result<()> {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), crate::config::VaultConfig::default())?;
    let subject = entity(0x62);
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"",
    )?;
    let old = entity(0x64);
    let new = entity(0x65);
    let retracted = entity(0x66);
    for id in [old, new, retracted] {
        // This public source-less write is the existing local contract, not
        // missing authorization state fabricated by deleting a private key.
        let body = ClaimBody::new(
            "profile.lifecycle_actor",
            ClaimSubject::Entity(subject),
            Value::from("local fact"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        vault.put_claim(&id, &body, TimeRange { start: 10, end: 99 }, 10)?;
        assert!(binding_digest(&vault, id)?.is_none());
    }
    let before = vault.store.gate_decisions(128)?;
    vault.supersede_claim(&new, &old, 30)?;
    vault.retract_claim(&retracted, 30)?;
    assert_eq!(
        vault.get_claim(&old)?.expect("history").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault.get_claim(&retracted)?.expect("history").lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert_eq!(vault.targets(&new, EdgeKind::Supersedes, None)?, vec![old]);
    for id in [old, retracted] {
        assert!(binding_digest(&vault, id)?.is_none());
    }
    let after = vault.store.gate_decisions(128)?;
    let added: Vec<_> = after.iter().filter(|row| !before.contains(row)).collect();
    // Generic supersession does not request a decision receipt. Retraction
    // does, and must record the local actor rather than invent an author.
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].claim_id, Some(*retracted.as_bytes()));
    assert_eq!(added[0].actor_class, "first_party");
    assert_eq!(added[0].actor_ref, None);
    Ok(())
}

#[test]
fn copied_unbound_evidence_cannot_borrow_actor_only_lifecycle_authority() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let control = entity(0x64);
    let unbound = entity(0x65);
    authored_local_claim(&vault, actor, control)?;
    let mut copied = vault.get_claim(&control)?.expect("authored");
    copied.source = None;
    // Public raw source-less admission is legitimate, but a copied actor
    // stamp is evidence only. It must not acquire the control's binding.
    vault.put_claim(&unbound, &copied, TimeRange { start: 10, end: 99 }, 10)?;
    assert!(binding_digest(&vault, unbound)?.is_none());
    actor_only_policy(&vault, actor)?;
    let raw = vault.get_raw(&unbound)?.expect("raw claim");
    let before = vault.store.gate_decisions(128)?;
    let error = vault
        .retract_claim(&unbound, 30)
        .expect_err("no actor authority");
    assert!(matches!(error, Error::Gate(GateError::GateWriteRejected {
        outcome: "pending",
        reason_codes,
    }) if reason_codes == vec!["gate.pending.actor_ceiling"]));
    assert_eq!(vault.get_raw(&unbound)?.expect("unchanged"), raw);
    assert_eq!(vault.store.gate_decisions(128)?, before);
    let error = vault
        .supersede_claim(&control, &unbound, 30)
        .expect_err("same unbound policy on supersession");
    assert!(matches!(error, Error::Gate(GateError::GateWriteRejected {
        outcome: "pending",
        reason_codes,
    }) if reason_codes == vec!["gate.pending.actor_ceiling"]));
    assert_eq!(vault.get_raw(&unbound)?.expect("unchanged"), raw);
    assert!(
        vault
            .targets(&control, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    vault.retract_claim(&control, 30)?;
    Ok(())
}

#[test]
fn replayed_copy_invalidates_binding_and_cannot_use_actor_bound_source_permits() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let control = entity(0x64);
    let unbound = entity(0x65);
    // The fixture grants ToolOutput and Generated only to the exact actor.
    // Use a normal predicate to avoid a pending-consent closure side path.
    let envelope = WriteEnvelope::with_lineage(
        actor,
        ClaimSource::ToolOutput,
        WriteProvenance::new(Value::from("restricted host lineage"))?,
        ClaimApprovalStatus::Auto,
        SourceLineage::of(ClaimSource::ToolOutput).with(ClaimSource::Generated),
    );
    for id in [control, unbound] {
        vault
            .batch()
            .claim_candidate(
                &id,
                ClaimCandidate::new(
                    "profile.lifecycle_actor",
                    ClaimSubject::Entity(entity(0x62)),
                    Value::from("fact"),
                    1.0,
                ),
                &envelope,
                TimeRange { start: 10, end: 99 },
                10,
            )
            .commit()?;
        assert_current_actor(&vault, id, actor)?;
    }
    let op = retract_op(&vault, unbound)?;
    let seal = {
        let txn = vault.store.env.read_txn()?;
        ClaimMaterialization::lifecycle(&vault.store, &txn, &op)?.expect("original seal")
    };
    let raw = vault.get_raw(&unbound)?.expect("authored row");
    // The test-only replicated fixture door is available without sync. This
    // is a successful raw replacement, not a rejected public raw write.
    vault
        .batch()
        .put_replicated(
            &unbound,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 10, end: 99 },
            10,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )
        .commit()?;
    assert_eq!(vault.get_raw(&unbound)?.expect("copied row"), raw);
    assert!(binding_digest(&vault, unbound)?.is_none());
    let error = vault
        .with_write_txn(|txn| {
            apply_owner_bound_claim_puts(&vault, txn, vec![op], vec![seal], false)
        })
        .expect_err("identical replay bytes cannot preserve a local seal");
    assert!(matches!(error, Error::InvalidClaimBody(_)));
    let before = vault.store.gate_decisions(128)?;
    let error = vault
        .retract_claim(&unbound, 30)
        .expect_err("copied evidence grants no source permit");
    // Auto claims include their source in the evaluator input. The policy
    // refusal occurs before the later SourceNotTrustedForAuto fallback.
    assert!(
        matches!(
            &error,
            Error::Gate(GateError::GateWriteRejected { outcome: "pending", reason_codes })
                if reason_codes == &vec!["gate.pending.source_trust"]
        ),
        "unexpected replay lifecycle refusal: {error:?}"
    );
    assert_eq!(vault.get_raw(&unbound)?.expect("unchanged"), raw);
    assert_eq!(vault.store.gate_decisions(128)?, before);
    vault.retract_claim(&control, 30)?;
    Ok(())
}
