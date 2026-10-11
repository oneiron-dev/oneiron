//! A self-host root move keeps the vault's own writing (OF-455). A ReRoot
//! retires every roster key, the engine writers' with the old root's, so a
//! bare ReRoot left every engine-signed claim quarantined and every engine
//! writer without a key the new secret could sign with.

use crate::authority::{AuthorityOp, CausalWriteDisposition, HostSlipIssuer};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{ClaimCandidate, EntityId, TimeRange, Vault, WriteEnvelope, WriteProvenance};
use rmpv::Value;

fn dreamer_writes(vault: &Vault, id: u8) -> EntityId {
    let actor = vault.dreamer_authority().unwrap();
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("dreamer")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let id = entity(id);
    let candidate = ClaimCandidate::new(
        "dreamer.proactivity.follow_up",
        ClaimSubject::Entity(actor.entity_ref()),
        Value::from("pending action"),
        0.7,
    );
    let envelope = crate::test_util::sign_machine_candidate(vault, &id, &candidate, &envelope);
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, TimeRange { start: 1, end: 1 }, 1)
        .commit()
        .unwrap();
    id
}

fn readable(vault: &Vault, id: EntityId) -> bool {
    vault.claim_write_disposition(&id).unwrap() == Some(CausalWriteDisposition::Admitted)
}

/// `root` revokes the Dreamer's live writer key as a device.
fn revoke_dreamer_device(vault: &Vault, root: &HostSlipIssuer) {
    let dreamer = vault.dreamer_authority().unwrap().entity_ref();
    let fold = vault.authority_fold().unwrap();
    let key = fold
        .actor_bindings
        .iter()
        .find(|(key, binding)| {
            binding.actor_ref == dreamer
                && fold.roster.get(*key).is_some_and(|device| !device.revoked)
        })
        .map(|(key, _)| key.clone())
        .unwrap();
    let now = vault.now_recorded_at();
    let revoke = root
        .sign_entry(
            fold.vault_id,
            fold.append_sequences[&root.public_key()] + 1,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::RevokeDevice { revoked_key: key },
            now,
        )
        .unwrap();
    vault
        .put_authority_log_entry(
            &revoke,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .unwrap();
}

#[test]
fn a_re_rooted_vault_keeps_engine_claims_and_writers_under_the_new_secret_only() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let old = crate::test_util::provision_engine_machines(&vault);
    let vault_id = vault.authority_fold().unwrap().vault_id.unwrap();
    let kept = dreamer_writes(&vault, 0x51);
    let retracted = dreamer_writes(&vault, 0x52);
    vault
        .retract_claim(&retracted, vault.now_recorded_at() + 1)
        .unwrap();
    assert!(readable(&vault, kept) && readable(&vault, retracted));

    let next = HostSlipIssuer::from_secret(b"successor self-host root").unwrap();
    let moved = vault.re_root_host(&old, &next).unwrap();
    assert_eq!(moved.vault_id, vault_id);
    assert_eq!(moved.writers_enrolled, 6, "every engine writer was live");
    assert_eq!((moved.histories_carried, moved.histories_left), (2, 0));
    assert_eq!(vault.authority_fold().unwrap().vault_id, Some(vault_id));

    // The old secret is refused; the new one is the host.
    assert!(vault.ensure_host_root_slip(&old).is_err());
    assert!(vault.re_root_host(&old, &next).is_err());
    vault.ensure_host_root_slip(&next).unwrap();

    // What the engine wrote under the old root reads as before.
    assert!(readable(&vault, kept), "a carried claim stays readable");
    assert!(readable(&vault, retracted));
    assert_eq!(
        vault
            .resolved_machine_claim(retracted)
            .unwrap()
            .current
            .lifecycle,
        ClaimLifecycleStatus::Retracted
    );

    // The next host open retains the writers' new keys, and they write.
    vault.provision_engine_machine_identities(&next).unwrap();
    let fresh = dreamer_writes(&vault, 0x53);
    assert!(readable(&vault, fresh));
    vault
        .retract_claim(&kept, vault.now_recorded_at() + 1)
        .unwrap();
    assert!(readable(&vault, kept), "a transition after the move");
}

/// A history the move left quarantined stays so: a lifecycle write under the
/// new root makes a packet at its ReRoot, and that packet is no carry.
#[test]
fn a_retraction_after_the_move_does_not_carry_a_history_the_move_left() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let old = crate::test_util::provision_engine_machines(&vault);
    let left = dreamer_writes(&vault, 0x54);
    assert!(readable(&vault, left));

    // The host revokes the Dreamer's writer key as a device, before the move.
    revoke_dreamer_device(&vault, &old);
    assert!(
        !readable(&vault, left),
        "a revoked writer's claim quarantines"
    );

    let next = HostSlipIssuer::from_secret(b"successor self-host root").unwrap();
    let moved = vault.re_root_host(&old, &next).unwrap();
    assert_eq!((moved.histories_carried, moved.histories_left), (0, 1));
    vault.provision_engine_machine_identities(&next).unwrap();
    let _ = vault.retract_claim(&left, vault.now_recorded_at() + 1);
    assert!(
        !readable(&vault, left),
        "a retraction carried a history the move left"
    );
}

/// A delete takes the move's carry with its history (ASTRA-1367b): a new
/// birth at the same id, signed by a writer key the new root then revokes,
/// was never carried, and a lifecycle write under that root does not make it
/// so.
#[test]
fn a_new_birth_at_a_deleted_carried_id_does_not_inherit_the_carry() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let old = crate::test_util::provision_engine_machines(&vault);
    let target = dreamer_writes(&vault, 0x55);
    let next = HostSlipIssuer::from_secret(b"successor self-host root").unwrap();
    let moved = vault.re_root_host(&old, &next).unwrap();
    assert_eq!((moved.histories_carried, moved.histories_left), (1, 0));
    vault.provision_engine_machine_identities(&next).unwrap();

    vault.batch().delete(&target).commit().unwrap();
    assert_eq!(dreamer_writes(&vault, 0x55), target);
    assert!(readable(&vault, target), "a new birth under the new root");
    revoke_dreamer_device(&vault, &next);
    assert!(
        !readable(&vault, target),
        "a revoked writer's claim quarantines"
    );
    let _ = vault.retract_claim(&target, vault.now_recorded_at() + 1);
    assert!(
        !readable(&vault, target),
        "a deleted history's carry admitted a new birth at its id"
    );
}

/// A replica reads a history the move carried (ASTRA-1367b, second P2). It
/// imports the signed authority history, receives the claim's signed rows and
/// adopts the new root's handoff, as the authenticated transfer does. The
/// carry is in that chain, so the replica admits what the source admits.
#[test]
fn a_replica_reads_a_history_the_move_carried() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let old = crate::test_util::provision_engine_machines(&vault);
    let target = dreamer_writes(&vault, 0x58);
    let next = HostSlipIssuer::from_secret(b"successor self-host root").unwrap();
    assert_eq!(
        vault.re_root_host(&old, &next).unwrap().histories_carried,
        1
    );
    assert!(readable(&vault, target));

    let replica_dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(replica_dir.path(), crate::VaultConfig::device()).unwrap();
    replica
        .import_signed_authority_history(&vault.export_signed_authority_history().unwrap())
        .unwrap();
    let dreamer = vault.dreamer_authority().unwrap().entity_ref();
    let at = TimeRange { start: 1, end: 1 };
    replica
        .put_entity(
            &dreamer,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            1,
            b"machine",
        )
        .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let controls =
        crate::claim::history_store::machine_history_ids_for_target(&vault.store, &txn, target)
            .unwrap();
    let handoff =
        crate::claim::history_projection::trusted_machine_handoff(&vault.store, &txn, target)
            .unwrap();
    drop(txn);
    let vault_id = handoff.vault_id;
    let signer = next.public_key();
    let pin = crate::claim::ClaimHistoryHandoffPin {
        vault_id: &vault_id,
        genesis_hash: &vault_id,
        expected_signer: &signer,
        scope: &handoff.scope,
        previous_handoff_hash: handoff.previous_handoff_hash,
        challenge: &handoff.challenge,
    };
    replica
        .pin_machine_history_handoff_pending(target, &handoff, &pin, &next)
        .unwrap();
    let replicate = |id: &EntityId| {
        let raw = vault.get_raw(id).unwrap().unwrap();
        let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
        replica
            .batch()
            .put_replicated(
                id,
                header.entity_type,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit()
            .unwrap();
    };
    replicate(&target);
    replica
        .batch()
        .edge(&target, crate::edge::EdgeKind::ClaimOf, &dreamer, 1.0)
        .commit()
        .unwrap();
    let mut controls = controls
        .into_iter()
        .map(|id| {
            let raw = vault.get_raw(&id).unwrap().unwrap();
            let body = crate::claim::decode_claim_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                true,
            )
            .unwrap();
            (id, body.predicate)
        })
        .collect::<Vec<_>>();
    controls.sort_by_key(|(_, predicate)| match predicate.as_str() {
        "machine.birth" => 0,
        "machine.transition" => 1,
        _ => 2,
    });
    for (id, _) in &controls {
        replicate(id);
    }
    replica
        .adopt_machine_history_handoff(target, &handoff, &pin)
        .unwrap();
    assert!(
        readable(&replica, target),
        "a replica quarantined a history the move carried"
    );
}
