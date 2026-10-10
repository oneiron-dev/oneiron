//! A self-host root move keeps the vault's own writing (OF-455). A ReRoot
//! retires every roster key, the engine writers' with the old root's, so a
//! bare ReRoot left every engine-signed claim quarantined and every engine
//! writer without a key the new secret could sign with.

use crate::authority::{CausalWriteDisposition, HostSlipIssuer};
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
