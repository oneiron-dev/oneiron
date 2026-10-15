//! The table's arms for signed histories and event ledgers: a held carrier
//! or event keeps every positive read back, while a restriction still lands
//! on the whole chain.

use super::*;

/// A held carrier leaves a machine claim's history incomplete: the owner's
/// approval projects only after the carrier's own answer.
pub(super) fn machine_history(reader: ConsolidationReader) -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let [machine, owner, target] = [test_id(0x52), test_id(0x43), test_id(0x53)];
    vault.put_entity(&machine, ENTITY_TYPE_MACHINE, test_time(1), 1, b"machine")?;
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, test_time(1), 1, b"owner")?;
    let issuer = crate::test_util::provision_engine_machines(&vault);
    vault.provision_host_machine_identity(&issuer, machine)?;
    crate::test_util::bind_test_owner(&vault, owner);
    let mut policy = crate::gate::default_policy_manifest()?;
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("system", &machine.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, crate::gate::default_policy_manifest_id()?, &policy)?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine fact"))?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "profile.color",
        ClaimSubject::Entity(machine),
        Value::from("blue"),
        1.0,
    );
    let signed = crate::test_util::sign_machine_candidate(&vault, &target, &candidate, &envelope);
    vault
        .batch()
        .claim_candidate(&target, candidate, &signed, test_time(10), 10)
        .commit()?;
    vault.approve_machine_claim_as(target, WriteActor::new(owner, EdgeActorClass::Human))?;
    let carriers = {
        let txn = vault.store.env.read_txn()?;
        crate::claim::history_store::machine_history_ids_for_target(&vault.store, &txn, target)?
    };
    // The birth, the owner's Approve event and its handoff.
    assert!(carriers.len() >= 3, "{reader:?}: carriers {carriers:?}");
    for carrier in carriers {
        check_transition(&vault, carrier, reader, |v, _| {
            match v.resolved_machine_claim(target) {
                Ok(view) => Ok(view.current.approval == ClaimApprovalStatus::Approved),
                Err(Error::Claim(crate::error::ClaimError::MachineClaimHistoryIncomplete)) => {
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        })?;
    }
    // The owner's retract through the memory door lands while the present
    // handoff waits, and reads back only after the owner's answer, as an
    // ancestor of the retract's own handoff.
    let pin = vault.resolved_machine_claim(target)?.handoff_digest;
    let carrier = EntityId::from_bytes(pin[..16].try_into().expect("content id"))?;
    let mut retracted = false;
    check_transition(&vault, carrier, reader, |v, _| {
        if !retracted {
            v.memory(owner, EdgeActorClass::Human)
                .claim_retract(&target.to_hex())
                .unwrap_or_else(|error| panic!("{reader:?}: the retract did not land: {error:?}"));
            retracted = true;
        }
        match v.resolved_machine_claim(target) {
            Ok(view) => {
                assert_eq!(
                    view.current.lifecycle,
                    ClaimLifecycleStatus::Retracted,
                    "{reader:?}: the retract did not land"
                );
                Ok(view.current.approval == ClaimApprovalStatus::Approved)
            }
            Err(Error::Claim(crate::error::ClaimError::MachineClaimHistoryIncomplete)) => Ok(false),
            Err(error) => Err(error),
        }
    })
}

/// A held event leaves its document unreadable; an expiry still lands on the
/// whole chain.
pub(super) fn esign_ledger(reader: ConsolidationReader) -> Result<()> {
    use crate::blob_artifact::esign::{
        DocumentKind, DocumentStatus, EsignAuditActor, EsignDocument, EsignItem, EsignRecipient,
        RecipientRole,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let person = test_id(0x43);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, test_time(1), 1, b"owner")?;
    crate::test_util::provision_engine_machines(&vault);
    let document = test_id(0x52);
    vault.put_blob_artifact(
        &document,
        &crate::blob_artifact::BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        test_time(1),
        1,
    )?;
    vault.append_blob_artifact_version(
        &document,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
        )),
        &crate::blob_artifact::BlobVersionProvenance::UserUpload,
        WriteActor::new(person, EdgeActorClass::Human),
        test_time(1),
        1,
    )?;
    let actor = || EsignAuditActor {
        actor: "test-owner".into(),
        ip: None,
        user_agent: None,
    };
    let body = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: 1000,
        items: vec![EsignItem {
            artifact_ref: document.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: test_id(0x54).to_hex(),
            email: "signer@example.test".into(),
            name: "Signer".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: 1000,
            principal_ref: None,
            automated: false,
        }],
        fields: Vec::new(),
        full_trail_appendix: true,
        lifecycle: None,
    };
    vault.create_esign_document(document, &body, actor(), 2)?;
    crate::blob_artifact::esign::mark_sent_for_test(&vault, document, actor(), 3)?;
    let sent = vault
        .claims_for_subject(&document)?
        .into_iter()
        .find(|id| {
            vault
                .get_claim(id)
                .ok()
                .flatten()
                .is_some_and(|body| body.predicate == "esign.sent")
        })
        .expect("sent event");
    check_transition(&vault, sent, reader, |v, _| {
        match v.esign_document(document) {
            Ok(state) => Ok(state.status == DocumentStatus::Pending),
            Err(Error::InvalidConfig(_)) => Ok(false),
            Err(error) => Err(error),
        }
    })?;
    // The expiry narrows the document while its event waits again.
    let pending = critical_confirm_pending(sent, 0x71, crate::unix_seconds_now());
    vault.with_write_txn(|txn| vault.store.put_pending_gate_consent_in_txn(txn, &pending))?;
    assert_eq!(
        vault.sweep_esign_expiry(&[document], 1001)?,
        1,
        "{reader:?}: the expiry did not land on a held chain"
    );
    assert!(
        matches!(vault.esign_document(document), Err(Error::InvalidConfig(_))),
        "{reader:?}: a held chain read back"
    );
    Ok(())
}
