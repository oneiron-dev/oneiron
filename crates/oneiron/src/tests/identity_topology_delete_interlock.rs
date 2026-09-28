//! Deletion publication owns the topology interlock through purge.

use super::*;
use crate::claim::ClaimSource;
use crate::edge::EdgeKind;
use crate::identity_topology::{
    IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp, ProposalRuling,
    ReassignmentMap, SplitOp, SurvivorshipPlan,
};

fn person(vault: &Vault, byte: u8) -> EntityId {
    let id = crate::test_util::entity(byte);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            test_time_range(100, 100),
            100,
            b"person",
        )
        .expect("put person");
    id
}

fn merge(source: EntityId, survivor: EntityId) -> IdentityTopologyOp {
    IdentityTopologyOp::Merge(MergeOp {
        sources: vec![source],
        survivor,
        evidence: IdentityOpEvidence::default(),
        survivorship_plan: SurvivorshipPlan::ReadThrough,
    })
}

/// LMDB orders reservation admission, topology apply and purge. No lock may
/// stay held across the rendezvous: the main thread must be able to attempt
/// both roles while the deleter is parked AFTER tombstone publication.
#[cfg(feature = "sync")]
#[test]
fn committed_tombstone_reservation_blocks_new_merges_until_hard_purge_finishes() -> Result<()> {
    for reason in [DeleteReason::UserHardDelete, DeleteReason::GdprDelete] {
        let (_dir, vault) = open_test_vault();
        let deleting = person(&vault, 0x31);
        let other = person(&vault, 0x32);
        let third = person(&vault, 0x33);
        let write = IdentityOpWrite::auto(ClaimSource::Inferred);
        let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        vault.test_hooks().install_delete_rendezvous(
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            deleting,
            arrived_tx,
            resume_rx,
        );
        std::thread::scope(|scope| -> Result<()> {
            let deleter = scope.spawn(|| vault.delete_entity_with_reason(&deleting, reason));
            arrived_rx.recv().expect("deleter reached publication seam");
            let source_result =
                vault.apply_identity_topology_op(&merge(deleting, other), &write, 210);
            let survivor_result =
                vault.apply_identity_topology_op(&merge(third, deleting), &write, 211);
            resume_tx
                .send(())
                .expect("resume deleter before checking results");
            assert!(source_result.is_err(), "reserved source must not merge");
            assert!(survivor_result.is_err(), "reserved survivor must not merge");
            let outcome = deleter.join().expect("deleter thread")?;
            assert!(outcome.existed);
            assert!(outcome.receipt_id.is_some());
            Ok(())
        })?;
        assert!(vault.get_raw(&deleting)?.is_none());
        assert!(!vault.edge_exists(&deleting, EdgeKind::MergedInto, &other)?);
        assert!(!vault.edge_exists(&third, EdgeKind::MergedInto, &deleting)?);
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .sync_state
                .get(&rtxn, &crate::deletion::local_hard_delete_key(&deleting))?
                .is_some()
        );
    }
    Ok(())
}

/// If a merge commits before the publication transaction's reservation,
/// deletion must refuse before it can publish a remote-visible tombstone.
#[cfg(feature = "sync")]
#[test]
fn merge_winning_prepublication_writer_orders_delete_to_clean_refusal() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let deleting = person(&vault, 0x41);
    let survivor = person(&vault, 0x44);
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    vault.test_hooks().install_delete_rendezvous(
        crate::deletion::DeleteRendezvous::BeforeFirstDeletionTxn,
        deleting,
        arrived_tx,
        resume_rx,
    );
    std::thread::scope(|scope| -> Result<()> {
        let deleter = scope
            .spawn(|| vault.delete_entity_with_reason(&deleting, DeleteReason::UserHardDelete));
        arrived_rx
            .recv()
            .expect("deleter reached pre-reservation seam");
        let applied = vault.apply_identity_topology_op(&merge(deleting, survivor), &write, 220);
        resume_tx
            .send(())
            .expect("resume deleter before checking results");
        applied?;
        assert!(
            deleter.join().expect("deleter thread").is_err(),
            "the merge won before reservation: no tombstone may publish"
        );
        Ok(())
    })?;
    assert!(vault.get_raw(&deleting)?.is_some());
    assert!(vault.edge_exists(&deleting, EdgeKind::MergedInto, &survivor)?);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .sync_state
            .get(&rtxn, &crate::deletion::local_hard_delete_key(&deleting))?
            .is_none()
    );
    Ok(())
}

/// Participant deletion auto-cancels a pending split without turning it into
/// a human rejection or a consent-ramp observation.
#[test]
fn deleting_split_participant_mints_one_separate_cancellation_receipt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let original = person(&vault, 0x51);
    let head = person(&vault, 0x52);
    let mut write = IdentityOpWrite::auto(ClaimSource::Inferred);
    write.approval = crate::claim::ClaimApprovalStatus::Proposed;
    let outcome = vault.apply_identity_topology_op(
        &IdentityTopologyOp::Split(SplitOp {
            entity: original,
            heads: vec![head],
            reassignment: ReassignmentMap::default(),
            evidence: IdentityOpEvidence::default(),
        }),
        &write,
        200,
    )?;
    let crate::identity_topology::IdentityOpOutcome::Parked { event: proposal } = outcome else {
        panic!("a split proposal must remain parked");
    };
    vault.delete_entity_with_reason(&original, DeleteReason::UserDelete)?;
    let receipts = vault.receipts(
        crate::receipt::ReceiptQuery::new(100)
            .with_kind(crate::receipt::ReceiptKind::IdentityLifecycle),
    )?;
    let cancellations: Vec<_> = receipts
        .iter()
        .filter(|receipt| receipt.outcome == "proposal_cancellation")
        .collect();
    assert_eq!(cancellations.len(), 1);
    assert_eq!(
        cancellations[0].fields.get("proposal_ref"),
        Some(&proposal.to_hex())
    );
    assert_eq!(
        cancellations[0].fields.get("reason").map(String::as_str),
        Some("participant_deleted")
    );
    let ruling = vault.resolve_identity_proposal(
        &proposal,
        ProposalRuling::Approve,
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        300,
    );
    assert!(
        ruling.is_err(),
        "a deleted participant cannot be approved later"
    );
    assert!(
        vault.identity_topology_event(&proposal)?.is_some(),
        "the original parked decision remains auditable"
    );
    Ok(())
}

/// Featureless has no publish commit. A contender that wins the LMDB writer
/// before the first destructive transaction remains the earlier topology
/// decision; the later delete must refuse without making a false dt: claim.
#[cfg(not(feature = "sync"))]
#[test]
fn featureless_merge_winning_before_first_destructive_txn_refuses_delete() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let deleting = person(&vault, 0x71);
    let survivor = person(&vault, 0x72);
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    vault.test_hooks().install_delete_rendezvous(
        crate::deletion::DeleteRendezvous::AfterTombstonePublish,
        deleting,
        arrived_tx,
        resume_rx,
    );
    std::thread::scope(|scope| -> Result<()> {
        let deleter = scope
            .spawn(|| vault.delete_entity_with_reason(&deleting, DeleteReason::UserHardDelete));
        arrived_rx
            .recv()
            .expect("cfg-off deletion before first writer");
        let merge_result = vault.apply_identity_topology_op(
            &merge(deleting, survivor),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            220,
        );
        resume_tx.send(()).expect("resume after contender commits");
        merge_result?;
        assert!(deleter.join().expect("deleter thread").is_err());
        Ok(())
    })?;
    assert!(vault.edge_exists(&deleting, EdgeKind::MergedInto, &survivor)?);
    assert!(vault.get_raw(&deleting)?.is_some());
    assert!(
        vault
            .store
            .sync_state
            .get(
                &vault.store.env.read_txn()?,
                &crate::deletion::local_hard_delete_key(&deleting),
            )?
            .is_none()
    );
    Ok(())
}
