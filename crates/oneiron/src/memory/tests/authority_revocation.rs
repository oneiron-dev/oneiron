//! Owner bindings, rooting, revocation, revocation-vs-delete races, rotation, and sidecars.

use super::support::*;
use super::*;

/// T9: on a ROOTED vault the three owner verbs demand a folded ACTIVE
/// human-class binding. This is the ESB-C fix: asserting `human` at the
/// facade is no longer enough — the authority log has to agree.
#[test]
fn owner_verbs_require_active_owner_binding_when_rooted() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x5E);
    let agent = put_person(&vault, 0x5F);
    let subject = put_person(&vault, 0x60);
    let owner_facade = facade_for(&vault, owner);
    let agent_facade = vault.memory(agent, EdgeActorClass::Agent);
    let agent_claim = agent_facade
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");

    root_vault_binding(&vault, 0x71, owner, "human");

    // Bound owner: every owner verb still works. No capability is removed by
    // this lane — the binding just has to exist.
    owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "minted"}),
            text_fields: None,
            edges: None,
            occurred_at: 700,
            learned_at: None,
        })
        .expect("bound owner mints PERSON");
    owner_facade
        .claim_retract(&agent_claim.claim_short_id)
        .expect("bound owner retracts another actor's claim");
    owner_facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("bound owner deletes");

    // An UNBOUND human actor on the same rooted vault is refused on all three.
    let stranger = put_person(&vault, 0x61);
    let stranger_facade = facade_for(&vault, stranger);
    let victim = put_person(&vault, 0x62);
    let other_claim = agent_facade
        .claim_upsert(&claim_input(
            "profile.color",
            &victim,
            "observed",
            serde_json::json!("teal"),
        ))
        .expect("second agent claim");
    for err in [
        stranger_facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 701,
                learned_at: None,
            })
            .expect_err("unbound PERSON mint"),
        stranger_facade
            .claim_retract(&other_claim.claim_short_id)
            .expect_err("unbound cross-actor retract"),
        stranger_facade
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
            .expect_err("unbound delete"),
    ] {
        assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
    }

    // Retracting your OWN claim is not an owner power and needs no binding.
    let self_claim = stranger_facade
        .claim_upsert(&claim_input(
            "profile.note",
            &victim,
            "user_stated",
            serde_json::json!("mine"),
        ))
        .expect("stranger writes own claim");
    stranger_facade
        .claim_retract(&self_claim.claim_short_id)
        .expect("self-retraction never needs an owner binding");
}

/// T10: an UNROOTED vault keeps today's store-truth behavior exactly.
///
/// This pins the ratified enforcement mode (S-AUTH3 D6 fork (a),
/// "enforce-when-root-exists"): teeth arrive when a host DECLARES authority,
/// not before. Every shipped vault has no authority log at all, so nothing
/// breaks on upgrade. [owner] fork note: under the alternate "hard flip"
/// ruling these three expectations invert to FORBIDDEN.
#[test]
fn unrooted_vault_keeps_store_truth_owner_verbs() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x63);
    let agent = put_person(&vault, 0x64);
    let subject = put_person(&vault, 0x65);
    let owner_facade = facade_for(&vault, owner);
    let agent_claim = vault
        .memory(agent, EdgeActorClass::Agent)
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");

    assert!(
        vault.authority_fold().expect("fold").vault_id.is_none(),
        "fixture must have no declared authority root"
    );
    owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "minted"}),
            text_fields: None,
            edges: None,
            occurred_at: 702,
            learned_at: None,
        })
        .expect("unrooted PERSON mint unchanged");
    owner_facade
        .claim_retract(&agent_claim.claim_short_id)
        .expect("unrooted cross-actor retract unchanged");
    owner_facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("unrooted delete unchanged");
}

/// T11: the binding class is EXACT and revocation is real.
#[test]
fn exact_class_binding_no_cross_class_satisfaction() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x66);
    let subject = put_person(&vault, 0x67);
    // Bound at "agent" only. A human-class owner verb must NOT be satisfied
    // by an agent-class binding — near-miss classes are the ESB-C defect.
    root_vault_binding(&vault, 0x72, owner, "agent");

    let err = facade_for(&vault, owner)
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("agent-class binding must not satisfy a human-class verb");
    assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
}

/// T11b: a RevokeActor watermark takes the owner's teeth away again.
#[test]
fn revoked_binding_forbids_owner_verbs() {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x68);
    let subject = put_person(&vault, 0x69);
    let facade = facade_for(&vault, owner);

    let (genesis, signing) = authority_root(0x73);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let owner_entry = |seq: u64, op: AuthorityOp, parents: Vec<[u8; 32]>| {
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                parent_hashes: parents,
                op,
                signer: AuthoritySignature {
                    suite: key.suite(),
                    public_key: key.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: 100 + seq,
            },
            &signing,
        )
    };
    let bind = owner_entry(
        1,
        AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: owner,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        vec![genesis_hash],
    );
    let bind_hash = crate::authority::authority_entry_hash(&bind).expect("bind hash");
    vault
        .put_authority_log_entries(&[(genesis, test_time(1), 1), (bind, test_time(2), 2)])
        .expect("root + bind");
    facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("bound owner deletes");

    let revoke = owner_entry(
        2,
        AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        },
        vec![bind_hash],
    );
    vault
        .put_authority_log_entries(&[(revoke, test_time(3), 3)])
        .expect("revoke binding");

    let victim = put_person(&vault, 0x6A);
    let err = facade
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("a revoked binding must lose its owner teeth");
    assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
}

/// fix-leg 5 item 1: the delete owner-gate is TOCTOU-closed.
///
/// `evaluate_deletion_gate` folds the owner binding in a read txn it then
/// DROPS. Everything the destructive transactions do afterwards runs on that
/// dropped snapshot's authority — so a `RevokeActor` committed in the window
/// between the two was, before this fix, never observed and the delete tore
/// anyway. The sibling owner verbs (`claim_retract`, the structural arm) never
/// had the hole because they fold INSIDE their write txns; this drives the race
/// deterministically through the ONE-1149 rendezvous seam and pins the same
/// behavior for deletion.
#[test]
fn revocation_racing_a_gated_delete_refuses_and_tears_nothing() {
    for reason in [
        SafeDeleteReason::UserDelete,
        SafeDeleteReason::UserHardDelete,
    ] {
        let (_dir, vault) = open_vault();
        let owner = put_person(&vault, 0x90);
        let subject = put_person(&vault, 0x91);
        let revoke = root_binding_with_pending_revocation(&vault, 0x92, owner);

        // Control: the binding is live, so the gate passes end to end.
        let warmup = put_person(&vault, 0x93);
        facade_for(&vault, owner)
            .safe_delete(&warmup.to_hex(), reason)
            .expect("control: a bound owner deletes");

        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        // The rendezvous fires from inside the delete AFTER its header read
        // proves the target exists and BEFORE it takes any write lock — i.e.
        // squarely inside the gate-to-purge window this test is about. The
        // seam belongs to this vault, so the deleter thread arms it there.
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);

        let err = std::thread::scope(|scope| {
            let deleter_gate = std::sync::Arc::clone(&gate);
            let vault_ref = &vault;
            let deleter = scope.spawn(move || {
                vault_ref.test_hooks().install_after_header_read_signal(tx);
                deleter_gate.wait();
                facade_for(vault_ref, owner).safe_delete(&subject.to_hex(), reason)
            });
            // Stage the revocation in a HELD write txn: LMDB MVCC keeps it
            // invisible to the deleter's gate fold, so the gate is guaranteed
            // to evaluate against the still-live binding.
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            vault
                .put_authority_log_entries_in_txn(&mut wtxn, &[(revoke, test_time(3), 3)])
                .expect("stage revocation");
            gate.wait();
            // The deleter has read its header and signalled; commit the
            // revocation now and release the write lock it is about to want.
            rx.recv()
                .expect("deleter must signal after the header read");
            wtxn.commit().expect("commit revocation");
            deleter
                .join()
                .expect("deleter thread must not panic")
                .expect_err("a revocation landing before the destructive commit must refuse")
        });

        // Names the real cause: the authority log refused this actor. A
        // concurrency refusal and a gate denial are both live alternatives
        // on this path, and only the code separates them.
        assert_eq!(
            err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED,
            "reason {reason:?}"
        );
        // Nothing torn: the subject survives intact.
        assert_eq!(
            vault.get_entity_type(&subject).expect("get subject"),
            Some(ENTITY_TYPE_PERSON),
            "reason {reason:?}: a refused delete must leave the entity whole"
        );
    }
}

/// fix-leg 6: a refusal must not publish.
///
/// fix-5 re-folded the owner at five destructive sites, but the sync leg's
/// authority lived in `stage_deletion_gate_recovery`'s transaction, which
/// COMMITS and drops its snapshot; `finish_crdt_tombstone_persist` then wrote
/// the CRDT snapshot, the `u:w:` carrier and the delete-bearing `q:` row in a
/// LATER transaction carrying no authority at all. A `RevokeActor` landing
/// between the two therefore let the tombstone reach peers and only the purge
/// re-check refused — `safe_delete` returned FORBIDDEN *after* an unauthorized
/// deletion had already been published, which is unrecoverable: a peer that
/// applied it has hard-deleted the entity.
///
/// The rendezvous fires exactly in that interval. The assertions are the
/// no-publish invariant, carrier by carrier: no live-doc tombstone, no `d:w:`
/// snapshot, no `u:w:` row, no `q:` queue row, and no pending gate sidecar
/// that a later replay could redeem.
#[cfg(feature = "sync")]
#[test]
fn revocation_racing_the_tombstone_publish_refuses_and_publishes_nothing() {
    use std::sync::Arc;

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    let owner = put_person(&vault, 0x94);
    let subject = put_person(&vault, 0x95);
    let revoke = root_binding_with_pending_revocation(&vault, 0x96, owner);

    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "facade-publish-boundary",
    ));
    // A connected peer: `route_live` would hand it the tombstone the instant
    // the publish leaked one.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.outbound().attach(tx);
    let window_key = WindowKey::from_timestamp(1);
    let window = manager
        .open_window(&window_key)
        .expect("open live deletion window");

    // Control: with the binding live, the same path publishes end to end — so
    // the assertions below pin the refusal, not a broken fixture.
    let warmup = put_person(&vault, 0x97);
    facade_for(&vault, owner)
        .safe_delete(&warmup.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("control: a bound owner publishes a tombstone");
    rx.try_recv().expect("control: the peer receives it");

    // Two-phase rendezvous: `arrived` fires once the deleter's gate sidecar is
    // durably staged (its txn committed, no lock held); `resume` releases it
    // into the publish txn after the revocation has landed. The deleter's own
    // staging txn takes the write lock, so the fix-5 held-txn trick would
    // deadlock here — the revocation has to commit while the deleter parks.
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
    vault.test_hooks().install_delete_rendezvous(
        crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
        subject,
        arrived_tx,
        resume_rx,
    );

    let (err, staged_decision_id) = std::thread::scope(|scope| {
        let vault_ref = &vault;
        let deleter = scope.spawn(move || {
            facade_for(vault_ref, owner)
                .safe_delete(&subject.to_hex(), SafeDeleteReason::UserHardDelete)
        });
        // The staged decision id: a refused delete returns no request id, so
        // this is the only handle on the sidecar the refusal must withdraw.
        let staged_decision_id = arrived_rx
            .recv()
            .expect("deleter must signal once its gate sidecar is staged")
            .expect("a hard arm stages a gate sidecar and names it here");
        // The pre-txn gate and the staging re-fold have BOTH already passed on
        // the live binding; the delete is parked believing it is authorized.
        vault
            .put_authority_log_entries(&[(revoke, test_time(3), 3)])
            .expect("commit revocation inside the publish window");
        resume_tx.send(()).expect("release the deleter");
        let err = deleter
            .join()
            .expect("deleter thread must not panic")
            .expect_err("a revocation landing before the publish commit must refuse");
        (err, staged_decision_id)
    });

    // The parked pre-gate authority refusal must survive the publish boundary
    // as itself — not degrade to a generic concurrency code, and not be
    // confusable with the gate denial the same verb can also raise.
    assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);

    // Victim intact.
    assert_eq!(
        vault.get_entity_type(&subject).expect("get subject"),
        Some(ENTITY_TYPE_PERSON),
        "a refused delete must leave the entity whole"
    );

    // No carrier published — live doc, snapshot, update row, queue row.
    assert!(
        window
            .doc
            .get_map("tombstones")
            .get(&subject.to_hex())
            .is_none(),
        "a refused delete must not leave a tombstone in the shared live doc"
    );
    assert!(
        rx.try_recv().is_err(),
        "a refused delete must not route an outbound update to the peer"
    );
    let snapshot = vault
        .sync_state_get(&format!("d:w:{window_key}"))
        .expect("read persisted window snapshot");
    if let Some(snapshot) = snapshot {
        let persisted = crate::sync::loro_support::doc_from_snapshot(&snapshot)
            .expect("persisted snapshot decodes");
        assert!(
            persisted
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach the d:w: snapshot"
        );
    }
    for update_key in vault
        .sync_state_keys_with_prefix(&format!("u:w:{window_key}:"))
        .expect("read pending update rows")
    {
        let bytes = vault
            .sync_state_get(&update_key)
            .expect("read update row")
            .expect("update row exists");
        let replayed = crate::sync::schema::create_window_doc("probe", &window_key);
        crate::sync::loro_support::import_doc(&replayed, &bytes).expect("update row imports");
        assert!(
            replayed
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach a u:w: carrier ({update_key})"
        );
    }
    let queue = crate::sync::SyncQueue::new(Arc::clone(&vault)).expect("open sync queue");
    for queued in queue.drain_updates().expect("drain queued updates") {
        let replayed = crate::sync::schema::create_window_doc("probe", &window_key);
        crate::sync::loro_support::import_doc(&replayed, &queued.encoded)
            .expect("queued update imports");
        assert!(
            replayed
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach a delete-bearing q: row"
        );
    }

    // No pending gate sidecar: the staging from the earlier txn must be
    // withdrawn by the refusal itself, or a later replay would redeem it as a
    // pending AUTHORIZED deletion.
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        vault
            .store
            .pending_deletion_gate_decision_in_txn(&rtxn, staged_decision_id)
            .expect("read sidecar")
            .is_none(),
        "a refused publish must leave no redeemable authority sidecar"
    );
    drop(rtxn);
    // ...and no authority record was minted for a deletion that never happened.
    assert!(
        vault
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.decision_id != staged_decision_id),
        "a refused publish must mint no gate decision"
    );
}

/// fix-leg 7 P1-1: the SOFT arm's publish must pass the gate too.
///
/// `user_delete` scrubs the body to a 25 B shell in one txn, then publishes the
/// tombstone. fix-5 re-folded the owner in the scrub txn and fix-6 gated the
/// hard arms' publish — but the soft arm called `write_crdt_tombstone(..., None,
/// None)`, so its publication passed NO gate at all. A `RevokeActor` landing
/// between the scrub commit and the publish was never observed: the tombstone
/// reached the live doc and the peer, the `d:w:`/`u:w:`/`q:` carriers persisted,
/// and the `pt:` marker the scrub txn had already committed stayed on disk as a
/// replayable propagation intent — an unauthorized soft delete, published.
///
/// Both legs, because they are different code paths through the publish: LIVE
/// (window open, registry-owned shared doc, `route_live` on the wire) and
/// TRANSIENT (window closed, doc import-merged from persisted state). fix-6's
/// concern list flagged the transient-leg symmetry as an open follow-up; it is
/// folded in here.
#[cfg(feature = "sync")]
#[test]
fn revocation_racing_the_soft_delete_publish_refuses_and_publishes_nothing() {
    for live_window in [true, false] {
        let leg = if live_window { "live" } else { "transient" };
        let mut harness = PublishBoundaryHarness::open("facade-soft-publish-boundary", live_window);
        let owner = put_person(&harness.vault, 0x20);
        let subject = put_person(&harness.vault, 0x2A);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2B, owner);

        // Control: with the binding live, the soft arm publishes end to end —
        // so the assertions below pin the refusal, not a broken fixture.
        let warmup = put_person(&harness.vault, 0x2C);
        facade_for(&harness.vault, owner)
            .safe_delete(&warmup.to_hex(), SafeDeleteReason::UserDelete)
            .expect("control: a bound owner soft-deletes");
        assert!(
            harness.snapshot_tombstoned(&warmup),
            "{leg} control: the d:w: snapshot must carry the warmup tombstone — \
             on both legs the publish txn persists it"
        );
        if live_window {
            assert!(
                harness.live_doc_tombstoned(&warmup),
                "{leg} control: the live doc must carry the warmup tombstone"
            );
            // `route_live` is the LIVE leg's last act. The transient leg has no
            // open window to route through — its delivery is the queued `q:`
            // row, which the control below leaves in place deliberately.
            assert!(
                harness.outbound.try_recv().is_ok(),
                "{leg} control: the peer receives the warmup tombstone"
            );
        }
        // Drain the control's outbound traffic so the refusal assertion below
        // reads an empty channel only if the REFUSED delete routed nothing.
        while harness.outbound.try_recv().is_ok() {}

        let err = safe_delete_with_revocation_at(
            &harness.vault,
            owner,
            subject,
            SafeDeleteReason::UserDelete,
            crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
            revoke,
        )
        .expect_err("a revocation landing before the publish commit must refuse");

        // The CODE is the assertion: the parked pre-gate authority refusal
        // must survive the publish boundary as itself, not degrade into the
        // generic concurrency refusal or into the gate's own FORBIDDEN.
        assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{leg}");
        // The shell scrub already committed — that is the pre-publication act
        // this arm is allowed to have done, and fix-5's re-fold gated it. What
        // must NOT exist is any published or replayable carrier.
        harness.assert_nothing_published(&subject, leg);
    }
}

/// fix-leg 7 P1-2 (a): a revocation committed AFTER the publish commit does NOT
/// refuse — the delete COMPLETES.
///
/// The publish commit is the delete's linearization point. fix-5 re-folded the
/// owner at the destructive steps that follow it (soft-erase, purge, headerless
/// purge), which meant a `RevokeActor` landing in the interval publish→purge
/// produced the rejected-call-publishes shape: the caller got FORBIDDEN while
/// the tombstone was already on the wire and peers were already tearing the
/// entity. That refusal is both unactionable and false — sync replay of the
/// published tombstone purges this replica regardless, so the local state the
/// refusal claims to have preserved does not survive anyway.
///
/// Under the ruling the answer is settled at publish: a revocation LMDB-ordered
/// after that commit simply follows an operation that was authorized when it
/// committed, which is ordinary linearizable ordering, not a race. Both
/// post-publication rendezvous points are driven, across every hard reason and
/// the headerless door.
///
/// MUTATION PROBE: re-adding an authority re-fold at any post-publish site
/// fails this test (the delete returns FORBIDDEN and the victim survives) while
/// the pre-publish regressions above still pass — the two directions are pinned
/// independently.
#[cfg(feature = "sync")]
#[test]
fn revocation_after_the_publish_commit_lets_the_delete_complete() {
    let steps = [
        // Entry to the first post-publication destructive step: the soft-erase
        // for gdpr/policy, the purge for user_hard_delete.
        crate::deletion::DeleteRendezvous::AfterTombstonePublish,
        // Entry to the purge on the arms that ran a soft-erase first.
        crate::deletion::DeleteRendezvous::BeforeHardPurge,
    ];
    let reasons = [
        SafeDeleteReason::UserHardDelete,
        SafeDeleteReason::GdprDelete,
        SafeDeleteReason::PolicyDelete,
    ];
    for live_window in [true, false] {
        for step in steps {
            for reason in reasons {
                let leg = if live_window { "live" } else { "transient" };
                let case = format!("{leg}/{step:?}/{reason:?}");
                let harness =
                    PublishBoundaryHarness::open("facade-post-publish-boundary", live_window);
                let owner = put_person(&harness.vault, 0x2D);
                let subject = put_person(&harness.vault, 0x2E);
                let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2F, owner);

                let receipt = safe_delete_with_revocation_at(
                    &harness.vault,
                    owner,
                    subject,
                    reason,
                    step,
                    revoke,
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "{case}: a revocation ordered AFTER the publish commit must not \
                         refuse a committed deletion, but got {}: {}",
                        err.code, err.message
                    )
                });

                assert!(receipt.existed, "{case}: the delete must claim the erasure");
                assert!(
                    receipt.receipt_ref.is_some(),
                    "{case}: every hard reason writes a REDACTION_AUDIT receipt"
                );
                // Torn for real: the entity row is gone, not merely shelled.
                assert_eq!(
                    harness
                        .vault
                        .get_entity_type(&subject)
                        .expect("get subject"),
                    None,
                    "{case}: the victim must be purged"
                );
                // ...and the `dt:` local hard-delete truth is durable.
                let rtxn = harness.vault.store.env.read_txn().expect("read txn");
                assert!(
                    harness
                        .vault
                        .local_hard_delete_marker_exists_in_txn(&rtxn, &subject)
                        .expect("read dt: marker"),
                    "{case}: the purge txn must write the dt: marker"
                );
            }
        }
    }
}

/// fix-leg 7 P1-2 (a), headerless door: same law where there is no header.
///
/// `delete_entity_without_header` erases orphan residue (a vector with no
/// entities row). It publishes a tombstone first and purges after, so it has the
/// same post-publication interval — and fix-5 put a re-fold in its purge txn
/// too. Driven separately because the residue fixture cannot be built through
/// `put_person`.
#[cfg(feature = "sync")]
#[test]
fn revocation_after_the_publish_commit_lets_a_headerless_delete_complete() {
    for live_window in [true, false] {
        let leg = if live_window { "live" } else { "transient" };
        let harness = PublishBoundaryHarness::open_for_vector_residue(
            "facade-headerless-boundary",
            live_window,
        );
        let owner = put_person(&harness.vault, 0x34);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x35, owner);

        // Headerless residue: a vector with no entities row, so the delete takes
        // `delete_entity_without_header`.
        let subject = EntityId::from_bytes([0x3B; 16]).expect("residue id");
        harness
            .vault
            .put_vector(&subject, &[0.1, 0.2, 0.3, 0.4])
            .expect("put orphan vector");
        assert!(
            harness.vault.get_raw(&subject).expect("get raw").is_none(),
            "{leg}: headerless precondition — no entities row"
        );

        let receipt = safe_delete_with_revocation_at(
            &harness.vault,
            owner,
            subject,
            SafeDeleteReason::GdprDelete,
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            revoke,
        )
        .unwrap_or_else(|err| {
            panic!(
                "{leg}: the headerless purge must not re-decide authority after \
                 publication, but got {}: {}",
                err.code, err.message
            )
        });

        // `existed` tracks the ENTITIES row, which a headerless residue has none
        // of by construction — so the erasure evidence here is the audit receipt
        // and the purged vector, exactly as the pre-existing headerless fixtures
        // assert.
        assert!(
            receipt.receipt_ref.is_some(),
            "{leg}: the headerless purge must write its REDACTION_AUDIT receipt"
        );
        assert_eq!(
            harness.vault.get_vector(&subject).expect("get vector"),
            None,
            "{leg}: the orphan vector must be purged"
        );
        let rtxn = harness.vault.store.env.read_txn().expect("read txn");
        assert!(
            harness
                .vault
                .local_hard_delete_marker_exists_in_txn(&rtxn, &subject)
                .expect("read dt: marker"),
            "{leg}: the headerless purge txn must write the dt: marker"
        );
    }
}

/// fix-leg 8 P1: WITHOUT a publish commit there is no linearization point, so
/// the first destructive transaction must still re-prove authority.
///
/// `write_crdt_tombstone` is a NO-OP in a build without `sync` — it publishes
/// nothing and returns `crdt_persisted: false`. fix-7 read "after the publish
/// commit, do not re-check" as unconditional and removed the soft-erase and
/// purge re-folds, which on this build removed the ONLY in-transaction authority
/// checks the hard arms had: nothing had published, so the check fix-7 relied on
/// never ran. A `RevokeActor` landing after `safe_delete`'s entry fold then let
/// `user_hard_delete` / `gdpr_delete` / `policy_delete` tear the entity locally,
/// append an `allow` gate record, and commit the `pt:` marker whose verbatim
/// tombstone bytes a later sync-enabled boot replays through
/// `replay_pending_tombstones` — an unauthorized deletion, published on a delay.
///
/// The refined rule keys on `crdt_persisted`, not on the cargo feature: a
/// `sync` build path that declines to publish must obey the same law, and a
/// `#[cfg]` here would silently exempt it. The rendezvous parks the deleter in
/// the window after the entry fold and before the first destructive commit —
/// which on this build is where `AfterTombstonePublish` fires, since the
/// "publish" it names did nothing.
///
/// MUTATION PROBE: drop the conditional reverify from the hard arms' first
/// destructive txn and this test fails — the delete succeeds, the victim is
/// purged, and the replayable `pt:` marker survives.
#[cfg(not(feature = "sync"))]
#[test]
fn revocation_after_a_nonpublishing_delete_refuses_and_tears_nothing() {
    for reason in [
        SafeDeleteReason::UserHardDelete,
        SafeDeleteReason::GdprDelete,
        SafeDeleteReason::PolicyDelete,
    ] {
        let case = format!("{reason:?}");
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = std::sync::Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"),
        );
        let owner = put_person(&vault, 0x40);
        let subject = put_person(&vault, 0x41);
        let revoke = root_binding_with_pending_revocation(&vault, 0x42, owner);

        let err = safe_delete_with_revocation_at(
            &vault,
            owner,
            subject,
            reason,
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            revoke,
        )
        .expect_err(&format!(
            "{case}: nothing published, so the first destructive txn is this \
             delete's linearization point and MUST refuse"
        ));

        assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{case}");
        assert!(
            err.message.contains("no active owner binding"),
            "{case}: the parked pre-gate error must survive, not degrade to a \
             generic concurrency code: {}",
            err.message
        );
        // Intact, not merely un-purged: the shell scrub must not have run either.
        assert_eq!(
            vault.get_entity_type(&subject).expect("get subject"),
            Some(ENTITY_TYPE_PERSON),
            "{case}: a refused delete must leave the entity whole"
        );
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("subject row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + b"facade person".len(),
            "{case}: the body must be un-scrubbed — a 25 B shell would mean the \
             soft-erase committed before the refusal"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

/// fix-leg 8 P1, headerless leg: same law where there is no header.
///
/// `delete_entity_without_header` erases orphan residue (a vector with no
/// entities row). Its pre-publication guards were the scope probe's read txn and
/// the publish txn's re-fold — and on a build with no `sync` the second does not
/// exist, so fix-7's removal of the purge re-fold left this door with NO
/// in-transaction authority check at all. The residue is the part that makes it
/// bite differently from the headerful arms: it is the actual user data (a
/// vector, a BM25 posting), and a refused delete must leave it whole.
///
/// MUTATION PROBE: drop the conditional reverify from the headerless purge txn
/// and this test fails — the residue is erased and the receipt is minted.
#[cfg(not(feature = "sync"))]
#[test]
fn revocation_after_a_nonpublishing_headerless_delete_refuses_and_tears_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = std::sync::Arc::new(
        crate::Vault::open(
            dir.path(),
            VaultConfig {
                embedding_model: Some("test/model@v1".to_owned()),
                dimensions: 4,
                ..VaultConfig::default()
            },
        )
        .expect("open vault"),
    );
    let owner = put_person(&vault, 0x43);
    let revoke = root_binding_with_pending_revocation(&vault, 0x44, owner);

    // Headerless residue: a vector with no entities row, so the delete takes
    // `delete_entity_without_header`.
    let subject = EntityId::from_bytes([0x45; 16]).expect("residue id");
    let residue = [0.1_f32, 0.2, 0.3, 0.4];
    vault
        .put_vector(&subject, &residue)
        .expect("put orphan vector");
    assert!(
        vault.get_raw(&subject).expect("get raw").is_none(),
        "headerless precondition — no entities row"
    );

    let err = safe_delete_with_revocation_at(
        &vault,
        owner,
        subject,
        SafeDeleteReason::GdprDelete,
        crate::deletion::DeleteRendezvous::AfterTombstonePublish,
        revoke,
    )
    .expect_err(
        "the headerless purge is this delete's ONLY durable act when nothing \
         published, so it MUST re-decide authority",
    );

    assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
    assert!(
        err.message.contains("no active owner binding"),
        "{}",
        err.message
    );
    // The residue itself survives — the point of the headerless door. Rows are
    // stored narrowed to f16, so the readback is the quantized residue.
    assert_eq!(
        vault.get_vector(&subject).expect("get vector"),
        Some(
            residue
                .iter()
                .map(|v| half::f16::from_f32(*v).to_f32())
                .collect::<Vec<_>>()
        ),
        "a refused headerless delete must leave the orphan vector intact"
    );
    assert_no_local_delete_artifacts(&vault, &subject, "headerless");
}

/// P2-b: `fold.vault_id == None` is TWO states, and only one of them may pass.
///
/// A log carrying two independent genesis roots folds to `vault_id: None` with
/// `ConflictingVaultRoot` issues and an EMPTY `actor_bindings` map — the same
/// shape as a vault that never declared authority. Reading that as "unrooted,
/// keep store truth" hands every owner verb to any caller precisely when the
/// authority root is contested, which is the fail-open this pins shut.
#[test]
fn conflicting_vault_roots_fail_owner_verbs_closed() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x6B);
    let subject = put_person(&vault, 0x6C);
    let facade = facade_for(&vault, owner);

    // Two independently rooted genesis entries in one log. Each is internally
    // valid; together they are a collapse.
    let (genesis_a, _) = authority_root(0x74);
    let (genesis_b, _) = authority_root(0x75);
    vault
        .put_authority_log_entries(&[(genesis_a, test_time(1), 1), (genesis_b, test_time(2), 2)])
        .expect("two independent roots are individually valid rows");

    let fold = vault.authority_fold().expect("fold");
    assert!(
        fold.vault_root_is_conflicted(),
        "fixture must produce the conflicting-roots collapse"
    );
    assert!(
        fold.vault_id.is_none() && fold.actor_bindings.is_empty(),
        "the collapse must be indistinguishable from unrooted on shape alone \
         — that indistinguishability IS the bug being pinned"
    );

    // INVALID_STATE, not FORBIDDEN: nothing is wrong with the caller, the
    // vault's authority is. The taxonomy is what tells a host to repair the
    // log rather than to go mint a binding.
    let err = facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("owner verbs must fail closed under conflicting roots");
    assert_eq!(err.code, MEMORY_CODE_INVALID_STATE);
    assert!(
        err.message.contains("conflicting vault roots"),
        "{}",
        err.message
    );

    // The other two owner verbs take the same door.
    for err in [
        facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 703,
                learned_at: None,
            })
            .expect_err("conflicted-root PERSON mint"),
        {
            let agent = put_person(&vault, 0x6D);
            let claim = vault
                .memory(agent, EdgeActorClass::Agent)
                .claim_upsert(&claim_input(
                    "profile.mood",
                    &subject,
                    "observed",
                    serde_json::json!("calm"),
                ))
                .expect("agent claim");
            facade
                .claim_retract(&claim.claim_short_id)
                .expect_err("conflicted-root cross-actor retract")
        },
    ] {
        assert_eq!(err.code, MEMORY_CODE_INVALID_STATE);
    }
}

/// A sidecar-less rotation must never hand the RETIRED key owner verbs through
/// the facade gate.
///
/// The owner gate reads `authority_fold_readonly_in_txn`, which used to omit
/// entries with no first-seen sidecar — leaving a delayable widen pending
/// forever. For `RotateKey` that is fail-OPEN: pending means the RETIRED key is
/// still a live owner-capable roster key. On a legacy rooted vault whose
/// rotation lost its sidecar, an attacker holding the retired key files a DAG
/// SIBLING `BindActor(retired_key, attacker, "human")` parented at genesis, and
/// the gate hands them every owner verb.
///
/// fix-3 closed that by synthesizing the migration's `learned_at.min(now)`.
/// fix-leg 4 removes `learned_at` from the answer entirely — it is peer-written,
/// so the long-past values in this fixture are the attacker's own claim — and
/// the gate suspends instead: INVALID_STATE while the fold cannot date the
/// rotation, cleared by one write-path fold, after which the rotation serves its
/// delay from local observation. Either way the retired key never authorizes.
#[test]
fn sidecarless_rotation_denies_owner_verbs_through_the_facade() {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (_dir, vault) = open_vault();
    let attacker = put_person(&vault, 0x76);
    let subject = put_person(&vault, 0x77);
    let facade = facade_for(&vault, attacker);

    let (genesis, signing) = authority_root(0x78);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let retired = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let successor = ed25519_dalek::SigningKey::from_bytes(&[0x79; 32]);
    let owner_entry = |seq: u64, op: AuthorityOp, ts: u64| {
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                // Every child parents at GENESIS: the squatting bind is a
                // sibling of the rotation, so no topological rule kills it and
                // only the rotation's MATURITY can.
                parent_hashes: vec![genesis_hash],
                op,
                signer: AuthoritySignature {
                    suite: retired.suite(),
                    public_key: retired.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts,
            },
            &signing,
        )
    };
    let rotate = owner_entry(
        1,
        AuthorityOp::RotateKey {
            old_key: retired.clone(),
            new_device: crate::authority::DeviceAuthority {
                key: AuthorityKey::Ed25519(successor.verifying_key().to_bytes()),
                transport_key_binding: [7; 32],
                attestation: crate::authority::AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: crate::authority::AuthorityTier::Software,
                roles: crate::authority::ROLE_OWNER | crate::authority::ROLE_ADMIN,
            },
        },
        101,
    );
    let squat = owner_entry(
        2,
        AuthorityOp::BindActor {
            authority_key: retired.clone(),
            actor_ref: attacker,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        102,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, test_time(1), 1),
            (rotate, test_time(2), 2),
            (squat, test_time(3), 3),
        ])
        .expect("legacy log rows are individually valid");

    // Rewind to the legacy shape: no sidecars, migration marker unset. The
    // long-past `learned_at` values are the attacker's claim that the rotation
    // elapsed ages ago — which fix-leg 4 refuses to act on.
    strip_authority_first_seen_state(&vault);

    // Pre-migration the fold cannot date the rotation, so every owner verb is
    // SUSPENDED — the gate refuses rather than reading maturity out of the
    // attacker's own `learned_at`.
    let agent = put_person(&vault, 0x7A);
    let claim = vault
        .memory(agent, EdgeActorClass::Agent)
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");
    for err in [
        facade
            .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
            .expect_err("retired key must not delete"),
        facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 704,
                learned_at: None,
            })
            .expect_err("retired key must not mint a PERSON"),
        facade
            .claim_retract(&claim.claim_short_id)
            .expect_err("retired key must not retract another actor's claim"),
    ] {
        assert_eq!(err.code, MEMORY_CODE_INVALID_STATE, "{}", err.message);
        assert!(
            err.message.contains("owner verbs are suspended"),
            "{}",
            err.message
        );
    }

    // The suspension is self-clearing, not a brick: one write-path fold records
    // the local observation and the rotation becomes datable. It is freshly
    // observed, so it now sits INSIDE its delay — the veto window a legacy
    // import is supposed to serve — rather than being declared elapsed by the
    // peer that shipped it.
    let full = vault.authority_fold().expect("fold");
    assert!(
        !full.pending_widens.is_empty(),
        "the rotation is dated at migration time, so its delay has not elapsed"
    );
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        vault
            .authority_fold_readonly_in_txn(&rtxn)
            .expect("a locally dated log folds"),
        full,
        "once observed locally the gate's fold agrees with the write-path fold"
    );
    drop(rtxn);
}

/// fix-3: a sidecar lost AFTER the one-shot migration is unrecoverable, so the
/// owner gate suspends rather than authorizing on a fold it cannot compute.
///
/// Distinct from the legacy case above: there the migration had not run and the
/// value is reproducible. Once the marker is set the migration will never revisit
/// that row, and both remaining guesses are unsafe — so this is INVALID_STATE
/// (the vault's authority is broken), never a silent pass.
#[test]
fn owner_verbs_suspend_when_a_first_seen_sidecar_is_lost_after_migration() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x7B);
    let subject = put_person(&vault, 0x7C);
    let facade = facade_for(&vault, owner);
    root_vault_binding(&vault, 0x7D, owner, "human");

    // Settle: the full fold is what sets the one-shot marker.
    vault.authority_fold().expect("fold");
    facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the bound owner works before the sidecar is lost");

    let sidecars = authority_first_seen_sidecar_keys(&vault);
    assert!(!sidecars.is_empty(), "the migration must have written rows");
    vault
        .with_write_txn(|wtxn| {
            for key in &sidecars {
                assert!(vault.store.sync_state.delete(wtxn, key.as_str())?);
            }
            Ok(())
        })
        .expect("drop the sidecars");

    let victim = put_person(&vault, 0x7E);
    let err = facade
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("an uncomputable fold must suspend owner verbs");
    assert_eq!(err.code, MEMORY_CODE_INVALID_STATE);
    assert!(
        err.message.contains("owner verbs are suspended"),
        "{}",
        err.message
    );
}
