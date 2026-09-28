//! Board acceptance: real claim rows, exact pinned text, no unchanged writes.
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

fn put(vault: &Vault, kind: u8, text: &str) -> EntityId {
    let id = EntityId::now();
    let raw = rmp_serde::to_vec_named(&serde_json::json!({"content": text})).unwrap();
    vault
        .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, &raw)
        .unwrap();
    id
}

#[test]
fn changed_turn_claims_carry_anchor_unchanged_turns_write_nothing_and_fold_exactly() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let owner = put(&vault, ENTITY_TYPE_PERSON, "owner");
    let a = put(&vault, ENTITY_TYPE_ASSET_TEXT, "scope alpha");
    let b = put(&vault, ENTITY_TYPE_ASSET_TEXT, "scope beta");
    let memory = put(&vault, ENTITY_TYPE_ASSET_TEXT, "original memory");
    let ephemeral = put(&vault, ENTITY_TYPE_ASSET_TEXT, "index only");
    let first = put(&vault, ENTITY_TYPE_TURN, "first");
    let middle = put(&vault, ENTITY_TYPE_TURN, "middle");
    let last = put(&vault, ENTITY_TYPE_TURN, "last");
    let selection = BoardSelection {
        allowed: BTreeSet::from([a, b]),
        active: BTreeSet::from([a]),
        pinned: BTreeSet::from([memory]),
        index_only: BTreeSet::from([ephemeral]),
        ..Default::default()
    };
    let receipt = vault
        .record_board_turn(
            &BoardTurn {
                turn: first,
                owner,
                at: 1,
                selection: selection.clone(),
            },
            10,
        )
        .unwrap();
    assert_eq!(receipt.changed_claims.len(), 3);
    for id in &receipt.changed_claims {
        let claim = vault.get_claim(id).unwrap().unwrap();
        assert_eq!(
            super::claims::decode_value(&claim.value).unwrap().1,
            receipt.source_revision_ref
        );
    }
    let recorded = vault.reconstruct_board(&first).unwrap();
    let unchanged = vault
        .record_board_turn(
            &BoardTurn {
                turn: middle,
                owner,
                at: 2,
                selection: selection.clone(),
            },
            11,
        )
        .unwrap();
    assert!(unchanged.changed_claims.is_empty());
    let expected_middle = vault.reconstruct_board(&middle).unwrap();
    assert_eq!(expected_middle.documents, recorded.documents);
    let updated = rmp_serde::to_vec_named(&serde_json::json!({"content": "new memory"})).unwrap();
    vault
        .put_entity(
            &memory,
            ENTITY_TYPE_ASSET_TEXT,
            TimeRange { start: 1, end: 1 },
            1,
            &updated,
        )
        .unwrap();
    let mut next = selection;
    next.active = BTreeSet::from([b]);
    let changed = vault
        .record_board_turn(
            &BoardTurn {
                turn: last,
                owner,
                at: 3,
                selection: next,
            },
            12,
        )
        .unwrap();
    assert_eq!(changed.changed_claims.len(), 1);
    let active = vault
        .get_claim(&changed.changed_claims[0])
        .unwrap()
        .unwrap();
    assert_eq!(active.predicate, "world_access.active");
    assert_eq!(
        super::claims::decode_value(&active.value).unwrap().1,
        changed.source_revision_ref
    );
    assert_eq!(vault.reconstruct_board(&middle).unwrap(), expected_middle);
    assert_eq!(
        vault
            .reconstruct_board(&last)
            .unwrap()
            .documents
            .get(&memory),
        Some(&updated)
    );
    assert!(
        !vault
            .reconstruct_board(&last)
            .unwrap()
            .documents
            .contains_key(&ephemeral)
    );
    vault.advance_board_compaction_horizon(&owner, 2).unwrap();
    assert!(
        matches!(vault.reconstruct_board(&first), Err(BoardHistoryError::BeyondCompactionHorizon { turn, retained_from: 2 }) if turn == first)
    );
    assert_eq!(vault.reconstruct_board(&middle).unwrap(), expected_middle);
}

#[test]
fn generic_claim_door_cannot_forge_board_authority_or_frontier() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let owner = put(&vault, ENTITY_TYPE_PERSON, "owner");
    let mut body = ClaimBody::new(
        "world_access.active",
        ClaimSubject::Entity(owner),
        super::claims::value(&BTreeSet::new(), crate::vault::RevisionRef([1; 16])),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(1);
    assert!(matches!(
        vault.put_claim(&EntityId::now(), &body, TimeRange { start: 1, end: 2 }, 1),
        Err(crate::error::Error::Claim(
            crate::error::ClaimError::ReservedPredicate { .. }
        ))
    ));
    body.value = rmpv::Value::Nil;
    assert!(matches!(
        super::claims::validate_board_claim(&body),
        Err(crate::error::Error::InvalidClaimBody(_))
    ));
}

#[test]
fn board_refuses_claims_withdrawn_before_recording_or_after_the_turn() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let owner = put(&vault, ENTITY_TYPE_PERSON, "owner");
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "core.fact",
        ClaimSubject::Entity(owner),
        rmpv::Value::from("memory"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let turn = put(&vault, ENTITY_TYPE_TURN, "first");
    // The board reads pinned claims with the owner's own scoped authority.
    crate::test_util::authorize_readers(&vault, &[owner.to_hex().as_str()]);
    let selection = BoardSelection {
        pinned: BTreeSet::from([claim]),
        ..Default::default()
    };
    vault
        .record_board_turn(
            &BoardTurn {
                turn,
                owner,
                at: 1,
                selection: selection.clone(),
            },
            1,
        )
        .unwrap();
    assert!(
        vault
            .reconstruct_board(&turn)
            .unwrap()
            .documents
            .contains_key(&claim)
    );
    vault.retract_claim(&claim, 2).unwrap();
    assert!(
        matches!(vault.reconstruct_board(&turn),Err(BoardHistoryError::UnreadableDocument(id)) if id==claim)
    );
    let next = put(&vault, ENTITY_TYPE_TURN, "second");
    assert!(
        matches!(vault.record_board_turn(&BoardTurn{turn:next,owner,at:2,selection},2),Err(BoardHistoryError::UnreadableDocument(id)) if id==claim)
    );
    assert!(matches!(
        vault.reconstruct_board(&next),
        Err(BoardHistoryError::UnknownTurn(_))
    ));
}

#[test]
fn index_only_is_disjoint_from_every_persisted_family() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let owner = put(&vault, ENTITY_TYPE_PERSON, "owner");
    let document = put(&vault, ENTITY_TYPE_ASSET_TEXT, "index only");
    let turn = put(&vault, ENTITY_TYPE_TURN, "first");
    for family in 0..5 {
        let mut selection = BoardSelection {
            index_only: BTreeSet::from([document]),
            ..Default::default()
        };
        match family {
            0 => {
                selection.allowed.insert(document);
            }
            1 => {
                selection.allowed.insert(document);
                selection.default_on.insert(document);
            }
            2 => {
                selection.allowed.insert(document);
                selection.active.insert(document);
            }
            3 => {
                selection.pinned.insert(document);
            }
            _ => {
                selection.top_snippet.insert(document);
            }
        }
        assert!(matches!(
            vault.record_board_turn(
                &BoardTurn {
                    turn,
                    owner,
                    at: 1,
                    selection
                },
                1
            ),
            Err(BoardHistoryError::InvalidSelection(_))
        ));
        assert!(matches!(
            vault.reconstruct_board(&turn),
            Err(BoardHistoryError::UnknownTurn(_))
        ));
    }
}

#[test]
fn board_claim_frontier_is_authenticated_without_rewriting_unchanged_families() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let owner = put(&vault, ENTITY_TYPE_PERSON, "owner");
    let document = put(&vault, ENTITY_TYPE_ASSET_TEXT, "pinned");
    let first = put(&vault, ENTITY_TYPE_TURN, "first");
    let second = put(&vault, ENTITY_TYPE_TURN, "second");
    let selection = BoardSelection {
        pinned: BTreeSet::from([document]),
        ..Default::default()
    };
    let receipt = vault
        .record_board_turn(
            &BoardTurn {
                turn: first,
                owner,
                at: 1,
                selection: selection.clone(),
            },
            10,
        )
        .unwrap();
    let unchanged = vault
        .record_board_turn(
            &BoardTurn {
                turn: second,
                owner,
                at: 2,
                selection: selection.clone(),
            },
            11,
        )
        .unwrap();
    assert!(unchanged.changed_claims.is_empty());
    assert_eq!(
        vault.reconstruct_board(&second).unwrap().selection,
        selection
    );
    let id = receipt.changed_claims[0];
    let mut body = vault.get_claim(&id).unwrap().unwrap();
    body.value = super::claims::value(&selection.pinned, crate::vault::RevisionRef([0xFF; 16]));
    let mut txn = vault.store.env.write_txn().unwrap();
    vault
        .put_reserved_claim_in_txn(
            &mut txn,
            &id,
            &body,
            TimeRange {
                start: 1,
                end: u64::MAX,
            },
            10,
        )
        .unwrap();
    txn.commit().unwrap();
    for turn in [first, second] {
        assert!(matches!(
            vault.reconstruct_board(&turn),
            Err(BoardHistoryError::MissingFrontier)
        ));
    }
}

#[test]
fn deleted_turns_cannot_reconstruct_shared_board_history() {
    for reason in [
        crate::DeleteReason::UserHardDelete,
        crate::DeleteReason::UserDelete,
    ] {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let owner = put(&vault, ENTITY_TYPE_PERSON, "owner");
        let document = put(&vault, ENTITY_TYPE_ASSET_TEXT, "pinned body");
        let first = put(&vault, ENTITY_TYPE_TURN, "removed turn");
        let sibling = put(&vault, ENTITY_TYPE_TURN, "retained turn");
        let selection = BoardSelection {
            pinned: BTreeSet::from([document]),
            ..Default::default()
        };
        for (turn, at) in [(first, 1), (sibling, 2)] {
            vault
                .record_board_turn(
                    &BoardTurn {
                        turn,
                        owner,
                        at,
                        selection: selection.clone(),
                    },
                    at,
                )
                .unwrap();
        }
        assert_eq!(
            vault.reconstruct_board(&first).unwrap().selection,
            selection
        );
        let retained = vault.reconstruct_board(&sibling).unwrap();
        vault.delete_entity_with_reason(&first, reason).unwrap();
        assert!(
            matches!(vault.reconstruct_board(&first), Err(BoardHistoryError::UnknownTurn(id)) if id == first)
        );
        assert_eq!(vault.reconstruct_board(&sibling).unwrap(), retained);
    }
}

#[test]
fn deleted_owners_cannot_reconstruct_retained_turns() {
    for reason in [
        crate::DeleteReason::UserHardDelete,
        crate::DeleteReason::UserDelete,
    ] {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let owner = put(&vault, ENTITY_TYPE_PERSON, "removed owner");
        let sibling_owner = put(&vault, ENTITY_TYPE_PERSON, "retained owner");
        let document = put(&vault, ENTITY_TYPE_ASSET_TEXT, "shared pinned body");
        let first = put(&vault, ENTITY_TYPE_TURN, "first");
        let second = put(&vault, ENTITY_TYPE_TURN, "second");
        let sibling = put(&vault, ENTITY_TYPE_TURN, "sibling");
        for (turn, owner, at) in [
            (first, owner, 1),
            (second, owner, 2),
            (sibling, sibling_owner, 3),
        ] {
            vault
                .record_board_turn(
                    &BoardTurn {
                        turn,
                        owner,
                        at,
                        selection: BoardSelection {
                            pinned: BTreeSet::from([document]),
                            ..Default::default()
                        },
                    },
                    at,
                )
                .unwrap();
        }
        let retained = vault.reconstruct_board(&sibling).unwrap();
        assert!(
            vault
                .reconstruct_board(&first)
                .unwrap()
                .documents
                .contains_key(&document)
        );
        vault.delete_entity_with_reason(&owner, reason).unwrap();
        for turn in [first, second] {
            assert!(
                matches!(vault.reconstruct_board(&turn), Err(BoardHistoryError::UnknownOwner(id)) if id == owner)
            );
            assert!(
                vault
                    .get_raw_with_mode(&turn, crate::vault::ReadMode::Live)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(vault.reconstruct_board(&sibling).unwrap(), retained);
    }
}

#[test]
fn board_history_reads_return_their_receipt() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let owner = put(&vault, ENTITY_TYPE_PERSON, "owner");
    let owner_key = crate::claim::ScopedReadActorKey::new(owner.to_hex()).unwrap();
    let document = put(&vault, ENTITY_TYPE_ASSET_TEXT, "scope alpha");
    let claim = EntityId::now();
    vault
        .put_claim(
            &claim,
            &ClaimBody::new(
                "core.fact",
                ClaimSubject::Entity(owner),
                rmpv::Value::from("memory"),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();

    // With no read grant the owner's ceiling denies every row: a turn over a
    // plain document records, and its receipt says the read was denied.
    let first = put(&vault, ENTITY_TYPE_TURN, "first");
    let plain = BoardSelection {
        allowed: BTreeSet::from([document]),
        ..Default::default()
    };
    let recorded = vault
        .record_board_turn(
            &BoardTurn {
                turn: first,
                owner,
                at: 1,
                selection: plain,
            },
            1,
        )
        .unwrap();
    assert!(recorded.read_receipt.applied.deny_all);
    assert!(
        recorded
            .read_receipt
            .narrowed_axes
            .contains(&"deny_all".to_owned())
    );
    assert_eq!(
        vault.reconstruct_board(&first).unwrap().read_receipt,
        recorded.read_receipt
    );
    // The same ceiling refuses a turn that pins a claim.
    let pinned = BoardSelection {
        pinned: BTreeSet::from([claim]),
        ..Default::default()
    };
    let second = put(&vault, ENTITY_TYPE_TURN, "second");
    assert!(matches!(
        vault.record_board_turn(
            &BoardTurn {
                turn: second,
                owner,
                at: 2,
                selection: pinned.clone(),
            },
            2,
        ),
        Err(BoardHistoryError::UnreadableDocument(id)) if id == claim
    ));

    // Granted, both the recording and the reconstruction return the owner's
    // own receipt for the pinned claim they read.
    crate::test_util::authorize_readers(&vault, &[owner.to_hex().as_str()]);
    let granted = vault
        .record_board_turn(
            &BoardTurn {
                turn: second,
                owner,
                at: 2,
                selection: pinned,
            },
            2,
        )
        .unwrap();
    let expected = vault.scoped_read(owner_key).read_receipt(None, 0).unwrap();
    assert!(!expected.applied.deny_all);
    assert_eq!(granted.read_receipt, expected);
    let board = vault.reconstruct_board(&second).unwrap();
    assert!(board.documents.contains_key(&claim));
    assert_eq!(board.read_receipt, expected);
}
