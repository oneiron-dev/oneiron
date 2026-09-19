//! Observable acceptance for durable text, cursor edits, fork sets and owner purge.

use super::*;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::edge::EdgeActorClass;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use crate::store::GateDecisionId;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

fn actor(vault: &Vault) -> Result<(WriteActor, AuthenticatedOwner)> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    let actor = WriteActor::new(id, EdgeActorClass::Human);
    let owner =
        vault.authenticate_owner(id, "principal:document-test", true, GateDecisionId::now())?;
    Ok((actor, owner))
}

fn entity(
    vault: &Vault,
    actor: WriteActor,
    owner: &AuthenticatedOwner,
    text: &str,
) -> Result<EntityId> {
    let entity = EntityId::now();
    vault.put_entity(
        &entity,
        ENTITY_TYPE_ASSET,
        TimeRange { start: 7, end: 7 },
        9,
        text.as_bytes(),
    )?;
    vault.migrate_entity_text(
        &entity,
        &TextField::Utf8Body,
        actor,
        &DocAuthorization::Owner(owner),
    )?;
    Ok(entity)
}

fn append(
    vault: &Vault,
    entity: EntityId,
    actor: WriteActor,
    owner: &AuthenticatedOwner,
    text: &str,
    at: u64,
) -> Result<Vec<u8>> {
    let length = vault.entity_text(&entity)?.chars().count();
    let anchor = vault.entity_text_anchor(&entity, length, length)?;
    vault.edit_entity_text(
        &entity,
        &[AnchoredEdit {
            actor: Some(actor),
            verb: EditVerb::AppendToSection {
                section: anchor,
                text: text.to_owned(),
            },
        }],
        &DocAuthorization::Owner(owner),
        at,
    )
}

fn edit_request(
    vault: &Vault,
    entity: EntityId,
    actor: WriteActor,
    text: &str,
) -> Result<ForkRequest> {
    let length = vault.entity_text(&entity)?.chars().count();
    Ok(ForkRequest {
        entity,
        base: vault.entity_text_frontier(&entity)?,
        actor,
        edits: vec![AnchoredEdit {
            actor: Some(actor),
            verb: EditVerb::InsertAfterAnchor {
                anchor: vault.entity_text_anchor(&entity, length, length)?,
                text: text.to_owned(),
            },
        }],
        rewrite: None,
    })
}

#[test]
fn birth_and_actor_timestamp_survive_snapshot_and_edits() -> Result<()> {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let id = EntityId::now();
    let mut doc = EntityDoc::open(id, "birth α", actor, 123)?;
    let born = doc.frontier();
    doc.edit_as(actor, 200, |text| {
        text.insert(text.len_unicode(), " and later")
            .map_err(|_| invalid("fixture insert"))
    })?;
    let reopened = EntityDoc::from_snapshot(&doc.export_snapshot()?)?;
    assert_eq!(reopened.text(), "birth α and later");
    assert_eq!(
        reopened.birth(),
        &Birth {
            entity: id.to_hex(),
            actor: actor.entity_ref().to_hex(),
            at: 123
        }
    );
    assert_eq!(reopened.text_at(&born)?, "birth α");
    // Birth metadata is not merely a sidecar: inspect the persisted change.
    let first = super::document::decode_frontier(&born)?.to_vec()[0];
    let snapshot_doc = loro::LoroDoc::new();
    snapshot_doc
        .import(&reopened.export_snapshot()?)
        .expect("public snapshot import");
    assert_eq!(
        snapshot_doc
            .get_change(first)
            .expect("birth commit")
            .timestamp,
        123
    );
    Ok(())
}

#[test]
fn bounded_registry_evicts_and_reopens_without_rewriting_the_record() -> Result<()> {
    let config = crate::test_util::embedding_test_config();
    let (dir, vault) = crate::test_util::open_test_vault_with(config.clone());
    let (writer, owner) = actor(&vault)?;
    vault.set_entity_doc_capacity(2)?;
    let mut ids = Vec::new();
    for label in ["alpha", "beta", "gamma"] {
        let id = entity(&vault, writer, &owner, label)?;
        let pointer = vault.get_raw(&id)?.expect("row");
        append(&vault, id, writer, &owner, " edited", 11)?;
        assert_eq!(vault.get_raw(&id)?.expect("row"), pointer);
        assert_eq!(vault.entity_text(&id)?, format!("{label} edited"));
        assert!(vault.entity_doc_registry_status()?.resident <= 2);
        ids.push(id);
    }
    assert_eq!(vault.entity_doc_registry_status()?.resident, 2);
    assert_eq!(vault.entity_text(&ids[0])?, "alpha edited");
    assert_eq!(vault.entity_text_birth(&ids[0])?.at, 7);
    let changes = vault.entity_text_changes(&ids[0])?;
    assert_eq!(changes.len(), 2);
    assert!(changes.iter().all(|change| change.actor == Some(writer)));
    assert_eq!(changes[0].timestamp, 7);
    assert_eq!(
        vault.entity_text_birth(&ids[0])?.actor,
        writer.entity_ref().to_hex()
    );
    // Existing read APIs expose a view; raw bytes remain a pointer.
    assert_eq!(vault.get(&ids[0])?.expect("view"), b"alpha edited");
    let denied = vault.put_entity(
        &ids[0],
        ENTITY_TYPE_ASSET,
        TimeRange { start: 7, end: 7 },
        12,
        b"clobber",
    );
    assert!(matches!(
        denied,
        Err(Error::Artifact(ArtifactError::InvalidEditManifest(_)))
    ));
    drop(vault);
    let reopened = Vault::open(dir.path(), config)?;
    assert_eq!(reopened.entity_doc_registry_status()?.resident, 0);
    assert_eq!(reopened.entity_text(&ids[0])?, "alpha edited");
    assert_eq!(reopened.entity_text_birth(&ids[0])?.at, 7);
    Ok(())
}

#[test]
fn concurrent_anchored_inserts_survive_and_invalid_calls_are_atomic() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (writer, owner) = actor(&vault)?;
    let id = entity(&vault, writer, &owner, "αbase")?;
    let anchor = vault.entity_text_anchor(&id, 0, 5)?;
    let a = AnchoredEdit {
        actor: Some(writer),
        verb: EditVerb::InsertAfterAnchor {
            anchor: anchor.clone(),
            text: " A".to_owned(),
        },
    };
    let b = AnchoredEdit {
        actor: Some(writer),
        verb: EditVerb::InsertAfterAnchor {
            anchor,
            text: " B".to_owned(),
        },
    };
    let authorization = DocAuthorization::Owner(&owner);
    std::thread::scope(|scope| {
        let auth = &authorization;
        let va = &vault;
        let left = scope.spawn(move || va.edit_entity_text(&id, &[a], auth, 11));
        let right = scope.spawn(move || va.edit_entity_text(&id, &[b], auth, 11));
        left.join().expect("first writer")?;
        right.join().expect("second writer")?;
        Ok::<(), Error>(())
    })?;
    let before = vault.entity_text(&id)?;
    assert!(before.starts_with("αbase"));
    assert!(before.contains(" A"));
    assert!(before.contains(" B"));
    let end = before.chars().count();
    let op = AnchoredEdit {
        actor: Some(writer),
        verb: EditVerb::AppendToSection {
            section: vault.entity_text_anchor(&id, end, end)?,
            text: "X".to_owned(),
        },
    };
    assert!(matches!(
        vault.edit_entity_text(
            &id,
            &vec![op.clone(); 51],
            &DocAuthorization::Owner(&owner),
            12
        ),
        Err(Error::Artifact(ArtifactError::InvalidEditManifest(_)))
    ));
    let mut missing = op.clone();
    missing.actor = None;
    assert!(matches!(
        vault.edit_entity_text(&id, &[op, missing], &DocAuthorization::Owner(&owner), 12),
        Err(Error::Artifact(ArtifactError::InvalidEditManifest(_)))
    ));
    assert_eq!(vault.entity_text(&id)?, before);
    Ok(())
}

#[test]
fn quote_replacement_tracks_live_unicode_positions_not_old_offsets() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (writer, owner) = actor(&vault)?;
    let id = entity(&vault, writer, &owner, "α one β two")?;
    let one = vault.entity_text_anchor(&id, 2, 5)?;
    let two = vault.entity_text_anchor(&id, 8, 11)?;
    vault.edit_entity_text(
        &id,
        &[AnchoredEdit {
            actor: Some(writer),
            verb: EditVerb::ReplaceQuotedSpan {
                span: one,
                text: "much longer".to_owned(),
            },
        }],
        &DocAuthorization::Owner(&owner),
        11,
    )?;
    vault.edit_entity_text(
        &id,
        &[AnchoredEdit {
            actor: Some(writer),
            verb: EditVerb::ReplaceQuotedSpan {
                span: two,
                text: "second".to_owned(),
            },
        }],
        &DocAuthorization::Owner(&owner),
        12,
    )?;
    assert_eq!(vault.entity_text(&id)?, "α much longer β second");
    Ok(())
}

#[test]
fn timeout_retains_every_output_byte_in_attributed_durable_rewrite() -> Result<()> {
    let config = crate::test_util::embedding_test_config();
    let (dir, vault) = crate::test_util::open_test_vault_with(config.clone());
    let (writer, owner) = actor(&vault)?;
    let id = entity(&vault, writer, &owner, "before")?;
    let proposal = EntityId::now();
    let output = "α full attempted text
"
    .repeat(1_000);
    let request = TextUpdateRequest {
        entity: id,
        proposal,
        base: vault.entity_text_frontier(&id)?,
        text: output.clone(),
        actor: writer,
        timeout_ms: 0,
        at: 11,
    };
    let TextUpdateOutcome::RewriteFork {
        fork,
        proposal: returned,
    } = vault.update_entity_text(&request, &DocAuthorization::Owner(&owner))?
    else {
        panic!("timeout must retain a fork");
    };
    assert_eq!(returned, proposal);
    assert_eq!(vault.entity_text(&id)?, "before");
    assert_eq!(vault.entity_text_fork_text(&fork)?, Some(output.clone()));
    let row = vault.entity_text_fork(&fork)?.expect("durable row");
    assert_eq!(row.proposal, proposal.to_hex());
    assert_eq!(row.base, request.base);
    assert_eq!(row.actor, writer.entity_ref().to_hex());
    assert!(row.rewrite);
    drop(vault);
    let reopened = Vault::open(dir.path(), config)?;
    assert_eq!(reopened.entity_text_fork_text(&fork)?, Some(output.clone()));
    assert_eq!(
        reopened.entity_text_proposal(&proposal)?.pending().count(),
        1
    );
    let owner = reopened.authenticate_owner(
        writer.entity_ref(),
        "principal:document-test",
        true,
        GateDecisionId::now(),
    )?;
    append(&reopened, id, writer, &owner, " concurrent tail", 12)?;
    assert!(matches!(
        reopened.settle_text_proposal(
            &proposal,
            SettleVerb::Switch,
            &DocAuthorization::Owner(&owner),
            writer,
            13
        ),
        Err(Error::Artifact(ArtifactError::EditProposalStale))
    ));
    let settled = reopened.settle_text_proposal(
        &proposal,
        SettleVerb::Merge,
        &DocAuthorization::Owner(&owner),
        writer,
        14,
    )?;
    assert!(
        settled
            .forks
            .iter()
            .all(|fork| fork.status == ForkStatus::Merged)
    );
    let merged = reopened.entity_text(&id)?;
    assert!(merged.contains(&output));
    assert!(merged.contains("concurrent tail"));
    Ok(())
}

#[test]
fn multiple_writer_forks_keep_distinct_durable_bases_and_merge_stale_edits() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (writer, owner) = actor(&vault)?;
    let id = entity(&vault, writer, &owner, "base")?;
    let first_id = EntityId::now();
    let first_req = edit_request(&vault, id, writer, " first")?;
    let first = vault.open_text_proposal(
        &first_id,
        std::slice::from_ref(&first_req),
        &DocAuthorization::ProposeOnly,
        10,
    )?;
    let first_fork = EntityId::from_hex(&first.forks[0].fork)?;
    assert_eq!(
        vault.entity_text_fork(&first_fork)?.expect("fork").base,
        first_req.base
    );
    append(&vault, id, writer, &owner, " live", 11)?;
    let second_id = EntityId::now();
    let second = vault.open_text_proposal(
        &second_id,
        &[edit_request(&vault, id, writer, " second")?],
        &DocAuthorization::ProposeOnly,
        12,
    )?;
    assert_ne!(first.forks[0].fork, second.forks[0].fork);
    assert_ne!(first.forks[0].base, second.forks[0].base);
    let stale = vault.settle_text_proposal(
        &first_id,
        SettleVerb::Switch,
        &DocAuthorization::Owner(&owner),
        writer,
        13,
    );
    assert!(matches!(
        stale,
        Err(Error::Artifact(ArtifactError::EditProposalStale))
    ));
    assert_eq!(vault.entity_text_proposal(&first_id)?.pending().count(), 1);
    vault.settle_text_proposal(
        &first_id,
        SettleVerb::Merge,
        &DocAuthorization::Owner(&owner),
        writer,
        14,
    )?;
    let merged = vault.entity_text(&id)?;
    assert!(merged.contains("first"));
    assert!(merged.contains("live"));
    assert_eq!(vault.entity_text_receipts(&id)?.len(), 1);
    assert!(matches!(
        vault.settle_text_proposal(
            &first_id,
            SettleVerb::Merge,
            &DocAuthorization::Owner(&owner),
            writer,
            15
        ),
        Err(Error::Artifact(
            ArtifactError::EditProposalAlreadySettled { .. }
        ))
    ));
    Ok(())
}

#[test]
fn explicit_rewrite_switch_moves_pointer_and_records_receipt() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (writer, owner) = actor(&vault)?;
    let id = entity(&vault, writer, &owner, "old text")?;
    let pointer = vault.get_raw(&id)?.expect("pointer");
    let proposal = EntityId::now();
    let opened = vault.open_text_proposal(
        &proposal,
        &[ForkRequest {
            entity: id,
            base: vault.entity_text_frontier(&id)?,
            actor: writer,
            edits: Vec::new(),
            rewrite: Some("replacement".to_owned()),
        }],
        &DocAuthorization::Owner(&owner),
        11,
    )?;
    assert_eq!(opened.pending().count(), 1);
    assert_eq!(vault.entity_text(&id)?, "old text");
    let settled = vault.settle_text_proposal(
        &proposal,
        SettleVerb::Switch,
        &DocAuthorization::Owner(&owner),
        writer,
        12,
    )?;
    assert_eq!(settled.forks[0].status, ForkStatus::Switched);
    assert_eq!(vault.entity_text(&id)?, "replacement");
    assert_ne!(vault.get_raw(&id)?.expect("new pointer"), pointer);
    let receipt = &vault.entity_text_receipts(&id)?[0];
    assert_eq!(receipt.verb, SettleVerb::Switch);
    assert_eq!(receipt.fork, opened.forks[0].fork);
    assert_eq!(vault.entity_text_birth(&id)?.at, 7);
    Ok(())
}

#[test]
fn per_entity_grants_land_in_scope_and_one_verdict_takes_pending_set() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (writer, owner) = actor(&vault)?;
    let left = entity(&vault, writer, &owner, "left")?;
    let right = entity(&vault, writer, &owner, "right")?;
    let target = format!("entity:{}", left.to_hex());
    vault.create_standing_grant(
        &owner,
        GrantBound::action(
            ActorBound::new(writer.entity_ref().to_hex())?,
            ActionClass::new("entity.text.edit")?,
            ActionEnvelope::new([target.clone()])?.with_target(target)?,
        )?,
    )?;
    let proposal = EntityId::now();
    let bundle = vault.open_text_proposal(
        &proposal,
        &[
            edit_request(&vault, left, writer, " changed")?,
            edit_request(&vault, right, writer, " changed")?,
        ],
        &DocAuthorization::StandingGrant,
        11,
    )?;
    assert_eq!(bundle.forks.len(), 2);
    assert_eq!(bundle.pending().count(), 1);
    assert_eq!(vault.entity_text(&left)?, "left changed");
    assert_eq!(vault.entity_text(&right)?, "right");
    assert_eq!(vault.entity_text_receipts(&left)?.len(), 1);
    assert!(matches!(
        vault.settle_text_proposal(
            &proposal,
            SettleVerb::Merge,
            &DocAuthorization::StandingGrant,
            writer,
            12
        ),
        Err(Error::Artifact(ArtifactError::SettleNotAuthorized(_)))
    ));
    assert_eq!(vault.entity_text_proposal(&proposal)?.pending().count(), 1);
    let accepted = vault.settle_text_proposal(
        &proposal,
        SettleVerb::Merge,
        &DocAuthorization::Owner(&owner),
        writer,
        13,
    )?;
    assert_eq!(accepted.pending().count(), 0);
    assert!(accepted.settled);
    assert_eq!(vault.entity_text(&right)?, "right changed");
    assert_eq!(vault.entity_text_receipts(&right)?.len(), 1);
    Ok(())
}

#[test]
fn proposal_set_reject_and_stale_switch_never_partially_apply() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (writer, owner) = actor(&vault)?;
    let a = entity(&vault, writer, &owner, "a")?;
    let b = entity(&vault, writer, &owner, "b")?;
    let proposal = EntityId::now();
    vault.open_text_proposal(
        &proposal,
        &[
            edit_request(&vault, a, writer, " A")?,
            edit_request(&vault, b, writer, " B")?,
        ],
        &DocAuthorization::ProposeOnly,
        11,
    )?;
    append(&vault, b, writer, &owner, " live", 12)?;
    assert!(matches!(
        vault.settle_text_proposal(
            &proposal,
            SettleVerb::Switch,
            &DocAuthorization::Owner(&owner),
            writer,
            13
        ),
        Err(Error::Artifact(ArtifactError::EditProposalStale))
    ));
    assert_eq!(vault.entity_text(&a)?, "a");
    assert_eq!(vault.entity_text_proposal(&proposal)?.pending().count(), 2);
    assert!(vault.entity_text_receipts(&a)?.is_empty());
    let rejected = vault.settle_text_proposal(
        &proposal,
        SettleVerb::Reject,
        &DocAuthorization::Owner(&owner),
        writer,
        14,
    )?;
    assert!(
        rejected
            .forks
            .iter()
            .all(|fork| fork.status == ForkStatus::Rejected)
    );
    assert_eq!(vault.entity_text(&b)?, "b live");
    Ok(())
}

#[test]
fn citation_v5_v9_floor_clamps_owner_purge_and_preserves_pinned_versions() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (writer, owner) = actor(&vault)?;
    let id = entity(&vault, writer, &owner, "seed")?;
    let mut v5 = Vec::new();
    let mut v7 = Vec::new();
    let mut v9 = Vec::new();
    let mut pin5 = None;
    for n in 1..=9 {
        let frontier = append(&vault, id, writer, &owner, &format!(" {n}"), 10 + n)?;
        if n == 5 || n == 9 {
            let anchor = vault.entity_text_anchor(&id, 0, 4)?;
            let pin = vault.pin_entity_text(
                &EntityId::now(),
                &id,
                &anchor,
                &DocAuthorization::Owner(&owner),
                writer,
            )?;
            if n == 5 {
                v5 = frontier.clone();
                pin5 = Some(pin);
            } else {
                v9 = frontier.clone();
            }
        }
        if n == 7 {
            v7 = frontier;
        }
    }
    assert_eq!(vault.oldest_entity_text_pin(&id)?, pin5);
    assert!(matches!(
        vault.check_entity_text_purge(&id, &v7),
        Err(Error::Artifact(ArtifactError::InvalidEditManifest(_)))
    ));
    let before = vault.entity_text(&id)?;
    let pinned5 = vault.entity_text_at(&id, &v5)?;
    let pinned9 = vault.entity_text_at(&id, &v9)?;
    assert!(matches!(
        vault.purge_entity_text_history(&id, &v9, &DocAuthorization::StandingGrant, 30),
        Err(Error::Artifact(ArtifactError::SettleNotAuthorized(_)))
    ));
    let receipt =
        vault.purge_entity_text_history(&id, &v9, &DocAuthorization::Owner(&owner), 30)?;
    assert_eq!(receipt.applied, v5);
    assert_eq!(vault.entity_text(&id)?, before);
    assert_eq!(vault.entity_text_at(&id, &v5)?, pinned5);
    assert_eq!(vault.entity_text_at(&id, &v9)?, pinned9);
    assert_eq!(vault.entity_text_purge_receipts(&id)?, vec![receipt]);
    let pin = pin5.expect("v5 pin");
    assert!(matches!(
        vault.resolve_entity_text_cursor(&id, &pin.anchor)?,
        CursorResolution::Live { .. }
    ));
    let request = edit_request(&vault, id, writer, " after purge")?;
    let resumed = vault.open_text_proposal(
        &EntityId::now(),
        &[request],
        &DocAuthorization::Owner(&owner),
        31,
    )?;
    assert!(
        resumed
            .forks
            .iter()
            .all(|fork| fork.status == ForkStatus::Merged)
    );
    assert_eq!(vault.entity_text(&id)?, format!("{before} after purge"));
    Ok(())
}

#[test]
fn purged_deleted_cursor_drifts_with_origin_quote_intact() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (writer, owner) = actor(&vault)?;
    let id = entity(&vault, writer, &owner, "old quoted text and live")?;
    let origin = vault.entity_text_anchor(&id, 0, 15)?;
    vault.edit_entity_text(
        &id,
        &[AnchoredEdit {
            actor: Some(writer),
            verb: EditVerb::ReplaceQuotedSpan {
                span: origin.clone(),
                text: "replacement".to_owned(),
            },
        }],
        &DocAuthorization::Owner(&owner),
        11,
    )?;
    let head = append(&vault, id, writer, &owner, " later", 12)?;
    vault.purge_entity_text_history(&id, &head, &DocAuthorization::Owner(&owner), 13)?;
    assert_eq!(
        vault.resolve_entity_text_cursor(&id, &origin)?,
        CursorResolution::Drifted { origin }
    );
    assert_eq!(vault.entity_text(&id)?, "replacement and live later");
    Ok(())
}

#[test]
fn map_field_migration_refuses_trailing_bytes_without_mutating_storage() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (actor, owner) = actor(&vault)?;
    let id = EntityId::now();
    let mut body =
        rmp_serde::to_vec_named(&serde_json::json!({"text":"retain every byte","other":7}))
            .unwrap();
    body.extend_from_slice(b"unparsed suffix");
    vault.put_entity(
        &id,
        ENTITY_TYPE_ASSET,
        TimeRange { start: 7, end: 7 },
        9,
        &body,
    )?;
    let before = vault.get_raw(&id)?;
    assert!(matches!(
        vault.migrate_entity_text(
            &id,
            &TextField::MapField("text".into()),
            actor,
            &DocAuthorization::Owner(&owner)
        ),
        Err(Error::Artifact(ArtifactError::InvalidEditManifest(_)))
    ));
    assert_eq!(vault.get_raw(&id)?, before);
    assert!(vault.entity_text(&id).is_err());
    Ok(())
}
