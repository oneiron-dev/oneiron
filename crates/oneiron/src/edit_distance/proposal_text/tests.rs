use super::*;

use crate::edge::EdgeActorClass;
use crate::edit_distance::finalized_proposal_text;
use crate::edit_distance::register_peer_actor;
use crate::edit_distance::tests::{put_actor, temp_vault};

fn insert_at(text: &LoroText, pos: usize, s: &str) -> Result<()> {
    text.insert(pos, s)
        .map_err(|_| Error::InvariantViolation("fixture insert"))
}

/// An artifact carried across a mid-window snapshot/reopen, edited on each side
/// by a different actor on a different device peer, attributes BOTH spans
/// correctly and replays back to the exact final text.
///
/// The reopen is the point: the stamp rides the commit MESSAGE precisely
/// because the commit ORIGIN would not survive this boundary.
#[test]
fn two_peers_across_a_reopen_attribute_and_replay_exactly() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let agent = put_actor(&vault, EdgeActorClass::Agent);

    let mut opened = ProposalTextArtifact::open(&vault, "hello world", &human, None).expect("open");
    register_peer_actor(&vault, opened.peer_id(), &human).expect("register human peer");
    opened
        .edit_as(&human, |text| insert_at(text, 5, ","))
        .expect("human edit");
    let snapshot = opened.export_snapshot().expect("snapshot");

    let mut resumed = ProposalTextArtifact::from_snapshot(&snapshot).expect("reopen");
    assert_eq!(resumed.artifact_ref(), opened.artifact_ref());
    assert_ne!(resumed.peer_id(), opened.peer_id(), "reopen is a new peer");
    register_peer_actor(&vault, resumed.peer_id(), &agent).expect("register agent peer");
    resumed
        .edit_as(&agent, |text| insert_at(text, text.len_unicode(), "!"))
        .expect("agent edit");

    let record = resumed.finalize(&vault).expect("finalize");
    assert_eq!(record.proposed_text, "hello world");
    assert_eq!(record.final_text, "hello, world!");

    let attributed = record
        .ops_by_actor
        .iter()
        .map(|(attribution, span)| {
            (
                *attribution,
                span.before_text.clone(),
                span.after_text.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        attributed,
        vec![
            (
                OpAttribution::Stamped(human),
                "hello world".to_owned(),
                "hello, world".to_owned()
            ),
            (
                OpAttribution::Stamped(agent),
                "hello, world".to_owned(),
                "hello, world!".to_owned()
            ),
        ]
    );
}

/// A stamp naming an UNREGISTERED actor is not honored: it resolves to the
/// writing peer's own registration, never to the actor the message names.
///
/// `WriteActor::new` and `edit_as` are public, so an unregistered stamped actor
/// is exactly as forgeable as one belonging to another peer — an honored
/// unregistered stamp would be an attribution write door. Distinguishing
/// co-resident actors on one device peer therefore requires binding each of
/// them; widening the rule is a blueprint amendment, banked for the board.
#[test]
fn an_unregistered_stamped_actor_falls_back_to_the_peer_registration() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let agent = put_actor(&vault, EdgeActorClass::Agent);

    let mut artifact = ProposalTextArtifact::open(&vault, "draft", &human, None).expect("open");
    register_peer_actor(&vault, artifact.peer_id(), &human).expect("register");
    artifact
        .edit_as(&agent, |text| {
            insert_at(text, text.len_unicode(), " reviewed")
        })
        .expect("agent edit");
    artifact
        .edit_as(&human, |text| insert_at(text, text.len_unicode(), "."))
        .expect("human edit");

    assert!(artifact.finalize(&vault).is_err());
}

/// A peer stamping an actor that belongs to a DIFFERENT peer is forging: the
/// stamp is dropped and the span falls back to the forging peer's own binding.
#[test]
fn a_stamp_naming_another_peers_actor_is_not_honored() {
    let (_tmp, vault) = temp_vault();
    let local = put_actor(&vault, EdgeActorClass::Human);
    let remote = put_actor(&vault, EdgeActorClass::Agent);

    let mut artifact = ProposalTextArtifact::open(&vault, "body", &local, None).expect("open");
    register_peer_actor(&vault, artifact.peer_id(), &local).expect("register writer");
    // `remote` is a different device's actor.
    register_peer_actor(&vault, artifact.peer_id() ^ 0xffff, &remote).expect("register remote");

    artifact
        .edit_as(&remote, |text| insert_at(text, 0, "forged "))
        .expect("edit stamped as the remote actor");

    assert!(artifact.finalize(&vault).is_err());
}

/// With no binding at all, a span is charged to the device peer — never
/// guessed onto the only actor in sight.
#[test]
fn an_unregistered_peer_falls_back_to_the_device_peer() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let elsewhere = put_actor(&vault, EdgeActorClass::Agent);
    register_peer_actor(&vault, 0xdead_beef, &elsewhere).expect("register an unrelated peer");

    let opened = ProposalTextArtifact::open(&vault, "x", &human, None).expect("open");
    let mut artifact =
        ProposalTextArtifact::from_snapshot(&opened.export_snapshot().unwrap()).unwrap();
    artifact
        .edit_as(&human, |text| insert_at(text, 1, "y"))
        .expect("edit");

    // Attribution still falls back to the device peer, but that fallback is
    // not an authenticated receipt and cannot authorize finalization.
    let changes = artifact
        .window_changes(
            &artifact.window_base().unwrap(),
            &artifact.doc.doc.oplog_frontiers(),
        )
        .unwrap();
    assert_eq!(
        artifact.attribute(&vault, changes.last().unwrap()).unwrap(),
        OpAttribution::DevicePeer
    );
    assert!(artifact.finalize(&vault).is_err());

    let unstamped =
        ProposalTextArtifact::from_snapshot(&opened.export_snapshot().unwrap()).unwrap();
    unstamped
        .doc
        .doc
        .get_text(TEXT_CONTAINER)
        .insert(1, "z")
        .expect("raw insert");
    unstamped
        .doc
        .doc
        .commit_with(CommitOptions::new().commit_msg("some other layer"));
    let changes = unstamped
        .window_changes(
            &unstamped.window_base().unwrap(),
            &unstamped.doc.doc.oplog_frontiers(),
        )
        .unwrap();
    assert_eq!(
        unstamped
            .attribute(&vault, changes.last().unwrap())
            .unwrap(),
        OpAttribution::DevicePeer
    );
    assert!(unstamped.finalize(&vault).is_err());
}

#[test]
fn finalize_retains_both_texts_and_the_source_turn() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let turn = EntityId::now();

    let mut artifact =
        ProposalTextArtifact::open(&vault, "proposed body", &human, Some(turn)).expect("open");
    let artifact_ref = artifact.artifact_ref();
    artifact
        .edit_as(&human, |text| {
            text.delete(0, 8)
                .map_err(|_| Error::InvariantViolation("fixture delete"))?;
            insert_at(text, 0, "final")
        })
        .expect("edit");
    let returned = artifact.finalize(&vault).expect("finalize");

    let stored = finalized_proposal_text(&vault, artifact_ref)
        .expect("read")
        .expect("present");
    assert_eq!(stored, returned);
    assert_eq!(stored.proposed_text, "proposed body");
    assert_eq!(stored.final_text, "final body");
    assert_eq!(stored.source_turn_ref, Some(turn));
    assert!(!stored.proposed_ref.as_bytes().is_empty());
    assert_ne!(stored.proposed_ref, stored.final_ref);
}

/// The window base is the open commit, and Loro must not fold the first edit
/// into it — the differing stamp is what keeps them apart, and a fold would
/// silently swallow the opening text into the window.
#[test]
fn the_open_commit_never_merges_with_the_first_edit() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);

    let mut artifact = ProposalTextArtifact::open(&vault, "seed", &human, None).expect("open");
    artifact
        .edit_as(&human, |text| insert_at(text, 4, "ling"))
        .expect("same-actor edit");

    let record = artifact.finalize(&vault).expect("finalize");
    assert_eq!(record.proposed_text, "seed");
    assert_eq!(record.final_text, "seedling");
    assert_eq!(
        record.ops_by_actor.len(),
        1,
        "only the edit is in the window"
    );
}

/// The stamp grammar round-trips, and a foreign or absent commit message is
/// simply unstamped rather than an error.
#[test]
fn stamp_parses_only_our_own_messages() {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Agent);
    let encoded = stamp(StampKind::Edit, &actor);
    assert_eq!(parse_stamp(Some(&encoded)), Some((StampKind::Edit, actor)));
    assert!(encoded.starts_with(PROPOSAL_TEXT_COMMIT_MSG_PREFIX));

    assert_eq!(parse_stamp(None), None);
    assert_eq!(parse_stamp(Some("bridge")), None);
    assert_eq!(parse_stamp(Some("")), None);
    assert_eq!(
        parse_stamp(Some("oneiron.edit_distance.v1 edit actor=nothex.human")),
        None
    );
    assert_eq!(
        parse_stamp(Some(
            "oneiron.edit_distance.v1 edit actor=00000000000000000000000000000001.overlord"
        )),
        None
    );
}

/// An edit that fails partway is still committed as its OWN change under its
/// own stamp: leaving its ops pending would fold them into the next actor's
/// change, and one change can carry only one attribution.
#[test]
fn a_failed_edit_still_lands_under_its_own_actor() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let agent = put_actor(&vault, EdgeActorClass::Agent);
    let birth = ProposalTextArtifact::open(&vault, "base", &human, None).unwrap();
    let mut artifact =
        ProposalTextArtifact::from_snapshot(&birth.export_snapshot().unwrap()).unwrap();
    register_peer_actor(&vault, artifact.peer_id(), &agent).unwrap();
    let failed = artifact.edit_as(&agent, |text| {
        insert_at(text, 0, "A")?;
        Err(Error::InvariantViolation("fixture failure"))
    });
    assert!(failed.is_err());
    let mut resumed =
        ProposalTextArtifact::from_snapshot(&artifact.export_snapshot().unwrap()).unwrap();
    register_peer_actor(&vault, resumed.peer_id(), &human).unwrap();
    resumed
        .edit_as(&human, |text| insert_at(text, text.len_unicode(), "!"))
        .unwrap();
    let record = resumed.finalize(&vault).unwrap();
    let spans = record
        .ops_by_actor
        .iter()
        .map(|(actor, span)| (*actor, span.after_text.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        spans,
        vec![
            (OpAttribution::Stamped(agent), "Abase".into()),
            (OpAttribution::Stamped(human), "Abase!".into())
        ]
    );
    assert_eq!(record.final_text, "Abase!");
}

/// A later opening is retained without shifting the birth window or losing
/// the peer's earlier text. A forged stamp still cannot claim another actor.
#[test]
fn a_second_open_marker_preserves_the_birth_window_and_all_attributed_ops() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);

    let opened = ProposalTextArtifact::open(&vault, "seed", &human, None).expect("open");
    let snapshot = opened.export_snapshot().expect("snapshot");

    // A synced peer forges a later open marker over its own edit.
    let peer_doc = doc_from_snapshot(&snapshot).expect("reopen");
    peer_doc.set_record_timestamp(true);
    peer_doc
        .get_text(TEXT_CONTAINER)
        .insert(4, " hidden")
        .expect("peer insert");
    peer_doc.commit_with(CommitOptions::new().commit_msg(&stamp(StampKind::Open, &human)));

    let mut forged =
        ProposalTextArtifact::from_snapshot(&export_snapshot(&peer_doc).expect("export"))
            .expect("reopen forged");
    forged
        .edit_as(&human, |text| {
            insert_at(text, text.len_unicode(), " visible")
        })
        .expect("later edit");

    assert_eq!(forged.window_base().unwrap(), opened.window_base().unwrap());
    assert_eq!(forged.text(), "seed hidden visible");
    // A later marker cannot move the base, but an unreceipted forged marker
    // must still fail authentication rather than mint a finalized record.
    assert!(forged.provenance(&vault).unwrap().is_none());
    assert!(forged.finalize(&vault).is_err());
}

#[test]
fn an_authenticated_second_open_keeps_the_earliest_window_base() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let mut artifact = ProposalTextArtifact::open(&vault, "seed", &human, None).unwrap();
    let birth_base = artifact.window_base().unwrap();
    artifact
        .edit_as(&human, |text| insert_at(text, text.len_unicode(), " first"))
        .unwrap();
    insert_at(&artifact.doc.doc.get_text(TEXT_CONTAINER), 10, " second").unwrap();
    artifact
        .commit_receipted(StampKind::Open, &human, None)
        .unwrap();
    assert_eq!(artifact.window_base().unwrap(), birth_base);
    let record = artifact.finalize(&vault).unwrap();
    assert_eq!(record.proposed_text, "seed");
    assert_eq!(record.final_text, "seed first second");
    assert_eq!(record.ops_by_actor.len(), 2);
    assert!(
        record
            .ops_by_actor
            .iter()
            .all(|(actor, _)| *actor == OpAttribution::Stamped(human))
    );
}

#[test]
fn made_by_two_commits_fold_and_birth_round_trips() {
    use crate::provenance::made_by::{MadeByClass, MadeByInputRole, MadeByProcess, MadeByTrigger};
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault, EdgeActorClass::Agent);
    let prompt = EntityId::now();
    let task = EntityId::now();
    for (id, kind) in [
        (prompt, crate::registry::ENTITY_TYPE_TURN),
        (task, crate::registry::ENTITY_TYPE_TASK),
    ] {
        vault
            .put_entity(
                &id,
                kind,
                crate::TimeRange { start: 1, end: 1 },
                1,
                &if kind == crate::registry::ENTITY_TYPE_TASK {
                    crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
                } else {
                    rmp_serde::to_vec_named(&serde_json::json!({"text":"fixture input"})).unwrap()
                },
            )
            .unwrap();
    }
    let process = MadeByProcess {
        actor: actor.entity_ref(),
        class: MadeByClass::Concluded,
        identity: "fixture/model@v1".into(),
        version: "v1".into(),
        params_hash: "fixture-params".into(),
    };
    let mut artifact = ProposalTextArtifact::open_generated(
        &vault,
        "first",
        &actor,
        prompt,
        MadeByTrigger::Task(task),
        process,
    )
    .unwrap();
    let birth_provenance = artifact.provenance(&vault).unwrap().unwrap();
    assert_eq!(
        birth_provenance.commits.len(),
        1,
        "birth is one receipted commit"
    );
    assert_eq!(
        artifact.doc.birth().entity,
        artifact.artifact_ref().entity_id().to_hex()
    );
    assert_eq!(artifact.doc.birth().actor, actor.entity_ref().to_hex());
    assert_eq!(
        artifact.doc.birth().at,
        birth_provenance.commits[0].made_by.at
    );
    assert_eq!(
        artifact.window_base().unwrap(),
        artifact.doc.doc.oplog_frontiers()
    );
    register_peer_actor(&vault, artifact.peer_id(), &actor).unwrap();
    artifact
        .edit_as(&actor, |text| {
            insert_at(text, text.len_unicode(), " second")
        })
        .unwrap();
    let provenance = artifact.provenance(&vault).unwrap().unwrap();
    assert_eq!(provenance.commits.len(), 2);
    assert_eq!(
        provenance.inputs.into_iter().collect::<Vec<_>>(),
        vec![prompt]
    );
    let birth = &provenance.commits[0].made_by;
    assert_eq!(birth.inputs[0].row, prompt);
    assert_eq!(birth.inputs[0].role, MadeByInputRole::Prompt);
    assert_eq!(birth.trigger, Some(MadeByTrigger::Task(task)));
    let snapshot = artifact.export_snapshot().unwrap();
    let reopened = ProposalTextArtifact::from_snapshot(&snapshot).unwrap();
    assert_eq!(
        reopened.provenance(&vault).unwrap().unwrap().commits,
        provenance.commits
    );
    // A peer can bypass the receipt writer. The read view excludes the whole
    // row, rather than laundering that unreceipted commit into provenance.
    reopened
        .doc
        .doc
        .get_text(TEXT_CONTAINER)
        .insert(0, "unreceipted ")
        .unwrap();
    reopened.doc.doc.commit();
    assert_eq!(reopened.provenance(&vault).unwrap(), None);
}

#[test]
fn generated_triggers_require_matching_entity_types_at_birth_and_import() {
    use crate::provenance::made_by::{
        MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
    };
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault, EdgeActorClass::Agent);
    let ask = EntityId::now();
    let task = EntityId::now();
    vault
        .put_entity(
            &ask,
            crate::registry::ENTITY_TYPE_TURN,
            crate::TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({"text":"Please summarize."})).unwrap(),
        )
        .unwrap();
    vault
        .put_entity(
            &task,
            crate::registry::ENTITY_TYPE_TASK,
            crate::TimeRange { start: 1, end: 1 },
            1,
            &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
        )
        .unwrap();
    let process = MadeByProcess {
        actor: actor.entity_ref(),
        class: MadeByClass::Concluded,
        identity: "fixture/model@v1".into(),
        version: "v1".into(),
        params_hash: "fixture".into(),
    };
    for field in 0..3 {
        let mut invalid = process.clone();
        match field {
            0 => invalid.identity = "x".repeat(257),
            1 => invalid.version = "x".repeat(257),
            _ => invalid.params_hash = "x".repeat(257),
        }
        assert!(matches!(
            ProposalTextArtifact::open_generated(
                &vault,
                "summary",
                &actor,
                ask,
                MadeByTrigger::Ask(ask),
                invalid,
            ),
            Err(Error::InvalidConfig(_))
        ));
    }
    let mut boundary = process.clone();
    boundary.identity = "x".repeat(256);
    boundary.version = "x".repeat(256);
    boundary.params_hash = "x".repeat(256);
    let boundary = ProposalTextArtifact::open_generated(
        &vault,
        "summary",
        &actor,
        ask,
        MadeByTrigger::Ask(ask),
        boundary,
    )
    .unwrap();
    assert!(boundary.provenance(&vault).unwrap().is_some());
    let valid = ProposalTextArtifact::open_generated(
        &vault,
        "summary",
        &actor,
        ask,
        MadeByTrigger::Ask(ask),
        process.clone(),
    )
    .unwrap();
    let reopened = ProposalTextArtifact::from_snapshot(&valid.export_snapshot().unwrap()).unwrap();
    assert!(reopened.provenance(&vault).unwrap().is_some());
    for trigger in [
        MadeByTrigger::Task(ask),
        MadeByTrigger::Ask(task),
        MadeByTrigger::Task(EntityId::now()),
    ] {
        assert!(matches!(
            ProposalTextArtifact::open_generated(
                &vault,
                "summary",
                &actor,
                ask,
                trigger.clone(),
                process.clone()
            ),
            Err(Error::InvalidConfig(_))
        ));
        // Build the same malformed history an imported snapshot can carry,
        // bypassing admission without weakening the public writer.
        let forged = ProposalTextArtifact::open_with_receipt(
            &vault,
            "summary",
            &actor,
            Some(ask),
            Some(MadeBy {
                inputs: vec![MadeByInput {
                    row: ask,
                    role: MadeByInputRole::Prompt,
                }],
                process: process.clone(),
                at: crate::unix_seconds_now(),
                trigger: Some(trigger),
            }),
        )
        .unwrap();
        let imported =
            ProposalTextArtifact::from_snapshot(&forged.export_snapshot().unwrap()).unwrap();
        assert_eq!(imported.provenance(&vault).unwrap(), None);
        assert!(imported.finalize(&vault).is_err());
    }
}
