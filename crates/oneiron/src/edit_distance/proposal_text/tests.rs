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

    let mut opened = ProposalTextArtifact::open("hello world", &human, None).expect("open");
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

/// Two actors on ONE device peer: the peer binding cannot tell them apart, so
/// the commit-message stamp is the only channel that can — and it is honored
/// for the unbound co-resident actor while the bound one stays bound.
#[test]
fn co_resident_actors_on_one_peer_are_distinguished_by_the_stamp() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let agent = put_actor(&vault, EdgeActorClass::Agent);

    let mut artifact = ProposalTextArtifact::open("draft", &human, None).expect("open");
    register_peer_actor(&vault, artifact.peer_id(), &human).expect("register");
    artifact
        .edit_as(&agent, |text| {
            insert_at(text, text.len_unicode(), " reviewed")
        })
        .expect("agent edit");
    artifact
        .edit_as(&human, |text| insert_at(text, text.len_unicode(), "."))
        .expect("human edit");

    let record = artifact.finalize(&vault).expect("finalize");
    let actors = record
        .ops_by_actor
        .iter()
        .map(|(attribution, _)| *attribution)
        .collect::<Vec<_>>();
    assert_eq!(
        actors,
        vec![OpAttribution::Stamped(agent), OpAttribution::Stamped(human)]
    );
    assert_eq!(record.final_text, "draft reviewed.");
}

/// A peer stamping an actor that belongs to a DIFFERENT peer is forging: the
/// stamp is dropped and the span falls back to the forging peer's own binding.
#[test]
fn a_stamp_naming_another_peers_actor_is_not_honored() {
    let (_tmp, vault) = temp_vault();
    let local = put_actor(&vault, EdgeActorClass::Human);
    let remote = put_actor(&vault, EdgeActorClass::Agent);

    let mut artifact = ProposalTextArtifact::open("body", &local, None).expect("open");
    register_peer_actor(&vault, artifact.peer_id(), &local).expect("register writer");
    // `remote` is a different device's actor.
    register_peer_actor(&vault, artifact.peer_id() ^ 0xffff, &remote).expect("register remote");

    artifact
        .edit_as(&remote, |text| insert_at(text, 0, "forged "))
        .expect("edit stamped as the remote actor");

    let record = artifact.finalize(&vault).expect("finalize");
    let (attribution, _) = record.ops_by_actor.last().expect("one span");
    assert_eq!(*attribution, OpAttribution::Registered(local));
}

/// With no binding at all, a span is charged to the device peer — never
/// guessed onto the only actor in sight.
#[test]
fn an_unregistered_peer_falls_back_to_the_device_peer() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let elsewhere = put_actor(&vault, EdgeActorClass::Agent);
    register_peer_actor(&vault, 0xdead_beef, &elsewhere).expect("register an unrelated peer");

    let mut artifact = ProposalTextArtifact::open("x", &human, None).expect("open");
    artifact
        .edit_as(&human, |text| insert_at(text, 1, "y"))
        .expect("edit");

    let record = artifact.finalize(&vault).expect("finalize");
    // `human` is bound to no peer, so its stamp is honored; the point of the
    // fixture is that nothing resolves through `elsewhere`.
    assert_eq!(
        record.ops_by_actor.last().map(|(a, _)| *a),
        Some(OpAttribution::Stamped(human))
    );

    let orphan = put_actor(&vault, EdgeActorClass::System);
    let unstamped = ProposalTextArtifact::open("x", &orphan, None).expect("open");
    // Commit with a message no parser of ours recognizes: the out-of-band edit
    // shape ED-02 owns.
    unstamped
        .doc
        .get_text(TEXT_CONTAINER)
        .insert(1, "z")
        .expect("raw insert");
    unstamped
        .doc
        .commit_with(CommitOptions::new().commit_msg("some other layer"));
    let record = unstamped.finalize(&vault).expect("finalize");
    assert_eq!(
        record.ops_by_actor.last().map(|(a, _)| *a),
        Some(OpAttribution::DevicePeer)
    );
}

/// Finalize retains both texts and the source turn, readable by artifact ref
/// after the artifact itself is gone — ED-09's reservoir contract.
#[test]
fn finalize_retains_both_texts_and_the_source_turn() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let turn = EntityId::now();

    let mut artifact =
        ProposalTextArtifact::open("proposed body", &human, Some(turn)).expect("open");
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

    let mut artifact = ProposalTextArtifact::open("seed", &human, None).expect("open");
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

/// An edit that fails partway is still committed under the actor that made it:
/// leaving its ops pending would fold them into the next actor's change.
#[test]
fn a_failed_edit_still_lands_under_its_own_actor() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let agent = put_actor(&vault, EdgeActorClass::Agent);

    let mut artifact = ProposalTextArtifact::open("base", &human, None).expect("open");
    let failed = artifact.edit_as(&agent, |text| {
        insert_at(text, 0, "A")?;
        Err(Error::InvariantViolation("fixture failure"))
    });
    assert!(failed.is_err());
    artifact
        .edit_as(&human, |text| insert_at(text, text.len_unicode(), "!"))
        .expect("human edit");

    let record = artifact.finalize(&vault).expect("finalize");
    let actors = record
        .ops_by_actor
        .iter()
        .map(|(attribution, _)| attribution.actor())
        .collect::<Vec<_>>();
    assert_eq!(actors, vec![Some(agent), Some(human)]);
    assert_eq!(record.final_text, "Abase!");
}
