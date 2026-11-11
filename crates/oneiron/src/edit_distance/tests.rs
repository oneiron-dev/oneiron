use super::*;

use crate::config::VaultConfig;
use crate::error::ClaimError;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

// ─── fixtures ───────────────────────────────────────────────────────────

pub(crate) fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

pub(crate) fn put_actor(vault: &Vault, class: EdgeActorClass) -> WriteActor {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"ed00 actor fixture",
        )
        .expect("put actor entity");
    WriteActor::new(id, class)
}

// ─── peer → actor registration ──────────────────────────────────────────

/// A registration is engine-authored evidence: it resolves by peer id, and the
/// generic public Claim API cannot forge one because `actor.*` is reserved.
#[test]
fn registration_resolves_and_is_reserved_from_public_writes() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let peer = 0x1234_5678_9abc_def0_u64;

    register_peer_actor(&vault, peer, &human).expect("register");
    assert_eq!(
        active_peer_actor(&vault, peer).expect("read active"),
        Some(human)
    );
    assert_eq!(
        peer_actor_at(&vault, peer, crate::unix_seconds_now()).expect("resolve now"),
        Some(human)
    );
    // A peer nobody registered resolves to nothing — never to the one actor
    // that happens to exist.
    assert_eq!(
        peer_actor_at(&vault, peer ^ 1, u64::MAX).expect("other"),
        None
    );

    let body = ClaimBody::new(
        PREDICATE_ACTOR_PEER_BINDING,
        ClaimSubject::Entity(human.entity_ref()),
        peer_binding_value(peer, EdgeActorClass::Human),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    let err = vault
        .put_claim(&EntityId::now(), &body, TimeRange { start: 1, end: 1 }, 1)
        .expect_err("public claim door must reject the reserved predicate");
    assert!(
        matches!(err, Error::Claim(ClaimError::ReservedPredicate { .. })),
        "{err:?}"
    );
}

/// Re-registration supersedes: exactly one row stays ACTIVE, and the OLD row
/// still answers for the instants it covered — ops committed before the switch
/// keep attributing to the actor bound then.
#[test]
fn reregistration_supersedes_and_stays_time_resolvable() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let agent = put_actor(&vault, EdgeActorClass::Agent);
    let peer = 42_u64;

    let first = register_peer_actor(&vault, peer, &human).expect("register human");
    let switch_at = crate::unix_seconds_now() + 10;
    supersede_with_actor_at(&vault, peer, &agent, switch_at);

    let first_body = vault.get_claim(&first).expect("read").expect("present");
    assert_eq!(first_body.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(first_body.valid_to, Some(switch_at));
    assert_eq!(
        active_peer_actor(&vault, peer).expect("one active row"),
        Some(agent)
    );

    assert_eq!(
        peer_actor_at(&vault, peer, switch_at - 1).expect("before switch"),
        Some(human)
    );
    assert_eq!(
        peer_actor_at(&vault, peer, switch_at + 1).expect("after switch"),
        Some(agent)
    );
}

/// The re-registration SECOND itself resolves to nothing.
///
/// Valid time is second-granular while ops are not, so an op stamped with the
/// switch second may have been written on either side of the switch. Resolving
/// it by the exclusive window end charges pre-switch ops to the actor that was
/// registered AFTER them — a guess between two actors, which the fallback is
/// not allowed to make.
#[test]
fn the_reregistration_second_is_ambiguous() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let agent = put_actor(&vault, EdgeActorClass::Agent);
    let peer = 43_u64;

    write_binding_at(&vault, peer, &human, 100, Some(200));
    write_binding_at(&vault, peer, &agent, 200, None);

    assert_eq!(
        peer_actor_at(&vault, peer, 199).expect("before"),
        Some(human)
    );
    assert_eq!(
        peer_actor_at(&vault, peer, 200).expect("switch second"),
        None
    );
    assert_eq!(
        peer_actor_at(&vault, peer, 201).expect("after"),
        Some(agent)
    );

    // The stamp is a second channel, not a guess: it names ONE of the two
    // actors that held the peer that second, and both held it honestly.
    for actor in [human, agent] {
        assert!(
            peer_actor_stamp_is_honored(&vault, peer, 200, &actor).expect("stamp rule"),
            "a stamp naming an actor bound that second stays honored"
        );
    }
}

/// A stamp naming an actor bound to NO peer is not evidence.
///
/// `WriteActor::new` is public, so an unregistered stamped actor is exactly as
/// forgeable as a mismatched one — honoring it would make the commit message a
/// write door into attribution (ARCH-0056 §2 / blueprint line 15: mismatch OR
/// unregistered → registration fallback, never the stamped actor).
#[test]
fn an_unregistered_stamped_actor_is_not_honored() {
    let (_tmp, vault) = temp_vault();
    let bound = put_actor(&vault, EdgeActorClass::Human);
    let unregistered = put_actor(&vault, EdgeActorClass::Agent);
    let peer = 44_u64;

    write_binding_at(&vault, peer, &bound, 100, None);

    assert!(
        peer_actor_stamp_is_honored(&vault, peer, 150, &bound).expect("bound actor"),
        "the peer's own bound actor is vouched for"
    );
    assert!(
        !peer_actor_stamp_is_honored(&vault, peer, 150, &unregistered).expect("unregistered"),
        "an unregistered stamped actor falls back to the registration"
    );
    // Before its binding opens, even the bound actor's stamp is unvouched.
    assert!(!peer_actor_stamp_is_honored(&vault, peer, 99, &bound).expect("before the window"));
}

/// Both binding read paths answer from the CLAIM substrate, so a row that
/// arrived by REPLICATION — claim entity and `claim_of` edge materialized, no
/// local index bookkeeping — resolves identically through each.
///
/// A local secondary index is write-side state: it exists only on the vault
/// that registered the peer. Indexing the peer→actor lookup while the stamp
/// rule read claims by subject made the two disagree on every replica.
#[test]
fn a_replicated_binding_resolves_through_both_read_paths() {
    let (_tmp, vault) = temp_vault();
    let remote = put_actor(&vault, EdgeActorClass::Agent);
    let peer = 0x5eed_u64;

    // Exactly what a replicated binding claim materializes locally.
    write_binding_at(&vault, peer, &remote, 100, None);

    assert_eq!(
        peer_actor_at(&vault, peer, 150).expect("fallback path"),
        Some(remote)
    );
    assert_eq!(
        active_peer_actor(&vault, peer).expect("active path"),
        Some(remote)
    );
    assert!(
        peer_actor_stamp_is_honored(&vault, peer, 150, &remote).expect("stamp path"),
        "the stamp rule must see the same binding the fallback sees"
    );
}

/// Two bindings opened in the same instant on different actors are ambiguous:
/// the resolver reports nothing rather than picking one.
#[test]
fn tied_bindings_resolve_to_nothing() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let agent = put_actor(&vault, EdgeActorClass::Agent);
    let peer = 7_u64;

    write_binding_at(&vault, peer, &human, 100, None);
    write_binding_at(&vault, peer, &agent, 100, None);

    assert_eq!(peer_actor_at(&vault, peer, 200).expect("tied"), None);
}

#[test]
fn retained_proposal_codec_pins_schema_attribution_and_rejects_malformed_bytes() {
    // Schema v5 keeps endpoint text by reference, with wall-admitted lifted text.
    let fixture: &[u8] = b"\x8a\xa1\x76\x05\xa8\x61\x72\x74\x69\x66\x61\x63\x74\xc4\x10\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\xac\x70\x72\x6f\x70\x6f\x73\x65\x64\x5f\x72\x65\x66\xc4\x01\x01\xa9\x66\x69\x6e\x61\x6c\x5f\x72\x65\x66\xc4\x01\x02\xa4\x68\x65\x61\x64\xc0\xab\x73\x6f\x75\x72\x63\x65\x5f\x74\x75\x72\x6e\xc4\x10\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x41\x42\x43\x44\x45\x46\xa5\x73\x70\x61\x6e\x73\x94\x8a\xa4\x70\x65\x65\x72\x09\xa3\x63\x74\x72\x03\xa3\x6c\x65\x6e\x02\xa7\x6c\x61\x6d\x70\x6f\x72\x74\x0b\xa2\x74\x73\x01\xa6\x62\x65\x66\x6f\x72\x65\xc4\x01\x01\xa5\x61\x66\x74\x65\x72\xc4\x01\x03\xa5\x74\x72\x75\x73\x74\xa7\x73\x74\x61\x6d\x70\x65\x64\xa5\x61\x63\x74\x6f\x72\xc4\x10\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\xa5\x63\x6c\x61\x73\x73\xa5\x68\x75\x6d\x61\x6e\x8a\xa4\x70\x65\x65\x72\x0a\xa3\x63\x74\x72\x00\xa3\x6c\x65\x6e\x01\xa7\x6c\x61\x6d\x70\x6f\x72\x74\x0c\xa2\x74\x73\x02\xa6\x62\x65\x66\x6f\x72\x65\xc4\x01\x03\xa5\x61\x66\x74\x65\x72\xc4\x01\x04\xa5\x74\x72\x75\x73\x74\xaa\x72\x65\x67\x69\x73\x74\x65\x72\x65\x64\xa5\x61\x63\x74\x6f\x72\xc4\x10\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\xa5\x63\x6c\x61\x73\x73\xa5\x61\x67\x65\x6e\x74\x8a\xa4\x70\x65\x65\x72\x0b\xa3\x63\x74\x72\x00\xa3\x6c\x65\x6e\x01\xa7\x6c\x61\x6d\x70\x6f\x72\x74\x0d\xa2\x74\x73\x03\xa6\x62\x65\x66\x6f\x72\x65\xc4\x01\x04\xa5\x61\x66\x74\x65\x72\xc4\x01\x05\xa5\x74\x72\x75\x73\x74\xaa\x72\x65\x67\x69\x73\x74\x65\x72\x65\x64\xa5\x61\x63\x74\x6f\x72\xc4\x10\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\xa5\x63\x6c\x61\x73\x73\xa6\x73\x79\x73\x74\x65\x6d\x8a\xa4\x70\x65\x65\x72\x0c\xa3\x63\x74\x72\x00\xa3\x6c\x65\x6e\x01\xa7\x6c\x61\x6d\x70\x6f\x72\x74\x0e\xa2\x74\x73\x04\xa6\x62\x65\x66\x6f\x72\x65\xc4\x01\x05\xa5\x61\x66\x74\x65\x72\xc4\x01\x02\xa5\x74\x72\x75\x73\x74\xab\x64\x65\x76\x69\x63\x65\x5f\x70\x65\x65\x72\xa5\x61\x63\x74\x6f\x72\xc0\xa5\x63\x6c\x61\x73\x73\xc0\xa6\x6c\x69\x66\x74\x65\x64\x83\xa8\x70\x72\x6f\x70\x6f\x73\x65\x64\xa1\x61\xa5\x66\x69\x6e\x61\x6c\xa1\x65\xa7\x63\x68\x61\x6e\x67\x65\x73\x94\x92\xa1\x61\xa1\x62\x92\xa1\x62\xa1\x63\x92\xa1\x63\xa1\x64\x92\xa1\x64\xa1\x65\xae\x6d\x61\x64\x65\x5f\x62\x79\x5f\x69\x6e\x70\x75\x74\x73\x90\xad\x62\x69\x72\x74\x68\x5f\x61\x74\x74\x65\x6d\x70\x74\xc0";
    let stored = decode_stored_proposal(fixture).expect("fixed v5 schema");
    let record = &stored.record;
    let (_tmp, vault) = temp_vault();
    let reader = {
        let txn = vault.store.env.read_txn().unwrap();
        RetainedProposal::open(text_ref::joined_in_txn(&vault.store, &txn, stored.clone()).unwrap())
    };
    assert_eq!(
        record.artifact_ref.entity_id().as_bytes(),
        b"abcdefghijklmnop"
    );
    assert_eq!(record.proposed_ref.as_bytes(), &[1]);
    assert_eq!(record.final_ref.as_bytes(), &[2]);
    assert_eq!(reader.proposed_text().into_text().as_deref(), Some("a"));
    assert_eq!(reader.final_text().into_text().as_deref(), Some("e"));
    assert_eq!(
        record.source_turn_ref.unwrap().as_bytes(),
        b"qrstuvwxyzABCDEF"
    );
    let actor = EntityId::from_bytes(*b"ABCDEFGHIJKLMNOP").unwrap();
    assert_eq!(record.ops_by_actor.len(), 4);
    assert_eq!(
        record.ops_by_actor[0].0,
        OpAttribution::Stamped(WriteActor::new(actor, EdgeActorClass::Human))
    );
    assert_eq!(
        record.ops_by_actor[1].0,
        OpAttribution::Registered(WriteActor::new(actor, EdgeActorClass::Agent))
    );
    assert_eq!(
        record.ops_by_actor[2].0,
        OpAttribution::Registered(WriteActor::new(actor, EdgeActorClass::System))
    );
    assert_eq!(record.ops_by_actor[3].0, OpAttribution::DevicePeer);
    let first = &record.ops_by_actor[0].1;
    assert_eq!(
        (
            first.peer_id,
            first.counter,
            first.len,
            first.lamport,
            first.timestamp
        ),
        (9, 3, 2, 11, 1)
    );
    let (before, after) = reader.change_texts(first);
    assert_eq!(
        (before.into_text().as_deref(), after.into_text().as_deref()),
        (Some("a"), Some("b"))
    );
    assert_eq!(encode_stored_proposal(&stored).unwrap(), fixture);
    vault
        .with_write_txn(|txn| {
            PROPOSAL_ARTIFACT.put(&vault.store, txn, &record.artifact_ref.entity_id(), &stored)
        })
        .unwrap();
    let retained = retained_proposal(&vault, record.artifact_ref)
        .unwrap()
        .unwrap();
    assert_eq!(retained.final_text().into_text().as_deref(), Some("e"));
    let txn = vault.store.env.read_txn().unwrap();
    let stored_again = PROPOSAL_ARTIFACT
        .get(&vault.store, &txn, &record.artifact_ref.entity_id())
        .unwrap()
        .unwrap();
    assert_eq!(encode_stored_proposal(&stored_again).unwrap(), fixture);

    let mut wrong_version = fixture.to_vec();
    wrong_version[3] = 6;
    let mut unknown_trust = fixture.to_vec();
    let trust = unknown_trust
        .windows(7)
        .position(|w| w == b"stamped")
        .unwrap();
    unknown_trust[trust] = b'x';
    let mut unknown_class = fixture.to_vec();
    let class = unknown_class
        .windows(5)
        .position(|w| w == b"human")
        .unwrap();
    unknown_class[class] = b'x';
    let mut negative_len = fixture.to_vec();
    let len = negative_len
        .windows(5)
        .position(|w| w == b"\xa3len\x02")
        .unwrap();
    negative_len[len + 4] = 0xff;
    let mut trailing = fixture.to_vec();
    trailing.push(0);
    for bytes in [
        wrong_version.as_slice(),
        unknown_trust.as_slice(),
        unknown_class.as_slice(),
        negative_len.as_slice(),
        trailing.as_slice(),
        &fixture[..fixture.len() - 1],
        b"\x80".as_slice(),
    ] {
        assert!(matches!(
            decode_stored_proposal(bytes),
            Err(Error::CorruptedIndex(_))
        ));
    }
}

/// Retention is write-once per artifact ref: re-persisting the same record is
/// idempotent, a DIFFERENT record under the same ref is refused.
///
/// The ref survives `from_snapshot`, so two clones of one artifact each
/// finalize their own history under the same key. Last-writer-wins would swap
/// ED-09's reservoir pair for a divergent clone's pair with no trace.
#[test]
fn a_divergent_finalize_cannot_overwrite_the_stored_record() {
    let (_tmp, vault) = temp_vault();
    let artifact_ref = ProposalArtifactRef::mint();
    let actor = put_actor(&vault, EdgeActorClass::Human);
    let stamp = crate::provenance::actor_stamp(&vault, actor).expect("actor stamp");
    let document = crate::entity_doc::EntityDoc::open_initialized(
        loro::LoroDoc::new(),
        artifact_ref.entity_id(),
        "draft",
        (actor, stamp),
        1,
        |_| Ok(()),
        "proposal codec fixture birth",
    )
    .expect("proposal document");
    let proposed_ref = LoroOpRef::from_bytes(document.frontier());
    document
        .doc
        .get_text("body")
        .insert(5, " left")
        .expect("first endpoint");
    document
        .doc
        .commit_with(loro::CommitOptions::new().commit_msg("first endpoint"));
    let record = FinalizedProposalText {
        artifact_ref,
        proposed_ref,
        final_ref: LoroOpRef::from_bytes(document.frontier()),
        ops_by_actor: Vec::new(),
        source_turn_ref: None,
        birth_attempt: None,
        made_by_inputs: Vec::new(),
    };

    put_finalized_proposal_text(&vault, &record, &document).expect("first finalize");
    put_finalized_proposal_text(&vault, &record, &document)
        .expect("re-finalizing the same bytes is a no-op");

    let divergent_document =
        crate::entity_doc::EntityDoc::from_snapshot(&document.export_snapshot().unwrap()).unwrap();
    let text = divergent_document.doc.get_text("body");
    text.delete(0, text.len_unicode())
        .expect("replace first endpoint");
    text.insert(0, "draft right").expect("divergent endpoint");
    divergent_document
        .doc
        .commit_with(loro::CommitOptions::new().commit_msg("divergent endpoint"));
    let divergent = FinalizedProposalText {
        final_ref: LoroOpRef::from_bytes(divergent_document.frontier()),
        ..record.clone()
    };
    let err = put_finalized_proposal_text(&vault, &divergent, &divergent_document)
        .expect_err("a divergent record must not overwrite");
    assert!(matches!(err, Error::InvariantViolation(_)), "{err:?}");
    assert_eq!(
        finalized_proposal_text(&vault, artifact_ref)
            .expect("read")
            .expect("present"),
        record,
        "the first record survives the refused write"
    );
}

// ─── helpers ────────────────────────────────────────────────────────────

/// Writes a binding row with an explicit window, bypassing `unix_seconds_now`
/// so a test can pin the instants a resolution depends on.
///
/// Writes the CLAIM and nothing else — which is also exactly the shape a
/// REPLICATED binding lands in on a peer vault.
fn write_binding_at(
    vault: &Vault,
    peer_id: u64,
    actor: &WriteActor,
    valid_from: u64,
    valid_to: Option<u64>,
) -> EntityId {
    let claim_id = EntityId::now();
    vault
        .with_write_txn(|wtxn| {
            let mut body = ClaimBody::new(
                PREDICATE_ACTOR_PEER_BINDING,
                ClaimSubject::Entity(actor.entity_ref()),
                peer_binding_value(peer_id, actor.actor_class()),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )?;
            body.valid_from = Some(valid_from);
            body.valid_to = valid_to;
            body.source = Some(ClaimSource::Observed);
            vault.put_reserved_claim_in_txn(
                wtxn,
                &claim_id,
                &body,
                TimeRange {
                    start: valid_from,
                    end: valid_from,
                },
                valid_from,
            )?;
            Ok(())
        })
        .expect("write binding");
    claim_id
}

/// `register_peer_actor` stamps `now`; this pins the switch instant so the
/// before/after resolution is deterministic.
fn supersede_with_actor_at(vault: &Vault, peer_id: u64, actor: &WriteActor, at: u64) {
    let new_id = write_binding_at(vault, peer_id, actor, at, None);
    let old_ids = vault
        .with_write_txn(|wtxn| peer_bindings_in_txn(vault, &*wtxn, peer_id))
        .expect("read rows")
        .into_iter()
        .filter(|binding| {
            binding.claim_id != new_id && binding.lifecycle == ClaimLifecycleStatus::Active
        })
        .map(|binding| binding.claim_id)
        .collect::<Vec<_>>();
    vault
        .with_write_txn(|wtxn| {
            for old_id in &old_ids {
                vault.supersede_reserved_claim_in_txn(wtxn, &new_id, old_id, at)?;
            }
            Ok(())
        })
        .expect("supersede");
}
