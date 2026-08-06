use super::*;

use crate::config::VaultConfig;
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
    );
    let err = vault
        .put_claim(&EntityId::now(), &body, TimeRange { start: 1, end: 1 }, 1)
        .expect_err("public claim door must reject the reserved predicate");
    assert!(matches!(err, Error::ReservedPredicate { .. }), "{err:?}");
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

/// Record round-trip: both texts, the window refs, the source turn and every
/// attributed span survive the store.
#[test]
fn finalized_record_round_trips() {
    let (_tmp, vault) = temp_vault();
    let human = put_actor(&vault, EdgeActorClass::Human);
    let turn = EntityId::now();
    let artifact_ref = ProposalArtifactRef::mint();

    let record = FinalizedProposalText {
        artifact_ref,
        proposed_ref: LoroOpRef::from_bytes(vec![1, 2, 3]),
        final_ref: LoroOpRef::from_bytes(vec![4, 5, 6]),
        ops_by_actor: vec![
            (
                OpAttribution::Stamped(human),
                OpSpan {
                    peer_id: 9,
                    counter: 3,
                    len: 2,
                    lamport: 11,
                    timestamp: 1_700_000_000,
                    before_text: "draft".to_owned(),
                    after_text: "draft!".to_owned(),
                },
            ),
            (
                OpAttribution::DevicePeer,
                OpSpan {
                    peer_id: 10,
                    counter: 0,
                    len: 1,
                    lamport: 12,
                    timestamp: 1_700_000_001,
                    before_text: "draft!".to_owned(),
                    after_text: "draft!?".to_owned(),
                },
            ),
        ],
        proposed_text: "draft".to_owned(),
        final_text: "draft!?".to_owned(),
        source_turn_ref: Some(turn),
    };

    put_finalized_proposal_text(&vault, &record).expect("persist");
    let read = finalized_proposal_text(&vault, artifact_ref)
        .expect("read")
        .expect("present");
    assert_eq!(read, record);
    assert_eq!(
        finalized_proposal_text(&vault, ProposalArtifactRef::mint()).expect("miss"),
        None
    );
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
    let record = FinalizedProposalText {
        artifact_ref,
        proposed_ref: LoroOpRef::from_bytes(vec![1]),
        final_ref: LoroOpRef::from_bytes(vec![2]),
        ops_by_actor: Vec::new(),
        proposed_text: "draft".to_owned(),
        final_text: "draft left".to_owned(),
        source_turn_ref: None,
    };

    put_finalized_proposal_text(&vault, &record).expect("first finalize");
    put_finalized_proposal_text(&vault, &record).expect("re-finalizing the same bytes is a no-op");

    let divergent = FinalizedProposalText {
        final_text: "draft right".to_owned(),
        ..record.clone()
    };
    let err = put_finalized_proposal_text(&vault, &divergent)
        .expect_err("a divergent record must not overwrite");
    assert!(
        matches!(err, Error::InvariantViolation(msg) if msg.contains("already finalized")),
        "{err:?}"
    );
    assert_eq!(
        finalized_proposal_text(&vault, artifact_ref)
            .expect("read")
            .expect("present"),
        record,
        "the first record survives the refused write"
    );
}

/// The class token is a storage ABI, pinned independently of Gate's policy key.
#[test]
fn actor_class_tokens_round_trip() {
    for class in [
        EdgeActorClass::Human,
        EdgeActorClass::Agent,
        EdgeActorClass::System,
    ] {
        assert_eq!(
            actor_class_from_token(actor_class_token(class)),
            Some(class)
        );
    }
    assert_eq!(actor_class_from_token("operator"), None);
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
            );
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
