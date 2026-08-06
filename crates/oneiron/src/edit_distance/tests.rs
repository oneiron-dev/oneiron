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
        peer_actor_at(&vault, peer, switch_at).expect("at switch"),
        Some(agent)
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
            vault
                .store
                .vault_meta
                .put(wtxn, &peer_actor_index_key(peer_id, &claim_id), &[])?;
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
        .with_write_txn(|wtxn| peer_binding_rows_in_txn(vault, &*wtxn, peer_id))
        .expect("read rows")
        .into_iter()
        .filter(|(id, body)| *id != new_id && body.lifecycle == ClaimLifecycleStatus::Active)
        .map(|(id, _)| id)
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
