use super::*;

#[test]
fn bounded_chat_runner_skips_a_poison_sitting_and_spends_empty_jobs() -> Result<()> {
    struct Host {
        poison: EntityId,
        actor: EntityId,
    }
    impl SessionActorDistiller for Host {
        fn distill(&self, brief: &SessionDistillBrief) -> Result<Vec<ActorNote>> {
            if brief.session == self.poison {
                return Err(Error::InvariantViolation("distiller unavailable"));
            }
            Ok(vec![ActorNote {
                actor: self.actor,
                kind: ActorNoteKind::Lesson,
                text: "verify the source before editing".to_owned(),
            }])
        }
    }
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let poison = witnessed_chat_session(&vault, 1, 200)?;
    let healthy = witnessed_chat_session(&vault, 2, 500)?;
    let empty = witnessed_chat_session(&vault, 0, 800)?;
    let host = Host { poison, actor };
    let first = drain_pending_session_actor_distills(&vault, 1, &host)?;
    assert_eq!(first.failures.len(), 1);
    assert_eq!(first.failures[0].0, poison);
    assert!(matches!(first.failures[0].1, Error::InvariantViolation(_)));
    assert_eq!(first.pending_sessions, 3);
    let second = drain_pending_session_actor_distills(&vault, 1, &host)?;
    assert_eq!(second.spent_sessions, vec![healthy]);
    assert_eq!(second.claims.len(), 1);
    assert_eq!(
        vault.get_claim(&second.claims[0])?.unwrap().predicate,
        PREDICATE_ACTOR_LESSON
    );
    let third = drain_pending_session_actor_distills(&vault, 1, &host)?;
    assert_eq!(third.spent_sessions, vec![empty]);
    assert!(third.claims.is_empty());
    assert_eq!(pending_session_actor_distills(&vault)?, vec![poison]);
    let retry = drain_pending_session_actor_distills(&vault, 1, &FixedDistiller(Vec::new()))?;
    assert_eq!(retry.spent_sessions, vec![poison]);
    assert_eq!(retry.pending_sessions, 0);
    let replay = drain_pending_session_actor_distills(&vault, 1, &host)?;
    assert!(replay.spent_sessions.is_empty());
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_TASK)?, 0);
    Ok(())
}
