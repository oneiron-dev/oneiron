use crate::conversation_dag::{AppendRecord, ScopePath, ScopeSelector};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

pub(crate) fn body(text: &str) -> Vec<u8> {
    rmp_serde::to_vec_named(&serde_json::json!({"txt": text})).unwrap()
}

pub(crate) fn fixture() -> (tempfile::TempDir, Vault, EntityId, WriteActor) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    vault
        .put_entity(
            &actor.entity_ref(),
            ENTITY_TYPE_PERSON,
            time(1),
            1,
            &body("author"),
        )
        .unwrap();
    grant(&vault, actor, true);
    let conv = EntityId::now();
    vault
        .put_entity(
            &conv,
            ENTITY_TYPE_CONVERSATION,
            time(1),
            1,
            &body("conversation"),
        )
        .unwrap();
    (dir, vault, conv, actor)
}

pub(crate) fn grant(vault: &Vault, actor: WriteActor, allow: bool) {
    crate::conversation_dag::test_support::put_dag_test_policy(vault, actor, allow).unwrap();
}

pub(crate) fn time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

pub(crate) fn input(
    conv: EntityId,
    parent: Option<EntityId>,
    advance: bool,
    actor: WriteActor,
) -> AppendRecord {
    AppendRecord {
        conversation: conv,
        parent,
        reply_to: None,
        advance,
        kind: crate::registry::ENTITY_TYPE_TURN,
        occurred: time(20),
        learned_at: 20,
        body: body("record"),
        text: vec![],
        session: None,
        actor,
    }
}

pub(crate) fn scope(conv: EntityId, path: ScopePath, include_forks: bool) -> ScopeSelector {
    ScopeSelector {
        conversation: conv,
        session: None,
        path,
        include_forks,
    }
}
