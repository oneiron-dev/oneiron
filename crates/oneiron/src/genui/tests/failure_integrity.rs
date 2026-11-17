use super::*;

/// Fault injection: removes an edge's paired rows past the delete door's room
/// guards, to build membership shapes the card must still judge.
fn tear_edge(vault: &crate::Vault, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
    use crate::ports::EdgeStoreStaging;
    vault.with_write_txn(|txn| vault.store.port_remove_edge_rows(txn, src, kind, tgt))
}

#[test]
fn surfaced_failure_card_accepts_canonical_witness_membership() -> Result<()> {
    use crate::edge::EdgeActorClass;
    use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};

    // Keep the production policy manifest so this exercises the real witness door.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device())?;
    let (failing, tree) = failed_run(&vault)?;
    let actor = put_actor(&vault, 0x66)?;
    let conversation = crate::test_util::entity(0x64);
    let turn = crate::test_util::entity(0x65);
    let message = crate::test_util::entity(0x67);
    let foreign = put_container(&vault, 0x6a, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: QA_MESSAGE_BODY.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 100,
        })
        .expect("witness a canonical Q&A message");

    let entry = qa_entry(message, actor, 100);
    let card_for = |thread: EntityId| {
        surfaced_failure_card(
            &vault,
            card_input(
                failing,
                tree.clone(),
                HealerQaFeed {
                    thread_ref: thread.to_hex(),
                    entries: vec![entry.clone()],
                },
            ),
        )
    };
    for thread in [turn, conversation] {
        let card = card_for(thread)?;
        assert_eq!(card.qa.thread_ref, thread.to_hex());
        assert_eq!(card.qa.entries, vec![entry.clone()]);
        assert_eq!(card.diagram.tree, tree);
    }
    assert!(matches!(card_for(foreign), Err(Error::InvalidConfig(_))));

    // Isolate the writer's direct MESSAGE --BelongsTo--> CONVERSATION edge.
    assert!(tear_edge(&vault, &turn, EdgeKind::ChildOf, &conversation)?);
    assert!(card_for(conversation).is_ok());
    vault.put_edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)?;

    // Without the direct edge, the writer's PartOf -> ChildOf path still binds.
    assert!(tear_edge(
        &vault,
        &message,
        EdgeKind::BelongsTo,
        &conversation
    )?);
    assert!(card_for(conversation).is_ok());
    assert!(
        card_for(turn).is_ok(),
        "direct PartOf membership is preserved"
    );
    assert!(matches!(card_for(foreign), Err(Error::InvalidConfig(_))));
    let outer = put_container(&vault, 0x6b, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    vault.put_edge(&conversation, EdgeKind::ChildOf, &outer, 1.0)?;
    assert!(matches!(card_for(outer), Err(Error::InvalidConfig(_))));

    // A witnessed author alone cannot substitute for a membership path.
    assert!(tear_edge(&vault, &message, EdgeKind::PartOf, &turn)?);
    assert!(matches!(
        card_for(conversation),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}
