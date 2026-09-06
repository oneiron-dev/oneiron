use super::*;
use crate::run_tree::RunTreeStatus;

#[test]
fn surfaced_failure_card_requires_existing_failed_status() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let feed = HealerQaFeed {
        thread_ref: crate::test_util::entity(0x64).to_hex(),
        entries: Vec::new(),
    };
    let stored_before = crate::AttemptQueue::new(&vault).get(failing)?;

    for status in [
        RunTreeStatus::Queued,
        RunTreeStatus::Running,
        RunTreeStatus::Paused,
        RunTreeStatus::Completed,
        RunTreeStatus::Cancelled,
    ] {
        let mut non_failed = tree.clone();
        non_failed.roots[0].status = status;
        let before = non_failed.clone();
        let error = surfaced_failure_card(
            &vault,
            card_input(failing, non_failed.clone(), feed.clone()),
        )
        .expect_err("a failure card cannot mark a non-Failed node");
        assert!(matches!(error, Error::InvalidConfig(_)), "{status:?}");
        assert_eq!(non_failed, before);
    }

    let card = surfaced_failure_card(&vault, card_input(failing, tree.clone(), feed.clone()))?;
    assert_eq!(card.diagram.tree, tree);
    assert_eq!(card.diagram.tree.roots[0].status, RunTreeStatus::Failed);
    assert_eq!(
        crate::AttemptQueue::new(&vault).get(failing)?,
        stored_before
    );

    // A matching Failed node must not mask another node with the same ID.
    for status in [RunTreeStatus::Failed, RunTreeStatus::Running] {
        let mut duplicate = tree.clone();
        let mut child = tree.roots[0].clone();
        child.status = status;
        duplicate.roots[0].children.push(child);
        let error = surfaced_failure_card(&vault, card_input(failing, duplicate, feed.clone()))
            .expect_err("duplicate IDs remain invalid even when one match is Failed");
        assert!(matches!(error, Error::InvalidConfig(_)));
    }
    Ok(())
}

#[test]
fn surfaced_failure_card_rejects_duplicate_authored_by_binding() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let actor = put_actor(&vault, 0x66)?;
    let impostor = put_actor(&vault, 0x6c)?;
    let message = put_qa_message(&vault, 0x67, thread, Some(actor), 100, 0)?;
    let card_for = |author| {
        surfaced_failure_card(
            &vault,
            card_input(
                failing,
                tree.clone(),
                HealerQaFeed {
                    thread_ref: thread.to_hex(),
                    entries: vec![qa_entry(message, author, 100)],
                },
            ),
        )
    };

    let card = card_for(actor)?;
    assert_eq!(card.qa.entries, vec![qa_entry(message, actor, 100)]);
    vault.put_edge(&message, EdgeKind::AuthoredBy, &impostor, 1.0)?;
    for author in [impostor, actor] {
        let error = card_for(author)
            .expect_err("neither author may claim a multiply-bound witnessed MESSAGE");
        assert!(matches!(error, Error::InvalidConfig(_)));
    }
    Ok(())
}
