use super::*;

fn fixture_card() -> Result<ProjectProposalCard> {
    ProjectProposalCard::new(
        "proposal-1",
        "owner",
        "message:conversation-7:turn-2",
        ProjectGoalDraft {
            goal: "Build a research index".to_owned(),
            why: "Find evidence faster".to_owned(),
            axes: vec!["coverage".to_owned(), "freshness".to_owned()],
        },
        ProjectProposalPicks {
            leader_agent_def_ref: "agent-def:research-lead".to_owned(),
            board_human_refs: vec!["person:owner".to_owned(), "person:reviewer".to_owned()],
            budget_share_bps: 1250,
            starting_skill_refs: vec!["skill:search".to_owned(), "skill:review".to_owned()],
        },
    )
}

#[test]
fn mcp_ui_consumes_generic_lowered_segments_with_declared_action() -> Result<()> {
    let card = fixture_card()?;
    let foreign =
        Of336Component::ProjectProposal(card.clone()).render(Of336SurfaceAdapter::McpUi)?;
    let segments: Vec<crate::lens::GeneratedUiSegment> =
        serde_json::from_value(foreign.tree["segments"].clone())
            .expect("existing segment wire decodes");
    let render = crate::lens::GeneratedUiRender::from_segments(&segments)?;
    assert_eq!(render.card_id.as_str(), card.card_id);
    assert_eq!(render.actions.len(), 1);
    assert_eq!(
        render.actions[0].action_id.as_str(),
        PROJECT_PROPOSAL_MINT_ACTION_ID
    );
    assert_eq!(render.actions[0].element_id.as_str(), "action-mint_project");
    assert_eq!(
        render.actions[0].tier,
        crate::lens::GeneratedUiActionTier::DeterministicTool
    );
    assert_eq!(
        render.actions[0].action.command.as_str(),
        "project_mint_intent"
    );
    let button = render
        .nodes
        .iter()
        .find(|node| node.id.as_str() == "action-mint_project")
        .expect("action node exists in lowered tree");
    assert!(matches!(button.atom, crate::lens::LensAtom::SelfUi(_)));
    assert!(render.nodes.iter().all(|node| matches!(
        node.atom,
        crate::lens::LensAtom::SelfUi(_) | crate::lens::LensAtom::TextBlock(_)
    )));
    assert_eq!(foreign.tree["fallback_text"], card.fallback_text());
    Ok(())
}

#[test]
fn unsupported_receipt_lowers_to_complete_project_details() -> Result<()> {
    let card = fixture_card()?;
    let text = card
        .generated_ui_card()?
        .render_for_surface(&crate::lens::GeneratedUiSurfaceCapabilities::text_only())?;
    assert!(
        text.actions.is_empty(),
        "a text-only surface cannot offer a button"
    );
    let fields = text
        .nodes
        .iter()
        .find(|node| node.id.as_str() == "project-proposal-fields")
        .expect("fields node survives lowering");
    let crate::lens::LensAtom::TextBlock(atom) = &fields.atom else {
        panic!("unsupported Receipt must lower to text");
    };
    let lowered = atom.fallback_text();
    assert_eq!(lowered, fields.fallback_text.as_str());
    for value in [
        "Build a research index",
        "Find evidence faster",
        "coverage",
        "freshness",
        "agent-def:research-lead",
        "person:owner",
        "person:reviewer",
        "1250",
        "skill:search",
        "skill:review",
        "message:conversation-7:turn-2",
    ] {
        assert!(lowered.contains(value), "text lowering omitted {value}");
    }
    Ok(())
}
