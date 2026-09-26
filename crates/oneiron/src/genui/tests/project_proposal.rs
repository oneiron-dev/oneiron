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

fn request(
    action_id: &str,
    action: ConsentActionKind,
    actor: &str,
) -> Result<ConsentActionRequest> {
    ConsentActionRequest::new(
        "proposal-1",
        action_id,
        action,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: actor.to_owned(),
        },
        ConsentSurface::EiriConversation,
        42,
    )
}

#[test]
fn project_proposal_renders_stably_on_all_surfaces() -> Result<()> {
    let card = fixture_card()?;
    let component = Of336Component::ProjectProposal(card.clone());
    let fallback = card.fallback_text();
    let mut digests = Vec::new();
    for adapter in [
        Of336SurfaceAdapter::EiriSpecCareRegister,
        Of336SurfaceAdapter::DashboardAtomKitAudit,
        Of336SurfaceAdapter::McpUi,
    ] {
        let rendered = component.render(adapter)?;
        assert_eq!(rendered.component_kind, Of336ComponentKind::ProjectProposal);
        assert_eq!(rendered.fallback_text, fallback);
        assert_eq!(rendered.actions, card.actions());
        assert_eq!(rendered.actions.len(), 1);
        let bytes = serde_json::to_vec(&rendered).expect("typed render serializes");
        digests.push(blake3::hash(&bytes).to_hex().to_string());
        assert_eq!(
            serde_json::from_slice::<Of336RenderedComponent>(&bytes).expect("typed render decodes"),
            rendered
        );
        if adapter == Of336SurfaceAdapter::EiriSpecCareRegister {
            assert_eq!(
                rendered.tree["elements"]["proposal"]["props"]["title"],
                "Build a research index"
            );
            assert_eq!(
                rendered.tree["elements"]["mint_project"]["props"]["action"]["typedAction"],
                "project_mint"
            );
        } else if adapter == Of336SurfaceAdapter::McpUi {
            assert_eq!(
                rendered.tree["props"]["starting_skill_refs"][0],
                "skill:search"
            );
        }
    }
    assert_eq!(
        digests,
        [
            "f18b926354b0dfb94c1bb2501ea3bd49a2c0bd9682e14340e4b97a5e830eb436",
            "29bdef8efb086b10d7332922f469fb8d757f650a33a92a45d6abdd8f95dddaba",
            "8820c2b4c2fef83d2e6201238936ef0368fd7415a1a2b8dfd9f24191e2346973",
        ],
        "adapter wire bytes changed"
    );
    Ok(())
}

#[test]
fn owner_tap_emits_intent_without_minting_a_project() -> Result<()> {
    let (_dir, vault, owner) = owner_context();
    let id = crate::test_util::entity(0xA8);
    let card = fixture_card()?;
    let intent = card.evaluate_action(
        &request(
            PROJECT_PROPOSAL_MINT_ACTION_ID,
            ConsentActionKind::ProjectMint,
            "owner",
        )?,
        &owner,
    )?;
    assert_eq!(intent.source_message_ref, card.source_message_ref);
    assert_eq!(intent.goal, card.goal);
    assert_eq!(intent.leader_agent_def_ref, card.leader_agent_def_ref);
    assert_eq!(intent.board_human_refs, card.board_human_refs);
    assert_eq!(intent.budget_share_bps, 1250);
    assert_eq!(intent.starting_skill_refs, card.starting_skill_refs);
    assert!(vault.project(id)?.is_none(), "tap only returns an intent");
    Ok(())
}

#[test]
fn forged_actions_and_untrusted_actor_return_no_intent_or_write() -> Result<()> {
    let (_dir, vault, owner) = owner_context();
    let attacker = authenticated_person(&vault, 0x73, "attacker");
    let card = fixture_card()?;
    let wrong_id = request("approve_once", ConsentActionKind::ProjectMint, "owner")?;
    let wrong_kind = request(
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::Approve,
        "owner",
    )?;
    let wrong_actor = request(
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::ProjectMint,
        "attacker",
    )?;
    let mut wrong_card = request(
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::ProjectMint,
        "owner",
    )?;
    wrong_card.component_id = "proposal-other".to_owned();
    for forged in [&wrong_id, &wrong_kind, &wrong_card] {
        assert!(matches!(
            card.evaluate_action(forged, &owner),
            Err(Error::InvalidConfig(_))
        ));
    }
    assert_eq!(
        card.evaluate_action(&wrong_actor, &attacker)
            .expect_err("another principal cannot confirm this proposal")
            .kind(),
        crate::error::ErrorKind::ConsentUnauthenticatedActor
    );
    let project_id = crate::test_util::entity(0xA8);
    assert!(vault.project(project_id)?.is_none());
    assert!(vault.project_room_changes(project_id)?.is_empty());
    Ok(())
}

#[test]
fn invalid_card_contents_fail_closed_on_render_and_tap() -> Result<()> {
    let (_dir, _vault, owner) = owner_context();
    let mut card = fixture_card()?;
    card.budget_share_bps = 10_001;
    assert!(
        Of336Component::ProjectProposal(card.clone())
            .render(Of336SurfaceAdapter::McpUi)
            .is_err()
    );
    assert!(
        card.evaluate_action(
            &request(
                PROJECT_PROPOSAL_MINT_ACTION_ID,
                ConsentActionKind::ProjectMint,
                "owner"
            )?,
            &owner
        )
        .is_err()
    );
    card = fixture_card()?;
    card.board_human_refs.clear();
    assert!(card.validate().is_err());
    card = fixture_card()?;
    card.goal.axes.push("coverage".to_owned());
    assert!(card.validate().is_err());
    card = fixture_card()?;
    card.starting_skill_refs = (0..128)
        .map(|index| format!("skill-{index}-{}", "x".repeat(1000)))
        .collect();
    assert!(
        card.validate().is_err(),
        "joined Atom Kit text must fit too"
    );
    Ok(())
}
