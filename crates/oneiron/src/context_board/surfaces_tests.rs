//! Acceptance fixtures for scope, read-set freshness, and capability shedding.

use super::*;
use crate::{
    EntityId,
    pipeline::{ResolvedWorldAuthority, WorldAuthoritySet},
};

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

#[test]
fn worlds_filter_before_projection_and_counting() {
    let worlds = [1, 2, 3, 4].map(|n| WorldPresence {
        id: id(n),
        label: format!("world-{n}"),
        trust: "trusted".into(),
    });
    let authority = ResolvedWorldAuthority {
        allowed_set: WorldAuthoritySet::new(false, [id(1), id(2), id(3)]).unwrap(),
        default_subset: WorldAuthoritySet::new(false, [id(1)]).unwrap(),
        active_set: WorldAuthoritySet::new(false, [id(1)]).unwrap(),
        allowed_claim_ids: vec![],
        default_claim_id: None,
    };
    let projected = WorldsSection::project(&worlds, &authority, 1);
    assert_eq!((projected.active_count, projected.off_count), (1, 2));
    assert!(projected.rows[0].contains("ACTIVE trusted world-1"));
    assert!(projected.rows[1].starts_with("off:"));
    assert!(projected.rows[1].ends_with("+1"));
    assert!(!projected.rows.join(" ").contains("world-4"));
    let allowed_only = WorldsSection::project(&worlds[..3], &authority, 1);
    assert_eq!(projected, allowed_only);
    let section = projected.board_section().unwrap();
    assert_eq!(section.policy().shed_rank, Some(ShedRank::WorldsToCounts));
    assert_eq!(section.count_rows(), ["active: 1 off: 2"]);
}

#[test]
fn changed_line_survives_epoch_and_rides_without_pushing() {
    let mut session = SessionReadSet::default();
    session.served("cl1", ServedLifecycle::Active); // rendered board row
    session.served("cl2", ServedLifecycle::Active); // get() body
    session.loaded_skill("sk1", "v2");
    let reopened: SessionReadSet =
        serde_json::from_slice(&serde_json::to_vec(&session).unwrap()).unwrap();
    let changes = reopened.changed(1, |key| match key {
        "cl1" => Some(ServedLifecycle::Superseded("cl3".into())),
        "cl2" => Some(ServedLifecycle::Retracted),
        _ => Some(ServedLifecycle::Active),
    });
    assert_eq!(
        changes.render(),
        ["changed[1:]{id,to}:", "cl1: superseded:cl3", "changed: +1"]
    );
    assert_eq!(changes.ride(None), None);
    let header = BoardBlockHeader {
        epoch: 9,
        scope: "base".into(),
    };
    let legend = BoardLegend::canonical();
    let render = render_board_block(
        &BoardFrame {
            header: &header,
            legend: &legend,
            sections: &[],
            changes: Some(&changes),
        },
        BoardBudgetRequest {
            harness_default_tok: 0,
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )
    .unwrap();
    assert!(
        render
            .text
            .lines()
            .nth(2)
            .unwrap()
            .starts_with("changed[1:]")
    );
    let frame = changes
        .ride(Some(BoardStreamFrame {
            epoch: 9,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: "task1".into(),
                line: "working".into(),
            }]),
        }))
        .unwrap();
    let FrameKind::Delta(rows) = frame.kind else {
        panic!("delta")
    };
    assert_eq!(rows[0].key, "changed");
    assert_eq!(
        rows[0].line,
        "changed[1:]{id,to}: cl1: superseded:cl3 changed: +1"
    );
    assert_eq!(rows.last().unwrap().key, "task1");
    assert_eq!(
        reopened.loaded_skills().collect::<Vec<_>>(),
        [("sk1", "v2")]
    );
}

#[test]
fn skills_found_and_agent_candidates_shed_before_memory_snippets() {
    let mut session = SessionReadSet::default();
    session.loaded_skill("sk-old", "1");
    let hits = [
        CapabilityHit {
            id: id(1),
            entity_type: crate::registry::ENTITY_TYPE_SKILL,
            label: "found-skill".into(),
        },
        CapabilityHit {
            id: id(2),
            entity_type: crate::registry::ENTITY_TYPE_AGENT_DEF,
            label: "found-agent".into(),
        },
    ];
    let skills = SkillsSection::project(&hits, &session);
    assert!(skills.found[0].contains("found-skill"));
    assert_eq!(skills.loaded, "loaded: sk-old@1");
    let agents = render_agents_section(&[], &[]).with_candidates(&hits);
    assert_eq!(agents.rows.len(), 1);
    assert_eq!(agents.rows[0].lane, AgentLane::Cand);
    // Replacing turn hits clears the old candidates and found rows, not loaded.
    assert!(agents.clone().with_candidates(&[]).rows.is_empty());
    assert_eq!(SkillsSection::project(&[], &session).loaded, skills.loaded);
    let tasks = render_tasks_section(&[], &[]);
    let [_, agent_section] = assemble_task_agent_sections(&tasks, &agents).unwrap();
    let sections = [
        skills.board_section().unwrap(),
        agent_section,
        BoardSection::new(
            "MEMORIES",
            vec![],
            vec!["snippet body ".repeat(10)],
            vec!["count: 1".into()],
            SectionPolicy {
                pinned: false,
                shed_rank: Some(ShedRank::MemoriesSnippets),
            },
        )
        .unwrap(),
    ];
    let header = BoardBlockHeader {
        epoch: 1,
        scope: "base".into(),
    };
    let legend = BoardLegend::canonical();
    let frame = BoardFrame {
        header: &header,
        legend: &legend,
        sections: &sections,
        changes: None,
    };
    // Find the budget where only the cheaper discovery tier has shed.
    let rendered = (1..500)
        .find_map(|cap| {
            let out = render_board_block(
                &frame,
                BoardBudgetRequest {
                    harness_default_tok: cap,
                    caller_limit_tok: None,
                    explicit_override_tok: None,
                },
            )
            .unwrap();
            (out.shed.applied.last() == Some(&ShedRank::CapabilityDiscovery)).then_some(out)
        })
        .expect("discovery tier has a reducing budget interval");
    assert!(!rendered.text.contains("found-skill"));
    assert!(!rendered.text.contains("found-agent"));
    assert!(rendered.text.contains("loaded: sk-old@1"));
    assert!(rendered.text.contains("snippet body"));
}

#[test]
fn new_pack_install_appears_on_existing_session_changed_line_without_push() {
    let mut session = SessionReadSet::default();
    let old = vec![("alice.tools".to_owned(), "ab".repeat(32))];
    let updated = vec![
        ("alice.tools".to_owned(), "cd".repeat(32)),
        ("alice.connector".to_owned(), "ef".repeat(32)),
    ];
    assert!(session.pack_changes(&updated, 16).rows.is_empty());
    session.observe_pack_inventory(&old);
    let changed = session.pack_changes(&updated, 16);
    assert_eq!(changed.rows.len(), 2);
    assert!(
        changed
            .render()
            .iter()
            .any(|row| row.contains("alice.connector: installed:"))
    );
    assert!(changed.ride(None).is_none());
    let frame = changed
        .ride(Some(BoardStreamFrame {
            epoch: 7,
            kind: FrameKind::Keyframe("<board>\nnote: current\nlegend: kinds\n</board>".into()),
        }))
        .expect("existing frame");
    let FrameKind::Keyframe(text) = frame.kind else {
        panic!("keyframe")
    };
    assert!(text.find("note:").unwrap() < text.find("alice.connector: installed:").unwrap());
    assert!(text.find("alice.connector: installed:").unwrap() < text.find("legend:").unwrap());
    let reopened: SessionReadSet =
        serde_json::from_slice(&serde_json::to_vec(&session).unwrap()).unwrap();
    assert_eq!(reopened.pack_changes(&updated, 16), changed);
}

#[test]
fn changed_rider_replaces_the_whole_block_and_clears_on_next_existing_frame() {
    let changes = ChangedLine {
        rows: vec![("cl1".into(), ServedLifecycle::Retracted)],
        overflow: 0,
    };
    let keyframe = changes
        .ride(Some(BoardStreamFrame {
            epoch: 3,
            kind: FrameKind::Keyframe("<board>\nnote: current\nlegend: kinds\n</board>".into()),
        }))
        .unwrap();
    let FrameKind::Keyframe(text) = &keyframe.kind else {
        panic!("keyframe")
    };
    assert!(text.find("note:").unwrap() < text.find("changed[").unwrap());
    assert!(text.find("changed[").unwrap() < text.find("legend:").unwrap());
    let mut receiver = AppliedStreamState::default();
    receiver.apply(keyframe);
    let delta = || {
        Some(BoardStreamFrame {
            epoch: 3,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: "task1".into(),
                line: "working".into(),
            }]),
        })
    };
    receiver.apply(changes.ride(delta()).unwrap());
    assert!(receiver.delta_overlay["changed"].contains("cl1: retracted"));
    receiver.apply(ChangedLine::default().ride(delta()).unwrap());
    assert_eq!(receiver.delta_overlay["changed"], "");
    assert_eq!(receiver.delta_overlay["task1"], "working");
    assert!(ChangedLine::default().ride(None).is_none());
}

#[test]
fn base_world_obeys_the_same_exclusion_and_active_off_count_rules() {
    let authority = |allowed, active| ResolvedWorldAuthority {
        allowed_set: WorldAuthoritySet::new(allowed, []).unwrap(),
        default_subset: WorldAuthoritySet::new(active, []).unwrap(),
        active_set: WorldAuthoritySet::new(active, []).unwrap(),
        allowed_claim_ids: vec![],
        default_claim_id: None,
    };
    let active = WorldsSection::project(&[], &authority(true, true), 1);
    assert_eq!(active.rows, ["base ACTIVE local"]);
    assert_eq!((active.active_count, active.off_count), (1, 0));
    let off = WorldsSection::project(&[], &authority(true, false), 1);
    assert_eq!(off.rows, ["off: base AVAILABLE-OFF local"]);
    assert_eq!((off.active_count, off.off_count), (0, 1));
    let hidden = WorldsSection::project(&[], &authority(false, false), 1);
    assert!(hidden.rows.is_empty());
    assert_eq!((hidden.active_count, hidden.off_count), (0, 0));
}
