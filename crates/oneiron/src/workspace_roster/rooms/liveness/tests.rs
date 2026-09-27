//! Read-time room thread liveness acceptance fixtures.
use super::*;
use crate::workspace_roster::RoomThreadFill;
fn id(n: u8) -> EntityId {
    EntityId::from_bytes([n; 16]).unwrap()
}
fn turn(n: u8, thread_of: Option<EntityId>, reply_to: Option<EntityId>, at: u64) -> RoomTurn {
    RoomTurn {
        turn_id: id(n).to_hex(),
        room_id: id(250).to_hex(),
        actor: id(251).to_hex(),
        addressed_agents: Default::default(),
        message_ids: vec![],
        reply_to: reply_to.map(|id| id.to_hex()),
        thread_of: thread_of.map(|id| id.to_hex()),
        at,
    }
}
#[test]
fn forty_threads_fold_under_three_exact_budgeted_lists_and_relist_on_reply() {
    let trunk = id(240);
    let mut turns = vec![turn(240, None, None, 1)];
    turns.extend((1..=40).map(|n| turn(n, Some(trunk), None, 1)));
    let mut tasks: Vec<_> = (1..=20)
        .map(|n| RoomThreadTask {
            task: id(n + 100),
            thread: id(n),
            open: true,
            wait: (n > 10).then_some(RoomThreadWait {
                task: id(n + 100),
                kind: RoomWaitKind::HumanTask,
                who: id(251),
                since: 10,
                next_nudge: Some(30),
            }),
            delivered: None,
        })
        .collect();
    let policy = RoomThreadPolicy {
        now: 1_000_000,
        fresh_for: 86_400,
        rows_per_list: 4,
        tokens_per_list: 2048,
        fill: RoomThreadFill::Recency,
        waits_per_thread: 8,
    };
    let initial = project(&turns, &tasks, policy).unwrap();
    assert_eq!((initial.active.rows.len(), initial.active.more), (4, 6));
    assert_eq!((initial.waiting.rows.len(), initial.waiting.more), (4, 6));
    assert_eq!((initial.quiet.rows.len(), initial.quiet.more), (4, 16));
    assert_eq!(initial.waiting.rows[0].waits[0].who, id(251));
    let rows = initial.render_rows(id(250));
    for lane in ["active", "waiting", "quiet"] {
        assert!(rows.iter().any(|row| row == &format!("threads {lane}: 10")
            || lane == "quiet" && row == "threads quiet: 20"));
    }
    assert!(
        rows.iter()
            .any(|row| row.contains("threads quiet: +16 more"))
    );
    for (lane, list) in [
        ("active", &initial.active),
        ("waiting", &initial.waiting),
        ("quiet", &initial.quiet),
    ] {
        let count = list.rows.len() + list.more;
        let heading = format!("threads {lane}: {count}");
        let footer = format!(
            "threads {lane}: +{} more; find=rooms.find(room_ref={}) get=rooms.get(room_ref={},turn_ref=<handle>)",
            list.more,
            id(250).to_hex(),
            id(250).to_hex()
        );
        let spent = crate::tokenizer::count_context_pack_tokens(&heading)
            + crate::tokenizer::count_context_pack_tokens(&footer)
            + list
                .rows
                .iter()
                .map(|row| crate::tokenizer::count_context_pack_tokens(&row.line(lane)))
                .sum::<usize>();
        assert!(spent <= policy.tokens_per_list);
    }
    turns.push(turn(90, None, Some(id(40)), policy.now));
    let replied = project(&turns, &tasks, policy).unwrap();
    assert_eq!((replied.active.rows.len(), replied.active.more), (4, 7));
    assert_eq!(replied.active.rows[0].handle, id(40));
    assert_eq!((replied.quiet.rows.len(), replied.quiet.more), (4, 15));
    tasks[0].open = false;
    tasks[0].delivered = Some((id(230), policy.now + 1));
    let delivered = project(&turns, &tasks, policy).unwrap();
    assert_eq!((delivered.active.rows.len(), delivered.active.more), (4, 6));
    assert_eq!((delivered.quiet.rows.len(), delivered.quiet.more), (4, 16));
    let full = project(
        &turns,
        &tasks,
        RoomThreadPolicy {
            rows_per_list: usize::MAX,
            ..policy
        },
    )
    .unwrap();
    let header = full
        .quiet
        .rows
        .iter()
        .find(|row| row.handle == id(1))
        .unwrap();
    assert_eq!((header.trunk, header.result_header), (trunk, Some(id(230))));
    // A reply after delivery reopens the same thread without any stored
    // liveness bit or close verb.
    turns.push(turn(91, None, Some(id(1)), policy.now + 2));
    let reactivated = project(&turns, &tasks, policy).unwrap();
    assert_eq!(reactivated.active.rows[0].handle, id(1));
}
#[test]
fn malformed_or_foreign_task_and_reply_links_fail_closed() {
    let turns = [turn(240, None, None, 1), turn(1, Some(id(240)), None, 2)];
    let task = RoomThreadTask {
        task: id(100),
        thread: id(88),
        open: true,
        wait: None,
        delivered: None,
    };
    assert!(project(&turns, &[task], RoomThreadPolicy::default()).is_err());
    let bad = [
        turn(240, None, None, 1),
        turn(1, Some(id(240)), None, 2),
        turn(3, None, Some(id(88)), 3),
    ];
    assert!(project(&bad, &[], RoomThreadPolicy::default()).is_err());
}

#[test]
fn ordinary_trunk_reply_is_not_a_thread_and_reply_before_wait_does_not_wake_it() {
    let trunk = id(240);
    let root = id(1);
    let turns = vec![
        turn(240, None, None, 1),
        turn(1, Some(trunk), None, 2),
        turn(2, None, Some(trunk), 3), // valid room response on the trunk
        turn(3, None, Some(root), 4),
    ];
    let wait = RoomThreadWait {
        task: id(100),
        kind: RoomWaitKind::Ask,
        who: id(251),
        since: 10,
        next_nudge: None,
    };
    let task = RoomThreadTask {
        task: id(100),
        thread: root,
        open: true,
        wait: Some(wait),
        delivered: None,
    };
    let policy = RoomThreadPolicy {
        now: 12,
        fresh_for: 86_400,
        rows_per_list: 4,
        tokens_per_list: 512,
        fill: RoomThreadFill::Stage,
        waits_per_thread: 8,
    };
    let folded = project(&turns, std::slice::from_ref(&task), policy).unwrap();
    assert!(folded.active.rows.is_empty());
    assert_eq!(folded.waiting.rows[0].handle, root);
    assert!(folded.waiting.rows[0].line("waiting").contains("kind=ask"));
    let mut turns = turns;
    turns.push(turn(4, None, Some(id(3)), 13));
    assert_eq!(
        project(&turns, &[task], policy).unwrap().active.rows[0].handle,
        root
    );
}

#[test]
fn reply_ancestry_is_memoized_and_multiple_waits_have_distinct_handles() {
    let mut turns = vec![turn(240, None, None, 1), turn(1, Some(id(240)), None, 2)];
    for n in 2..200u8 {
        turns.push(turn(n, None, Some(id(n - 1)), u64::from(n)));
    }
    let waits = [10, 11].map(|n| RoomThreadTask {
        task: id(n + 200),
        thread: id(1),
        open: true,
        wait: Some(RoomThreadWait {
            task: id(n + 200),
            kind: RoomWaitKind::HumanTask,
            who: id(n),
            since: 200,
            next_nudge: Some(250),
        }),
        delivered: None,
    });
    let projection = project(
        &turns,
        &waits,
        RoomThreadPolicy {
            now: 1_000,
            fresh_for: 1,
            rows_per_list: 8,
            tokens_per_list: 512,
            fill: RoomThreadFill::Stage,
            waits_per_thread: 8,
        },
    )
    .unwrap();
    let row = &projection.waiting.rows[0];
    assert_eq!(row.last_message_at, 199);
    assert_eq!(row.waits.len(), 2);
    let line = row.line("waiting");
    assert!(line.contains(&id(210).to_hex()));
    assert!(line.contains(&id(211).to_hex()));
}

#[test]
fn policy_fill_switches_due_first_to_recent_wait_with_one_row_budget() {
    let turns = vec![
        turn(240, None, None, 1),
        turn(1, Some(id(240)), None, 10),
        turn(2, Some(id(240)), None, 20),
    ];
    let tasks = [1u8, 2]
        .into_iter()
        .map(|n| RoomThreadTask {
            task: id(n + 100),
            thread: id(n),
            open: true,
            delivered: None,
            wait: Some(RoomThreadWait {
                task: id(n + 100),
                kind: RoomWaitKind::HumanTask,
                who: id(251),
                since: 5,
                next_nudge: Some(if n == 1 { 30 } else { 300 }),
            }),
        })
        .collect::<Vec<_>>();
    let stage = RoomThreadPolicy {
        now: 1000,
        fresh_for: 1,
        rows_per_list: 1,
        tokens_per_list: 2048,
        fill: RoomThreadFill::Stage,
        waits_per_thread: 8,
    };
    assert_eq!(
        project(&turns, &tasks, stage).unwrap().waiting.rows[0].handle,
        id(1)
    );
    let recency = stage.narrowed(crate::gate::RoomThreadSettings {
        fresh_for: 1,
        rows_per_list: 1,
        tokens_per_list: 2048,
        fill: RoomThreadFill::Recency,
        waits_per_thread: 8,
    });
    assert_eq!(
        project(&turns, &tasks, recency).unwrap().waiting.rows[0].handle,
        id(2)
    );
}

#[test]
fn exact_room_footer_budget_refuses_floor_and_honors_row_boundary() {
    let room = EntityId::from_hex("b7bef252b4d019b6516847f69b71cb42").unwrap();
    let mut policy = RoomThreadPolicy {
        now: 1000,
        fresh_for: 1,
        rows_per_list: 2,
        tokens_per_list: 64,
        fill: RoomThreadFill::Recency,
        waits_per_thread: 8,
    };
    assert!(project_in_room(&[], &[], policy, room).is_err());
    policy.tokens_per_list = 128;
    let empty = project_in_room(&[], &[], policy, room).unwrap();
    let lines = empty.render_rows(room);
    let quiet = lines
        .iter()
        .filter(|line| line.starts_with("threads quiet:"))
        .collect::<Vec<_>>();
    assert!(
        quiet
            .iter()
            .map(|line| crate::tokenizer::count_context_pack_tokens(line))
            .sum::<usize>()
            <= 128
    );
    let turns = vec![
        RoomTurn {
            room_id: room.to_hex(),
            ..turn(240, None, None, 1)
        },
        RoomTurn {
            room_id: room.to_hex(),
            ..turn(1, Some(id(240)), None, 2)
        },
    ];
    let full = project_in_room(&turns, &[], policy, room).unwrap();
    let exact_lines = full.render_rows(room);
    let exact = exact_lines
        .iter()
        .filter(|line| line.starts_with("threads quiet:") || line.starts_with("quiet "))
        .map(|line| crate::tokenizer::count_context_pack_tokens(line))
        .sum::<usize>();
    assert!(exact <= 128);
    policy.tokens_per_list = exact;
    assert_eq!(
        project_in_room(&turns, &[], policy, room)
            .unwrap()
            .quiet
            .rows
            .len(),
        1
    );
    policy.tokens_per_list = exact - 1;
    let below = project_in_room(&turns, &[], policy, room);
    if let Ok(projected) = below {
        assert!(projected.quiet.rows.is_empty());
        let spent = projected
            .render_rows(room)
            .iter()
            .filter(|line| line.starts_with("threads quiet:"))
            .map(|line| crate::tokenizer::count_context_pack_tokens(line))
            .sum::<usize>();
        assert!(spent <= exact - 1);
    }
}
