//! Read-time room thread liveness acceptance fixtures.
use super::*;
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
        tokens_per_list: 512,
    };
    let initial = project(&turns, &tasks, policy).unwrap();
    assert_eq!((initial.active.rows.len(), initial.active.more), (4, 6));
    assert_eq!((initial.waiting.rows.len(), initial.waiting.more), (4, 6));
    assert_eq!((initial.quiet.rows.len(), initial.quiet.more), (4, 16));
    assert_eq!(initial.waiting.rows[0].waits[0].who, id(251));
    let rows = initial.render_rows();
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
            "threads {lane}: +{} more; find=rooms_find_threads get=rooms_get_thread",
            list.more
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
