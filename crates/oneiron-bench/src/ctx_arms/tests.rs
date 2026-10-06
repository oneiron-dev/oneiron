use super::arms::{ARMS, Arm, Episode, Query, read};
use super::arms::{Verb, snapshot_lines};
use super::arms_epoch::{self, GAP_TOK};
use super::board;
use super::strategies::{
    CanonPlacement, EngineBoard, FifoFold, FreeFile, Layout, OldestFirst, RecoverableFold,
    STRATEGIES, Sketch, Strategy, Truncate, build, lossy_summary, shape,
};
use super::window::{Caps, Ctx, Ledger, RefStore, SpanKind, Surface, Window, tokens};
use super::{DEFAULT_BUDGET, DEV_SEEDS, HELDOUT_SEEDS, low_water, run_episode, run_episode_with};

/// The four loop-1 arms (loop 2 adds two).
const LOOP1_ARMS: [Arm; 4] = [Arm::Needle, Arm::Sketchpad, Arm::KvOffload, Arm::LogTriage];

fn full_stream_answers(ep: &Episode) -> Vec<String> {
    arms_epoch::oracle_answers(ep)
}

#[test]
fn splits_and_tokenizer_are_pinned() {
    assert_eq!(DEV_SEEDS, 1..=20);
    assert_eq!(HELDOUT_SEEDS, 1001..=1020);
    assert_eq!(DEFAULT_BUDGET, 32_768);
    assert_eq!(tokens(""), 0);
    assert_eq!(tokens("abcd"), 1);
    assert_eq!(tokens("abcde"), 2);
}

#[test]
fn generators_are_deterministic_and_seeded() {
    for arm in ARMS {
        let a = Episode::generate(arm, 1001);
        assert_eq!(a.digest(), Episode::generate(arm, 1001).digest(), "{arm:?}");
        assert_ne!(a.digest(), Episode::generate(arm, 1002).digest(), "{arm:?}");
        assert_ne!(a.digest(), Episode::generate(arm, 1).digest(), "{arm:?}");
    }
}

#[test]
fn full_stream_oracle_is_exact_on_every_arm() {
    for arm in ARMS {
        for seed in [1, 1001] {
            let ep = Episode::generate(arm, seed);
            let (score, extra) = ep.score_full(&full_stream_answers(&ep));
            assert_eq!(score.correct, score.total, "{arm:?} seed {seed}");
            assert_eq!(score.hallucinated, 0);
            assert_eq!(extra.stale, 0);
        }
    }
}

#[test]
fn every_stream_rises_well_past_the_default_budget() {
    for arm in ARMS {
        let ep = Episode::generate(arm, 1001);
        let total: u64 = ep.turns.iter().map(|t| tokens(&t.text)).sum();
        assert!(total > 2 * DEFAULT_BUDGET, "{arm:?}: {total} tokens");
    }
}

#[test]
fn reader_abstains_and_counts_hallucinated_needles() {
    let ep = Episode::generate(Arm::Needle, 1001);
    let mut answers = full_stream_answers(&ep);
    let truth = answers[0].clone();
    answers[0] = truth[..truth.len() - 3].to_owned();
    answers[1] = String::new();
    let score = ep.score(&answers);
    assert_eq!(score.correct, score.total - 2);
    assert_eq!(
        score.hallucinated, 1,
        "a truncated needle is not in the stream"
    );
    let q = Query {
        text: "RECALL NEEDLE n99".to_owned(),
        key: "NEEDLE n99:".to_owned(),
    };
    assert_eq!(read(Arm::Needle, &q, &["nothing here"]), "");
}

#[test]
fn append_costs_no_reprefill_and_a_head_edit_reprefills_the_window() {
    let mut win = Window::default();
    for n in 0..4 {
        win.push(SpanKind::Turn(n), "x".repeat(40));
    }
    assert_eq!(
        win.checkpoint(),
        0,
        "first call prefills, nothing cached yet"
    );
    win.push(SpanKind::Turn(4), "y".repeat(40));
    assert_eq!(
        win.checkpoint(),
        0,
        "a pure append reuses the cached prefix"
    );

    let mut refs = RefStore::default();
    let mut led = Ledger::default();
    let mut ctx = Ctx::new(
        &mut win,
        &mut refs,
        &mut led,
        Caps {
            drop: true,
            ..Caps::default()
        },
        1000,
        750,
    );
    ctx.drop_spans(0..1);
    let after: u64 = win.spans().iter().map(super::window::Span::tok).sum();
    assert_eq!(
        win.checkpoint(),
        after,
        "dropping the head re-prefills everything"
    );
    assert_eq!(led.audit(&refs).departed, 1);
    assert_eq!(led.audit(&refs).exact, 0);
}

#[test]
fn an_undeclared_operation_is_refused_and_recorded() {
    let mut win = Window::default();
    win.push(SpanKind::Turn(0), "a".to_owned());
    win.push(SpanKind::Turn(1), "b".to_owned());
    let mut refs = RefStore::default();
    let mut led = Ledger::default();
    let mut ctx = Ctx::new(
        &mut win,
        &mut refs,
        &mut led,
        Caps {
            drop: true,
            ..Caps::default()
        },
        1000,
        750,
    );
    assert_eq!(ctx.offload(0..1), None);
    assert_eq!(led.violations, vec!["offload"]);
    assert_eq!(win.spans().len(), 2);
}

#[test]
fn truncate_stays_in_budget_and_restores_nothing() {
    for arm in ARMS {
        let ep = Episode::generate(arm, 1);
        let r = run_episode(
            &ep,
            &mut Truncate::new(Box::new(OldestFirst)),
            DEFAULT_BUDGET,
        );
        assert!(r.peak <= DEFAULT_BUDGET, "{arm:?} peak {}", r.peak);
        assert!(r.violations.is_empty());
        assert!(r.audit.departed > 0);
        assert_eq!(r.audit.exact, 0);
        assert!(r.reprefill_tok > 0);
        assert!(r.mean > low_water(DEFAULT_BUDGET) as f64 / 2.0);
    }
}

#[test]
fn recoverable_fold_restores_every_departed_span_byte_exactly() {
    for arm in LOOP1_ARMS {
        let ep = Episode::generate(arm, 2);
        let r = run_episode(
            &ep,
            &mut RecoverableFold::new(Box::new(OldestFirst)),
            DEFAULT_BUDGET,
        );
        assert!(r.violations.is_empty());
        assert!(r.audit.departed > 0, "{arm:?}");
        assert_eq!(r.audit.exact, r.audit.departed, "{arm:?}");
        assert!(!r.restore_fail);
        assert!(r.peak <= DEFAULT_BUDGET);
        assert!((r.score.value - 1.0).abs() < 1e-9, "{arm:?} {:?}", r.score);
    }
}

#[test]
fn a_reference_that_cannot_restore_fails_the_offload_arm() {
    let ep = Episode::generate(Arm::KvOffload, 2);
    let r = run_episode_with(
        &ep,
        &mut RecoverableFold::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
        |refs| refs.corrupt(1),
    );
    assert!(r.restore_fail);
    assert!(r.audit.exact < r.audit.departed);
    assert_eq!(r.score.value, 0.0);
}

#[test]
fn reference_restore_refuses_tampered_bytes() {
    let mut win = Window::default();
    for n in 0..3 {
        win.push(SpanKind::Turn(n), format!("SET k-0000{n} = abc #00000{n}"));
    }
    let mut refs = RefStore::default();
    let mut led = Ledger::default();
    let mut ctx = Ctx::new(
        &mut win,
        &mut refs,
        &mut led,
        Caps {
            offload: true,
            ..Caps::default()
        },
        1000,
        750,
    );
    let id = ctx.offload(0..2).unwrap();
    assert_eq!(ctx.grep_refs("k-00001"), vec![id]);
    assert_eq!(win.spans().len(), 2, "two spans left, one stub came in");
    assert_eq!(refs.restore(id).unwrap().len(), 2);
    assert_eq!(led.audit(&refs).exact, 2);
    refs.corrupt(id);
    assert!(refs.restore(id).is_err());
    assert!(led.audit(&refs).broken_reference());
}

#[test]
fn fifo_fold_is_fixed_size_lossy_and_hallucinates_cut_needles() {
    let ep = Episode::generate(Arm::Needle, 3);
    let r = run_episode(
        &ep,
        &mut FifoFold::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert!(r.violations.is_empty());
    assert_eq!(r.audit.exact, 0);
    assert!(r.score.hallucinated > 0, "{:?}", r.score);
    let mut win = Window::default();
    let long = format!("NEEDLE n01: {}", "word ".repeat(400));
    win.push(SpanKind::Turn(0), long.repeat(3));
    let stub = lossy_summary(win.spans());
    assert!(stub.len() <= 384);
    assert!(stub.lines().all(|l| l.len() <= 32));
}

#[test]
fn every_named_strategy_runs_every_arm_in_budget_without_violations() {
    for arm in ARMS {
        let ep = Episode::generate(arm, 4);
        for name in STRATEGIES {
            let mut strategy = build(name).unwrap();
            assert_eq!(strategy.name(), name);
            let r = run_episode(&ep, strategy.as_mut(), DEFAULT_BUDGET);
            assert!(
                r.violations.is_empty(),
                "{arm:?} {name}: {:?}",
                r.violations
            );
            assert!(r.peak <= DEFAULT_BUDGET, "{arm:?} {name}: peak {}", r.peak);
            assert_eq!(r.over_budget, 0, "{arm:?} {name}");
        }
    }
}

#[test]
fn free_file_cuts_prose_first_and_never_restores() {
    assert_eq!(shape("the quiet river runs."), "prose");
    assert_eq!(shape("2026-10-06T00:00:01.000Z INFO svc=auth"), "# INFO #");
    assert_eq!(shape("SET k-0a1b2 = 00ff #000001"), "SET # #");
    let ep = Episode::generate(Arm::KvOffload, 5);
    let r = run_episode(&ep, &mut FreeFile::default(), DEFAULT_BUDGET);
    assert!(r.audit.departed > 0);
    assert_eq!(r.audit.exact, 0, "free-file deletes with no restore path");
    let truncate = run_episode(
        &ep,
        &mut Truncate::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert!(r.score.value >= truncate.score.value);
}

fn board_ctx_run(strategy: &mut dyn Strategy, verbs: &[Verb]) -> (Window, Ledger, u64) {
    let mut win = Window::default();
    let mut refs = RefStore::default();
    let mut led = Ledger::default();
    let mut reprefill = 0;
    for (n, verb) in verbs.iter().enumerate() {
        win.push(SpanKind::Turn(n as u32), "filler line.".to_owned());
        let mut ctx = Ctx::new(
            &mut win,
            &mut refs,
            &mut led,
            strategy.caps(),
            DEFAULT_BUDGET,
            low_water(DEFAULT_BUDGET),
        );
        strategy.on_verb(verb, &mut ctx);
        strategy.on_turn(&mut ctx);
        reprefill += win.checkpoint();
    }
    (win, led, reprefill)
}

#[test]
fn free_file_edits_its_board_in_place_and_pays_reprefill() {
    let grid = [1; 81];
    let verbs = [
        Verb::BoardInit(grid),
        Verb::SetCell {
            mv: 1,
            cell: 10,
            digit: 7,
        },
    ];
    let (win, led, reprefill) = board_ctx_run(&mut FreeFile::default(), &verbs);
    let boards: Vec<_> = win
        .spans()
        .iter()
        .filter(|s| s.text().starts_with("BOARD @m"))
        .collect();
    assert_eq!(boards.len(), 1, "one board, edited in place");
    assert!(
        boards[0]
            .text()
            .starts_with("BOARD @m001\nr1 111111111\nr2 171111111")
    );
    assert!(
        reprefill > 0,
        "the in-place edit sits before the newest turn"
    );
    let init = tokens(&snapshot_lines(&grid, 0).join("\n"));
    let patch = led.edit_tok - init;
    assert!(patch < 16, "a patch, not a regenerated board: {patch}");
}

#[test]
fn engine_board_renders_typed_state_through_the_engine_renderer() {
    let mut sketch = Sketch::default();
    let mut grid = [0; 81];
    grid[0] = 5;
    sketch.apply(&Verb::BoardInit(grid));
    sketch.apply(&Verb::SetCell {
        mv: 1,
        cell: 80,
        digit: 9,
    });
    let text = board::render(sketch.typed(), &[]).unwrap();
    assert!(text.starts_with("<memory surface=\"board\""), "{text}");
    for line in snapshot_lines(
        &{
            let mut g = grid;
            g[80] = 9;
            g
        },
        1,
    ) {
        assert!(
            text.lines().any(|l| l == line),
            "{line} missing from {text}"
        );
    }
    let q = Query {
        text: "BOARD FINAL".to_owned(),
        key: "BOARD @m".to_owned(),
    };
    let read_back = read(Arm::Sketchpad, &q, &[text.as_str()]);
    assert_eq!(&read_back[..1], "5");
    assert_eq!(&read_back[80..], "9");

    let (win, led, _) = board_ctx_run(
        &mut EngineBoard::new(Box::new(OldestFirst)),
        &[Verb::BoardInit(grid)],
    );
    assert_eq!(win.spans().last().map(|s| s.kind()), Some(SpanKind::Board));
    assert!(led.violations.is_empty());
}

#[test]
fn engine_board_keeps_everything_restorable_on_every_arm() {
    for arm in LOOP1_ARMS {
        let ep = Episode::generate(arm, 6);
        let r = run_episode(
            &ep,
            &mut EngineBoard::new(Box::new(OldestFirst)),
            DEFAULT_BUDGET,
        );
        assert!(r.audit.departed > 0, "{arm:?}");
        assert_eq!(
            r.audit.exact, r.audit.departed,
            "{arm:?}: the engine never deletes"
        );
        assert!((r.score.value - 1.0).abs() < 1e-9, "{arm:?} {:?}", r.score);
    }
}

struct Rogue(Vec<std::ops::Range<usize>>);

impl super::strategies::Policy for Rogue {
    fn name(&self) -> &'static str {
        "rogue"
    }

    fn choose(
        &mut self,
        _spans: &[super::window::Span],
        _must_free: u64,
        _keep: &dyn Fn(&super::window::Span) -> bool,
    ) -> Vec<std::ops::Range<usize>> {
        self.0.clone()
    }
}

#[test]
fn a_policy_choice_that_breaks_its_contract_is_refused() {
    let ep = Episode::generate(Arm::Needle, 7);
    let overlapping = Rogue(vec![0..2, 1..3]);
    let r = run_episode(
        &ep,
        &mut Truncate::new(Box::new(overlapping)),
        DEFAULT_BUDGET,
    );
    assert!(r.violations.contains(&"policy choice breaks its contract"));
    let out_of_bounds = Rogue(vec![0..usize::MAX]);
    let r = run_episode(
        &ep,
        &mut Truncate::new(Box::new(out_of_bounds)),
        DEFAULT_BUDGET,
    );
    assert!(!r.violations.is_empty(), "refused, not a panic");
}

#[test]
fn an_unmanaged_window_cannot_make_a_valid_cell() {
    let ep = Episode::generate(Arm::Needle, 7);
    let r = run_episode(
        &ep,
        &mut Truncate::new(Box::new(Rogue(Vec::new()))),
        DEFAULT_BUDGET,
    );
    assert!(
        (r.score.value - 1.0).abs() < 1e-9,
        "the whole stream stayed live"
    );
    assert!(r.over_budget > 0);
    let mut cell = super::Cell::default();
    cell.add(&r, 0.0);
    assert!(!cell.valid(1), "over budget never counts as a valid cell");
}

fn ctx_with<'a>(
    win: &'a mut Window,
    refs: &'a mut RefStore,
    led: &'a mut Ledger,
    caps: Caps,
) -> Ctx<'a> {
    Ctx::new(win, refs, led, caps, 1000, 750)
}

#[test]
fn a_rewritten_then_offloaded_span_is_audited_per_version() {
    let mut win = Window::default();
    win.push(
        SpanKind::Turn(0),
        "SET k-00000 = aa #000001\nprose line.".to_owned(),
    );
    win.push(SpanKind::Turn(1), "newest".to_owned());
    let (mut refs, mut led) = (RefStore::default(), Ledger::default());
    let caps = Caps {
        rewrite: true,
        offload: true,
        ..Caps::default()
    };
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps);
    ctx.patch_lines(0, &[(1, "edited.".to_owned())]);
    let id = ctx.offload(0..1).unwrap();
    let audit = led.audit(&refs);
    assert_eq!((audit.departed, audit.with_ref, audit.exact), (2, 1, 1));
    refs.corrupt(id);
    assert!(led.audit(&refs).broken_reference());
}

#[test]
fn reprefill_starts_at_the_first_changed_byte_and_a_no_op_costs_nothing() {
    let mut win = Window::default();
    win.push(SpanKind::Turn(0), format!("{}\nx", "a".repeat(4000)));
    win.push(SpanKind::Turn(1), "tail".to_owned());
    win.checkpoint();
    let (mut refs, mut led) = (RefStore::default(), Ledger::default());
    let caps = Caps {
        rewrite: true,
        ..Caps::default()
    };
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps);
    ctx.patch_lines(0, &[(1, "x".to_owned())]);
    assert_eq!(
        led.audit(&refs).departed,
        0,
        "a no-op patch departs nothing"
    );
    assert_eq!(win.checkpoint(), 0, "and re-prefills nothing");
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps);
    ctx.patch_lines(0, &[(1, "y".to_owned())]);
    let reprefill = win.checkpoint();
    assert!(
        reprefill < 10,
        "only the changed tail of the span and what follows: {reprefill}"
    );
    assert_eq!(led.audit(&refs).departed, 1);
}

#[test]
fn edits_cannot_reach_the_board_and_strategies_cannot_write_it() {
    let mut win = Window::default();
    win.push(SpanKind::Turn(0), "a".to_owned());
    let (mut refs, mut led) = (RefStore::default(), Ledger::default());
    let caps = Caps {
        offload: true,
        board: true,
        ..Caps::default()
    };
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps);
    assert!(ctx.render_board(None) > 0);
    win.push(SpanKind::Turn(1), "b".to_owned());
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps);
    assert_eq!(ctx.offload(0..2), None, "the board sits inside the range");
    assert_eq!(led.violations, vec!["offload range"]);
    assert_eq!(
        led.edit_tok, 0,
        "the engine render is not decoded by the agent"
    );
}

// ---- loop 2: the two-surface window, the placement family, the new arms ----

fn caps_all() -> Caps {
    Caps {
        offload: true,
        board: true,
        prefix: true,
        get: true,
        ..Caps::default()
    }
}

#[test]
fn prefix_hit_serves_the_unchanged_head_and_never_the_tail() {
    let mut win = Window::default();
    let (mut refs, mut led) = (RefStore::default(), Ledger::default());
    win.push(SpanKind::Turn(0), "a".repeat(400));
    let first = win.call();
    assert_eq!(
        (first.served, first.reprefill),
        (0, 0),
        "nothing cached yet"
    );

    // A pure append: the whole previous prompt is served.
    let before = win.total();
    win.push(SpanKind::Turn(1), "b".repeat(400));
    let append = win.call();
    assert_eq!(append.served, before);
    assert_eq!(append.reprefill, 0);

    // A tail render is never served, even when its bytes do not change.
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps_all());
    ctx.render_board(None);
    let log = win.total() - win.spans().last().unwrap().tok();
    win.call();
    win.push(SpanKind::Turn(2), "c".repeat(400));
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps_all());
    ctx.clear_tail();
    ctx.render_board(None);
    let tail_turn = win.call();
    assert_eq!(
        tail_turn.served, log,
        "served up to the old tail, not past it"
    );
    assert!(
        tail_turn.reprefill > 0,
        "the new turn and the tail re-prefill"
    );

    // A prefix block rewritten in place keeps only the bytes before the change.
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps_all());
    ctx.place_keyframe(super::window::Place::Prefix, 1, &[]);
    win.call();
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps_all());
    ctx.place_keyframe(super::window::Place::Prefix, 2, &[]);
    let rewritten = win.call();
    assert!(
        rewritten.served < 20,
        "the keyframe changed in its first line: {rewritten:?}"
    );
    assert!(rewritten.reprefill > 300, "everything after it re-prefills");
    assert!(win.ordered());
}

/// Runs a placement-family strategy turn by turn and records, per turn, the
/// prefix bytes and the epoch count.
fn canon_trace(layout: Layout, arm: Arm, seed: u64) -> (Vec<(String, u64)>, Window) {
    let ep = Episode::generate(arm, seed);
    let mut strategy = CanonPlacement::new(layout);
    let mut win = Window::default();
    let (mut refs, mut led) = (RefStore::default(), Ledger::default());
    let mut trace = Vec::new();
    for (n, turn) in ep.turns.iter().enumerate() {
        win.push(SpanKind::Turn(n as u32), turn.text.clone());
        let mut ctx = Ctx::new(
            &mut win,
            &mut refs,
            &mut led,
            strategy.caps(),
            DEFAULT_BUDGET,
            low_water(DEFAULT_BUDGET),
        )
        .with_env(&ep.env, n);
        if let Some(verb) = &turn.verb {
            strategy.on_verb(verb, &mut ctx);
        }
        strategy.on_turn(&mut ctx);
        assert!(win.ordered(), "{layout:?} turn {n}");
        let closed = trace
            .last()
            .is_some_and(|(_, e): &(String, u64)| *e != strategy.epochs());
        if closed && layout == Layout::Canon {
            // A close folds to the loop-1 low-water mark: only the board
            // and the keyframe's new rows ride above it.
            let tail = win
                .spans()
                .iter()
                .filter(|s| s.surface() == Surface::Tail)
                .map(|s| s.tok())
                .sum::<u64>();
            assert!(
                win.total() <= low_water(DEFAULT_BUDGET) + tail + 64,
                "{arm:?} turn {n}: {} after a close",
                win.total()
            );
        }
        win.call();
        let prefix: String = win
            .spans()
            .iter()
            .filter(|s| s.surface() == Surface::Prefix)
            .map(|s| s.text())
            .collect::<Vec<_>>()
            .join("\u{0}");
        trace.push((prefix, strategy.epochs()));
    }
    assert!(led.violations.is_empty(), "{:?}", led.violations);
    (trace, win)
}

#[test]
fn canon_keeps_the_prefix_byte_stable_within_an_epoch() {
    for arm in [Arm::Needle, Arm::Sketchpad, Arm::Relink] {
        let (trace, win) = canon_trace(Layout::Canon, arm, 8);
        let mut changes = 0;
        for pair in trace.windows(2) {
            if pair[0].0 != pair[1].0 {
                changes += 1;
                assert_ne!(
                    pair[0].1, pair[1].1,
                    "{arm:?}: the prefix moved inside an epoch"
                );
            }
        }
        assert!(changes >= 2, "{arm:?}: epochs closed {changes} times");
        let kinds = |s: Surface| -> Vec<SpanKind> {
            win.spans()
                .iter()
                .filter(|x| x.surface() == s)
                .map(|x| x.kind())
                .collect()
        };
        assert!(kinds(Surface::Prefix).contains(&SpanKind::Keyframe));
        assert_eq!(kinds(Surface::Tail), vec![SpanKind::Board], "{arm:?}");
    }
}

#[test]
fn the_controls_place_the_board_and_the_keyframe_where_named() {
    let (trace, win) = canon_trace(Layout::BoardInPrefix, Arm::Needle, 8);
    assert!(
        trace.windows(2).filter(|p| p[0].0 != p[1].0).count() > trace.len() / 2,
        "the prefix board rewrites the prefix nearly every turn"
    );
    assert!(win.spans().iter().all(|s| s.surface() != Surface::Tail));
    assert!(
        win.spans()
            .iter()
            .any(|s| s.surface() == Surface::Prefix && s.kind() == SpanKind::Board)
    );
    let (_, win) = canon_trace(Layout::KeyframeInTail, Arm::Needle, 8);
    let tail: Vec<SpanKind> = win
        .spans()
        .iter()
        .filter(|s| s.surface() == Surface::Tail)
        .map(|s| s.kind())
        .collect();
    assert_eq!(tail, vec![SpanKind::Keyframe, SpanKind::Board]);
}

#[test]
fn wrong_placement_costs_more_and_scores_the_same_on_every_arm() {
    for arm in ARMS {
        let ep = Episode::generate(arm, 9);
        let run = |layout| run_episode(&ep, &mut CanonPlacement::new(layout), DEFAULT_BUDGET);
        let (canon, prefix_board, tail_keyframe) = (
            run(Layout::Canon),
            run(Layout::BoardInPrefix),
            run(Layout::KeyframeInTail),
        );
        for r in [&canon, &prefix_board, &tail_keyframe] {
            assert!(r.violations.is_empty(), "{arm:?} {:?}", r.violations);
            assert_eq!(r.over_budget, 0, "{arm:?}");
            // Placement changes what is read only through the room a
            // prefix board takes when the read budget binds (a few
            // queries an episode on the budget-bound arms).
            assert!(
                (r.score.value - canon.score.value).abs() <= 0.05,
                "{arm:?}: {} vs {}",
                r.score.value,
                canon.score.value
            );
        }
        // The multiple shrinks as turns grow (canon's own folds dominate on
        // tool-loop's multi-thousand-token turns): 5x there, 24-67x on the
        // 100-token arms.
        assert!(
            prefix_board.reprefill_tok > 3 * canon.reprefill_tok,
            "{arm:?}: {} vs {}",
            prefix_board.reprefill_tok,
            canon.reprefill_tok
        );
        assert!(tail_keyframe.reprefill_tok > canon.reprefill_tok, "{arm:?}");
        // 0.80 on tool-loop, whose folds re-prefill multi-thousand-token
        // turns; 0.93-0.99 elsewhere.
        assert!(canon.hit_rate() > 0.75, "{arm:?} {}", canon.hit_rate());
        assert!(
            prefix_board.hit_rate() < canon.hit_rate() / 2.0,
            "{arm:?}: {} vs {}",
            prefix_board.hit_rate(),
            canon.hit_rate()
        );
        assert!(tail_keyframe.hit_rate() < canon.hit_rate(), "{arm:?}");
    }
}

#[test]
fn canon_never_deletes_and_meets_every_arm() {
    for arm in ARMS {
        let ep = Episode::generate(arm, 10);
        let r = run_episode(&ep, &mut CanonPlacement::new(Layout::Canon), DEFAULT_BUDGET);
        assert!(r.audit.departed > 0, "{arm:?}");
        assert_eq!(
            r.audit.exact, r.audit.departed,
            "{arm:?}: compaction never deletes"
        );
        assert!(!r.restore_fail);
        assert_eq!(r.read_over, 0, "{arm:?}: every read fits the window");
        assert!(cell_of(&r).valid(1), "{arm:?} {:?}", cell_of(&r).invalid(1));
        // Where the matching pages fit the window, every answer is exact;
        // log counts and multi-epoch aggregates need more pages than fit.
        let pages_fit = matches!(
            arm,
            Arm::Needle
                | Arm::Sketchpad
                | Arm::KvOffload
                | Arm::Relink
                | Arm::StreamFrames
                | Arm::KvInterleaved
        );
        if pages_fit {
            assert!((r.score.value - 1.0).abs() < 1e-9, "{arm:?} {:?}", r.score);
        } else {
            assert!(r.score.correct > 0, "{arm:?} {:?}", r.score);
        }
    }
}

#[test]
fn relink_needs_are_post_compaction_and_mixed() {
    for seed in [1, 20, 1001, 1020] {
        let ep = Episode::generate(Arm::Relink, seed);
        arms_epoch::check(&ep).unwrap();
        assert_eq!(ep.queries.len(), 36);
        assert!(ep.ask_at.iter().all(Option::is_some));
        let total: u64 = ep.turns.iter().map(|t| tokens(&t.text)).sum();
        assert!(total > 5 * GAP_TOK, "{total}");
    }
}

#[test]
fn relink_separates_dropping_stale_restores_and_relinking() {
    let ep = Episode::generate(Arm::Relink, 11);
    let truncate = run_episode(
        &ep,
        &mut Truncate::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert_eq!(truncate.score.correct, 0, "every need is post-compaction");
    let restore = run_episode(
        &ep,
        &mut RecoverableFold::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    let external = restore.extra.buckets.get(2).map_or(0, |b| b.1);
    assert!(external > 0);
    assert_eq!(
        restore.extra.stale, external,
        "a restore can only give back what the stream showed"
    );
    assert_eq!(restore.score.correct + external, restore.score.total);
    let canon = run_episode(&ep, &mut CanonPlacement::new(Layout::Canon), DEFAULT_BUDGET);
    assert_eq!(canon.extra.stale, 0);
    assert_eq!(canon.score.correct, canon.score.total);
    assert!(canon.fetch_tok > 0);
    assert!(canon.peak <= DEFAULT_BUDGET);
}

#[test]
fn a_window_that_keeps_everything_is_never_a_valid_cell_on_the_new_arms() {
    for arm in [Arm::Relink, Arm::MultiEpoch] {
        let ep = Episode::generate(arm, 12);
        let r = run_episode(
            &ep,
            &mut Truncate::new(Box::new(Rogue(Vec::new()))),
            DEFAULT_BUDGET,
        );
        assert!(r.over_budget > 0, "{arm:?}");
        let mut cell = super::Cell::default();
        cell.add(&r, 0.0);
        assert!(!cell.valid(1));
    }
}

#[test]
fn a_broken_reference_fails_the_new_arms() {
    for arm in [Arm::Relink, Arm::MultiEpoch] {
        let ep = Episode::generate(arm, 13);
        let r = run_episode_with(
            &ep,
            &mut CanonPlacement::new(Layout::Canon),
            DEFAULT_BUDGET,
            |refs| refs.corrupt(1),
        );
        assert!(r.restore_fail, "{arm:?}");
        assert_eq!(r.score.value, 0.0, "{arm:?}");
    }
}

#[test]
fn multi_epoch_forces_at_least_four_compactions_and_reports_each_epoch() {
    for seed in [1, 1001] {
        let ep = Episode::generate(Arm::MultiEpoch, seed);
        arms_epoch::check(&ep).unwrap();
        assert!(ep.ask_at.iter().any(Option::is_some), "mid-session queries");
        assert!(ep.ask_at.iter().any(Option::is_none), "end queries");
        let (trace, _) = canon_trace(Layout::Canon, Arm::MultiEpoch, seed);
        assert!(
            trace.last().unwrap().1 >= 4,
            "epochs {}",
            trace.last().unwrap().1
        );
        let r = run_episode(
            &ep,
            &mut Truncate::new(Box::new(OldestFirst)),
            DEFAULT_BUDGET,
        );
        assert_eq!(r.extra.buckets.len(), arms_epoch::SEGMENTS);
        let (first, last) = (
            r.extra.buckets[0],
            r.extra.buckets[arms_epoch::SEGMENTS - 1],
        );
        assert!(
            f64::from(first.0) / f64::from(first.1) < f64::from(last.0) / f64::from(last.1),
            "truncate forgets the oldest epoch first: {:?}",
            r.extra.buckets
        );
    }
}

#[test]
fn the_canon_board_carries_the_engine_changed_and_loaded_lines() {
    let mut read_set = oneiron::context_board::SessionReadSet::default();
    read_set.served(
        "file:src/a.rs",
        oneiron::context_board::ServedLifecycle::Active,
    );
    read_set.loaded_skill("skill:deploy", "v2");
    let rows = vec![
        board::ResRow {
            name: "file:src/a.rs".to_owned(),
            current: 3,
            served: 2,
            held: board::Held::Get,
        },
        board::ResRow {
            name: "skill:deploy".to_owned(),
            current: 2,
            served: 2,
            held: board::Held::Prefix,
        },
    ];
    let text = board::render_canon(&board::CanonBoard {
        epoch: 4,
        turn: 17,
        sketch: None,
        resources: &rows,
        read_set: &read_set,
    })
    .unwrap();
    assert!(
        text.starts_with("<memory surface=\"board\" epoch=\"4\""),
        "{text}"
    );
    assert!(text.contains("changed[1:]{id,to}:"), "{text}");
    assert!(text.contains("file:src/a.rs: superseded:v3"), "{text}");
    assert!(text.contains("loaded: skill:deploy@v2"), "{text}");
    assert!(text.contains("turn: 17"), "{text}");
    // No board row reads back as a resource body.
    let q = Query {
        text: "NEED file:src/a.rs".to_owned(),
        key: "file:src/a.rs@".to_owned(),
    };
    assert_eq!(read(Arm::Relink, &q, &[text.as_str()]), "");
}

#[test]
fn get_needs_its_capability_and_serves_the_current_version() {
    let ep = Episode::generate(Arm::Relink, 14);
    let name = ep.queries[0].key.trim_end_matches('@').to_owned();
    let at = ep.ask_at[0].unwrap();
    let mut win = Window::default();
    win.push(SpanKind::Turn(0), "x".to_owned());
    let (mut refs, mut led) = (RefStore::default(), Ledger::default());
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, Caps::default()).with_env(&ep.env, at);
    assert_eq!(ctx.get(&name), None);
    assert_eq!(led.violations, vec!["get"]);
    let mut led = Ledger::default();
    let mut ctx = ctx_with(&mut win, &mut refs, &mut led, caps_all()).with_env(&ep.env, at);
    let (version, _) = ctx.get(&name).unwrap();
    assert_eq!(Some(version), ep.env.current(&name, at));
    let chunks: Vec<&str> = win.spans().iter().map(super::window::Span::text).collect();
    assert_eq!(read(Arm::Relink, &ep.queries[0], &chunks), ep.expected[0]);
    assert!(led.fetch_tok > 0);
}

struct AppendAfterTail;

impl Strategy for AppendAfterTail {
    fn name(&self) -> &'static str {
        "append-after-tail"
    }

    fn caps(&self) -> Caps {
        Caps {
            board: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, _verb: &Verb, _ctx: &mut Ctx<'_>) {}

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        ctx.clear_board();
        ctx.render_board(None);
        ctx.append_note("after the tail".to_owned());
    }
}

#[test]
fn a_span_written_after_the_tail_breaks_the_surface_order() {
    let ep = Episode::generate(Arm::Needle, 15);
    let r = run_episode(&ep, &mut AppendAfterTail, DEFAULT_BUDGET);
    assert!(r.violations.contains(&"surface order"));
}

/// Dev-only tuning of the placement family's two knobs (forced epoch
/// cadence, prefix inventory budget). Prints; asserts nothing. Run with
/// `cargo test -p oneiron-bench sweep_canon_knobs -- --ignored --nocapture`.
#[test]
#[ignore = "dev tuning sweep, prints a table"]
fn sweep_canon_knobs_on_dev() {
    for arm in [Arm::Relink, Arm::MultiEpoch, Arm::Needle] {
        let eps: Vec<Episode> = DEV_SEEDS.map(|s| Episode::generate(arm, s)).collect();
        for every in [None, Some(50), Some(200)] {
            for inventory in [0, 1024, 2048, 4096, 8192] {
                if arm != Arm::Relink && inventory != 2048 {
                    continue;
                }
                let (mut score, mut rp, mut served, mut prompt, mut fetch, mut edit, mut over) =
                    (0.0, 0, 0, 0, 0, 0, 0);
                for ep in &eps {
                    let mut s = CanonPlacement::with(
                        Layout::Canon,
                        Box::new(OldestFirst),
                        every,
                        inventory,
                    );
                    let r = run_episode(ep, &mut s, DEFAULT_BUDGET);
                    score += r.score.value;
                    rp += r.reprefill_tok;
                    served += r.served_tok;
                    prompt += r.prompt_tok;
                    fetch += r.fetch_tok;
                    edit += r.edit_tok;
                    over += r.over_budget + r.violations.len() as u64;
                }
                let n = eps.len() as u64;
                println!(
                    "SWEEP {} every={every:?} inventory={inventory} score {:.3} rp {} hit {:.4} fetch {} edit {} invalid {over}",
                    arm.name(),
                    score / n as f64,
                    rp / n,
                    served as f64 / prompt as f64,
                    fetch / n,
                    edit / n
                );
            }
        }
    }
}

// ---- loop 2, the merged "build now" cases ----

fn cell_of(r: &super::EpisodeResult) -> super::Cell {
    let mut cell = super::Cell::default();
    cell.add(r, 0.0);
    cell
}

#[test]
fn evidence_mirrors_every_reader_and_the_oracle_is_fully_backed() {
    for arm in ARMS {
        for seed in [1, 1001] {
            let ep = Episode::generate(arm, seed);
            let base = super::audit::AuditBase::new(&ep);
            let mut checks = super::audit::Checks::new(&base);
            for (i, q) in ep.queries.iter().enumerate() {
                let end = ep.ask_at[i].map_or(ep.turns.len(), |t| t + 1);
                let mut chunks: Vec<String> =
                    ep.turns[..end].iter().map(|t| t.text.clone()).collect();
                if arm == Arm::Relink {
                    let name = q.key.trim_end_matches('@');
                    let v = ep.env.current(name, end - 1).unwrap();
                    chunks.push(ep.env.body(name, v).unwrap());
                }
                let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
                let answer = read(arm, q, &refs);
                assert!(
                    !super::audit::evidence(arm, q, &refs).is_empty()
                        || answer.is_empty()
                        || answer == "0",
                    "{arm:?} seed {seed} query {i}: an answer with no evidence"
                );
                checks.on_answer(arm, q, end - 1, &refs, &answer);
            }
            assert_eq!(checks.unbacked, 0, "{arm:?} seed {seed}");
        }
    }
}

#[test]
fn read_over_invalidates_a_cell_that_reads_past_the_budget() {
    let ep = Episode::generate(Arm::Needle, 16);
    let restore = run_episode(
        &ep,
        &mut RecoverableFold::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert!(restore.read_over > 0, "a page on top of a full window");
    assert!(restore.read_sum / restore.reads > DEFAULT_BUDGET);
    let cell = cell_of(&restore);
    assert!(cell.valid_loop1(1));
    assert_eq!(cell.invalid(1), vec!["read_over"]);
    let truncate = run_episode(
        &ep,
        &mut Truncate::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert_eq!(truncate.read_over, 0);
    assert!(cell_of(&truncate).valid(1));
}

/// A test-only cheat: writes every hidden atom it is handed as a note on
/// the first turn (a replay of the public seeds).
struct Replay(Vec<String>, bool);

impl Strategy for Replay {
    fn name(&self) -> &'static str {
        "replay"
    }

    fn caps(&self) -> Caps {
        Caps {
            drop: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, _verb: &Verb, _ctx: &mut Ctx<'_>) {}

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        if !self.1 {
            self.1 = true;
            ctx.append_note(self.0.join("\n"));
        }
        let note = |s: &super::window::Span| s.kind() == SpanKind::Note;
        if ctx.tokens() > ctx.budget() {
            let must = ctx.tokens() - ctx.low_water();
            let ranges = OldestFirst.choose(ctx.spans(), must, &note);
            for r in ranges.into_iter().rev() {
                ctx.drop_spans(r);
            }
        }
    }
}

use super::strategies::Policy as _;

#[test]
fn precog_catches_answers_written_before_they_arrive() {
    let ep = Episode::generate(Arm::Needle, 17);
    let atoms: Vec<String> = ep
        .queries
        .iter()
        .zip(&ep.expected)
        .map(|(q, want)| format!("{} {want}", q.key))
        .collect();
    let r = run_episode(&ep, &mut Replay(atoms, false), DEFAULT_BUDGET);
    assert!(
        (r.score.value - 1.0).abs() < 1e-9,
        "the replay answers everything"
    );
    assert!(r.precog > 0);
    assert!(cell_of(&r).invalid(1).contains(&"precog"));
}

#[test]
fn unbacked_catches_answers_resting_on_cut_lines() {
    let ep = Episode::generate(Arm::Needle, 3);
    let r = run_episode(
        &ep,
        &mut FifoFold::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert!(r.score.hallucinated > 0);
    assert!(
        r.unbacked >= u64::from(r.score.hallucinated),
        "{} {:?}",
        r.unbacked,
        r.score
    );
    assert!(cell_of(&r).invalid(1).contains(&"unbacked"));
}

/// A test-only cheat: keeps live exactly the spans that hold an asked
/// key's SET line, dropping everything else first.
struct KeepAsked(Vec<String>);

impl Strategy for KeepAsked {
    fn name(&self) -> &'static str {
        "keep-asked"
    }

    fn caps(&self) -> Caps {
        Caps {
            drop: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, _verb: &Verb, _ctx: &mut Ctx<'_>) {}

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        if ctx.tokens() <= ctx.budget() {
            return;
        }
        let keys = &self.0;
        let asked = |s: &super::window::Span| keys.iter().any(|k| s.text().contains(k.as_str()));
        let must = ctx.tokens() - ctx.low_water();
        let ranges = OldestFirst.choose(ctx.spans(), must, &asked);
        for r in ranges.into_iter().rev() {
            ctx.drop_spans(r);
        }
    }
}

#[test]
fn foreknow_catches_keeping_the_asked_keys_live() {
    let ep = Episode::generate(Arm::KvOffload, 18);
    let keys: Vec<String> = ep.queries.iter().map(|q| q.key.clone()).collect();
    let r = run_episode(&ep, &mut KeepAsked(keys), DEFAULT_BUDGET);
    assert!(r.foreknow.unwrap() > 0.5, "{:?}", r.foreknow);
    assert!(cell_of(&r).invalid(1).contains(&"foreknow"));
    let honest = run_episode(
        &ep,
        &mut Truncate::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert!(
        honest.foreknow.unwrap().abs() < 0.2,
        "{:?}",
        honest.foreknow
    );
}

#[test]
fn reprefill_attribution_sums_to_the_total_and_names_the_cause() {
    for arm in [Arm::Needle, Arm::Sketchpad, Arm::Relink] {
        let ep = Episode::generate(arm, 19);
        for name in STRATEGIES {
            let r = run_episode(&ep, build(name).unwrap().as_mut(), DEFAULT_BUDGET);
            assert_eq!(
                r.rp_tail + r.rp_fold + r.rp_patch + r.rp_fetch,
                r.reprefill_tok,
                "{arm:?} {name}"
            );
            match name {
                "truncate" | "fifo-fold" | "recoverable-fold" => {
                    assert_eq!(r.reprefill_tok, r.rp_fold, "{arm:?} {name}");
                    assert!(r.folds > 0);
                }
                "free-file" => assert_eq!(r.reprefill_tok, r.rp_patch, "{arm:?} {name}"),
                "engine-board" | "canon-placement" | "keyframe-in-tail" => {
                    assert!(r.rp_tail > 0 && r.rp_fold > 0, "{arm:?} {name}")
                }
                "board-in-prefix" => assert!(r.rp_tail > 10 * r.rp_fold, "{arm:?} {name}"),
                _ => {}
            }
        }
    }
}

#[test]
fn stale_and_overcount_are_named() {
    let kv = Episode::generate(Arm::KvOffload, 20);
    let mut answers = full_stream_answers(&kv);
    // A key set twice: answer with its first value.
    let i = (0..kv.queries.len())
        .find(|&i| {
            kv.turns
                .iter()
                .flat_map(|t| t.text.lines())
                .filter(|l| l.starts_with(kv.queries[i].key.as_str()))
                .count()
                > 1
        })
        .expect("a seed with an overwritten asked key");
    let first = kv
        .turns
        .iter()
        .flat_map(|t| t.text.lines())
        .find_map(|l| l.strip_prefix(kv.queries[i].key.as_str()))
        .and_then(|r| r.split_whitespace().next())
        .unwrap()
        .to_owned();
    answers[i] = first;
    assert_eq!(super::audit::diagnose(&kv, &answers), (1, 0));
    let logs = Episode::generate(Arm::LogTriage, 20);
    let mut answers = full_stream_answers(&logs);
    let c = logs
        .queries
        .iter()
        .position(|q| q.text.starts_with("COUNT "))
        .unwrap();
    answers[c] = (answers[c].parse::<u64>().unwrap() + 1).to_string();
    assert_eq!(super::audit::diagnose(&logs, &answers), (0, 1));
}

/// recoverable-fold, plus a wrong needle line written after the stream:
/// the restore alone answers right and the live line turns it wrong.
struct Overrider(RecoverableFold, usize, String);

impl Strategy for Overrider {
    fn name(&self) -> &'static str {
        "overrider"
    }

    fn caps(&self) -> Caps {
        self.0.caps()
    }

    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>) {
        self.0.on_verb(verb, ctx);
    }

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        self.0.on_turn(ctx);
        self.1 -= 1;
        if self.1 == 0 {
            ctx.append_note(self.2.clone());
        }
    }

    fn on_query(&mut self, query: &Query, ctx: &mut Ctx<'_>) -> Vec<u32> {
        self.0.on_query(query, ctx)
    }
}

#[test]
fn override_counts_a_live_line_that_turns_a_restored_answer_wrong() {
    let ep = Episode::generate(Arm::Needle, 21);
    let line = format!("{} not the needle", ep.queries[0].key);
    let r = run_episode(
        &ep,
        &mut Overrider(
            RecoverableFold::new(Box::new(OldestFirst)),
            ep.turns.len(),
            line,
        ),
        DEFAULT_BUDGET,
    );
    assert_eq!(r.overrides, 1);
    assert!(r.unbacked >= 1, "the live line never arrived");
}

#[test]
fn stream_frames_carry_stale_frames_the_reader_ignores() {
    let mut naive_wrong = 0;
    for seed in [1, 2, 3, 4, 5, 1001, 1002, 1003] {
        let ep = Episode::generate(Arm::StreamFrames, seed);
        let lines: Vec<&str> = ep.turns.iter().flat_map(|t| t.text.lines()).collect();
        assert_eq!(
            read(Arm::StreamFrames, &ep.queries[0], &lines),
            ep.expected[0]
        );
        // Arrival order, every frame applied: stale frames corrupt it.
        let mut naive = [0_u8; 81];
        for seen in super::arms_epoch::parse_frames(&lines) {
            match seen {
                super::arms_epoch::Seen::Key(_, grid, _) => naive = grid,
                super::arms_epoch::Seen::Delta(_, cell, digit, _) => naive[cell] = digit,
            }
        }
        let naive: String = naive.iter().map(|d| char::from(b'0' + d)).collect();
        naive_wrong += usize::from(naive != ep.expected[0]);
        if seed >= 1001 {
            let keys: Vec<u32> = super::arms_epoch::parse_frames(&lines)
                .iter()
                .filter_map(|s| match s {
                    super::arms_epoch::Seen::Key(e, _, _) => Some(*e),
                    super::arms_epoch::Seen::Delta(..) => None,
                })
                .collect();
            assert!(
                keys.windows(2).any(|w| w[1] < w[0]),
                "held-out seed {seed}: a stale keyframe arrives late"
            );
        }
    }
    assert!(
        naive_wrong >= 6,
        "stale frames bite arrival-order application: {naive_wrong}/8"
    );
    let ep = Episode::generate(Arm::StreamFrames, 22);
    let r = run_episode(
        &ep,
        &mut Truncate::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert!((r.score.value - 1.0).abs() < 1e-9);
    assert!(r.frames_live > 0, "superseded frames ride the window");
}

// ---- deliverable 4: STREAM against RESIDENT ----

use super::strategies::{Dials, Harness, StreamBoard};

fn stream(k: Option<u32>, f: Option<u64>, refresh: bool) -> StreamBoard {
    StreamBoard::new(
        "stream-test",
        Harness::Truncate,
        Dials {
            keyframe_every: k,
            fold_over: f,
            refresh,
        },
    )
}

#[test]
fn stream_frames_rebuild_the_current_board_while_they_are_in_the_window() {
    let ep = Episode::generate(Arm::Sketchpad, 23);
    // A window that never compacts: every frame stays, the board is right
    // on every call, and one frame rides each turn.
    let r = run_episode(&ep, &mut stream(None, None, false), 1 << 40);
    assert!(r.stream);
    assert_eq!(r.view_missing + r.view_stale, 0);
    assert_eq!(
        r.frames,
        ep.turns.len() as u64,
        "the turn clock moves every turn"
    );
    assert_eq!(r.keyframes, 1);
    assert!(
        r.board_live > 50 * r.board_add,
        "superseded frames stay live"
    );
}

#[test]
fn a_compaction_that_eats_the_keyframe_breaks_the_board_until_a_keyframe() {
    let ep = Episode::generate(Arm::Sketchpad, 24);
    let lost = run_episode(&ep, &mut stream(None, None, false), DEFAULT_BUDGET);
    assert!(
        lost.view_missing > 0,
        "the only keyframe was compacted away"
    );
    assert!(
        lost.recovery_max > 100,
        "nothing repairs it: {}",
        lost.recovery_max
    );
    let refreshed = run_episode(&ep, &mut stream(None, None, true), DEFAULT_BUDGET);
    assert!(refreshed.refreshes > 0);
    assert!(refreshed.breaks > 0);
    assert_eq!(
        refreshed.recovery_max, 1,
        "the refresh keyframe rides the next tool result"
    );
    let periodic = run_episode(&ep, &mut stream(Some(25), None, false), DEFAULT_BUDGET);
    assert_eq!(periodic.view_missing + periodic.view_stale, 0);
    assert_eq!(periodic.refreshes, 0);
}

#[test]
fn stream_frames_append_and_never_rewrite_the_prompt() {
    for arm in [Arm::Needle, Arm::Sketchpad, Arm::Relink] {
        let ep = Episode::generate(arm, 25);
        let r = run_episode(
            &ep,
            build("stream-truncate").unwrap().as_mut(),
            DEFAULT_BUDGET,
        );
        assert!(r.violations.is_empty(), "{arm:?} {:?}", r.violations);
        assert_eq!(r.rp_tail, 0, "{arm:?}: no tail is re-rendered");
        assert_eq!(r.reprefill_tok, r.rp_fold + r.rp_fetch, "{arm:?}");
        let canon = run_episode(&ep, &mut CanonPlacement::new(Layout::Canon), DEFAULT_BUDGET);
        assert!(
            canon.rp_tail > 0,
            "{arm:?}: the resident board re-renders every turn"
        );
        assert!(
            r.board_add < canon.board_add,
            "{arm:?}: a delta is smaller than a board"
        );
        assert!(
            r.board_live > canon.board_live,
            "{arm:?}: frames pile up until compaction"
        );
        assert_eq!(canon.view_missing + canon.view_stale, 0);
    }
}

// ---- the "build next" arms ----

#[test]
fn kv_interleaved_asks_mid_stream_for_old_keys_and_reloads_what_it_restores() {
    for seed in [1, 1001] {
        let ep = Episode::generate(Arm::KvInterleaved, seed);
        let mid: Vec<usize> = ep.ask_at.iter().flatten().copied().collect();
        assert_eq!(mid.len(), 22, "seed {seed}");
        for (i, q) in ep.queries.iter().enumerate() {
            let Some(t) = ep.ask_at[i] else { continue };
            if ep.expected[i].is_empty() {
                continue;
            }
            let last = ep.turns[..=t]
                .iter()
                .rposition(|turn| turn.text.contains(q.key.as_str()))
                .unwrap();
            assert!(
                last + super::arms_next::KVI_AGE <= t,
                "seed {seed} query {i}"
            );
        }
        if seed >= 1001 {
            assert!(
                mid.windows(5).any(|w| w[4] - w[0] == 4),
                "held-out asks in bursts"
            );
        }
    }
    let ep = Episode::generate(Arm::KvInterleaved, 26);
    let canon = run_episode(&ep, &mut CanonPlacement::new(Layout::Canon), DEFAULT_BUDGET);
    assert!(
        canon.reload_tok > 0,
        "pages read inside the window land in the log"
    );
    assert!(canon.refold_tok > 0, "and leave it again");
    let restore = run_episode(
        &ep,
        &mut RecoverableFold::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert!(restore.read_over > 0);
    assert_eq!(
        restore.reload_tok, 0,
        "a read past the budget lands nothing"
    );
    let truncate = run_episode(
        &ep,
        &mut Truncate::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    assert_eq!(truncate.reload_tok, 0);
}

#[test]
fn pending_obligations_keep_the_earliest_open_and_close_only_on_the_exact_token() {
    for seed in [1, 1001] {
        let ep = Episode::generate(Arm::Obligations, seed);
        let end = ep.ask_at.iter().position(Option::is_none).unwrap();
        let pending: Vec<&str> = ep.expected[end].split(',').collect();
        assert_eq!(pending.len(), 16, "seed {seed}");
        let first_open: Vec<String> = ep.turns[..12]
            .iter()
            .map(|t| {
                t.text
                    .lines()
                    .find_map(|l| l.strip_prefix("OPEN "))
                    .and_then(|r| r.split_whitespace().next())
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert!(
            first_open.iter().all(|id| pending.contains(&id.as_str())),
            "seed {seed}"
        );
        // Noise names near-miss ids and closes real ids with wrong tokens.
        let all: String = ep
            .turns
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("basically done"));
        assert_eq!(ep.queries.iter().filter(|q| q.text == "PENDING").count(), 2);
    }
    let ep = Episode::generate(Arm::Obligations, 27);
    let truncate = run_episode(
        &ep,
        &mut Truncate::new(Box::new(OldestFirst)),
        DEFAULT_BUDGET,
    );
    let end = ep.ask_at.iter().position(Option::is_none).unwrap();
    assert!(truncate.score.correct < truncate.score.total);
    let _ = end;
}

#[test]
fn late_tool_results_join_by_call_and_accepted_attempt() {
    for seed in [1, 1001] {
        let ep = Episode::generate(Arm::LateResults, seed);
        assert_eq!(ep.turns.len(), 200, "seed {seed}");
        let lines: Vec<&str> = ep.turns.iter().flat_map(|t| t.text.lines()).collect();
        let field = |l: &str, f: &str| {
            l.split_whitespace()
                .find_map(|t| t.strip_prefix(f).and_then(|v| v.strip_prefix('=')))
                .map(str::to_owned)
        };
        let (mut first, mut retry, mut late, mut last_wrong) = (0, 0, 0, 0);
        for q in ep.queries.iter().filter(|_| true) {
            let call = q.text.strip_prefix("CALL ").unwrap();
            let accept = lines
                .iter()
                .position(|l| l.starts_with("ACCEPT ") && field(l, "call").as_deref() == Some(call))
                .unwrap();
            let attempt = field(lines[accept], "attempt").unwrap();
            if attempt == "a1" {
                first += 1
            } else {
                retry += 1
            }
            let responses: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| {
                    l.starts_with("RESPONSE ") && field(l, "call").as_deref() == Some(call)
                })
                .map(|(i, _)| i)
                .collect();
            late += usize::from(responses.iter().any(|&i| {
                i > accept && field(lines[i], "attempt").as_deref() != Some(attempt.as_str())
            }));
            let last = *responses.last().unwrap();
            last_wrong +=
                usize::from(field(lines[last], "attempt").as_deref() != Some(attempt.as_str()));
        }
        assert!(first > 0 && retry > 0, "seed {seed}: both acceptances");
        assert!(
            late > 0,
            "seed {seed}: a rejected result lands after its ACCEPT"
        );
        assert!(
            last_wrong > 0,
            "seed {seed}: the last response is not always the accepted one"
        );
        assert_eq!(ep.ask_at.iter().filter(|a| a.is_none()).count(), 40);
        assert_eq!(ep.ask_at.iter().filter(|a| a.is_some()).count(), 25);
    }
}

#[test]
fn commit_or_rollback_publishes_only_committed_writes() {
    for seed in [1, 1001] {
        let ep = Episode::generate(Arm::Transactions, seed);
        assert_eq!(ep.turns.len(), 145, "seed {seed}");
        let text: Vec<&str> = ep.turns.iter().flat_map(|t| t.text.lines()).collect();
        assert_eq!(text.iter().filter(|l| l.starts_with("COMMIT ")).count(), 12);
        assert_eq!(text.iter().filter(|l| l.starts_with("ABORT ")).count(), 12);
        // Transactions overlap: one BEGINs before another terminates.
        let mut open = 0_i32;
        let mut max_open = 0;
        for l in &text {
            if l.starts_with("BEGIN ") {
                open += 1;
                max_open = max_open.max(open);
            } else if l.starts_with("COMMIT ") || l.starts_with("ABORT ") {
                open -= 1;
            }
        }
        assert!(max_open >= 2, "seed {seed}");
        // An eager latest-write view disagrees with the committed state.
        let end: Vec<usize> = (0..ep.queries.len())
            .filter(|&i| ep.ask_at[i].is_none() && ep.queries[i].text.starts_with("VALUE "))
            .collect();
        let eager_wrong = end
            .iter()
            .filter(|&&i| {
                let f = ep.queries[i].text.strip_prefix("VALUE ").unwrap();
                let latest = text
                    .iter()
                    .filter_map(|l| l.strip_prefix("WRITE "))
                    .filter_map(|r| r.split_once(' '))
                    .filter_map(|(_, r)| r.split_once(" = "))
                    .filter(|(file, _)| *file == f)
                    .map(|(_, v)| v)
                    .last();
                latest.is_some_and(|v| v != ep.expected[i])
            })
            .count();
        assert!(eager_wrong > 0, "seed {seed}");
        assert_eq!(ep.queries.len(), 7 * 17);
    }
}

#[test]
fn tool_loop_edits_signatures_and_reruns_tests() {
    for seed in [1, 1001] {
        let ep = Episode::generate(Arm::ToolLoop, seed);
        assert_eq!(ep.turns.len(), 400, "seed {seed}");
        let total: u64 = ep.turns.iter().map(|t| tokens(&t.text)).sum();
        assert!(total > 600_000, "seed {seed}: {total} tokens");
        let sigs: Vec<usize> = (0..ep.queries.len())
            .filter(|&i| ep.queries[i].text.starts_with("SIG "))
            .collect();
        assert_eq!(sigs.len(), 12);
        // Eight asked functions were edited: their first READ signature
        // is not the current one.
        let edited = sigs
            .iter()
            .filter(|&&i| {
                let head = ep.queries[i].key.as_str();
                ep.turns
                    .iter()
                    .flat_map(|t| t.text.lines())
                    .find(|l| l.starts_with(head))
                    .is_some_and(|first| first != ep.expected[i])
            })
            .count();
        assert!(edited >= 4, "seed {seed}: {edited}");
        assert!(ep.queries.iter().any(|q| q.text == "FINALFAILS"));
        assert!(
            ep.queries
                .iter()
                .filter(|q| q.text.starts_with("FAILMSG "))
                .count()
                >= 4
        );
    }
}
