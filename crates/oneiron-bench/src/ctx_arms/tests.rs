use super::arms::{ARMS, Arm, Episode, Query, read};
use super::arms::{Verb, snapshot_lines};
use super::board;
use super::strategies::{
    EngineBoard, FifoFold, FreeFile, OldestFirst, RecoverableFold, STRATEGIES, Sketch, Strategy,
    Truncate, build, lossy_summary, shape,
};
use super::window::{Caps, Ctx, Ledger, RefStore, SpanKind, Window, tokens};
use super::{DEFAULT_BUDGET, DEV_SEEDS, HELDOUT_SEEDS, low_water, run_episode, run_episode_with};

fn full_stream_answers(ep: &Episode) -> Vec<String> {
    let full: Vec<&str> = ep.turns.iter().map(|t| t.text.as_str()).collect();
    ep.queries.iter().map(|q| read(ep.arm, q, &full)).collect()
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
            let score = ep.score(&full_stream_answers(&ep));
            assert_eq!(score.correct, score.total, "{arm:?} seed {seed}");
            assert_eq!(score.hallucinated, 0);
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
    for arm in ARMS {
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
    for arm in ARMS {
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
