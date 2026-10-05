use super::arms::{ARMS, Arm, Episode, Query, read};
use super::strategies::{FifoFold, OldestFirst, RecoverableFold, Truncate, lossy_summary};
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
    let mut ctx = Ctx {
        win: &mut win,
        refs: &mut refs,
        led: &mut led,
        caps: Caps {
            drop: true,
            ..Caps::default()
        },
        budget: 1000,
        low_water: 750,
    };
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
    let mut ctx = Ctx {
        win: &mut win,
        refs: &mut refs,
        led: &mut led,
        caps: Caps {
            drop: true,
            ..Caps::default()
        },
        budget: 1000,
        low_water: 750,
    };
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
    let mut ctx = Ctx {
        win: &mut win,
        refs: &mut refs,
        led: &mut led,
        caps: Caps {
            offload: true,
            ..Caps::default()
        },
        budget: 1000,
        low_water: 750,
    };
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
