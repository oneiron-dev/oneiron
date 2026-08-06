use super::*;

// ─── fixtures ───────────────────────────────────────────────────────────

/// A block of `count` distinct lines, each stamped with `tag` so two blocks
/// with different tags share not one line.
fn wall(tag: char, count: usize) -> String {
    (0..count)
        .map(|line| format!("{tag}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The pairs every invariant below is checked against — one of each shape the
/// lane can meet.
fn shapes() -> Vec<(&'static str, &'static str)> {
    vec![
        ("", ""),
        ("", "alpha\nbravo"),
        ("alpha", "alpha"),
        ("alpha", "bravo"),
        ("alpha\ncharlie", "alpha\nbravo\ncharlie"),
        (
            "alpha\nbravo\ncharlie\ndelta",
            "alpha\nBRAVO\ncharlie\ndelta\necho",
        ),
        ("one\ntwo\nthree\nfour", "three\nfour\none\ntwo"),
        ("aaa\naaa\naaa", "aaa\naaa\naaa\naaa\naaa"),
    ]
}

// ─── the scale's two ends ───────────────────────────────────────────────

/// Identity is the zero of the scale, and every line is a survivor. Nothing
/// here is a special case in the code — it falls out of the affix trim.
#[test]
fn an_untouched_text_scores_zero() {
    let text = "alpha\nbravo\ncharlie";
    let diff = myers_line_diff(text, text);

    assert_eq!(diff.d_norm, 0.0);
    assert_eq!(
        diff.ops,
        OpsSummary {
            ins: 0,
            del: 0,
            kept: 3,
            moved: 0,
            approx: false,
        }
    );
}

/// The other end, and the fixture that pins the SUM denominator: one line
/// rewritten is `del = 1` AND `ins = 1`, so mass 2 over a window of `1 + 1`
/// scores exactly 1. A max denominator would score the same edit 2.
#[test]
fn a_wholly_rewritten_text_scores_exactly_one() {
    assert_eq!(myers_line_diff("alpha", "bravo").d_norm, 1.0);
    assert_eq!(
        myers_line_diff("alpha\nbravo", "charlie\ndelta").d_norm,
        1.0
    );
    // Appearing from nothing is a full replacement too — there is no
    // survivor to weigh against.
    assert_eq!(myers_line_diff("", "alpha\nbravo").d_norm, 1.0);
}

/// Two empty texts divide nothing by nothing: `0.0`, not a NaN that would
/// later refuse to serialize into a Δ.
#[test]
fn an_empty_window_is_zero_not_a_division() {
    let diff = myers_line_diff("", "");
    assert_eq!(diff.d_norm, 0.0);
    assert_eq!(diff.ops, OpsSummary::default());
}

// ─── the script itself ──────────────────────────────────────────────────

/// A known script, counted exactly: `bravo` left, `BRAVO` and `echo`
/// arrived, three lines never moved. The shared head is trimmed rather than
/// diffed, which is why `kept` includes it.
#[test]
fn a_known_edit_script_counts_arrivals_departures_and_survivors() {
    let diff = myers_line_diff(
        "alpha\nbravo\ncharlie\ndelta",
        "alpha\nBRAVO\ncharlie\ndelta\necho",
    );
    assert_eq!(
        diff.ops,
        OpsSummary {
            ins: 2,
            del: 1,
            kept: 3,
            moved: 0,
            approx: false,
        }
    );
    // 3 / (4 + 5).
    assert!((diff.d_norm - 1.0 / 3.0).abs() < 1e-6, "{}", diff.d_norm);
}

/// A pure insertion and the pure deletion that undoes it are the same amount
/// of change — the property the sum denominator exists to give.
#[test]
fn an_insertion_and_its_undo_weigh_the_same() {
    let inserted = myers_line_diff("alpha\ncharlie", "alpha\nbravo\ncharlie");
    let deleted = myers_line_diff("alpha\nbravo\ncharlie", "alpha\ncharlie");

    assert_eq!(inserted.ops.ins, 1);
    assert_eq!(inserted.ops.del, 0);
    assert_eq!(deleted.ops.del, 1);
    assert_eq!(deleted.ops.ins, 0);
    assert_eq!(inserted.d_norm, deleted.d_norm);
}

/// A repeated run must not let the head and tail trim claim the same line
/// twice, which would report more survivors than there are lines.
#[test]
fn a_repeated_run_does_not_double_count_its_survivors() {
    let diff = myers_line_diff("aaa\naaa\naaa", "aaa\naaa\naaa\naaa\naaa");
    assert_eq!(
        diff.ops,
        OpsSummary {
            ins: 2,
            del: 0,
            kept: 3,
            moved: 0,
            approx: false,
        }
    );
}

/// The line model, pinned because silent equality is the kind of thing a
/// reader should not have to discover: this lane measures what a decider
/// changed, and terminating a file differently is not that.
#[test]
fn a_trailing_newline_is_not_an_edit() {
    assert_eq!(
        myers_line_diff("alpha\nbravo", "alpha\nbravo\n").d_norm,
        0.0
    );
}

// ─── pass 2 — moves ─────────────────────────────────────────────────────

/// A relocated block is ONE relocation, charged `MOVE_DISCOUNT` of what the
/// same block costs when it is genuinely replaced. Both halves are measured
/// here, because the discount only means something against the price it
/// replaces.
#[test]
fn a_relocated_block_costs_the_discount_of_a_replaced_one() {
    let relocated = myers_line_diff("one\ntwo\nthree\nfour", "three\nfour\none\ntwo");
    let replaced = myers_line_diff("one\ntwo\nthree\nfour", "three\nfour\nfive\nsix");

    assert_eq!(
        relocated.ops,
        OpsSummary {
            ins: 0,
            del: 0,
            kept: 2,
            moved: 2,
            approx: false,
        },
        "a paired line leaves ins/del entirely"
    );
    assert_eq!(
        replaced.ops,
        OpsSummary {
            ins: 2,
            del: 2,
            kept: 2,
            moved: 0,
            approx: false,
        }
    );
    assert!(
        (relocated.d_norm - MOVE_DISCOUNT * replaced.d_norm).abs() < 1e-6,
        "{} is not {MOVE_DISCOUNT}x {}",
        relocated.d_norm,
        replaced.d_norm
    );
}

/// Pairing is by multiplicity, not presence: the surplus deletion stays a
/// deletion, so the discount can never be claimed for content that did not
/// actually survive.
#[test]
fn move_pairing_respects_multiplicity() {
    assert_eq!(pair_moves(&[7, 7, 7], &[7, 7]), 2);
    assert_eq!(pair_moves(&[7, 7], &[7, 7, 7]), 2);
    assert_eq!(pair_moves(&[1, 2], &[3, 4]), 0);
    assert_eq!(pair_moves(&[], &[1]), 0);
}

// ─── the cap ────────────────────────────────────────────────────────────

/// Past the cap the counts are a BOUND and the diff says so. It still
/// returns, still lands in `[0, 1]`, and still pairs moves — the flag is the
/// only thing that changes.
#[test]
fn a_script_past_the_cap_returns_marked_approximate() {
    let before = wall('a', MAX_EDIT_SCRIPT);
    let after = wall('b', MAX_EDIT_SCRIPT);
    let diff = myers_line_diff(&before, &after);

    assert!(diff.approximate());
    assert!(diff.ops.approx, "the flag rides the Δ, not just the diff");
    assert_eq!(
        diff.d_norm, 1.0,
        "nothing survived, so nothing is discounted"
    );

    // The same walls, merely reordered, are still recognized as survivors:
    // the fallback charges a replacement, and pass 2 takes it back.
    let shuffled = myers_line_diff(&before, &wall_reversed(&before));
    assert!(shuffled.approximate());
    assert_eq!(shuffled.ops.moved, u32_saturating(MAX_EDIT_SCRIPT));
    assert!(shuffled.d_norm < 0.2, "{}", shuffled.d_norm);
}

fn wall_reversed(text: &str) -> String {
    text.lines().rev().collect::<Vec<_>>().join("\n")
}

/// A one-line edit inside a 10k-line artifact is exact and cheap — the affix
/// trim leaves Myers two lines to think about, which is what keeps the cap
/// from firing on size alone.
#[test]
fn a_small_edit_in_a_large_artifact_stays_exact() {
    let before = wall('a', 10_000);
    let after = before.replacen("a5000\n", "a5000-amended\n", 1);
    assert_ne!(before, after, "the fixture must actually edit something");

    let diff = myers_line_diff(&before, &after);
    assert_eq!(
        diff.ops,
        OpsSummary {
            ins: 1,
            del: 1,
            kept: 9_999,
            moved: 0,
            approx: false,
        }
    );
}

// ─── invariants across every shape ──────────────────────────────────────

/// Three properties that must hold whatever the input: the score is a
/// fraction, every line is accounted for exactly once on each side, and the
/// measurement does not depend on which text was called `before`.
#[test]
fn every_shape_is_bounded_accounted_for_and_symmetric() {
    for (before, after) in shapes() {
        let diff = myers_line_diff(before, after);
        let reversed = myers_line_diff(after, before);
        let ops = diff.ops;

        assert!(
            (0.0..=1.0).contains(&diff.d_norm),
            "{before:?} -> {after:?} scored {}",
            diff.d_norm
        );
        assert_eq!(
            u32_saturating(before.lines().count()),
            ops.del + ops.moved + ops.kept,
            "{before:?} -> {after:?} loses lines on the before side"
        );
        assert_eq!(
            u32_saturating(after.lines().count()),
            ops.ins + ops.moved + ops.kept,
            "{before:?} -> {after:?} loses lines on the after side"
        );
        assert_eq!(
            diff.d_norm, reversed.d_norm,
            "{before:?} -> {after:?} is not symmetric"
        );
    }
}
