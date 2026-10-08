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
    // Counted in characters, a terminator per line. `bravo` -> `BRAVO`
    // shares no letter, so its line is charged whole: 6 out, 6 in, plus the
    // 5 of `echo`; `alpha`, `charlie` and `delta` survive (6 + 8 + 6).
    assert_eq!(
        diff.ops,
        OpsSummary {
            ins: 11,
            del: 6,
            kept: 20,
            moved: 0,
            approx: false,
        }
    );
    // 17 / (26 + 31).
    assert!((diff.d_norm - 17.0 / 57.0).abs() < 1e-6, "{}", diff.d_norm);
}

/// A repeated run must not let the head and tail trim claim the same line
/// twice, which would report more survivors than there are lines.
#[test]
fn a_repeated_run_does_not_double_count_its_survivors() {
    let diff = myers_line_diff("aaa\naaa\naaa", "aaa\naaa\naaa\naaa\naaa");
    assert_eq!(
        diff.ops,
        OpsSummary {
            ins: 8,
            del: 0,
            kept: 12,
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
    // Equal-length lines, so the price does not depend on which pair the
    // script keeps.
    let relocated = myers_line_diff("one\ntwo\nsix\nten", "six\nten\none\ntwo");
    let replaced = myers_line_diff("one\ntwo\nsix\nten", "six\nten\nfox\nbee");

    assert_eq!(
        relocated.ops,
        OpsSummary {
            ins: 0,
            del: 0,
            kept: 8,
            moved: 8,
            approx: false,
        },
        "a paired line leaves ins/del entirely"
    );
    assert_eq!(
        replaced.ops,
        OpsSummary {
            ins: 8,
            del: 8,
            kept: 8,
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
    // The longer anchor forces the repeated lines into the unmatched regions.
    let before = "repeat\nrepeat\nrepeat\nanchor-a\nanchor-b\nanchor-c\nanchor-d\n";
    let after = "anchor-a\nanchor-b\nanchor-c\nanchor-d\nrepeat\nrepeat\n";
    // `repeat` weighs 7 with its terminator, an anchor 9: two pairs move
    // (14), one `repeat` is deleted (7), over 57 + 50 characters.
    let expected_score = (7.0 + 2.0 * 14.0 * MOVE_DISCOUNT) / 107.0;

    let forward = myers_line_diff(before, after);
    assert_eq!(forward.ops.moved, 14);
    assert_eq!(forward.ops.del, 7);
    assert_eq!(forward.ops.ins, 0);
    assert!((forward.d_norm - expected_score).abs() < 1e-6);

    let reverse = myers_line_diff(after, before);
    assert_eq!(reverse.ops.moved, 14);
    assert_eq!(reverse.ops.del, 0);
    assert_eq!(reverse.ops.ins, 7);
    assert!((reverse.d_norm - expected_score).abs() < 1e-6);
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
    assert_eq!(
        (shuffled.ops.ins, shuffled.ops.del),
        (0, 0),
        "every line pairs"
    );
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
            ins: 8,
            del: 0,
            kept: 58_890,
            moved: 0,
            approx: false,
        },
        "the character pass charges `-amended`, not the line"
    );
}

/// The accounting reference: characters of the normalized lines, a
/// terminator each, blank lines dropped.
fn normalized_len(text: &str) -> u32 {
    text.lines()
        .map(collapse_whitespace)
        .filter(|line| !line.is_empty())
        .map(|line| u32_saturating(line.chars().count() + 1))
        .sum()
}

// ─── invariants across every shape ──────────────────────────────────────

/// Three properties that must hold whatever the input: the score is a
/// fraction, every character is accounted for exactly once on each side, and the
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
            normalized_len(before),
            ops.del + ops.moved + ops.kept,
            "{before:?} -> {after:?} loses characters on the before side"
        );
        assert_eq!(
            normalized_len(after),
            ops.ins + ops.moved + ops.kept,
            "{before:?} -> {after:?} loses characters on the after side"
        );
        assert_eq!(
            diff.d_norm, reversed.d_norm,
            "{before:?} -> {after:?} is not symmetric"
        );
    }
}
