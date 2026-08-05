//! Context Board forward test oracle — epic ONE-1692, opened by ONE-1693 (CB-01).
//!
//! Contract-level red tests for all four Context Board clusters, derived from
//! the ticket acceptance criteria (ONE-1694..ONE-1711) and the ratified design
//! `oneiron-v1/design/out/08b-Context-Board-extension.md` (16/16, 2026-07-15),
//! which extends `08-Memory-Board-design.md` (the board surface is renamed
//! Context Board; the Eiri v4 activated-memories tier keeps its names).
//!
//! Shape of every test:
//! * `#[ignore = "armed by ONE-XXXX"]` — dormant until its ticket lands.
//! * An `arm_*` seam function whose body is `unimplemented!()`. Its doc
//!   comment is the fixture spec. The ARMING ticket replaces the seam body
//!   (and may freely adapt the seam signature or move the test to the owning
//!   crate), then removes the `#[ignore]`.
//! * Asserts are the contract: exact counts and equalities, never `any()`.
//!   Arming NEVER weakens, loosens, or removes an assert.
//!
//! Observation structs are contract shapes, not API proposals — every field
//! is asserted by at least one test.

// Contract shapes are constructed only once their arming ticket lands.
#![allow(dead_code)]

// ════════════════════════════════════════════════════════════════════════
// CB-T — frame/board-block render (ONE-1694 renderer)
// ════════════════════════════════════════════════════════════════════════
mod cb_t {
    /// The whole engine-rendered Context Board block as one string.
    struct BoardBlockRender {
        text: String,
    }

    /// ONE-1694 fixture: any non-empty board (1 world, 1 pinned memory,
    /// 1 running task) rendered in RESIDENT mode. Returns the full block.
    fn arm_render_board_block() -> BoardBlockRender {
        use oneiron::context_board::{
            BoardBlockHeader, BoardBudgetRequest, BoardFrame, BoardLegend, BoardSection,
            SectionPolicy, TaskBoardStatus, TaskIntentPresence, render_board_block,
            render_tasks_section,
        };

        let running_task = TaskIntentPresence {
            id: "tk_a".to_owned(),
            status: TaskBoardStatus::Running,
            label: None,
            acked: false,
            realizing_jobs: Vec::new(),
        };
        let tasks = render_tasks_section(&[running_task], &[]);
        let pinned = SectionPolicy {
            pinned: true,
            shed_rank: None,
        };
        let sections = [
            BoardSection::new(
                "WORLDS",
                vec!["wd_1 active".to_owned()],
                Vec::new(),
                Vec::new(),
                pinned,
            )
            .expect("WORLDS fixture is a valid pinned section"),
            BoardSection::new(
                "MEMORIES",
                vec!["cl_1 pinned".to_owned()],
                Vec::new(),
                Vec::new(),
                pinned,
            )
            .expect("MEMORIES fixture is a valid pinned section"),
            BoardSection::new(
                "TASKS",
                tasks.rows.iter().map(|row| row.line.clone()).collect(),
                Vec::new(),
                Vec::new(),
                pinned,
            )
            .expect("TASKS fixture is a valid pinned section"),
        ];
        let header = BoardBlockHeader {
            epoch: 47,
            scope: "WorldSet(wd_1)".to_owned(),
        };
        let legend = BoardLegend::canonical();
        let frame = BoardFrame {
            header: &header,
            legend: &legend,
            sections: &sections,
        };
        BoardBlockRender {
            text: render_board_block(
                &frame,
                BoardBudgetRequest {
                    harness_default_tok: 1200,
                    caller_limit_tok: None,
                    explicit_override_tok: None,
                },
            )
            .expect("fixture frame renders")
            .text,
        }
    }

    /// ONE-1797 · ARCH-0067 §8 contract: the board render wrapper is the
    /// canonical `<memory surface="board" …>` XML fence, never the dead
    /// `[CONTEXT_BOARD …]` bracket wrapper and never `[MEMORY_BOARD …]`.
    /// Attribute order is part of the golden output: `surface`, `epoch`,
    /// `scope`, `budget_tok`. Token-boundary exact: a tag like
    /// `<memory surface="board_evil" …>` must NOT satisfy this test, and the
    /// check must fail closed on malformed renders (no slice panics).
    ///
    /// The function name predates the wrapper rename and is kept for
    /// continuity per ONE-1797; its contract is the one above.
    #[test]
    fn board_block_opens_with_context_board_render_tag() {
        let render = arm_render_board_block();
        let first_line = render.text.lines().next().expect("block has a first line");
        assert!(
            first_line
                .strip_prefix("<memory ")
                .and_then(|rest| rest.strip_suffix('>'))
                .is_some(),
            "opening tag must be a complete <memory …> line"
        );
        assert_eq!(
            first_line,
            "<memory surface=\"board\" epoch=\"47\" scope=\"WorldSet(wd_1)\" budget_tok=\"1200\">"
        );
        assert_eq!(render.text.matches("<memory surface=\"board\" ").count(), 1);
        assert_eq!(render.text.matches("</memory>").count(), 1);
        assert_eq!(render.text.matches("surface=\"board_evil\"").count(), 0);
        assert_eq!(render.text.matches("MEMORY_BOARD").count(), 0);
        assert_eq!(render.text.matches("[CONTEXT_BOARD").count(), 0);
        assert_eq!(render.text.matches("[/CONTEXT_BOARD]").count(), 0);
    }
}
