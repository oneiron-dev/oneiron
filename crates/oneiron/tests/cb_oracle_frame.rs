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
            BoardBlockHeader, BoardSection, TaskBoardStatus, TaskIntentPresence,
            render_board_block, render_tasks_section,
        };

        let running_task = TaskIntentPresence {
            id: "tk_a".to_owned(),
            status: TaskBoardStatus::Running,
            label: None,
            acked: false,
            realizing_jobs: Vec::new(),
        };
        let tasks = render_tasks_section(&[running_task], &[]);
        let sections = [
            BoardSection {
                name: "WORLDS".to_owned(),
                rows: vec!["wd_1 active".to_owned()],
            },
            BoardSection {
                name: "MEMORIES".to_owned(),
                rows: vec!["cl_1 pinned".to_owned()],
            },
            BoardSection {
                name: "TASKS".to_owned(),
                rows: tasks.rows.iter().map(|row| row.line.clone()).collect(),
            },
        ];
        let header = BoardBlockHeader {
            epoch: 47,
            scope: "WorldSet(wd_1)".to_owned(),
        };
        BoardBlockRender {
            text: render_board_block(&header, &sections),
        }
    }

    /// ONE-1694 · 08b §0/§1 (r1) · CB-01 contract: the board render tag is
    /// `[CONTEXT_BOARD …]`, never `[MEMORY_BOARD …]`. Token-boundary exact:
    /// a tag like `[CONTEXT_BOARD_EVIL …]` must NOT satisfy this test, and
    /// the check must fail closed on malformed renders (no slice panics).
    #[test]
    fn board_block_opens_with_context_board_render_tag() {
        let render = arm_render_board_block();
        let first_line = render.text.lines().next().expect("block has a first line");
        assert!(
            first_line
                .strip_prefix("[CONTEXT_BOARD ")
                .and_then(|rest| rest.strip_suffix(']'))
                .is_some(),
            "opening tag must be a complete [CONTEXT_BOARD …] line"
        );
        assert_eq!(render.text.matches("[CONTEXT_BOARD ").count(), 1);
        assert_eq!(render.text.matches("[/CONTEXT_BOARD]").count(), 1);
        assert_eq!(render.text.matches("MEMORY_BOARD").count(), 0);
    }
}
