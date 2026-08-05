//! Board frame — the block envelope over already-rendered section rows.

use super::one_line_token;

/// Header tokens of the block envelope (08b §0 shape:
/// `[CONTEXT_BOARD epoch=47 scope=WorldSet(...)]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardBlockHeader {
    pub epoch: u64,
    pub scope: String,
}

/// One assembled block section: a name token over one-line rows. TASKS and
/// AGENTS rows come from their typed section renders; other sections pass
/// whatever one-line rows their renderers produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardSection {
    pub name: String,
    pub rows: Vec<String>,
}

/// Assembles the full Context Board block: one `[CONTEXT_BOARD …]` open-tag
/// line, each section's name and one-line rows, one `[/CONTEXT_BOARD]`
/// close-tag line. Every embedded token rides [`one_line_token`], so an
/// injected control character can never mint or split a physical line; the
/// block is render output only — no code path parses it back into state
/// (08b §0 keystone).
#[must_use]
pub fn render_board_block(header: &BoardBlockHeader, sections: &[BoardSection]) -> String {
    let row_count: usize = sections.iter().map(|section| 1 + section.rows.len()).sum();
    let mut lines = Vec::with_capacity(2 + row_count);
    lines.push(format!(
        "[CONTEXT_BOARD epoch={} scope={}]",
        header.epoch,
        one_line_token(&header.scope)
    ));
    for section in sections {
        lines.push(one_line_token(&section.name));
        lines.extend(section.rows.iter().map(|row| one_line_token(row)));
    }
    lines.push("[/CONTEXT_BOARD]".to_owned());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn board_block_envelope_is_exactly_one_open_one_close() {
        let header = BoardBlockHeader {
            epoch: 47,
            scope: "WorldSet(wd_1)".to_owned(),
        };
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
                rows: vec!["tk_a running".to_owned()],
            },
        ];

        let text = render_board_block(&header, &sections);

        let first_line = text.lines().next().expect("block must have a first line");
        assert!(
            first_line
                .strip_prefix("[CONTEXT_BOARD ")
                .and_then(|rest| rest.strip_suffix(']'))
                .is_some()
        );
        assert_eq!(first_line, "[CONTEXT_BOARD epoch=47 scope=WorldSet(wd_1)]");
        assert_eq!(text.matches("[CONTEXT_BOARD ").count(), 1);
        assert_eq!(text.matches("[/CONTEXT_BOARD]").count(), 1);
        assert_eq!(text.matches("MEMORY_BOARD").count(), 0);
        assert_eq!(text.lines().count(), 8);

        let hostile_header = BoardBlockHeader {
            epoch: 47,
            scope: "WorldSet(\nwd_1)".to_owned(),
        };
        let hostile_sections = [
            BoardSection {
                name: "WORLDS\nSPOOF".to_owned(),
                rows: vec!["wd_1\ractive".to_owned()],
            },
            BoardSection {
                name: "MEMORIES".to_owned(),
                rows: vec!["cl_1 pinned".to_owned()],
            },
            BoardSection {
                name: "TASKS".to_owned(),
                rows: vec!["tk_a\nrunning".to_owned()],
            },
        ];

        let hostile = render_board_block(&hostile_header, &hostile_sections);

        assert_eq!(hostile.lines().count(), text.lines().count());
        assert_eq!(hostile.matches("[CONTEXT_BOARD ").count(), 1);
        assert_eq!(hostile.matches("[/CONTEXT_BOARD]").count(), 1);
        assert_eq!(hostile.matches("MEMORY_BOARD").count(), 0);
    }
}
