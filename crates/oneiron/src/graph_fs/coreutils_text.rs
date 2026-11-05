//! Core half of `graph_fs::coreutils_text`: its store-layer items live in `oneiron_store::graph_fs::coreutils_text` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::graph_fs::coreutils_text::*;

use super::paging::{CommandOutputBuilder, SealedPosition};

/// Prints the lines of `bytes` from `from`, each as `render` makes it (`None`
/// skips it), until `max_lines` are printed or the page is full. A line
/// longer than a whole page prints across pages, cut on a character
/// boundary. Returns how many lines it finished, and where the next page
/// resumes when the page filled first.
pub(super) fn page_lines(
    bytes: &[u8],
    from: LinePosition,
    out: &mut CommandOutputBuilder,
    max_lines: usize,
    mut render: impl FnMut(&str) -> Option<String>,
) -> (usize, Option<LinePosition>) {
    let mut finished = 0;
    let mut at = from;
    while at.line < bytes.len() && finished < max_lines {
        let rest = &bytes[at.line..];
        // Lines end at `\n` or `\r\n`, as `str::lines` splits them.
        let (line, next) = match rest.iter().position(|byte| *byte == b'\n') {
            Some(end) => (
                rest[..end].strip_suffix(b"\r").unwrap_or(&rest[..end]),
                at.line + end + 1,
            ),
            None => (rest, bytes.len()),
        };
        if let Some(rendered) = render(&String::from_utf8_lossy(line)) {
            if let Some(printed) = out.push_line(&rendered, at.printed) {
                at.printed = printed;
                return (finished, Some(at));
            }
            finished += 1;
        }
        at = LinePosition {
            line: next,
            printed: 0,
        };
    }
    (finished, None)
}
