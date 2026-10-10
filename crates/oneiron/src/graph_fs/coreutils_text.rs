//! Bounded text rendering for Graph-FS grep, head and path walks, and the
//! position a page of one file's lines resumes from.
use super::paging::{CommandOutputBuilder, SealedPosition};

pub(super) fn literal_grep_pattern(pattern: &str) -> Option<&str> {
    let pattern = pattern.trim();
    if pattern.is_empty() || !pattern.is_ascii() {
        return None;
    }
    if pattern.bytes().any(|byte| {
        matches!(
            byte,
            b'.' | b'*'
                | b'+'
                | b'?'
                | b'['
                | b']'
                | b'('
                | b')'
                | b'{'
                | b'}'
                | b'|'
                | b'^'
                | b'$'
                | b'\\'
        )
    }) {
        return None;
    }
    Some(pattern)
}

/// Where a page of lines resumes: the line (the byte that starts it in a
/// file, or its rank in a ranked listing), and how much of its rendering the
/// pages before already printed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct LinePosition {
    pub(super) line: usize,
    pub(super) printed: usize,
}

impl SealedPosition for LinePosition {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = (self.line as u64).to_be_bytes().to_vec();
        bytes.extend_from_slice(&(self.printed as u64).to_be_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (line, printed) = bytes.split_first_chunk::<8>()?;
        Some(Self {
            line: usize::try_from(u64::from_be_bytes(*line)).ok()?,
            printed: usize::try_from(u64::from_be_bytes(printed.try_into().ok()?)).ok()?,
        })
    }
}

/// Where a `head` resumes: its place in the file, and how many lines the
/// pages before printed.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct HeadPosition {
    pub(super) lines: LinePosition,
    pub(super) printed: usize,
}

impl SealedPosition for HeadPosition {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.lines.to_bytes();
        bytes.extend_from_slice(&(self.printed as u64).to_be_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (lines, printed) = bytes.split_last_chunk::<8>()?;
        Some(Self {
            lines: LinePosition::from_bytes(lines)?,
            printed: usize::try_from(u64::from_be_bytes(*printed)).ok()?,
        })
    }
}

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

pub(super) fn join_graph_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}
