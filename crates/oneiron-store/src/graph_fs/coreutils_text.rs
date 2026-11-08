//! Bounded text rendering for Graph-FS grep, head and path walks, and the
//! position a page of one file's lines resumes from.
use crate::graph_fs::paging::SealedPosition;

pub fn literal_grep_pattern(pattern: &str) -> Option<&str> {
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
pub struct LinePosition {
    pub line: usize,
    pub printed: usize,
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
pub struct HeadPosition {
    pub lines: LinePosition,
    pub printed: usize,
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

pub fn join_graph_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}
