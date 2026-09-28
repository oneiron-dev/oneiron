//! Bounded text rendering for Graph-FS grep and path walks.
use super::paging::CommandOutputBuilder;

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

pub(super) fn append_grep_file_matches(
    path: &str,
    bytes: &[u8],
    pattern: &str,
    out: &mut CommandOutputBuilder,
    total: &mut usize,
) {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines().filter(|line| line.contains(pattern)) {
        let rendered = format!("{path}:{line}\n");
        if !out.try_push(rendered.as_bytes()) {
            break;
        }
        *total += 1;
    }
}

pub(super) fn join_graph_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}
