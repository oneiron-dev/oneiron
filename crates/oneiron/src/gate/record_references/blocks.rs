//! The block structure [`super::parse_record_links`] reads a text's lines
//! through (CommonMark, as far as finding links needs it): fenced and
//! indented code, raw HTML blocks, list items and paragraphs. Every
//! indentation is measured from the content column of the list item a line
//! sits in, so a line indented under a list item is that item's text, and
//! only a line four columns past the item's content is code. No link syntax
//! lives here.

use super::{HtmlBlockEnd, fence_line, html_block_start, indent_columns, line_end_at};

/// What one line is to the inline scan.
pub(super) enum Line {
    /// Code, raw HTML, a blank line or an empty list item: no link is read
    /// in it.
    Skip,
    /// Text, read for links from byte `from` of the line.
    Inline {
        from: usize,
        /// The line opens a paragraph (or a heading): no code span reaches
        /// back before it.
        starts_paragraph: bool,
        /// An ATX heading: a code span in it ends with the line.
        heading: bool,
        /// The line opens with a block quote marker, whose following lines
        /// continue its paragraph rather than open a quote.
        quoted: bool,
    },
}

/// The open blocks, line by line.
#[derive(Default)]
pub(super) struct Blocks {
    /// The open fence: its mark and run.
    fence: Option<(u8, usize)>,
    /// The open raw HTML block, by what ends it.
    html: Option<HtmlBlockEnd>,
    /// The content columns of the open list items, outermost first.
    items: Vec<usize>,
    /// The last line opened or continued a paragraph: a lazy line may
    /// continue it, and indented code may not interrupt it.
    in_paragraph: bool,
}

impl Blocks {
    /// Reads the next line (without its `\n`) and says what it is.
    pub(super) fn line(&mut self, line: &[u8]) -> Line {
        let blank = line.iter().all(u8::is_ascii_whitespace);
        let lead = lead(line);
        let mut col = indent_columns(line);
        // A line indented less than an open item's content leaves that item,
        // and any code or HTML open in it, unless it lazily continues the
        // item's paragraph.
        if !blank && self.items.last().is_some_and(|&content| col < content) {
            let lazy =
                self.in_paragraph && !opens_block(&line[lead..], col - self.base_for(col), true);
            if lazy {
                return Line::Inline {
                    from: lead,
                    starts_paragraph: false,
                    heading: false,
                    quoted: false,
                };
            }
            self.items.retain(|&content| content <= col);
            self.fence = None;
            self.html = None;
            self.in_paragraph = false;
        }
        let mut base = self.items.last().copied().unwrap_or(0);
        if let Some(open) = self.fence {
            if let Some(next) = fence_line(Some(open), col.saturating_sub(base), &line[lead..]) {
                self.fence = next;
            }
            return Line::Skip;
        }
        if let Some(end) = self.html {
            if end.ends_at(line) {
                self.html = None;
            }
            return Line::Skip;
        }
        if blank {
            self.in_paragraph = false;
            return Line::Skip;
        }
        if col.saturating_sub(base) >= 4 && !self.in_paragraph {
            return Line::Skip;
        }
        let mut from = lead;
        // The blocks this line opens, each inside the item the one before it
        // opened (`- - text`, `1. ``` `).
        loop {
            let rest = &line[from..];
            let relative = col.saturating_sub(base);
            if let Some(next) = fence_line(None, relative, rest) {
                self.fence = next;
                self.in_paragraph = false;
                return Line::Skip;
            }
            if relative <= 3
                && let Some(end) = html_block_start(rest, !self.in_paragraph)
            {
                if !end.ends_at(rest) {
                    self.html = Some(end);
                }
                self.in_paragraph = false;
                return Line::Skip;
            }
            let marker = if relative <= 3 && !thematic_break(rest) {
                list_marker(rest, col)
            } else {
                None
            };
            let Some(marker) = marker.filter(|marker| !self.in_paragraph || marker.interrupts)
            else {
                break;
            };
            base = col + marker.columns;
            self.items.push(base);
            self.in_paragraph = false;
            if marker.empty || marker.code {
                return Line::Skip;
            }
            from += marker.bytes;
            col = base;
        }
        let rest = &line[from..];
        let opening = col.saturating_sub(base) <= 3;
        let heading = opening && atx_heading(rest);
        let starts_paragraph = !self.in_paragraph || heading;
        let ends = heading
            || (opening
                && (thematic_break(rest) || (self.in_paragraph && setext_underline(rest))));
        self.in_paragraph = !ends;
        Line::Inline {
            from,
            starts_paragraph,
            heading,
            quoted: opening && rest.first() == Some(&b'>'),
        }
    }

    /// Where the paragraph a line ending at `line_end` sits in ends, in
    /// `bytes`: the start of the first later line that is blank or opens a
    /// block, read under the list items open now. A code span never crosses
    /// it. A paragraph in a block quote (`quoted`) continues on the quote's
    /// later lines.
    pub(super) fn paragraph_end(&self, bytes: &[u8], line_end: usize, quoted: bool) -> usize {
        let mut at = line_end;
        while at < bytes.len() {
            let start = at + 1;
            let end = line_end_at(bytes, start, bytes.len());
            let line = &bytes[start..end];
            if line.iter().all(u8::is_ascii_whitespace) {
                return start;
            }
            let col = indent_columns(line);
            let rest = &line[lead(line)..];
            let relative = col - self.base_for(col);
            let outside = self.items.last().is_some_and(|&content| col < content);
            let quote_line = quoted && rest.first() == Some(&b'>');
            if (opens_block(rest, relative, outside) && !quote_line)
                || (relative <= 3 && setext_underline(rest))
            {
                return start;
            }
            at = end;
        }
        bytes.len()
    }

    /// The content column of the innermost open item a line at `col` sits
    /// in: none is 0.
    fn base_for(&self, col: usize) -> usize {
        self.items
            .iter()
            .rev()
            .find(|&&content| content <= col)
            .copied()
            .unwrap_or(0)
    }
}

/// The leading spaces and tabs of `line`, in bytes.
fn lead(line: &[u8]) -> usize {
    line.iter()
        .take_while(|&&byte| byte == b' ' || byte == b'\t')
        .count()
}

/// Whether `rest` (a line from its first non-blank byte, `relative` columns
/// into its container) opens a block that ends a paragraph. A list item
/// counts only where one may interrupt a paragraph, or, with `any_item`,
/// as any item an open list may take next.
fn opens_block(rest: &[u8], relative: usize, any_item: bool) -> bool {
    relative <= 3
        && (fence_line(None, 0, rest).is_some()
            || html_block_start(rest, false).is_some()
            || atx_heading(rest)
            || thematic_break(rest)
            || rest.first() == Some(&b'>')
            || list_marker(rest, 0).is_some_and(|marker| any_item || marker.interrupts))
}

/// One list item marker.
struct Marker {
    /// Its bytes, with the blanks after it.
    bytes: usize,
    /// The columns from its first byte to the item's content.
    columns: usize,
    /// Nothing follows it on its line.
    empty: bool,
    /// The item's content opens with indented code.
    code: bool,
    /// It may interrupt a paragraph: a non-empty bullet, or an ordered
    /// item numbered 1.
    interrupts: bool,
}

/// The list item marker `rest` (a line from its first non-blank byte, at
/// column `col`) opens: `-`, `+` or `*`, or one to nine digits and `.` or
/// `)`, then a blank or the line's end.
fn list_marker(rest: &[u8], col: usize) -> Option<Marker> {
    let digits = rest
        .iter()
        .take(10)
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let width = match rest.first()? {
        b'-' | b'+' | b'*' => 1,
        _ if (1..=9).contains(&digits) && matches!(rest.get(digits), Some(b'.' | b')')) => {
            digits + 1
        }
        _ => return None,
    };
    if !rest.get(width).is_none_or(u8::is_ascii_whitespace) {
        return None;
    }
    let marker_end = col + width;
    let mut column = marker_end;
    let mut bytes = width;
    for &byte in &rest[width..] {
        match byte {
            b' ' => column += 1,
            b'\t' => column += 4 - column % 4,
            _ => break,
        }
        bytes += 1;
    }
    let empty = rest[bytes..].iter().all(u8::is_ascii_whitespace);
    let spaces = column - marker_end;
    let code = !empty && spaces > 4;
    Some(Marker {
        bytes,
        // An empty item, or one whose content opens with indented code,
        // takes its content one column past the marker.
        columns: if empty || code {
            width + 1
        } else {
            column - col
        },
        empty,
        code,
        interrupts: !empty && (width == 1 || rest[..digits] == *b"1"),
    })
}

/// Whether `rest` is a thematic break: three or more of one of `*`, `-` and
/// `_`, with only blanks between.
fn thematic_break(rest: &[u8]) -> bool {
    let Some(&mark) = rest.first() else {
        return false;
    };
    if !matches!(mark, b'*' | b'-' | b'_') {
        return false;
    }
    let mut count = 0;
    for &byte in rest {
        if byte == mark {
            count += 1;
        } else if !byte.is_ascii_whitespace() {
            return false;
        }
    }
    count >= 3
}

/// Whether `rest` opens an ATX heading: one to six `#`, then a blank or the
/// line's end.
fn atx_heading(rest: &[u8]) -> bool {
    let marks = rest.iter().take_while(|&&byte| byte == b'#').count();
    (1..=6).contains(&marks) && rest.get(marks).is_none_or(u8::is_ascii_whitespace)
}

/// Whether `rest` is a setext heading underline: a run of `=` or of `-`,
/// then only blanks.
fn setext_underline(rest: &[u8]) -> bool {
    let Some(&mark) = rest.first() else {
        return false;
    };
    if mark != b'=' && mark != b'-' {
        return false;
    }
    let run = rest.iter().take_while(|&&byte| byte == mark).count();
    rest[run..].iter().all(u8::is_ascii_whitespace)
}
