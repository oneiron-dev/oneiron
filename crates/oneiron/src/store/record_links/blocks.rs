//! The block structure [`super::parse_record_links`] reads a text's lines
//! through (CommonMark, as far as finding links needs it): block quotes,
//! list items, fenced and indented code, raw HTML blocks and paragraphs. A
//! line first passes the containers open around it, outermost first: a
//! block quote by its `>` marker, a list item by indenting to its content
//! column. Every indentation is then measured from the content column of the
//! innermost container the line sits in, so a line indented under a list
//! item is that item's text, `>     code` is code inside a quote, and only a
//! line four columns past its container's content is code. No link syntax
//! lives here.

use super::{HtmlBlockEnd, fence_line, html_block_start, line_end_at};

/// What one line is to the inline scan.
pub(super) enum Line {
    /// Code, raw HTML, a blank line or an empty list item: no link is read
    /// in it.
    Skip,
    /// Text, read for links from byte `from` of the line, past its quote
    /// markers and indentation.
    Inline {
        from: usize,
        /// The line opens a paragraph (or a heading): no code span reaches
        /// back before it.
        starts_paragraph: bool,
        /// An ATX heading: a code span in it ends with the line.
        heading: bool,
    },
}

/// One open container: a block quote, which a line stays in only through
/// its `>` marker, or a list item, which a line stays in by indenting to its
/// content.
#[derive(Clone, Copy)]
struct Container {
    /// The column the container's content starts at.
    content: usize,
    quote: bool,
}

/// How far a line's container prefix reached: the byte and column after it,
/// and the content column of the innermost container it entered.
#[derive(Clone, Copy)]
struct Cursor {
    at: usize,
    col: usize,
    base: usize,
}

/// The open blocks, line by line.
#[derive(Default)]
pub(super) struct Blocks {
    /// The open fence: its mark and run.
    fence: Option<(u8, usize)>,
    /// The open raw HTML block, by what ends it.
    html: Option<HtmlBlockEnd>,
    /// The open block quotes and list items, outermost first.
    containers: Vec<Container>,
    /// The last line opened or continued a paragraph: a lazy line may
    /// continue it, and indented code may not interrupt it.
    in_paragraph: bool,
}

impl Blocks {
    /// Reads the next line (without its `\n`) and says what it is.
    pub(super) fn line(&mut self, line: &[u8]) -> Line {
        let (cursor, entered) = self.enter(line);
        let (mut from, mut col) = skip_blanks(line, cursor.at, cursor.col);
        let blank = line[from..].iter().all(u8::is_ascii_whitespace);
        // A line that leaves an open container leaves any code or HTML open
        // in it too, unless it lazily continues the container's paragraph.
        if entered < self.containers.len() {
            let lazy = !blank
                && self.in_paragraph
                && !opens_block(&line[from..], col.saturating_sub(cursor.base), true);
            if lazy {
                return Line::Inline {
                    from,
                    starts_paragraph: false,
                    heading: false,
                };
            }
            self.containers.truncate(entered);
            self.fence = None;
            self.html = None;
            self.in_paragraph = false;
        }
        let mut base = cursor.base;
        if let Some(open) = self.fence {
            if let Some(next) = fence_line(Some(open), col.saturating_sub(base), &line[from..]) {
                self.fence = next;
            }
            return Line::Skip;
        }
        if let Some(end) = self.html {
            // Past the quote markers, so a quote's own `>` never ends it.
            if end.ends_at(&line[from..]) {
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
        // The blocks this line opens, each inside the container the one
        // before it opened (`- - text`, `1. ``` `, `> - text`, `- > text`).
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
            let here = Cursor {
                at: from,
                col,
                base,
            };
            if let Some(quote) = quote_marker(line, here) {
                self.containers.push(Container {
                    content: quote.base,
                    quote: true,
                });
                self.in_paragraph = false;
                base = quote.base;
                (from, col) = skip_blanks(line, quote.at, quote.col);
                if line[from..].iter().all(u8::is_ascii_whitespace) || col.saturating_sub(base) >= 4
                {
                    return Line::Skip;
                }
                continue;
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
            self.containers.push(Container {
                content: base,
                quote: false,
            });
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
            || (opening && (thematic_break(rest) || (self.in_paragraph && setext_underline(rest))));
        self.in_paragraph = !ends;
        Line::Inline {
            from,
            starts_paragraph,
            heading,
        }
    }

    /// Where the paragraph a line ending at `line_end` sits in ends, in
    /// `bytes`: the start of the first later line that is blank or opens a
    /// block, read through the containers open now. A code span never
    /// crosses it. A later line that leaves a container continues the
    /// paragraph lazily unless it opens a block.
    pub(super) fn paragraph_end(&self, bytes: &[u8], line_end: usize) -> usize {
        let mut at = line_end;
        while at < bytes.len() {
            let start = at + 1;
            let end = line_end_at(bytes, start, bytes.len());
            let line = &bytes[start..end];
            let (cursor, entered) = self.enter(line);
            let (from, col) = skip_blanks(line, cursor.at, cursor.col);
            let rest = &line[from..];
            if rest.iter().all(u8::is_ascii_whitespace) {
                return start;
            }
            let relative = col.saturating_sub(cursor.base);
            let outside = entered < self.containers.len();
            if opens_block(rest, relative, outside)
                || (!outside && relative <= 3 && setext_underline(rest))
            {
                return start;
            }
            at = end;
        }
        bytes.len()
    }

    /// Walks `line` through the open containers, outermost first: how far
    /// their prefix reached, and how many of them the line stays in. A line
    /// blank from there on stays in a list item, never in a block quote
    /// without its marker.
    fn enter(&self, line: &[u8]) -> (Cursor, usize) {
        let mut cursor = Cursor {
            at: 0,
            col: 0,
            base: 0,
        };
        for (entered, container) in self.containers.iter().enumerate() {
            if container.quote {
                match quote_marker(line, cursor) {
                    Some(next) => cursor = next,
                    None => return (cursor, entered),
                }
            } else {
                let (at, col) = skip_blanks(line, cursor.at, cursor.col);
                let blank = line[at..].iter().all(u8::is_ascii_whitespace);
                if !blank && col < container.content {
                    return (cursor, entered);
                }
                cursor.base = container.content;
            }
        }
        (cursor, self.containers.len())
    }
}

/// The spaces and tabs from byte `at` of `line`, which sits at column `col`:
/// the byte and column of what follows them. A tab runs to the next multiple
/// of four.
fn skip_blanks(line: &[u8], mut at: usize, mut col: usize) -> (usize, usize) {
    while let Some(&byte) = line.get(at) {
        match byte {
            b' ' => col += 1,
            b'\t' => col += 4 - col % 4,
            _ => break,
        }
        at += 1;
    }
    (at, col)
}

/// The block quote marker past `cursor`'s blanks, when it sits at most three
/// columns into `cursor`'s container: a `>`, and one blank after it that
/// belongs to the marker. The cursor past it has the quote's content column
/// as its `base`; a tab after the `>` is left for the line's indentation,
/// less the one column the marker takes from it.
fn quote_marker(line: &[u8], cursor: Cursor) -> Option<Cursor> {
    let (at, col) = skip_blanks(line, cursor.at, cursor.col);
    if col.saturating_sub(cursor.base) > 3 || line.get(at) != Some(&b'>') {
        return None;
    }
    let (at, col) = (at + 1, col + 1);
    Some(match line.get(at) {
        Some(b' ') => Cursor {
            at: at + 1,
            col: col + 1,
            base: col + 1,
        },
        Some(b'\t') => Cursor {
            at,
            col,
            base: col + 1,
        },
        _ => Cursor { at, col, base: col },
    })
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
