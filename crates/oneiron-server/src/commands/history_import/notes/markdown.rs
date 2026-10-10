//! What `import notes` reads in one note: its YAML frontmatter, and the
//! `[[links]]` it makes outside code.
//!
//! Code is what CommonMark calls code: fenced blocks (also inside a block
//! quote or a list item), indented blocks outside lists, and inline spans,
//! which may run over the lines of one paragraph. This is a reader of the
//! common shapes, not a full CommonMark parser.

use std::collections::HashMap;

/// A `[[link]]` as written: its target, and whether it embeds (`![[...]]`).
pub(super) struct Link {
    /// The note it names, without an alias (`|...`), heading (`#...`) or
    /// block (`^...`). Empty for a link to a heading of the note itself.
    pub(super) target: String,
    pub(super) embed: bool,
}

/// What the frontmatter says about a note.
pub(super) struct Front {
    /// `title`, else `name`.
    pub(super) title: Option<String>,
    /// `type`, else `metadata.type`.
    pub(super) label: Option<String>,
    /// Every key and value as it decodes, each as it is, one `key: value`
    /// a line: an escape in the file can spell what its text does not show.
    pub(super) decoded: String,
}

/// The YAML a note opens with, between a first line `---` and the next line
/// `---` or `...`, and the body after it. A byte-order mark is not part of
/// either.
pub(super) fn split_frontmatter(text: &str) -> (Option<&str>, &str) {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(after) = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
    else {
        return (None, text);
    };
    let mut offset = 0;
    for line in after.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\r', '\n']);
        if bare == "---" || bare == "..." {
            return (Some(&after[..offset]), &after[offset + line.len()..]);
        }
        offset += line.len();
    }
    (None, text)
}

/// The frontmatter's title and type; `None` when it is not YAML.
pub(super) fn frontmatter(yaml: &str) -> Option<Front> {
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml).ok()?;
    let mut decoded = String::new();
    write_decoded(&value, &mut decoded);
    let text = |value: Option<&serde_yaml_ng::Value>| {
        value
            .and_then(serde_yaml_ng::Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    Some(Front {
        title: text(value.get("title")).or_else(|| text(value.get("name"))),
        label: text(value.get("type")).or_else(|| {
            text(
                value
                    .get("metadata")
                    .and_then(|metadata| metadata.get("type")),
            )
        }),
        decoded,
    })
}

/// Every key and value of `value` as it is, a nested map's or list's on
/// lines of their own. Never written out as YAML again: that would escape a
/// control character again, and the token beside it with it.
fn write_decoded(value: &serde_yaml_ng::Value, out: &mut String) {
    use serde_yaml_ng::Value;
    match value {
        Value::Null => {}
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => out.push_str(text),
        Value::Sequence(items) => {
            for item in items {
                out.push('\n');
                write_decoded(item, out);
            }
        }
        Value::Mapping(fields) => {
            for (key, value) in fields {
                out.push('\n');
                write_decoded(key, out);
                out.push_str(": ");
                write_decoded(value, out);
            }
        }
        Value::Tagged(tagged) => {
            out.push_str(&tagged.tag.to_string());
            out.push(' ');
            write_decoded(&tagged.value, out);
        }
    }
}

/// Every `[[link]]` in `body` outside code.
pub(super) fn wikilinks(body: &str) -> Vec<Link> {
    let mut links = Vec::new();
    let mut paragraph = String::new();
    let mut fence: Option<Fence> = None;
    let mut indented_code = false;
    let mut in_list = false;
    // Where the current list item's content starts, and the block-quote
    // depth the outermost open list sits at.
    let mut item_column = 0;
    let mut list_depth = 0;
    let mut after_blank = true;
    for line in body.lines() {
        let line = expand_prefix(line);
        if let Some(open) = fence {
            // A fence ends with its closing line, or with the quote or list
            // item it opened in. Quote markers past its own are code.
            let (depth, inner) = unquote(&line, Some(open.depth));
            let content = inner.trim_start();
            let item_ended = open
                .item_column
                .is_some_and(|column| !content.is_empty() && indent(inner) < column);
            if depth == open.depth && !item_ended {
                if run(content, open.mark) >= open.len
                    && content.trim_start_matches(open.mark).trim().is_empty()
                {
                    fence = None;
                }
                continue;
            }
            fence = None;
            in_list &= !item_ended;
        }
        let (depth, inner) = unquote(&line, None);
        // Where the line starts at the list's own depth, which decides
        // whether a block ends the list: a quote inside a list item is
        // indented within the item, and a line outside the list's quote is
        // at the margin.
        let margin = if depth < list_depth {
            0
        } else {
            indent(unquote(&line, Some(list_depth)).1)
        };
        let indent = indent(inner);
        let mut content = inner.trim_start();
        if content.is_empty() {
            span_links(&std::mem::take(&mut paragraph), &mut links);
            after_blank = true;
            continue;
        }
        if indented_code && indent >= 4 {
            continue;
        }
        indented_code = false;
        // Indented code cannot interrupt a paragraph, but it follows any
        // other block (a heading, a rule, a closed fence) directly.
        if indent >= 4 && !in_list && paragraph.is_empty() {
            indented_code = true;
            continue;
        }
        let mut item = false;
        if let Some(rest) = list_item(content).filter(|_| !thematic_break(content)) {
            span_links(&std::mem::take(&mut paragraph), &mut links);
            list_depth = if in_list {
                list_depth.min(depth)
            } else {
                depth
            };
            in_list = true;
            item = true;
            let text = rest.trim_start();
            item_column = indent + content.len() - text.len() + usize::from(text.is_empty());
            content = text;
        } else if margin < 2 && after_blank {
            in_list = false;
        }
        after_blank = false;
        // A `===` line under a paragraph makes it a heading, which ends there.
        if !paragraph.is_empty() && content.trim_end().chars().all(|c| c == '=') {
            span_links(&std::mem::take(&mut paragraph), &mut links);
            continue;
        }
        // A rule or a heading is a block of its own, and one at the margin
        // ends a list.
        if thematic_break(content) || heading(content) {
            span_links(&std::mem::take(&mut paragraph), &mut links);
            span_links(content, &mut links);
            in_list &= item || margin >= 2;
            continue;
        }
        if let Some(mark) = fence_mark(content)
            && (indent < 4 || in_list)
        {
            span_links(&std::mem::take(&mut paragraph), &mut links);
            in_list &= item || margin >= 2;
            // A fence in a quote inside the item ends with that quote.
            fence = Some(Fence {
                mark,
                len: run(content, mark),
                depth,
                item_column: (in_list && depth == list_depth).then_some(item_column),
            });
            continue;
        }
        paragraph.push_str(content);
        paragraph.push('\n');
    }
    span_links(&paragraph, &mut links);
    links
}

/// An open code fence: its character and length, the block-quote depth it
/// opened at, and where the content of the list item it opened in starts.
#[derive(Clone, Copy)]
struct Fence {
    mark: char,
    len: usize,
    depth: usize,
    item_column: Option<usize>,
}

/// The line with the tabs among its leading spaces and quote markers
/// expanded to the columns they reach, so a marker's padding and the indent
/// after it are counted where they stand.
fn expand_prefix(line: &str) -> std::borrow::Cow<'_, str> {
    let lead = line
        .find(|c: char| !matches!(c, ' ' | '\t' | '>'))
        .unwrap_or(line.len());
    if !line[..lead].contains('\t') {
        return line.into();
    }
    let mut out = String::with_capacity(line.len() + 8);
    for c in line[..lead].chars() {
        if c == '\t' {
            let to = 4 - out.len() % 4;
            out.extend(std::iter::repeat_n(' ', to));
        } else {
            out.push(c);
        }
    }
    out.push_str(&line[lead..]);
    out.into()
}

/// A line without up to `most` block-quote markers (all of them when
/// `None`), each with the one space after it, and how many it had.
fn unquote(line: &str, most: Option<usize>) -> (usize, &str) {
    let mut rest = line;
    let mut depth = 0;
    while most.is_none_or(|most| depth < most) {
        let trimmed = rest.trim_start_matches(' ');
        if rest.len() - trimmed.len() > 3 {
            break;
        }
        let Some(inner) = trimmed.strip_prefix('>') else {
            break;
        };
        depth += 1;
        rest = inner.strip_prefix(' ').unwrap_or(inner);
    }
    (depth, rest)
}

/// Columns of leading whitespace; a tab moves to the next multiple of four.
fn indent(line: &str) -> usize {
    let mut columns = 0;
    for c in line.chars() {
        match c {
            ' ' => columns += 1,
            '\t' => columns += 4 - columns % 4,
            _ => break,
        }
    }
    columns
}

fn run(text: &str, mark: char) -> usize {
    text.chars().take_while(|&c| c == mark).count()
}

/// The fence character `content` opens a code block with: three or more
/// backticks (and none after them) or tildes.
fn fence_mark(content: &str) -> Option<char> {
    ['`', '~'].into_iter().find(|&mark| {
        run(content, mark) >= 3 && (mark == '~' || !content.trim_start_matches('`').contains('`'))
    })
}

/// `---`, `***` or `___`, spaces allowed between.
fn thematic_break(content: &str) -> bool {
    ['-', '*', '_'].into_iter().any(|mark| {
        content.chars().filter(|&c| c == mark).count() >= 3
            && content.chars().all(|c| c == mark || c == ' ' || c == '\t')
    })
}

/// An ATX heading: one to six `#` and a space, or nothing after them.
fn heading(content: &str) -> bool {
    let marks = run(content, '#');
    (1..=6).contains(&marks)
        && content[marks..]
            .chars()
            .next()
            .is_none_or(|c| c == ' ' || c == '\t')
}

/// The rest of a line that opens a list item (`-`, `*`, `+`, or `1.` / `1)`,
/// then a space or nothing).
fn list_item(content: &str) -> Option<&str> {
    let digits = content.chars().take_while(char::is_ascii_digit).count();
    let rest = if (1..=9).contains(&digits) {
        content[digits..].strip_prefix(['.', ')'])?
    } else {
        content.strip_prefix(['-', '*', '+'])?
    };
    (rest.is_empty() || rest.starts_with([' ', '\t'])).then_some(rest)
}

/// The links in one paragraph's text, skipping its inline code spans and
/// escaped brackets. A span runs from a run of backticks to the next run of
/// exactly as many; a run with no match is plain text.
///
/// One pass: the scan keeps where the next `]]` is and which backtick runs
/// lie ahead (as cmark does), so it never searches the same bytes twice for
/// either.
fn span_links(text: &str, links: &mut Vec<Link>) {
    let bytes = text.as_bytes();
    // The first `]]` at or after where one was last looked for; `Some(None)`
    // once none is left.
    let mut closing: Option<Option<usize>> = None;
    // The last start of each length of backtick run seen ahead, and whether
    // a search for a closing run has reached the end: past that, a length
    // not seen beyond an opening run has no match.
    let mut runs: HashMap<usize, usize> = HashMap::new();
    let mut runs_seen = false;
    let mut at = 0;
    while at < bytes.len() {
        // A backslash makes the punctuation after it plain text.
        if bytes[at] == b'\\' && bytes.get(at + 1).is_some_and(u8::is_ascii_punctuation) {
            at += 2;
            continue;
        }
        if bytes[at] == b'`' {
            let ticks = bytes[at..].iter().take_while(|&&b| b == b'`').count();
            let after = at + ticks;
            let mut close = None;
            if !runs_seen || runs.get(&ticks).is_some_and(|&last| last >= after) {
                let mut probe = after;
                while probe < bytes.len() {
                    if bytes[probe] == b'`' {
                        let found = bytes[probe..].iter().take_while(|&&b| b == b'`').count();
                        let last = runs.entry(found).or_insert(probe);
                        *last = (*last).max(probe);
                        if found == ticks {
                            close = Some(probe + found);
                            break;
                        }
                        probe += found;
                    } else {
                        probe += 1;
                    }
                }
                reading(probe - after);
                runs_seen |= close.is_none();
            }
            at = close.unwrap_or(after);
            continue;
        }
        if bytes[at..].starts_with(b"[[") {
            let start = at + 2;
            let end = match closing {
                Some(Some(end)) if end >= start => Some(end),
                Some(None) => None,
                _ => {
                    let found = text[start..].find("]]").map(|end| start + end);
                    reading(found.map_or(text.len(), |end| end + 2) - start);
                    closing = Some(found);
                    found
                }
            };
            if let Some(end) = end {
                let inner = &text[start..end];
                let stop = inner.find(['[', '\n']);
                reading(stop.map_or(inner.len(), |stop| stop + 1));
                if stop.is_none() {
                    links.push(Link {
                        target: inner
                            .split('|')
                            .next()
                            .and_then(|target| target.split(['#', '^']).next())
                            .unwrap_or_default()
                            .trim()
                            .to_owned(),
                        embed: at > 0 && bytes[at - 1] == b'!',
                    });
                    at = end + 2;
                    continue;
                }
            }
        }
        at += 1;
    }
}

#[cfg(test)]
thread_local! {
    /// The bytes the link scan may still read ahead of where it stands: a
    /// test sets it, and the scan panics past it.
    static READS_LEFT: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// Counts `bytes` the link scan read ahead of where it stands (a test hook).
fn reading(bytes: usize) {
    #[cfg(test)]
    READS_LEFT.with(|left| {
        left.set(
            left.get()
                .checked_sub(bytes)
                .expect("the link scan read a paragraph more than once"),
        );
    });
    #[cfg(not(test))]
    let _ = bytes;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(body: &str) -> Vec<String> {
        wikilinks(body)
            .into_iter()
            .map(|link| link.target)
            .collect()
    }

    /// Sol review 1 (#1, #3, #6, #8) and its re-checks (#1, #3, #13-#16):
    /// code spans over lines, indented and quoted code, a byte-order mark
    /// before a fence and escaped brackets hold no links; lists keep theirs;
    /// a heading, a list item or the end of a quote ends what opened in it.
    #[test]
    fn links_in_code_are_not_links() {
        assert_eq!(targets("Before `code\n[[a]]\ncode` after [[b]].\n"), ["b"]);
        assert_eq!(targets("Example:\n\n    [[a]]\n\n[[b]]\n"), ["b"]);
        assert_eq!(targets("> ```\n> [[a]]\n> ```\n> [[b]]\n"), ["b"]);
        assert_eq!(targets("- item\n\n    more [[a]]\n"), ["a"]);
        assert_eq!(targets("- item\n    [[a]]\n"), ["a"]);
        assert_eq!(targets("text\n    [[a]]\n"), ["a"]);
        let (_, body) = split_frontmatter("\u{feff}~~~\n[[a]]\n~~~\n[[b]]\n");
        assert_eq!(targets(body), ["b"]);
        assert_eq!(
            targets("[[a|alias]] ![[b.png]] [[#here]] [[c#h]]"),
            ["a", "b.png", "", "c"]
        );
        assert_eq!(
            targets("`` a ` [[x]] `` [[y]] ``unclosed [[z]]"),
            ["y", "z"]
        );
        assert_eq!(targets("\\[[a]] [[b]] \\`[[c]]`"), ["b", "c"]);
        assert_eq!(targets("# Heading `\nSee [[b]] and `.\n"), ["b"]);
        assert_eq!(targets("- a `x\n- b [[b]] `y\n"), ["b"]);
        assert_eq!(targets("- ```\n  [[a]]\n  ```\n\n[[b]]\n"), ["b"]);
        assert_eq!(targets("> ```\n> [[a]]\n\n[[b]]\n"), ["b"]);
        assert_eq!(targets("- - -\n\n    [[a]]\n\n[[b]]\n"), ["b"]);
        assert_eq!(targets("- item\n# Heading\n\n    [[a]]\n\n[[b]]\n"), ["b"]);
        assert_eq!(targets(">\t[[b]]\n"), ["b"]);
        assert_eq!(targets("- # Heading `\n  See [[b]] and `.\n"), ["b"]);
        assert_eq!(targets("> > ```\n> > [[a]]\n> [[b]]\n"), ["b"]);
        assert_eq!(targets("```\n> ```\n[[a]]\n```\n[[b]]\n"), ["b"]);
        assert_eq!(targets("> \t[[b]]\n"), ["b"]);
        assert_eq!(targets(">\t  [[a]]\n"), Vec::<String>::new());
        assert_eq!(targets("- ```\n  [[a]]\n\n[[b]]\n"), ["b"]);
        assert_eq!(targets("- ```\n  [[a]]\n\n [[b]]\n"), ["b"]);
        assert_eq!(targets("1. ```\n   [[a]]\n\n  [[b]]\n"), ["b"]);
        assert_eq!(targets("1. ```\n   [[a]]\n   ```\n   [[b]]\n"), ["b"]);
        assert_eq!(targets("Heading `\n===\nSee [[b]] and `.\n"), ["b"]);
    }

    /// Greptile (#1351, markdown.rs:154): indented code was code only after
    /// a blank line, so an indented line right after a heading or a closed
    /// fence read as text and made a link. It is code wherever no paragraph
    /// is open; a paragraph's indented line still links.
    #[test]
    fn indented_code_after_a_block_is_code() {
        let none = Vec::<String>::new();
        assert_eq!(targets("# Heading\n    [[alpha]]\n"), none);
        assert_eq!(targets("```\ncode\n```\n    [[alpha]]\n"), none);
        assert_eq!(
            targets("~~~\ncode\n~~~\n    [[alpha]]\n    [[beta]]\n"),
            none
        );
        assert_eq!(targets("***\n    [[alpha]]\n"), none);
        assert_eq!(targets("Heading\n===\n    [[alpha]]\n"), none);
        assert_eq!(targets("> ```\n> code\n    [[alpha]]\n"), none);
        assert_eq!(targets("Text and\n    [[alpha]]\n"), ["alpha"]);
        assert_eq!(targets("# Heading\nText and\n    [[alpha]]\n"), ["alpha"]);
        // Sol on this fix: a block in a quote inside a list item does not
        // end the list, so the item's next line is its text, not code.
        assert_eq!(targets("- item\n  > # Heading\n    [[alpha]]\n"), ["alpha"]);
        assert_eq!(targets("- item\n  > ***\n    [[alpha]]\n"), ["alpha"]);
        assert_eq!(
            targets("- item\n  > ```\n  > [[a]]\n  > ```\n    [[alpha]]\n"),
            ["alpha"]
        );
        assert_eq!(targets("- item\n\n> # Heading\n\n    [[alpha]]\n"), none);
    }

    /// Astra 4 and Greptile (markdown.rs:301): at every `[[` the scan looked
    /// for `]]` through the rest of the paragraph, and at every backtick run
    /// for its closer, so a 1 MiB paragraph of unclosed ones took about
    /// 2^39 steps. Each such paragraph is now read ahead a bounded number
    /// of times.
    #[test]
    fn a_paragraph_is_read_in_one_pass() {
        let mib = 1 << 20;
        let paragraphs = [
            format!("x{}", "[".repeat(mib)),
            format!("{}]]", "[".repeat(mib)),
            // Runs of 1448 backticks down to one: none has a closer.
            (1..=1448).rev().fold("x ".to_owned(), |text, ticks| {
                text + &"`".repeat(ticks) + " "
            }),
        ];
        for paragraph in paragraphs {
            READS_LEFT.with(|left| left.set(4 * paragraph.len()));
            let links = wikilinks(&paragraph);
            READS_LEFT.with(|left| left.set(usize::MAX));
            assert!(links.iter().all(|link| link.target.is_empty()));
        }
    }
}
