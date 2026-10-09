//! What `import notes` reads in one note: its YAML frontmatter, and the
//! `[[links]]` it makes outside code.
//!
//! Code is what CommonMark calls code: fenced blocks (also inside a block
//! quote or a list item), indented blocks outside lists, and inline spans,
//! which may run over the lines of one paragraph. This is a reader of the
//! common shapes, not a full CommonMark parser.

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
    })
}

/// Every `[[link]]` in `body` outside code.
pub(super) fn wikilinks(body: &str) -> Vec<Link> {
    let mut links = Vec::new();
    let mut paragraph = String::new();
    let mut fence: Option<Fence> = None;
    let mut indented_code = false;
    let mut in_list = false;
    let mut after_blank = true;
    for line in body.lines() {
        let (quoted, inner) = unquote(line);
        if let Some(open) = fence {
            // A fence in a block quote ends with the quote.
            if !open.quoted || quoted {
                let content = inner.trim_start();
                if run(content, open.mark) >= open.len
                    && content.trim_start_matches(open.mark).trim().is_empty()
                {
                    fence = None;
                }
                continue;
            }
            fence = None;
        }
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
        if indent >= 4 && after_blank && !in_list && paragraph.is_empty() {
            indented_code = true;
            continue;
        }
        // A rule or a heading is a block of its own, and a heading at the
        // margin ends a list.
        if thematic_break(content) || heading(content) {
            span_links(&std::mem::take(&mut paragraph), &mut links);
            span_links(content, &mut links);
            in_list &= indent >= 2;
            after_blank = false;
            continue;
        }
        if let Some(rest) = list_item(content) {
            span_links(&std::mem::take(&mut paragraph), &mut links);
            in_list = true;
            content = rest.trim_start();
        } else if indent == 0 && after_blank {
            in_list = false;
        }
        after_blank = false;
        if let Some(mark) = fence_mark(content)
            && (indent < 4 || in_list)
        {
            span_links(&std::mem::take(&mut paragraph), &mut links);
            fence = Some(Fence {
                mark,
                len: run(content, mark),
                quoted,
            });
            continue;
        }
        paragraph.push_str(content);
        paragraph.push('\n');
    }
    span_links(&paragraph, &mut links);
    links
}

/// An open code fence: its character, its length, and whether it opened in
/// a block quote.
#[derive(Clone, Copy)]
struct Fence {
    mark: char,
    len: usize,
    quoted: bool,
}

/// A line without its block-quote markers, and whether it had any.
fn unquote(line: &str) -> (bool, &str) {
    let mut rest = line;
    let mut quoted = false;
    loop {
        let trimmed = rest.trim_start_matches(' ');
        if rest.len() - trimmed.len() > 3 {
            return (quoted, rest);
        }
        match trimmed.strip_prefix('>') {
            Some(inner) => {
                quoted = true;
                rest = inner.strip_prefix([' ', '\t']).unwrap_or(inner);
            }
            None => return (quoted, rest),
        }
    }
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
/// escaped brackets. A span
/// runs from a run of backticks to the next run of exactly as many; a run
/// with no match is plain text.
fn span_links(text: &str, links: &mut Vec<Link>) {
    let bytes = text.as_bytes();
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
            let mut probe = after;
            while probe < bytes.len() {
                if bytes[probe] == b'`' {
                    let found = bytes[probe..].iter().take_while(|&&b| b == b'`').count();
                    if found == ticks {
                        close = Some(probe + found);
                        break;
                    }
                    probe += found;
                } else {
                    probe += 1;
                }
            }
            at = close.unwrap_or(after);
            continue;
        }
        if bytes[at..].starts_with(b"[[")
            && let Some(end) = text[at + 2..].find("]]")
        {
            let inner = &text[at + 2..at + 2 + end];
            if !inner.contains(['[', '\n']) {
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
                at += end + 4;
                continue;
            }
        }
        at += 1;
    }
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

    /// Sol review 1 (#1, #3, #6, #8) and its re-check (#1, #3, #13-#15):
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
    }
}
