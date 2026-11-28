use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use super::VerbTree;
use super::index::{Node, VerbRow};

const NO_DESCRIPTION: &str = "(no description in the verb table)";

struct Field<'a> {
    name: &'a str,
    optional: bool,
    ty: &'a str,
}

pub(super) fn is_word_char(char: char) -> bool {
    char.is_ascii_alphanumeric() || char == '_'
}

pub(super) fn is_type_name(text: &str) -> bool {
    text.as_bytes().first().is_some_and(u8::is_ascii_uppercase) && text.chars().all(is_word_char)
}

// The generated signatures use identifiers for types. A quoted literal or an
// object key with the same spelling does not introduce a type dependency.
pub(super) fn type_references(mut text: &str) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        loop {
            let start = text.find(|ch| is_word_char(ch) || matches!(ch, '\'' | '"' | '`'))?;
            text = &text[start..];
            if let Some(quote) = text
                .chars()
                .next()
                .filter(|&ch| matches!(ch, '\'' | '"' | '`'))
            {
                let mut escaped = false;
                let end = text[1..].find(|ch| {
                    if std::mem::take(&mut escaped) {
                        return false;
                    }
                    escaped = ch == '\\';
                    ch == quote
                })?;
                text = &text[end + 2..];
                continue;
            }
            let end = text.find(|ch| !is_word_char(ch)).unwrap_or(text.len());
            let name = &text[..end];
            text = &text[end..];
            let after = text.trim_start();
            let after = after.strip_prefix('?').unwrap_or(after).trim_start();
            if is_type_name(name) && !after.starts_with(':') {
                return Some(name);
            }
        }
    })
}

pub(super) fn text_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn split_top_level(text: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let mut quote = None;
    for (index, char) in text.char_indices() {
        if let Some(delimiter) = quote {
            if char == delimiter {
                quote = None;
            }
            continue;
        }
        match char {
            '"' | '\'' | '`' => quote = Some(char),
            '{' | '[' | '(' | '<' => depth += 1,
            '}' | ']' | ')' | '>' => depth -= 1,
            _ => {}
        }
        if char == separator && depth == 0 {
            parts.push(&text[start..index]);
            start = index + char.len_utf8();
        }
    }
    if !text[start..].trim().is_empty() {
        parts.push(&text[start..]);
    }
    parts
}

fn first_sentence(text: &str) -> String {
    if text.is_empty() {
        return NO_DESCRIPTION.to_owned();
    }
    let sentence = text
        .match_indices(['.', ';'])
        .find(|&(index, _)| text[index + 1..].starts_with(' '))
        .map_or(text, |(index, _)| &text[..=index]);
    if text_len(sentence) <= 120 {
        return sentence.to_owned();
    }
    let mut units = 0;
    let prefix: String = sentence
        .chars()
        .take_while(|char| {
            units += char.len_utf16();
            units < 120
        })
        .collect();
    format!("{}…", prefix.trim_end())
}

fn example_value(ty: &str) -> String {
    let plain = ty.strip_suffix(" | null").unwrap_or(ty).trim();
    match plain {
        "string" | "unknown" => "\"…\"".to_owned(),
        "number" => "0".to_owned(),
        "boolean" => "false".to_owned(),
        _ if plain.starts_with('"') => plain.split(" | ").next().unwrap_or(plain).to_owned(),
        _ if plain.ends_with("[]") => "[]".to_owned(),
        _ => format!("{{ /* {plain} */ }}"),
    }
}

fn input_parameters(input: &str) -> Cow<'_, str> {
    // The index puts a positional signature's parameter list in the input slot.
    let positional = input
        .strip_prefix('(')
        .and_then(|text| text.strip_suffix(')'))
        .and_then(|text| text.split_once(": "))
        .is_some_and(|(name, _)| !name.is_empty() && name.chars().all(is_word_char));
    if positional {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(format!("(input: {input})"))
    }
}

fn type_body(declaration: &str) -> &str {
    declaration
        .strip_prefix("type ")
        .map_or(declaration, |rest| rest.trim_start_matches(is_word_char))
}

pub(super) fn child_label(child: &Node, hidden: &BTreeMap<String, String>) -> String {
    if child.has_visible_children(hidden) {
        format!("{}({})", child.name, child.visible_count(hidden))
    } else {
        child.name.clone()
    }
}

fn branch_line(node: &Node, hidden: &BTreeMap<String, String>) -> String {
    let names: Vec<_> = node
        .ordered_children(hidden)
        .into_iter()
        .map(|child| child_label(child, hidden))
        .collect();
    let mut shown = String::new();
    let mut width = 0;
    let mut shown_count = 0;
    for name in &names {
        let len = text_len(name);
        if width + len + 1 > 150 {
            break;
        }
        if !shown.is_empty() {
            shown.push(' ');
            width += 1;
        }
        shown.push_str(name);
        width += len;
        shown_count += 1;
    }
    let rest = names.len() - shown_count;
    let suffix = if rest > 0 {
        format!(" +{rest} more")
    } else {
        String::new()
    };
    let callable = node.visible_verb(hidden);
    let count = node.visible_count(hidden) - callable as usize;
    let detail = if callable {
        " under this callable verb"
    } else {
        ""
    };
    let plural = if count == 1 { "" } else { "s" };
    format!(
        "{}  {count} verb{plural}{detail}: {shown}{suffix}",
        node.path
    )
}

impl VerbTree {
    fn input_fields<'a>(&'a self, input: &'a str, depth: usize) -> Option<Vec<Field<'a>>> {
        if input.is_empty() || depth > 3 {
            return None;
        }
        let expression = input.trim();
        if expression == "EmptyRequest" {
            return Some(Vec::new());
        }
        let mut body = expression;
        if !expression.is_empty() && expression.chars().all(is_word_char) {
            let declaration = self.index.types.get(expression)?;
            body = declaration
                .strip_prefix("type ")?
                .strip_prefix(expression)?
                .strip_prefix(" = ")?
                .strip_suffix(';')?
                .trim();
            if !body.is_empty() && body.chars().all(is_word_char) {
                return self.input_fields(body, depth + 1);
            }
        }
        if body == "Record<string, never>" {
            return Some(Vec::new());
        }
        let fields = body.strip_prefix('{')?.strip_suffix('}')?;
        if split_top_level(body, '|').len() > 1 || split_top_level(body, '&').len() > 1 {
            return None;
        }
        split_top_level(fields, ';')
            .into_iter()
            .map(|part| {
                let (key, ty) = part.trim().split_once(": ")?;
                let (name, optional) = key
                    .strip_suffix('?')
                    .map_or((key, false), |name| (name, true));
                if name.is_empty() || !name.chars().all(is_word_char) || ty.is_empty() {
                    return None;
                }
                Some(Field {
                    name,
                    optional,
                    ty: ty.trim(),
                })
            })
            .collect()
    }

    fn fields_text(&self, row: &VerbRow) -> String {
        let Some(fields) = self.input_fields(&row.input, 0) else {
            return input_parameters(&row.input).into_owned();
        };
        if fields.is_empty() {
            return "({})".to_owned();
        }
        let mut shown: Vec<_> = fields
            .iter()
            .filter(|field| !field.optional)
            .take(7)
            .map(|field| field.name.to_owned())
            .collect();
        let room = 7_usize.saturating_sub(shown.len());
        let optional: Vec<_> = fields.iter().filter(|field| field.optional).collect();
        shown.extend(
            optional
                .iter()
                .take(room)
                .map(|field| format!("{}?", field.name)),
        );
        let hidden = optional.len().saturating_sub(room);
        if hidden > 0 {
            shown.push(format!("+{hidden} optional"));
        }
        format!("({{ {} }})", shown.join(", "))
    }

    pub(super) fn line(&self, path: &str) -> Option<String> {
        let row = self.index.verbs.get(path)?;
        Some(format!(
            "{path}{}  {}",
            self.fields_text(row),
            first_sentence(&row.description)
        ))
    }

    pub(super) fn takes(&self, path: &str) -> Option<String> {
        let row = self.index.verbs.get(path)?;
        let Some(fields) = self.input_fields(&row.input, 0) else {
            return Some(format!("{path}{}", input_parameters(&row.input)));
        };
        if fields.is_empty() {
            return Some(format!("{path}({{}})"));
        }
        let fields = fields
            .iter()
            .map(|field| {
                let optional = if field.optional { "?" } else { "" };
                format!("{}{optional}: {}", field.name, field.ty)
            })
            .collect::<Vec<_>>()
            .join(", ");
        Some(format!("{path}({{ {fields} }})"))
    }

    fn referenced_types<'a>(&'a self, text: &str) -> Vec<&'a str> {
        let mut seen = BTreeSet::new();
        text.split(|char| !is_word_char(char))
            .filter(|word| word.len() > 1 && is_type_name(word))
            .filter_map(|word| self.index.types.get_key_value(word))
            .map(|(name, _)| name.as_str())
            .filter(|name| seen.insert(*name))
            .collect()
    }

    fn generated_example(&self, path: &str, row: &VerbRow) -> String {
        let Some(fields) = self.input_fields(&row.input, 0) else {
            return format!("await {path}(/* {} */)", row.input);
        };
        let required: Vec<_> = fields
            .iter()
            .filter(|field| !field.optional)
            .map(|field| format!("{}: {}", field.name, example_value(field.ty)))
            .collect();
        if required.is_empty() {
            return format!("await {path}({{}})");
        }
        format!("await {path}({{ {} }})", required.join(", "))
    }

    pub(super) fn example(&self, path: &str) -> Option<String> {
        let row = self.index.verbs.get(path)?;
        Some(
            row.example
                .clone()
                .unwrap_or_else(|| self.generated_example(path, row)),
        )
    }

    pub(super) fn verb_full(&self, path: &str, row: &VerbRow) -> String {
        self.verb_full_with(path, row, false)
    }

    pub(super) fn verb_full_with(&self, path: &str, row: &VerbRow, strict: bool) -> String {
        let parameters = input_parameters(&row.input);
        let stored_result = if row.output == "unknown"
            || (strict && !self.index.types.contains_key("StoredResult"))
        {
            ""
        } else {
            " | StoredResult"
        };
        let mut lines = vec![format!(
            "{path}{parameters}: Promise<{}{stored_result}>",
            row.output
        )];
        let description = if row.description.is_empty() {
            NO_DESCRIPTION
        } else {
            &row.description
        };
        lines.push(format!("  {description}"));
        let mut seen = BTreeSet::new();
        let mut frontier = self.referenced_types(&format!("{} {}", row.input, row.output));
        let mut budget = 3200;
        let mut skipped = Vec::new();
        for _ in 0..2 {
            let mut next = Vec::new();
            for name in frontier {
                if !seen.insert(name) {
                    continue;
                }
                let declaration = &self.index.types[name];
                let len = text_len(declaration);
                if len > budget || len > 1400 {
                    skipped.push(name);
                    continue;
                }
                budget -= len;
                lines.push(format!("  {declaration}"));
                next.extend(self.referenced_types(type_body(declaration)));
            }
            frontier = next;
        }
        let mut unique = BTreeSet::new();
        let deeper: Vec<_> = frontier
            .into_iter()
            .filter(|name| !seen.contains(name))
            .chain(skipped)
            .filter(|name| unique.insert(*name))
            .collect();
        if let Some(first) = deeper.first() {
            let names = deeper[..deeper.len().min(12)].join(", ");
            let more = if deeper.len() > 12 { ", …" } else { "" };
            if strict && !self.index.verbs.contains_key("verbs.expand") {
                lines.push(format!("  more types, by name: {names}{more}"));
            } else {
                lines.push(format!(
                    "  more types, by name: verbs.expand(\"{first}\")  ({names}{more})"
                ));
            }
        }
        if let Some(example) = &row.example {
            lines.push(format!("  example: {example}"));
        } else if !strict {
            lines.push(format!("  example: {}", self.generated_example(path, row)));
        }
        lines.join("\n")
    }

    pub(super) fn expand_type(&self, path: &str) -> Option<String> {
        let declaration = self.index.types.get(path)?;
        let mut lines = vec![declaration.as_str()];
        for name in self
            .referenced_types(type_body(declaration))
            .into_iter()
            .take(8)
        {
            let referenced = &self.index.types[name];
            if text_len(referenced) <= 900 {
                lines.push(referenced);
            }
        }
        Some(lines.join("\n"))
    }

    pub(super) fn expand_node(&self, node: &Node, hidden: &BTreeMap<String, String>) -> String {
        self.expand_node_with(node, hidden, false)
    }

    pub(super) fn expand_node_with(
        &self,
        node: &Node,
        hidden: &BTreeMap<String, String>,
        strict: bool,
    ) -> String {
        let children = node.ordered_children(hidden);
        if children.is_empty() && node.visible_verb(hidden) {
            return self.verb_full_with(&node.path, &self.index.verbs[&node.path], strict);
        }
        let tip = if strict && !self.index.verbs.contains_key("verbs.expand") {
            ""
        } else {
            "; verbs.expand(\"<path>\") on any of them goes one level deeper"
        };
        let mut lines = vec![format!(
            "{} · {} verbs · a line per child{tip}",
            node.path,
            node.visible_count(hidden),
        )];
        if node.visible_verb(hidden)
            && let Some(line) = self.line(&node.path)
        {
            lines.push(format!("{line}   (callable itself)"));
        }
        for child in &children {
            if child.visible_verb(hidden)
                && let Some(line) = self.line(&child.path)
            {
                lines.push(line);
            }
        }
        for child in children {
            if child.has_visible_children(hidden) {
                lines.push(branch_line(child, hidden));
            }
        }
        lines.join("\n")
    }
}
