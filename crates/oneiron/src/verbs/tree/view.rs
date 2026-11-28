use std::collections::{BTreeMap, BTreeSet};

use oneiron_store::note_kind::RetentionDefault;

use super::index::{Node, name_order};
use super::render::is_word_char;
use super::render::{child_label, text_len};
use super::{NoteKindLine, RenderedView, VerbTree, ViewOptions};

fn grouped(number: usize) -> String {
    let digits = number.to_string();
    let mut grouped = String::new();
    for (index, digit) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(char::from(digit));
    }
    grouped
}

fn note_kinds(kinds: &[NoteKindLine]) -> String {
    kinds
        .iter()
        .map(|kind| {
            let quoted = format!("\"{}\"", kind.kind);
            match (kind.retention, kind.archive_after_days) {
                (RetentionDefault::SessionSealed, _) => format!("{quoted} (this session only)"),
                (RetentionDefault::ArchiveAfterDays, Some(days)) => {
                    format!("{quoted} (archived after {days} days)")
                }
                _ => quoted,
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn discovery_note_kinds(text: &mut String, path: &str, options: &ViewOptions<'_>) {
    if path == super::discovery::NOTE_CREATE && !options.note_kinds.is_empty() {
        text.push_str("\n  NOTE kind is one of ");
        text.push_str(&note_kinds(options.note_kinds));
        text.push('.');
    }
}

fn wrap_names(names: impl IntoIterator<Item = String>, indent: &str, lines: &mut Vec<String>) {
    let mut current = indent.to_owned();
    let mut width = text_len(indent);
    for name in names {
        let len = text_len(&name);
        if width + len + 1 > 118 && !current.trim().is_empty() {
            lines.push(current.trim_end().to_owned());
            current = indent.to_owned();
            width = text_len(indent);
        }
        current.push_str(&name);
        current.push(' ');
        width += len + 1;
    }
    if !current.trim().is_empty() {
        lines.push(current.trim_end().to_owned());
    }
}

impl VerbTree {
    fn coarse_tree(&self, base: &BTreeSet<&str>, hidden: &BTreeMap<String, String>) -> String {
        let mut families = Vec::new();
        let mut singles = Vec::new();
        for node in self.root.children.values() {
            if node.has_visible_children(hidden) {
                families.push((node.visible_count(hidden), node));
            } else if node.visible_verb(hidden) && !base.contains(node.path.as_str()) {
                singles.push(node.name.as_str());
            }
        }
        families.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| name_order(&a.1.name, &b.1.name)));
        let shown = |child: &Node| {
            child.has_visible_children(hidden)
                || (child.visible_verb(hidden) && !base.contains(child.path.as_str()))
        };
        let mut lines = Vec::new();
        for (count, family) in families {
            let description = self
                .index
                .families
                .get(&family.name)
                .map_or("", String::as_str);
            lines.push(
                format!("{}  {} verbs  {description}", family.name, grouped(count))
                    .trim_end()
                    .to_owned(),
            );
            if family.name == "vault" {
                for (label, members) in &self.index.vault_capabilities {
                    let names = members
                        .iter()
                        .filter_map(|name| family.children.get(name))
                        .filter(|child| shown(child))
                        .map(|child| child_label(child, hidden));
                    lines.push(format!("  {label}:"));
                    wrap_names(names, "      ", &mut lines);
                }
            } else {
                let names = family
                    .ordered_children(hidden)
                    .into_iter()
                    .filter(|child| shown(child))
                    .map(|child| child_label(child, hidden));
                wrap_names(names, "  ", &mut lines);
            }
        }
        lines.push(format!(
            "single verbs  {}  {}",
            singles.len(),
            singles.join(" ")
        ));
        lines.join("\n")
    }

    fn visible_node(&self, path: &str, options: &ViewOptions<'_>) -> Option<&Node> {
        self.node_at(path)
            .filter(|node| !path.is_empty() && node.outside_grant(options.hidden).is_none())
    }

    /// A path the hidden map takes out (a hidden verb, or a branch with every verb hidden):
    /// the view leaves it out without naming it, as search and the coarse tree do.
    fn grant_hidden(&self, path: &str, hidden: &BTreeMap<String, String>) -> bool {
        hidden.contains_key(path)
            || (!path.is_empty()
                && self
                    .node_at(path)
                    .is_some_and(|node| node.outside_grant(hidden).is_some()))
    }

    fn without_hidden_paths(&self, text: &str, hidden: &BTreeMap<String, String>) -> String {
        text.split('\n')
            .filter(|line| {
                !line
                    .split(|char| !is_word_char(char) && char != '.')
                    .map(|token| token.trim_end_matches('.'))
                    .any(|token| token.contains('.') && self.grant_hidden(token, hidden))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn full_subtree(
        &self,
        node: &Node,
        hidden: &BTreeMap<String, String>,
        blocks: &mut Vec<String>,
    ) {
        if node.visible_verb(hidden) {
            blocks.push(self.verb_full(&node.path, &self.index.verbs[&node.path]));
        }
        for child in node.ordered_children(hidden) {
            self.full_subtree(child, hidden, blocks);
        }
    }

    fn full_discovery_subtree<'a>(
        &'a self,
        node: &'a Node,
        options: &ViewOptions<'_>,
        blocks: &mut Vec<String>,
        shown: &mut BTreeSet<&'a str>,
    ) {
        if let Some(row) = self.index.verbs.get(&node.path)
            && shown.insert(node.path.as_str())
        {
            let mut text = self.verb_full_with(&node.path, row, true);
            discovery_note_kinds(&mut text, &node.path, options);
            blocks.push(text);
        }
        for child in node.ordered_children(options.hidden) {
            self.full_discovery_subtree(child, options, blocks, shown);
        }
    }

    pub(super) fn render_view(&self, options: &ViewOptions<'_>) -> RenderedView {
        self.render_view_with(options, false)
    }

    pub(super) fn render_view_with(&self, options: &ViewOptions<'_>, strict: bool) -> RenderedView {
        let mut base = Vec::new();
        let mut shown_base = BTreeSet::new();
        let mut shown_full = BTreeSet::new();
        let mut not_shown = Vec::new();
        let kinds = note_kinds(options.note_kinds);
        for path in options.base {
            let node = self.visible_node(path, options);
            let authored = self.index.base.get(path);
            // The generator gates the authored paths; only the tree calls may
            // have authored text without a corresponding node.
            let tree_call = path.starts_with("verbs.")
                && authored.is_some()
                && self.node_at(path).is_none()
                && !options.hidden.contains_key(path);
            if node.is_none() && !tree_call {
                if !self.grant_hidden(path, options.hidden) {
                    not_shown.push(path.as_str());
                }
                continue;
            }
            if let Some(text) = authored.filter(|_| !options.hidden.contains_key(path)) {
                let text = text.replace("{note_kinds}", &kinds);
                if !strict || shown_full.insert(path.as_str()) {
                    base.push(self.without_hidden_paths(&text, options.hidden));
                }
            } else if let Some(node) = node {
                let mut blocks = Vec::new();
                if strict {
                    self.full_discovery_subtree(node, options, &mut blocks, &mut shown_full);
                } else {
                    self.full_subtree(node, options.hidden, &mut blocks);
                }
                if !strict || !blocks.is_empty() {
                    base.push(self.without_hidden_paths(&blocks.join("\n\n"), options.hidden));
                }
            }
            shown_base.insert(path.as_str());
        }
        let base_count = if strict { shown_full.len() } else { base.len() };
        let head = self
            .index
            .head
            .trim_end()
            .replace("{TOTAL}", &grouped(self.root.visible_count(options.hidden)))
            .replace("{BASE_COUNT}", &grouped(base_count));
        let head = self.without_hidden_paths(&head, options.hidden);
        let mut expanded = Vec::new();
        for path in options.expanded {
            if let Some(node) = self.visible_node(path, options) {
                let mut block = if strict {
                    self.expand_node_with(node, options.hidden, true)
                } else {
                    self.expand_node(node, options.hidden)
                };
                if strict && node.children.is_empty() {
                    discovery_note_kinds(&mut block, path, options);
                }
                expanded.push((
                    path.as_str(),
                    self.without_hidden_paths(&block, options.hidden),
                ));
            } else if !self.grant_hidden(path, options.hidden) {
                not_shown.push(path.as_str());
            }
        }
        let coarse = self.coarse_tree(&shown_base, options.hidden);
        let coarse_tip = if !strict
            || (self.index.verbs.contains_key("verbs.expand")
                && self.node_at("vault.mail").is_some())
        {
            self.without_hidden_paths(
                "Before you call one: return await verbs.expand(\"vault.mail\") \
                 shows its verbs and their fields.",
                options.hidden,
            )
        } else {
            String::new()
        };
        let render = |keep: usize| {
            let mut text = head.clone();
            for block in &base {
                text.push_str("\n\n");
                text.push_str(block);
            }
            if keep > 0 {
                text.push_str("\n\nEXPANDED FOR THIS VAULT (setting code_mode.view)");
                for (_, block) in &expanded[..keep] {
                    text.push('\n');
                    text.push_str(block);
                }
            } else if !expanded.is_empty() || !not_shown.is_empty() {
                text.push('\n');
            }
            if keep < expanded.len() {
                let dropped = expanded[keep..]
                    .iter()
                    .map(|(path, _)| *path)
                    .filter(|path| !options.hidden.contains_key(*path))
                    .collect::<Vec<_>>();
                if !dropped.is_empty() {
                    text.push_str("\nnot expanded for size: ");
                    text.push_str(&dropped.join(", "));
                }
            }
            if !not_shown.is_empty() {
                text.push_str("\nnot shown (not in the tree): ");
                text.push_str(&not_shown.join(", "));
            }
            text.push_str(
                "\n\nTHE REST, by name only. A name with (n) is a branch of n verbs; \
                           the labels before a colon are not paths.",
            );
            if !coarse_tip.is_empty() {
                text.push('\n');
                text.push_str(&coarse_tip);
            }
            text.push('\n');
            text.push_str(&coarse);
            text.push('\n');
            text
        };
        let mut keep = expanded.len();
        let mut text = render(keep);
        let mut tokens = crate::count_context_pack_tokens(&text);
        while tokens > options.budget_tok as usize && keep > 0 {
            keep -= 1;
            text = render(keep);
            tokens = crate::count_context_pack_tokens(&text);
        }
        if tokens > options.budget_tok as usize {
            text.push_str(&format!(
                "the base alone is {tokens} tokens, over code_mode.view.budget_tok {}\n",
                options.budget_tok,
            ));
            tokens = crate::count_context_pack_tokens(&text);
        }
        let not_expanded = expanded[keep..]
            .iter()
            .map(|(path, _)| (*path).to_owned())
            .collect();
        RenderedView {
            text,
            tokens,
            not_expanded,
        }
    }
}
