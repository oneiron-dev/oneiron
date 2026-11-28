//! Project a catalogue before any discovery text is rendered or scored.

use std::collections::BTreeSet;

use super::index::{Index, VerbRow};
use super::render::{is_type_name, is_word_char, type_references};
use super::{NoteKindLine, OwnedViewOptions, TreeRefusalCode, VerbTree};

pub(super) const NOTE_CREATE: &str = "vault.notes.create";
pub(super) const NO_MATCH: &str = "0 verbs match.";

/// Canonical callable paths established by a trusted host door.
#[derive(Debug, Default)]
pub struct AdmittedRows(BTreeSet<String>);

impl<S: Into<String>> FromIterator<S> for AdmittedRows {
    fn from_iter<T: IntoIterator<Item = S>>(iter: T) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

/// Whether the caller can discover the owner's installed NOTE kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteKindAudience {
    /// Live, unattenuated vault owner.
    Owner,
    /// All other callers.
    NonOwner,
}

/// An unsupported, absent or unadmitted discovery path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRefusal {
    /// Always `UnknownPath`.
    pub code: TreeRefusalCode,
    /// Fixed text; never includes any part of the requested path.
    pub message: &'static str,
}

/// A tree and its rendering options containing only the admitted projection.
pub struct DiscoveryView(Option<(VerbTree, OwnedViewOptions)>);

impl DiscoveryView {
    /// Discovery with no established authority or no admitted paths.
    pub fn empty() -> Self {
        Self(None)
    }

    /// Expand an admitted node or reachable type; the empty path shows the default view.
    pub fn expand(&self, path: &str) -> Result<String, DiscoveryRefusal> {
        let unknown = || DiscoveryRefusal {
            code: TreeRefusalCode::UnknownPath,
            message: "No such discovery path.",
        };
        let Some((tree, options)) = &self.0 else {
            return if path.is_empty() {
                Ok(
                    "ONEIRON VERBS · 0 verbs in one tree · 0 shown in full, the rest by name\n"
                        .into(),
                )
            } else {
                Err(unknown())
            };
        };
        let options = options.as_options();
        if path.is_empty() {
            return Ok(tree.render_view_with(&options, true).text);
        }
        if let Some(node) = tree.node_at(path) {
            let mut text = tree.expand_node_with(node, options.hidden, true);
            if node.children.is_empty() {
                super::view::discovery_note_kinds(&mut text, path, &options);
            }
            return Ok(text);
        }
        tree.expand_type(path).ok_or_else(unknown)
    }

    /// Search admitted rows by exact dotted path or by words (ten hits by default).
    pub fn search(&self, query: &str, under: Option<&str>, limit: Option<usize>) -> String {
        self.0.as_ref().map_or_else(
            || NO_MATCH.to_owned(),
            |(tree, options)| {
                tree.search_discovery(
                    query,
                    under.unwrap_or(""),
                    limit.unwrap_or(10),
                    &options.as_options(),
                )
            },
        )
    }
}

impl VerbTree {
    /// Project the catalogue using door-proven rows and the caller's NOTE kind audience.
    pub fn discovery_view(
        &self,
        admitted: AdmittedRows,
        mut options: OwnedViewOptions,
        audience: NoteKindAudience,
    ) -> DiscoveryView {
        let settings = options.as_options();
        let verbs: BTreeSet<_> = self
            .index
            .verbs
            .keys()
            .map(String::as_str)
            .filter(|path| admitted.0.contains(*path) && !settings.hidden.contains_key(*path))
            .collect();
        if verbs.is_empty() {
            return DiscoveryView::empty();
        }
        let kinds = verbs
            .contains(NOTE_CREATE)
            .then(|| options.discovery_note_kinds(audience))
            .unwrap_or_default();
        let branches = verbs
            .iter()
            .flat_map(|&path| path.match_indices('.').map(move |(i, _)| &path[..i]))
            .collect();
        let projection = Projection {
            source: self,
            verbs,
            branches,
            kind_names: &kinds,
            hidden: settings.hidden,
        };
        let tree = VerbTree::from_discovery_index(projection.index());
        options.restrict_for_discovery(&tree, kinds);
        DiscoveryView(Some((tree, options)))
    }
}

struct Projection<'a> {
    source: &'a VerbTree,
    verbs: BTreeSet<&'a str>,
    branches: BTreeSet<&'a str>,
    kind_names: &'a [NoteKindLine],
    hidden: &'a std::collections::BTreeMap<String, String>,
}

fn path_words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|ch| !is_word_char(ch) && ch != '.')
        .map(|word| word.trim_matches('.'))
        .filter(|word| !word.is_empty())
}

fn type_words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|ch| !is_word_char(ch))
        .filter(|word| is_type_name(word))
}

fn quoted(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    let quote = text.chars().next().filter(|&ch| matches!(ch, '\'' | '"'))?;
    let (value, rest) = text[1..].split_once(quote)?;
    (!value.contains('\\')).then_some((value, rest))
}

fn literal_properties<'a>(
    text: &'a str,
    key: &'a str,
) -> impl Iterator<Item = Option<&'a str>> + 'a {
    text.match_indices(key).filter_map(move |(i, key)| {
        let value = text[i + key.len()..]
            .trim_start_matches(['\'', '"'])
            .trim_start()
            .strip_prefix(':')?;
        Some(
            quoted(value)
                .filter(|(_, rest)| rest.trim_start().starts_with([',', '}']))
                .map(|(value, _)| value),
        )
    })
}

impl Projection<'_> {
    fn path_allowed(&self, path: &str) -> bool {
        if self.verbs.contains(path) {
            return true;
        }
        if self.hidden.contains_key(path)
            || self.source.index.verbs.contains_key(path)
            || matches!(path, "execute" | "verbs.expand" | "verbs.search")
        {
            return false;
        }
        if self.branches.contains(path) {
            return true;
        }
        let family = path.split('.').next().unwrap_or(path);
        !self.source.root.children.contains_key(family) && family != "verbs"
    }

    fn safe(&self, text: &str, types: &BTreeSet<&str>) -> bool {
        path_words(text).all(|path| self.path_allowed(path))
            && super::vault_view::kind_mentions_are_visible(text, self.kind_names)
            && type_words(text)
                .all(|name| types.contains(name) || !self.source.index.types.contains_key(name))
    }

    fn example_safe(&self, text: &str, types: &BTreeSet<&str>) -> bool {
        if !self.safe(text, types)
            || ["?.", " .", "\\u", "\\x"]
                .into_iter()
                .any(|pattern| text.contains(pattern))
        {
            return false;
        }
        for (i, call) in text.match_indices("verbs.expand") {
            let rest = &text[i + call.len()..];
            let Some((target, after)) = rest.trim_start().strip_prefix('(').and_then(quoted) else {
                return false;
            };
            if !after.trim_start().starts_with(')')
                || !(self.verbs.contains(target)
                    || self.branches.contains(target)
                    || types.contains(target))
            {
                return false;
            }
        }
        // An indexed namespace access is not a proven static path.
        if text.match_indices('[').any(|(i, _)| {
            let path = text[..i]
                .trim_end()
                .rsplit(|ch| !is_word_char(ch) && ch != '.')
                .next()
                .unwrap_or("");
            let root = path.split('.').next().unwrap_or("");
            root == "verbs" || self.source.root.children.contains_key(root)
        }) {
            return false;
        }
        if text.contains("verbs.search")
            && literal_properties(text, "under").any(|path| {
                !path.is_some_and(|path| self.verbs.contains(path) || self.branches.contains(path))
            })
        {
            return false;
        }
        if text.contains(NOTE_CREATE)
            && literal_properties(text, "kind").any(|kind| {
                !kind.is_some_and(|name| self.kind_names.iter().any(|line| line.kind == name))
            })
        {
            return false;
        }
        true
    }

    fn prose(&self, text: &str, types: &BTreeSet<&str>, show_examples: bool) -> String {
        let examples = text
            .lines()
            .take_while(|line| {
                let line = line.trim_start();
                !line.starts_with("e.g.")
                    && !line.starts_with("example:")
                    && !line.starts_with("```")
                    && !line.contains("await ")
            })
            .count();
        let mut lines = text.lines();
        let mut safe: Vec<_> = lines
            .by_ref()
            .take(examples)
            .filter(|line| {
                (!line.contains("{note_kinds}") || !self.kind_names.is_empty())
                    && self.safe(line, types)
                    && (!line.contains("verbs.expand(") || self.example_safe(line, types))
            })
            .collect();
        let example = show_examples.then(|| lines.collect::<Vec<_>>().join("\n"));
        if let Some(example) = example
            .as_deref()
            .filter(|text| !text.is_empty() && self.example_safe(text, types))
        {
            safe.push(example);
        }
        safe.join("\n")
    }

    fn reachable_types(&self) -> BTreeSet<&str> {
        let source = &self.source.index;
        let mut allowed: BTreeSet<_> = source.types.keys().map(String::as_str).collect();
        loop {
            let mut pending: Vec<_> = self
                .verbs
                .iter()
                .flat_map(|&path| {
                    let row = &source.verbs[path];
                    [&row.input, &row.output].into_iter()
                })
                .filter(|text| self.safe(text, &allowed))
                .flat_map(|text| type_references(text))
                .collect();
            let mut reachable = BTreeSet::new();
            while let Some(name) = pending.pop() {
                if allowed.contains(name) && !reachable.contains(name) {
                    let declaration = &source.types[name];
                    if self.safe(declaration, &allowed) {
                        reachable.insert(name);
                        pending.extend(type_references(declaration));
                    }
                }
            }
            if reachable == allowed {
                return reachable;
            }
            // A forbidden dependency can make its containing declaration or signature unsafe.
            allowed = reachable;
        }
    }

    fn index(&self) -> Index {
        let source = &self.source.index;
        let reachable = self.reachable_types();
        let signature = |text: &str| {
            if self.safe(text, &reachable) {
                text.to_owned()
            } else {
                "unknown".into()
            }
        };
        let verbs = self
            .verbs
            .iter()
            .map(|&path| {
                let original = &source.verbs[path];
                (
                    path.to_owned(),
                    VerbRow {
                        input: signature(&original.input),
                        output: signature(&original.output),
                        description: self.prose(&original.description, &reachable, false),
                        example: original
                            .example
                            .as_ref()
                            .filter(|example| self.example_safe(example, &reachable))
                            .cloned(),
                    },
                )
            })
            .collect();
        Index {
            revision: String::new(),
            verbs,
            types: reachable
                .iter()
                .map(|&name| (name.to_owned(), source.types[name].clone()))
                .collect(),
            families: source
                .families
                .iter()
                .filter(|(name, _)| self.branches.contains(name.as_str()))
                .map(|(name, text)| (name.clone(), self.prose(text, &reachable, false)))
                .collect(),
            vault_capabilities: source
                .vault_capabilities
                .iter()
                .filter_map(|(label, members)| {
                    if !self.safe(label, &reachable) {
                        return None;
                    }
                    let members: Vec<_> = members
                        .iter()
                        .filter(|member| {
                            let path = format!("vault.{member}");
                            self.verbs.contains(path.as_str())
                                || self.branches.contains(path.as_str())
                        })
                        .cloned()
                        .collect();
                    (!members.is_empty()).then(|| (label.clone(), members))
                })
                .collect(),
            head: self.prose(&source.head, &reachable, false),
            base: source
                .base
                .iter()
                .filter(|(path, _)| self.verbs.contains(path.as_str()))
                .map(|(path, text)| (path.clone(), self.prose(text, &reachable, true)))
                .filter(|(_, text)| !text.is_empty())
                .collect(),
        }
    }
}
