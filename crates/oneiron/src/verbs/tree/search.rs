use std::collections::BTreeSet;

use super::index::{Node, name_order};
use super::{TreeRefusal, TreeRefusalCode, VerbTree, ViewOptions};

const STOP_WORDS: &[&str] = &[
    "a", "an", "the", "of", "to", "for", "in", "on", "and", "or", "by", "with", "from", "my", "is",
    "it", "that", "this", "how", "do", "can",
];

fn stems(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|char: char| !char.is_ascii_alphanumeric())
        .filter(|word| word.len() > 1 && !STOP_WORDS.contains(word))
        .map(|word| {
            let stem = ["ing", "ed", "es", "s"]
                .into_iter()
                .find_map(|suffix| word.strip_suffix(suffix))
                .filter(|stem| stem.len() >= 3);
            stem.unwrap_or(word).to_owned()
        })
        .collect()
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<_> = b.encode_utf16().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, a) in a.encode_utf16().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, &b) in b.iter().enumerate() {
            let current = row[j + 1];
            row[j + 1] = (current + 1)
                .min(row[j] + 1)
                .min(previous + (a != b) as usize);
            previous = current;
        }
    }
    row[b.len()]
}

fn walk_nearby<'a>(
    node: &'a Node,
    prefix_len: usize,
    bad: &str,
    last: &str,
    level: usize,
    options: &ViewOptions<'_>,
    candidates: &mut Vec<(isize, &'a str)>,
) {
    for child in node.children.values() {
        if child.visible_count(options.hidden) == 0 {
            continue;
        }
        if !options.hidden.contains_key(&child.path) {
            let tail = &child.path[prefix_len..];
            let distance = edit_distance(tail, bad)
                .min(edit_distance(&child.name, last) + (level > 0) as usize);
            let contains = child.name.contains(last) || last.contains(child.name.as_str());
            candidates.push((
                distance as isize - if contains { 2 } else { 0 },
                &child.path,
            ));
        }
        if level < 2 {
            walk_nearby(child, prefix_len, bad, last, level + 1, options, candidates);
        }
    }
}

fn under_path(path: &str, under: &str) -> bool {
    under.is_empty()
        || path == under
        || path
            .strip_prefix(under)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

impl VerbTree {
    fn authored_base<'a>(&'a self, path: &str, options: &ViewOptions<'_>) -> Option<&'a str> {
        if !options.base.iter().any(|entry| entry == path) {
            return None;
        }
        self.index
            .base
            .get(path)
            .map(String::as_str)
            .filter(|text| !text.is_empty())
    }

    fn search_verbs<'a>(
        &'a self,
        query: &str,
        under: &str,
        limit: usize,
        options: &ViewOptions<'_>,
    ) -> (usize, Vec<&'a str>) {
        let wanted = stems(query);
        let mut hits = Vec::new();
        for (path, row) in &self.index.verbs {
            if !under_path(path, under) || options.hidden.contains_key(path) {
                continue;
            }
            let base = self.authored_base(path, options);
            let name_stems = stems(path);
            let description_stems = stems(&format!("{} {}", row.description, base.unwrap_or("")));
            let mut score = 0;
            let mut matched = 0;
            for word in &wanted {
                if name_stems.contains(word) {
                    score += 3;
                    matched += 1;
                } else if description_stems.contains(word) {
                    score += 1;
                    matched += 1;
                }
            }
            if matched == 0 {
                continue;
            }
            if matched == wanted.len() {
                score += 4;
            }
            if base.is_some() && (matched == wanted.len() || matched >= 2) {
                score += 3;
            }
            // Use hundredths so subtraction and tie-breaking stay exact.
            hits.push((
                score * 100 - path.split('.').count() as isize,
                path.as_str(),
            ));
        }
        hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| name_order(a.1, b.1)));
        (
            hits.len(),
            hits.into_iter().take(limit).map(|(_, path)| path).collect(),
        )
    }

    pub(super) fn nearest_paths(&self, path: &str, options: &ViewOptions<'_>) -> Vec<String> {
        let mut node = &self.root;
        let mut segments = path.split('.').peekable();
        while let Some(child) = segments.peek().and_then(|&part| node.children.get(part)) {
            if child.visible_count(options.hidden) == 0 {
                break;
            }
            node = child;
            segments.next();
        }
        let bad = segments.collect::<Vec<_>>().join(".");
        let prefix_len = if node.path.is_empty() {
            0
        } else {
            node.path.len() + 1
        };
        let last = bad.rsplit('.').next().unwrap_or(&bad);
        let mut candidates = Vec::new();
        walk_nearby(node, prefix_len, &bad, last, 0, options, &mut candidates);
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| name_order(a.1, b.1)));
        if candidates.is_empty() && !bad.is_empty() {
            return self
                .search_verbs(&bad, "", 5, options)
                .1
                .into_iter()
                .map(str::to_owned)
                .collect();
        }
        candidates
            .into_iter()
            .take(5)
            .map(|(_, path)| path.to_owned())
            .collect()
    }

    pub(super) fn nearest_types(&self, name: &str) -> Vec<String> {
        let mut candidates: Vec<_> = self
            .index
            .types
            .keys()
            .map(|candidate| (edit_distance(name, candidate), candidate))
            .collect();
        candidates.sort();
        candidates
            .into_iter()
            .take(5)
            .map(|(_, name)| name.clone())
            .collect()
    }

    pub(super) fn search_query(
        &self,
        query: &str,
        under: &str,
        limit: usize,
        options: &ViewOptions<'_>,
    ) -> Result<String, TreeRefusal> {
        if !under.is_empty() {
            let node = self.node_at(under).ok_or_else(|| TreeRefusal {
                code: TreeRefusalCode::UnknownPath,
                message: format!("no branch at \"{under}\""),
                nearest: self.nearest_paths(under, options),
                needs: None,
            })?;
            if let Some(refusal) = node.outside_grant(options.hidden) {
                return Err(refusal);
            }
        }
        let (total, hits) = self.search_verbs(query, under, limit, options);
        let scope = if under.is_empty() {
            String::new()
        } else {
            format!(" under {under}")
        };
        if total == 0 {
            let branch = if under.is_empty() { "vault" } else { under };
            return Ok(format!(
                "0 verbs match \"{query}\"{scope}. Search reads verb names and their one-line descriptions: try the noun \
                 (claim, note, task, mail) and one action word, or verbs.expand(\"{branch}\") to read the branch names."
            ));
        }
        let plural = if total == 1 { "" } else { "s" };
        let mut lines = vec![format!(
            "{total} verb{plural} match \"{query}\"{scope}; best {}:",
            hits.len()
        )];
        for path in &hits {
            if let Some(mut line) = self.line(path) {
                if self.authored_base(path, options).is_some() {
                    line.push_str("   [base: in your setup text]");
                }
                lines.push(line);
            }
        }
        if total > hits.len() {
            let more = total - hits.len();
            let quoted = serde_json::to_string(query).unwrap_or_default();
            if !under.is_empty() {
                lines.push(format!(
                    "{more} more; raise the limit: verbs.search({quoted}, {{ under: \"{under}\", limit: {} }})",
                    total.min(40)
                ));
            } else if let Some(branch) = hits
                .iter()
                .map(|path| path.split('.').take(2).collect::<Vec<_>>().join("."))
                .find(|path| {
                    !options.hidden.contains_key(path)
                        && self
                            .node_at(path)
                            .is_some_and(|node| node.has_visible_children(options.hidden))
                })
            {
                lines.push(format!(
                    "{more} more; narrow it: verbs.search({quoted}, {{ under: \"{branch}\" }})"
                ));
            }
        }
        Ok(lines.join("\n"))
    }
}
