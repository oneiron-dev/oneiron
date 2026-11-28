use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer};

use super::{TreeRefusal, TreeRefusalCode, VerbTree};

#[derive(Debug, Deserialize)]
pub(super) struct Index {
    pub revision: String,
    pub verbs: BTreeMap<String, VerbRow>,
    pub types: BTreeMap<String, String>,
    pub families: BTreeMap<String, String>,
    #[serde(deserialize_with = "ordered_capabilities")]
    pub vault_capabilities: Vec<(String, Vec<String>)>,
    pub head: String,
    pub base: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct VerbRow {
    pub description: String,
    pub input: String,
    pub output: String,
    pub example: Option<String>,
}

fn ordered_capabilities<'de, D>(deserializer: D) -> Result<Vec<(String, Vec<String>)>, D::Error>
where
    D: Deserializer<'de>,
{
    // serde_json preserves object insertion order in this workspace.
    let labels = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
    labels
        .into_iter()
        .map(|(label, members)| {
            serde_json::from_value(members)
                .map(|members| (label, members))
                .map_err(serde::de::Error::custom)
        })
        .collect()
}

#[derive(Debug, Default)]
pub(super) struct Node {
    pub path: String,
    pub name: String,
    pub callable: bool,
    pub children: BTreeMap<String, Node>,
}

impl Node {
    fn insert(&mut self, path: &str) {
        let mut node = self;
        let mut prefix = String::new();
        for segment in path.split('.') {
            if !prefix.is_empty() {
                prefix.push('.');
            }
            prefix.push_str(segment);
            node = node
                .children
                .entry(segment.to_owned())
                .or_insert_with(|| Self {
                    path: prefix.clone(),
                    name: segment.to_owned(),
                    ..Self::default()
                });
        }
        node.callable = true;
    }

    pub(super) fn visible_verb(&self, hidden: &BTreeMap<String, String>) -> bool {
        self.callable && !hidden.contains_key(&self.path)
    }

    pub(super) fn visible_count(&self, hidden: &BTreeMap<String, String>) -> usize {
        usize::from(self.visible_verb(hidden))
            + self
                .children
                .values()
                .map(|child| child.visible_count(hidden))
                .sum::<usize>()
    }

    pub(super) fn has_visible_children(&self, hidden: &BTreeMap<String, String>) -> bool {
        self.children
            .values()
            .any(|child| child.visible_count(hidden) > 0)
    }

    pub(super) fn ordered_children<'a>(
        &'a self,
        hidden: &BTreeMap<String, String>,
    ) -> Vec<&'a Self> {
        let mut children: Vec<_> = self
            .children
            .values()
            .filter(|child| child.visible_count(hidden) > 0)
            .collect();
        children.sort_by(|a, b| name_order(&a.name, &b.name));
        children
    }

    pub(super) fn outside_grant(&self, hidden: &BTreeMap<String, String>) -> Option<TreeRefusal> {
        let mut grants = BTreeSet::new();
        if self.visible_count(hidden) == 0 {
            self.collect_grants(hidden, &mut grants);
        }
        if grants.is_empty() {
            return None;
        }
        let needs = grants.into_iter().collect::<Vec<_>>().join(", ");
        Some(TreeRefusal {
            code: TreeRefusalCode::OutsideGrant,
            message: format!("{} is outside this grant: it needs {needs}", self.path),
            nearest: Vec::new(),
            needs: Some(needs),
        })
    }

    fn collect_grants<'a>(
        &self,
        hidden: &'a BTreeMap<String, String>,
        grants: &mut BTreeSet<&'a str>,
    ) {
        if self.callable
            && let Some(grant) = hidden.get(&self.path)
        {
            grants.insert(grant.as_str());
        }
        for child in self.children.values() {
            child.collect_grants(hidden, grants);
        }
    }
}

// The stand-in uses localeCompare for these ASCII names and paths. Compare
// letters by their lowercase form first; underscores sort before dots.
pub(super) fn name_order(a: &str, b: &str) -> std::cmp::Ordering {
    fn weight(byte: u8) -> u8 {
        match byte {
            b'_' => 0,
            b'.' => 1,
            _ => byte.to_ascii_lowercase(),
        }
    }
    a.bytes()
        .map(weight)
        .cmp(b.bytes().map(weight))
        .then_with(|| {
            a.bytes()
                .map(|byte| byte.is_ascii_uppercase())
                .cmp(b.bytes().map(|byte| byte.is_ascii_uppercase()))
        })
}

impl VerbTree {
    pub(super) fn from_discovery_index(index: Index) -> Self {
        let mut root = Node::default();
        for path in index.verbs.keys() {
            root.insert(path);
        }
        Self { index, root }
    }

    pub(super) fn parse_index(json: &str) -> Result<Self, String> {
        let index: Index = serde_json::from_str(json)
            .map_err(|error| format!("invalid verb tree index: {error}"))?;
        let mut root = Node::default();
        for path in index.verbs.keys() {
            root.insert(path);
        }
        Ok(Self { index, root })
    }

    pub(super) fn node_at(&self, path: &str) -> Option<&Node> {
        if path.is_empty() {
            return Some(&self.root);
        }
        path.split('.')
            .try_fold(&self.root, |node, part| node.children.get(part))
    }
}
