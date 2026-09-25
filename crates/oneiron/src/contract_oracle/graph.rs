//! Workspace dependency closure from resolved `cargo metadata --format-version 1` JSON.
use super::invalid;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Component, Path};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedTests {
    /// Cargo package IDs, not ambiguous or renamed dependency spellings.
    pub packages: BTreeSet<String>,
    pub targets: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceGraph {
    roots: BTreeMap<String, String>,
    downstream: BTreeMap<String, BTreeSet<String>>,
    targets: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Deserialize)]
struct Metadata {
    workspace_root: String,
    workspace_members: Vec<String>,
    packages: Vec<Package>,
    resolve: Option<Resolve>,
}
#[derive(Deserialize)]
struct Package {
    id: String,
    manifest_path: String,
    targets: Vec<Target>,
}
#[derive(Deserialize)]
struct Target {
    name: String,
    test: bool,
}
#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<ResolveNode>,
}
#[derive(Deserialize)]
struct ResolveNode {
    id: String,
    dependencies: Vec<String>,
}

impl WorkspaceGraph {
    /// The caller supplies resolved metadata from the exact candidate workspace.
    /// `--no-deps` metadata without a resolve graph is refused, not approximated.
    pub fn from_cargo_metadata(json: &[u8]) -> Result<Self> {
        if json.len() > 32 * 1024 * 1024 {
            return Err(invalid("Cargo metadata exceeds limit"));
        }
        let metadata: Metadata =
            serde_json::from_slice(json).map_err(|_| invalid("invalid Cargo metadata JSON"))?;
        let resolve = metadata
            .resolve
            .ok_or_else(|| invalid("Cargo metadata must include resolve graph"))?;
        let members: BTreeSet<_> = metadata.workspace_members.into_iter().collect();
        if members.len() > 10_000 {
            return Err(invalid("workspace exceeds oracle limit"));
        }
        let mut roots = BTreeMap::new();
        let mut targets = BTreeMap::new();
        for package in metadata
            .packages
            .into_iter()
            .filter(|p| members.contains(&p.id))
        {
            let directory = Path::new(&package.manifest_path)
                .parent()
                .ok_or_else(|| invalid("manifest path has no directory"))?;
            let relative = directory
                .strip_prefix(&metadata.workspace_root)
                .map_err(|_| invalid("workspace member outside workspace root"))?;
            if relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(invalid("workspace package path is not normalized"));
            }
            roots.insert(
                package.id.clone(),
                relative.to_string_lossy().replace('\\', "/"),
            );
            targets.insert(
                package.id,
                package
                    .targets
                    .into_iter()
                    .filter(|t| t.test)
                    .map(|t| t.name)
                    .collect(),
            );
        }
        if roots.keys().cloned().collect::<BTreeSet<_>>() != members {
            return Err(invalid("workspace metadata omits a member"));
        }
        let mut downstream: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for node in resolve.nodes {
            if !members.contains(&node.id) {
                continue;
            }
            seen.insert(node.id.clone());
            // Include normal, build and dev edges. Cargo has already resolved renames,
            // workspace inheritance, target conditions and path dependency identities.
            for dependency in node.dependencies {
                if members.contains(&dependency) {
                    downstream
                        .entry(dependency)
                        .or_default()
                        .insert(node.id.clone());
                }
            }
        }
        if seen != members {
            return Err(invalid("resolve graph omits a workspace member"));
        }
        Ok(Self {
            roots,
            downstream,
            targets,
        })
    }

    pub fn affected_tests<S: AsRef<str>>(
        &self,
        changed_files: impl IntoIterator<Item = S>,
    ) -> Result<AffectedTests> {
        let mut affected = BTreeSet::new();
        for file in changed_files {
            let file = file.as_ref();
            if file.is_empty()
                || Path::new(file)
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(invalid("changed path must be normalized and relative"));
            }
            if matches!(file, "Cargo.lock" | "Cargo.toml" | "rust-toolchain.toml")
                || file.starts_with(".cargo/")
            {
                affected.extend(self.roots.keys().cloned());
                continue;
            }
            let max_length = self
                .roots
                .values()
                .filter(|directory| owns(directory, file))
                .map(String::len)
                .max();
            if let Some(length) = max_length {
                affected.extend(
                    self.roots
                        .iter()
                        .filter(|(_, dir)| dir.len() == length && owns(dir, file))
                        .map(|(id, _)| id.clone()),
                );
            }
        }
        let mut queue: VecDeque<_> = affected.iter().cloned().collect();
        while let Some(id) = queue.pop_front() {
            if let Some(dependents) = self.downstream.get(&id) {
                for dependent in dependents {
                    if affected.insert(dependent.clone()) {
                        queue.push_back(dependent.clone());
                    }
                }
            }
        }
        let targets = affected
            .iter()
            .filter_map(|id| {
                self.targets
                    .get(id)
                    .map(|targets| (id.clone(), targets.clone()))
            })
            .collect();
        Ok(AffectedTests {
            packages: affected,
            targets,
        })
    }
}

fn owns(directory: &str, file: &str) -> bool {
    directory.is_empty()
        || file
            .strip_prefix(directory)
            .is_some_and(|tail| tail.starts_with('/'))
}
