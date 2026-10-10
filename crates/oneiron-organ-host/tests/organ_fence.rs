//! OF-060 F4: the engine never depends on an organ, and an organ never
//! depends on the engine (ARCH-0075 section 9, `docengine:organ-host`).
//!
//! An organ crate says so in its manifest: `[package.metadata.oneiron]
//! organ = true`. The fence walks workspace path dependencies (normal and
//! build, every target table; dev-dependencies are test-only and excluded)
//! from each engine root and from each organ.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Crates that run the engine. None may reach an organ.
const ENGINE_ROOTS: [&str; 4] = [
    "oneiron",
    "oneiron-server",
    "oneiron-organ-host",
    "oneiron-organ-protocol",
];

/// What an organ may never reach.
const ENGINE_CRATES: [&str; 3] = ["oneiron", "oneiron-server", "oneiron-organ-host"];

/// Organs still compiled into the engine, each waiting for its move behind
/// the host. Each move PR deletes its name; the list only shrinks.
const PENDING_MOVE: [&str; 3] = ["oneiron-seal", "oneiron-docedit", "oneiron-xlsx-formula"];

/// Organs that run behind the host. Each must say so in its manifest, so the
/// fence walks it; the list only grows.
const HOSTED: [&str; 1] = ["oneiron-image"];

struct Manifest {
    organ: bool,
    /// Workspace crates this one reaches through normal or build deps.
    deps: BTreeSet<String>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits at crates/<name>")
        .to_path_buf()
}

fn path_deps(table: Option<&toml::Value>, into: &mut BTreeSet<String>) {
    let Some(table) = table.and_then(toml::Value::as_table) else {
        return;
    };
    for (name, spec) in table {
        let Some(spec) = spec.as_table() else {
            continue;
        };
        if spec.contains_key("path") {
            let package = spec
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(name);
            into.insert(package.to_owned());
        }
    }
}

fn read_manifests() -> BTreeMap<String, Manifest> {
    let crates = workspace_root().join("crates");
    let mut manifests = BTreeMap::new();
    for entry in std::fs::read_dir(&crates).expect("read crates/") {
        let path = entry.expect("dir entry").path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let doc: toml::Value = text.parse().expect("manifest parses");
        let Some(name) = doc
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
        else {
            continue;
        };
        let organ = doc
            .get("package")
            .and_then(|package| package.get("metadata"))
            .and_then(|metadata| metadata.get("oneiron"))
            .and_then(|oneiron| oneiron.get("organ"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let mut deps = BTreeSet::new();
        for key in ["dependencies", "build-dependencies"] {
            path_deps(doc.get(key), &mut deps);
        }
        if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
            for target in targets.values() {
                for key in ["dependencies", "build-dependencies"] {
                    path_deps(target.get(key), &mut deps);
                }
            }
        }
        manifests.insert(name.to_owned(), Manifest { organ, deps });
    }
    manifests
}

/// Every workspace crate `root` reaches, with one path to each.
fn reach(manifests: &BTreeMap<String, Manifest>, root: &str) -> BTreeMap<String, Vec<String>> {
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stack = vec![vec![root.to_owned()]];
    while let Some(path) = stack.pop() {
        let Some(last) = path.last() else { continue };
        let Some(manifest) = manifests.get(last) else {
            continue;
        };
        for dep in &manifest.deps {
            if seen.contains_key(dep) || dep == root {
                continue;
            }
            let mut next = path.clone();
            next.push(dep.clone());
            seen.insert(dep.clone(), next.clone());
            stack.push(next);
        }
    }
    seen
}

#[test]
fn of060_f4_engine_never_depends_on_an_organ() {
    let manifests = read_manifests();
    let organs: BTreeSet<&str> = manifests
        .iter()
        .filter(|(_, manifest)| manifest.organ)
        .map(|(name, _)| name.as_str())
        .chain(PENDING_MOVE)
        .collect();
    let mut violations = Vec::new();
    for root in ENGINE_ROOTS {
        assert!(manifests.contains_key(root), "engine root {root} not found");
        for (dep, path) in reach(&manifests, root) {
            // A pending organ is excused only on its edge from the engine
            // crate (or from another pending organ), never anywhere new.
            let via = path.len().checked_sub(2).and_then(|at| path.get(at));
            let pending = PENDING_MOVE.contains(&dep.as_str())
                && via.is_some_and(|via| via == "oneiron" || PENDING_MOVE.contains(&via.as_str()));
            if organs.contains(dep.as_str()) && !pending {
                violations.push(path.join(" -> "));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "OF-060 F4: an engine crate reaches an organ:\n{}",
        violations.join("\n"),
    );
}

#[test]
fn of060_f4_organs_never_depend_on_the_engine() {
    let manifests = read_manifests();
    let mut violations = Vec::new();
    for (name, manifest) in &manifests {
        if !manifest.organ {
            continue;
        }
        for (dep, path) in reach(&manifests, name) {
            if ENGINE_CRATES.contains(&dep.as_str()) {
                violations.push(path.join(" -> "));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "OF-060 F4: an organ reaches the engine:\n{}",
        violations.join("\n"),
    );
}

#[test]
fn of060_f4_pending_moves_are_still_real() {
    // A moved organ must leave the pending list in the same PR, so the list
    // never excuses an edge that no longer exists.
    let manifests = read_manifests();
    let engine = reach(&manifests, "oneiron");
    for pending in PENDING_MOVE {
        assert!(
            engine.contains_key(pending),
            "{pending} no longer sits under oneiron: delete it from PENDING_MOVE",
        );
    }
}

#[test]
fn of060_f4_hosted_organs_are_marked() {
    // An unmarked organ would drop out of both walks above unseen.
    let manifests = read_manifests();
    for organ in HOSTED {
        assert!(
            manifests.get(organ).is_some_and(|manifest| manifest.organ),
            "{organ} must mark [package.metadata.oneiron] organ = true",
        );
    }
}
