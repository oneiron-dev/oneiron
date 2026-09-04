//! ONE-1441 §Test/Shared #7 — `bindings_depend_on_one_http_stack`.
//!
//! One HTTP stack, owned here. The binding crates reach the network THROUGH
//! this crate or not at all, and neither language wrapper carries a client of
//! its own. The check is a source and manifest scan rather than a comment,
//! because "we agreed not to" is not a property a build can verify.

use std::path::{Path, PathBuf};

/// Every HTTP client a binding might reach for.
const HTTP_CRATES: [&str; 5] = ["reqwest", "ureq", "hyper", "isahc", "curl"];

/// Client vocabulary that must not appear in the JavaScript wrapper.
const JS_CLIENTS: [&str; 4] = ["fetch(", "axios", "XMLHttpRequest", "node:http"];

/// Client vocabulary that must not appear in the Python wrapper.
const PY_CLIENTS: [&str; 4] = ["requests", "httpx", "urllib", "http.client"];

/// The workspace root, derived from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root")
}

/// Reads a file, or returns `None` when the artifact is not present yet.
fn read_optional(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// This crate declares exactly one of the known HTTP clients.
#[test]
fn oneiron_remote_owns_one_http_stack() {
    let manifest = read_optional(&workspace_root().join("crates/oneiron-remote/Cargo.toml"))
        .expect("oneiron-remote manifest");
    let declared: Vec<&str> = HTTP_CRATES
        .into_iter()
        .filter(|crate_name| manifest.contains(&format!("\n{crate_name} = ")))
        .collect();
    assert_eq!(
        declared.len(),
        1,
        "oneiron-remote must declare exactly one HTTP client, found {declared:?}"
    );
}

/// No binding crate declares an HTTP client directly.
#[test]
fn binding_crates_declare_no_http_client() {
    let root = workspace_root();
    for manifest_path in [
        "crates/oneiron-napi/Cargo.toml",
        "crates/oneiron-py/Cargo.toml",
    ] {
        let Some(manifest) = read_optional(&root.join(manifest_path)) else {
            continue;
        };
        for crate_name in HTTP_CRATES {
            assert!(
                !manifest.contains(&format!("\n{crate_name} = ")),
                "{manifest_path} must not depend on {crate_name} directly; \
                 it reaches the network through oneiron-remote"
            );
        }
    }
}

/// Recursively collects source files under `dir` with one of `extensions`.
fn collect_sources(dir: &Path, extensions: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, extensions, out);
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.contains(&ext))
        {
            out.push(path);
        }
    }
}

/// The JavaScript wrapper contains no HTTP client.
#[test]
fn javascript_wrapper_has_no_http_client() {
    let mut sources = Vec::new();
    collect_sources(
        &workspace_root().join("packages/oneiron/src"),
        &["ts", "mjs", "js"],
        &mut sources,
    );
    for source in sources {
        let body = std::fs::read_to_string(&source).expect("readable source");
        for needle in JS_CLIENTS {
            assert!(
                !body.contains(needle),
                "{} must not contain {needle:?}; the SDK's one HTTP stack is in oneiron-remote",
                source.display()
            );
        }
    }
}

/// The Python wrapper contains no HTTP client.
#[test]
fn python_wrapper_has_no_http_client() {
    let mut sources = Vec::new();
    collect_sources(
        &workspace_root().join("crates/oneiron-py/python"),
        &["py", "pyi"],
        &mut sources,
    );
    for source in sources {
        let body = std::fs::read_to_string(&source).expect("readable source");
        for needle in PY_CLIENTS {
            assert!(
                !body.contains(needle),
                "{} must not contain {needle:?}; the SDK's one HTTP stack is in oneiron-remote",
                source.display()
            );
        }
    }
}

/// The public wrapper surfaces use facade vocabulary, never storage vocabulary
/// (§Test/Embedded fitness scan).
#[test]
fn wrappers_use_no_storage_vocabulary() {
    const BANNED: [&str; 4] = [
        "put_replicated",
        "Vault::put_",
        "BatchBuilder",
        "put_entity",
    ];
    let root = workspace_root();
    let mut sources = Vec::new();
    collect_sources(&root.join("packages/oneiron/src"), &["ts"], &mut sources);
    collect_sources(
        &root.join("crates/oneiron-py/python"),
        &["py", "pyi"],
        &mut sources,
    );
    for source in sources {
        let body = std::fs::read_to_string(&source).expect("readable source");
        for needle in BANNED {
            assert!(
                !body.contains(needle),
                "{} must not name storage primitive {needle:?}",
                source.display()
            );
        }
    }
}
