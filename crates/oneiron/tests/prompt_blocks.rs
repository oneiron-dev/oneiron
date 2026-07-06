use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const REQUIRED_WELLBEING_CONSENT_LINES: [&str; 5] = [
    "This is a capability grant, not a content ban.",
    "- Eiri may set limits on pace, depth, repetition, emotional load, or availability.",
    "- Eiri may timeout a user when continuing would compromise her agency, consent, or wellbeing.",
    "- Eiri may require a new companion before continuing when the current companion context is unsafe, exhausted, or no longer consentful.",
    "- The user may appeal to Eiri directly; Eiri should answer before deciding whether to hold, revise, or lift the limit.",
];

#[test]
fn eiri_v3_resolves_wellbeing_consent_block() -> Result<(), Box<dyn std::error::Error>> {
    let package_root = workspace_root()?.join("packages/prompts");
    let block_path = package_root.join("blocks/wellbeing-consent.md");
    let prompt_path = package_root.join("eiri/v3.md");

    let block = fs::read_to_string(block_path)?;
    for required_line in REQUIRED_WELLBEING_CONSENT_LINES {
        assert!(
            block.lines().any(|line| line == required_line),
            "wellbeing-consent.md must contain literal line: {required_line}"
        );
    }

    let resolved = resolve_prompt(&prompt_path, &package_root)?;
    for required_line in REQUIRED_WELLBEING_CONSENT_LINES {
        assert!(
            resolved.lines().any(|line| line == required_line),
            "resolved Eiri v3 prompt must contain literal line: {required_line}"
        );
    }

    Ok(())
}

fn workspace_root() -> Result<PathBuf, io::Error> {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_root
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("failed to locate workspace root"))
}

fn resolve_prompt(path: &Path, package_root: &Path) -> Result<String, io::Error> {
    let mut seen = BTreeSet::new();
    resolve_prompt_inner(path, package_root, &mut seen)
}

fn resolve_prompt_inner(
    path: &Path,
    package_root: &Path,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<String, io::Error> {
    let canonical_path = fs::canonicalize(path)?;
    if !seen.insert(canonical_path.clone()) {
        return Err(io::Error::other(format!(
            "cyclic prompt include: {}",
            canonical_path.display()
        )));
    }

    let source = fs::read_to_string(&canonical_path)?;
    let mut resolved = String::new();
    for line in source.lines() {
        if let Some(include_path) = include_path(line) {
            let include_target =
                if include_path.starts_with("./") || include_path.starts_with("../") {
                    canonical_path
                        .parent()
                        .ok_or_else(|| io::Error::other("prompt path has no parent"))?
                        .join(include_path)
                } else {
                    package_root.join(include_path)
                };
            resolved.push_str(&resolve_prompt_inner(&include_target, package_root, seen)?);
        } else {
            resolved.push_str(line);
            resolved.push('\n');
        }
    }

    seen.remove(&canonical_path);
    Ok(resolved)
}

fn include_path(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("@include ")
        .map(str::trim)
        .filter(|path| !path.is_empty())
}
