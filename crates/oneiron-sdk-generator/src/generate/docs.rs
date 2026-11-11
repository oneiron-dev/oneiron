//! Port of packages/oneiron/scripts/agent-docs.py:49-65 (generated_artifacts) and :129-135 (write): the three
//! agent-SDK reference docs a `--out-dir` run writes beside its outputs (Engine ruling SDKGEN-DOCS = A: the Rust
//! `--out-dir` writes them itself, where Python's spawned `agent-docs.py --from <dir> --out <dir>`).
//!
//! `agent-docs.py` reads two of its inputs from the outputs just written (`--from <dir>`): so does this port, after
//! the writes, with `read_text`.

use std::path::Path;

use super::outputs::join;
use crate::error::GenerateError;
use crate::py::read_text;
use crate::py::value::Value;
use crate::verb_table::load_verbs;

/// agent-docs.py:20 (GENERATED): the generated mirror files, in `generated_artifacts`' order.
pub(crate) const GENERATED: [&str; 3] = [
    "docs/agent-sdk/types.md",
    "docs/agent-sdk/facade-types.md",
    "docs/agent-sdk/verbs.md",
];

/// agent-docs.py:58: the head of `verbs.md`.
const CENSUS_HEAD: &str = "# Memory Wire facade census\n\nThis is the complete **shipped SDK facade**, in verb-name order. It is\nnot a claim that every engine-internal method is a public SDK verb.\n`scripts/sdk/verbs/` owns this list.\nNames are stable: a new export or rename must update the engine catalog,\nboth bindings and their export-census tests in one change.\n\n";

/// Port of agent-docs.py:49-65 (generated_artifacts): the mirror files made from the verb table and the generated SDK
/// outputs: `types.md`, `facade-types.md` and `verbs.md`, in that order. `src` is the `--from` directory (the
/// `--out-dir` just written): `crates/oneiron-py/python/oneiron/_facade_verbs.pyi` and
/// `packages/oneiron/src/facade-types.ts` are read back from it after the writes, as Python's child reads them (so
/// two outputs that are one file, a hard link or a symlink, give the text written last), in Python's read order.
pub(crate) fn generated_artifacts(
    root: &Path,
    src: &Path,
) -> Result<[(&'static str, String); 3], GenerateError> {
    let ts = read_text(&root.join("packages/oneiron/src/types.ts"))?;
    let mut py = read_text(&root.join("crates/oneiron-py/python/oneiron/__init__.pyi"))?;
    py += &read_text(&join(
        src,
        "crates/oneiron-py/python/oneiron/_facade_verbs.pyi",
    ))?;
    let facade_ts = read_text(&join(src, "packages/oneiron/src/facade-types.ts"))?;
    // agent-docs.py:56-57: the verb files again, in sorted path order, each `json.loads(path.read_text())`; the
    // memory rows' names. The module level read and checked the same files, so `load_verbs` reads them as Python's
    // loop does (its name check holds again).
    let rows = load_verbs(&root.join("scripts/sdk/verbs"))?;
    let mut census = CENSUS_HEAD.to_owned();
    let mut verbs = Vec::new();
    for row in &rows {
        let memory = row
            .get("context")
            .is_none_or(|context| context.is_str("memory"));
        if memory {
            let name = row.get("name").map_or_else(String::new, Value::str);
            verbs.push(format!("- `{name}`"));
        }
    }
    census += &verbs.join("\n");
    census.push('\n');
    let [types, facade_types, verbs_md] = GENERATED;
    Ok([
        (
            types,
            format!(
                "# Memory Wire type contract\n\n## JavaScript / TypeScript\n\n```ts\n{ts}```\n\n## Python\n\n```python\n{py}```\n"
            ),
        ),
        (
            facade_types,
            format!(
                "# Memory Wire facade types\n\nThe Python stubs carry the same names in the generated `facade_types.pyi`.\n\n```ts\n{facade_ts}```\n"
            ),
        ),
        (verbs_md, census),
    ])
}

/// Port of agent-docs.py:129-135 (write): each file under `out`, unless it is there with that text already (read with
/// universal newlines, so a CRLF copy of the same text stays as it is).
pub(crate) fn write(files: &[(&str, String)], out: &Path) -> Result<(), GenerateError> {
    for (name, contents) in files {
        let path = join(out, name);
        if path.exists() && read_text(&path)? == *contents {
            continue;
        }
        if let Some(parent) = path.parent() {
            super::outputs::mkdir_parents(parent)?;
        }
        super::outputs::write_text(&path, contents)?;
    }
    Ok(())
}
