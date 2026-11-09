//! Port of packages/oneiron/scripts/agent-docs.py:49-65 (generated_artifacts) and :129-135 (write): the three
//! agent-SDK reference docs a `--out-dir` run writes beside its outputs (Engine ruling SDKGEN-DOCS = A: the Rust
//! `--out-dir` writes them itself, where Python's spawned `agent-docs.py --from <dir> --out <dir>`).
//!
//! `agent-docs.py` reads two of its inputs from the outputs just written (`--from <dir>`): here they come from
//! `outputs()` itself, decoded as `read_text()` would decode the files `write_text()` wrote (universal newlines).

use std::path::Path;

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

/// What `Path.read_text()` returns for a file `Path.write_text(text)` wrote: Python reads with universal newlines,
/// so `\r\n` and a lone `\r` come back as `\n`.
fn read_back(text: &str) -> String {
    if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text.to_owned()
    }
}

/// Port of agent-docs.py:49-65 (generated_artifacts): the mirror files made from the verb table and the generated SDK
/// outputs: `types.md`, `facade-types.md` and `verbs.md`, in that order. `facade_verbs_pyi` and `facade_types_ts` are
/// the `outputs()` texts of `crates/oneiron-py/python/oneiron/_facade_verbs.pyi` and
/// `packages/oneiron/src/facade-types.ts`, which Python reads back from the `--out-dir` directory.
pub(crate) fn generated_artifacts(
    root: &Path,
    facade_verbs_pyi: &str,
    facade_types_ts: &str,
) -> Result<[(&'static str, String); 3], GenerateError> {
    let ts = read_text(&root.join("packages/oneiron/src/types.ts"))?;
    let mut py = read_text(&root.join("crates/oneiron-py/python/oneiron/__init__.pyi"))?;
    py += &read_back(facade_verbs_pyi);
    let facade_ts = read_back(facade_types_ts);
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
        let path = super::outputs::join(out, name);
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

#[cfg(test)]
mod tests {
    use super::*;

    // python3 -c "import pathlib; p = pathlib.Path('t'); p.write_text('a\r\nb\rc\n'); print(repr(p.read_text()))"
    #[test]
    fn read_back_is_universal_newlines() {
        assert_eq!(read_back("a\r\nb\rc\n"), "a\nb\nc\n");
        assert_eq!(read_back("plain\n"), "plain\n");
        assert_eq!(read_back("\r\r\n"), "\n\n");
    }
}
