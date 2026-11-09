//! Port of generate.py:2241-2604 (`outputs`) and of `main`'s `--out-dir` branch (generate.py:2950-2958): G4b ports
//! both whole. Until then they hold the outputs the PRs below G4b port as real outputs: the code-mode catalog
//! fragment (G2).

use std::path::Path;

use super::{Generator, HEADER};
use crate::catalog_fragment::catalog_fragment;
use crate::error::GenerateError;

impl Generator {
    /// Partial port of generate.py:2241-2604 (`outputs`): each output's repo path and text (`None` for a deletion),
    /// in the order of Python's `files` dict. So far only generate.py:2582-2585, the catalog fragment over
    /// `CODE_MODE_ROWS` with its own inventory (G2). G4b: every output, in Python's call order.
    pub(crate) fn outputs(&self) -> Result<Vec<(&'static str, Option<String>)>, GenerateError> {
        let mut files = Vec::new();
        // generate.py:2585 `files.update(catalog_fragment(ROOT, CODE_MODE_ROWS, HEADER))`
        let rows = self.rows.select(&self.code_mode_rows);
        for (path, text) in catalog_fragment(&self.root, &rows, HEADER, &self.type_names)? {
            files.push((path, Some(text)));
        }
        Ok(files)
    }
}

/// Partial port of generate.py:2950-2958 (`main`, `--out-dir`): writes each output of `outputs()` that is not a
/// deletion to `<dir>/<repo path>`, making its directory first. G4b: every output (this writes only the three of
/// the catalog fragment, G2), then the three agent-SDK docs (SDKGEN-DOCS = A).
pub(crate) fn write_out_dir(root: &Path, dir: &Path) -> Result<(), GenerateError> {
    let generator = Generator::new(root)?;
    for (path, text) in generator.outputs()? {
        let Some(text) = text else {
            continue;
        };
        let target = dir.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| GenerateError::os(&error, parent))?;
        }
        std::fs::write(&target, text).map_err(|error| GenerateError::os(&error, &target))?;
    }
    Ok(())
}
