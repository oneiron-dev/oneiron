//! Port of generate.py:2241-2604 (`outputs`) and of `main`'s `--out-dir` branch (generate.py:2950-2958): G4b ports
//! both whole. Until then they hold the outputs the PRs below G4b port as real outputs: the code-mode catalog
//! fragment (G2).

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

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
    // argparse's `type=Path`: the directory as Python spells it in a message.
    let dir = pure_path(dir);
    for (path, text) in generator.outputs()? {
        let Some(text) = text else {
            continue;
        };
        // target = args.out_dir/path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(text)
        let target = if dir == Path::new(".") {
            PathBuf::from(path)
        } else {
            dir.join(path)
        };
        mkdir_parents(&parent(&target))?;
        std::fs::write(&target, text).map_err(|error| GenerateError::os(&error, &target))?;
    }
    Ok(())
}

/// `pathlib.PurePosixPath(dir)`: the path Python's `Path` spells, lexically normalised: no `.` parts, no repeated or
/// trailing separator, `.` for nothing; a leading `//` (exactly two) stays, as POSIX lets it mean another root. It
/// resolves nothing (`..` and symlinks stay).
fn pure_path(dir: &Path) -> PathBuf {
    let bytes = dir.as_os_str().as_encoded_bytes();
    let mut out = PathBuf::new();
    for component in dir.components() {
        match component {
            Component::RootDir if bytes.starts_with(b"//") && !bytes.starts_with(b"///") => {
                out.push("//");
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// `PurePath.parent`: `.` above a relative path's first part; the root is its own parent.
fn parent(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
        Some(parent) => parent.to_path_buf(),
        None => path.to_path_buf(),
    }
}

/// Port of `Path.mkdir(parents=True, exist_ok=True)` (CPython 3.14 pathlib): `os.mkdir`; on a missing parent the
/// parents first, then this one again; any other failure is none when the path is a directory. The failure Python
/// raises names the directory it failed on.
fn mkdir_parents(path: &Path) -> Result<(), GenerateError> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let above = parent(path);
            if above == path {
                return Err(GenerateError::os(&error, path));
            }
            mkdir_parents(&above)?;
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() != ErrorKind::NotFound && path.is_dir() => Ok(()),
                Err(error) => Err(GenerateError::os(&error, path)),
            }
        }
        Err(_) if path.is_dir() => Ok(()),
        Err(error) => Err(GenerateError::os(&error, path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_path_spells_the_path_as_python() {
        // python3 -c "from pathlib import Path; [print(repr(s), repr(str(Path(s)))) for s in
        //   ['./out', 'a/./b', '//a', '///a', 'a//b/', '.', '', '../x/./y', '/']]"
        for (dir, expected) in [
            ("./out", "out"),
            ("a/./b", "a/b"),
            ("//a", "//a"),
            ("///a", "/a"),
            ("a//b/", "a/b"),
            (".", "."),
            ("", "."),
            ("../x/./y", "../x/y"),
            ("/", "/"),
        ] {
            assert_eq!(pure_path(Path::new(dir)), Path::new(expected), "{dir:?}");
        }
        // str(Path('x.ts').parent), str(Path('/').parent)
        assert_eq!(parent(Path::new("x.ts")), Path::new("."));
        assert_eq!(parent(Path::new("/")), Path::new("/"));
    }
}
