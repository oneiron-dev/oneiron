//! Keeps scoped-read implementation ownership out of the run adapters.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            rust_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn code_without_comments(line: &str, block_depth: &mut usize) -> String {
    let mut code = Vec::new();
    let mut bytes = line.bytes().peekable();
    while let Some(byte) = bytes.next() {
        match (byte, bytes.peek().copied()) {
            (b'/', Some(b'*')) => {
                let _ = bytes.next();
                *block_depth += 1;
            }
            (b'*', Some(b'/')) if *block_depth > 0 => {
                let _ = bytes.next();
                *block_depth -= 1;
            }
            (b'/', Some(b'/')) if *block_depth == 0 => break,
            _ if *block_depth == 0 => code.push(byte),
            _ => {}
        }
    }
    String::from_utf8_lossy(&code).into_owned()
}

#[test]
fn scoped_read_implementations_are_owned_by_run_rows() -> io::Result<()> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for directory in ["src/code_run", "src/engine_executor"] {
        let mut files = Vec::new();
        rust_files(&manifest.join(directory), &mut files)?;
        assert!(!files.is_empty(), "no Rust files scanned in {directory}");
        files.sort();
        for file in files {
            let source = fs::read_to_string(&file)?;
            let mut block_depth = 0;
            for (index, line) in source.lines().enumerate() {
                let code = code_without_comments(line, &mut block_depth);
                if code.contains("with_claim_status(") || code.contains("persist_grant_clock(") {
                    violations.push(format!("{}:{}", file.display(), index + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "run adapters still own scoped-read implementations:\n{}",
        violations.join("\n")
    );
    Ok(())
}
