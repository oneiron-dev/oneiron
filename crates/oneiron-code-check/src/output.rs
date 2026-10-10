//! Reads `tsc --pretty false` output. Both backends print it byte for byte
//! alike, so one reader serves both.

use crate::{CheckFailure, Diagnostic, PROGRAM_FILE};

const CATEGORIES: [&str; 4] = ["error", "warning", "suggestion", "message"];

/// The diagnostics of one check, in program coordinates.
pub(crate) fn diagnostics(stdout: &[u8]) -> Result<Vec<Diagnostic>, CheckFailure> {
    let text = std::str::from_utf8(stdout).map_err(|_| CheckFailure::UnreadableOutput)?;
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        // A message chain continues on indented lines.
        if line.starts_with(' ') {
            let previous = diagnostics
                .last_mut()
                .ok_or(CheckFailure::UnreadableOutput)?;
            previous.message.push('\n');
            previous.message.push_str(line);
            continue;
        }
        diagnostics.push(diagnostic(line).ok_or(CheckFailure::UnreadableOutput)?);
    }
    Ok(diagnostics)
}

/// `file(line,column): category TScode: message`, or the same without the
/// place for a diagnostic about the whole check.
fn diagnostic(line: &str) -> Option<Diagnostic> {
    let (place, rest) = match line.split_once("): ") {
        Some((place, rest)) if !CATEGORIES.iter().any(|c| line.starts_with(c)) => {
            (Some(place), rest)
        }
        _ => (None, line),
    };
    let (category, rest) = rest.split_once(" TS")?;
    let (code, message) = rest.split_once(": ")?;
    if !CATEGORIES.contains(&category) {
        return None;
    }
    let code = code.parse().ok()?;
    let (file, line, column) = match place {
        None => (None, 0, 0),
        Some(place) => {
            let (file, position) = place.rsplit_once('(')?;
            let (line, column) = position.split_once(',')?;
            let line: u32 = line.parse().ok()?;
            // The envelope's first line precedes the program.
            let line = if file == PROGRAM_FILE {
                line.checked_sub(1)?
            } else {
                line
            };
            (Some(file.to_owned()), line, column.parse().ok()?)
        }
    };
    Some(Diagnostic {
        file,
        line,
        column,
        category: category.to_owned(),
        code,
        message: message.to_owned(),
    })
}
