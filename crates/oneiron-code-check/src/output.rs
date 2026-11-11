//! Reads `tsc --pretty false` output. Every backend prints it byte for byte
//! alike, so one reader serves them all, and it reads every message whole.

use crate::{CheckFailure, Diagnostic, PROGRAM_FILES};

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

/// The whole diagnostics of a check that stopped before it ended: every
/// complete line up to the first that is not one, the line the stop cut
/// short dropped.
pub(crate) fn partial_diagnostics(stdout: &[u8]) -> Vec<Diagnostic> {
    let whole = stdout
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(&[][..], |end| &stdout[..end]);
    let text = match std::str::from_utf8(whole) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&whole[..error.valid_up_to()]).unwrap_or_default(),
    };
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') {
            let Some(previous) = diagnostics.last_mut() else {
                break;
            };
            previous.message.push('\n');
            previous.message.push_str(line);
            continue;
        }
        let Some(diagnostic) = diagnostic(line) else {
            break;
        };
        diagnostics.push(diagnostic);
    }
    diagnostics
}

/// `file(line,column): category TScode: message`, or the same without the
/// place for a diagnostic about the whole check.
fn diagnostic(line: &str) -> Option<Diagnostic> {
    located(line).or_else(|| {
        let (category, code, message) = body(line)?;
        Some(Diagnostic {
            file: None,
            line: 0,
            column: 0,
            category: category.to_owned(),
            code,
            message: message.to_owned(),
        })
    })
}

fn located(text: &str) -> Option<Diagnostic> {
    let (place, rest) = text.split_once("): ")?;
    let (file, position) = place.rsplit_once('(')?;
    let (line, column) = position.split_once(',')?;
    let line: u32 = line.parse().ok()?;
    // The envelope's first line precedes the program, in either language.
    let line = if PROGRAM_FILES.contains(&file) {
        line.checked_sub(1)?
    } else {
        line
    };
    let (category, code, message) = body(rest)?;
    Some(Diagnostic {
        file: Some(file.to_owned()),
        line,
        column: column.parse().ok()?,
        category: category.to_owned(),
        code,
        message: message.to_owned(),
    })
}

/// `category TScode: message`.
fn body(text: &str) -> Option<(&str, u32, &str)> {
    let (category, rest) = text.split_once(" TS")?;
    if !CATEGORIES.contains(&category) {
        return None;
    }
    let (code, message) = rest.split_once(": ")?;
    Some((category, code.parse().ok()?, message))
}

#[cfg(test)]
mod tests {
    use super::diagnostics;

    /// tsc's `--pretty false` forms: a placed diagnostic in a declaration
    /// file whose name starts like a category, one in the program (shifted
    /// past the envelope's first line) with a continued message chain, and
    /// one about the whole check.
    #[test]
    fn reads_placed_continued_and_global_diagnostics() {
        let printed = "errors.d.ts(1,23): error TS2304: Cannot find name 'MissingType'.\n\
            program.js(3,5): error TS2322: Type 'number' is not assignable to type 'string'.\n  \
            The expected type comes from property 'text'.\n\
            error TS5023: Unknown compiler option 'x'.\n";
        let found = diagnostics(printed.as_bytes()).unwrap();
        let places: Vec<_> = found
            .iter()
            .map(|d| (d.file.as_deref(), d.line, d.column, d.code))
            .collect();
        assert_eq!(
            places,
            [
                (Some("errors.d.ts"), 1, 23, 2304),
                (Some("program.js"), 2, 5, 2322),
                (None, 0, 0, 5023),
            ]
        );
        assert!(
            found[1]
                .message
                .ends_with("\n  The expected type comes from property 'text'.")
        );
        assert!(diagnostics(b"Segmentation fault\n").is_err());
    }
}
