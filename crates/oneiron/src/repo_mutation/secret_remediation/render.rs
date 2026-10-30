//! The reference a remediation writes where a marked literal stood (FIX
//! 7608 slice 6): an expression in the file's own language that reads the
//! secret's environment variable, which a run is given (slice 7). It
//! replaces the whole quoted literal, so the code keeps its shape.
//!
//! CALL RENDERER-UNRESOLVED: a file form this renderer writes no reference
//! for (a structured config file, an unknown language, a constant context
//! whose language takes no runtime call there) answers `None`. The
//! remediation keeps that key as an explicit unresolved action naming its
//! path, never a guessed patch and never a refusal. A constant context is
//! read by the file's language (FIX 10977): a `const` declaration on the
//! literal's line or opened before it, a `case` label where cases are
//! constants, and an annotation's or attribute's argument.

use super::text::line_before;

/// Writes the reference that stands for one secret's environment variable
/// in a file's code.
#[derive(Debug, Clone, Copy, Default)]
pub struct RepoSecretReferenceRenderer;

impl RepoSecretReferenceRenderer {
    /// The expression that replaces a quoted literal in the file at `path`
    /// whose bytes are `content`, reading the variable `env_name`. `at` is
    /// the literal's opening quote. `None` when the file's form has no
    /// reference this renderer writes (CALL RENDERER-UNRESOLVED).
    #[must_use]
    pub fn reference(path: &str, content: &[u8], at: usize, env_name: &str) -> Option<String> {
        let file = path.rsplit('/').next().unwrap_or(path);
        let extension = file.rsplit_once('.')?.1.to_ascii_lowercase();
        let identifier = env_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        // Each language below whose constants take no runtime call.
        let constant = constant_context(&extension, content, at);
        match extension.as_str() {
            "py" | "pyw" if imports_python_os(content) => {
                Some(format!("os.environ[\"{env_name}\"]"))
            }
            "py" | "pyw" => Some(format!("__import__(\"os\").environ[\"{env_name}\"]")),
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" if identifier => {
                Some(format!("process.env.{env_name}"))
            }
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" => {
                Some(format!("process.env[\"{env_name}\"]"))
            }
            "rb" => Some(format!("ENV.fetch(\"{env_name}\")")),
            // A build-time read: the same `&'static str` a literal is, in
            // a constant too.
            "rs" => Some(format!("env!(\"{env_name}\")")),
            "go" if !constant && imports_go_os(content) => {
                Some(format!("os.Getenv(\"{env_name}\")"))
            }
            "java" | "scala" | "groovy" if !constant => {
                Some(format!("System.getenv(\"{env_name}\")"))
            }
            "kt" | "kts" if !constant => Some(format!("System.getenv(\"{env_name}\")")),
            "cs" if !constant => Some(format!(
                "System.Environment.GetEnvironmentVariable(\"{env_name}\")"
            )),
            "php" if !constant => Some(format!("getenv('{env_name}')")),
            "sh" | "bash" | "zsh" | "ksh" | "envrc" => Some(format!("\"${{{env_name}}}\"")),
            _ => None,
        }
    }
}

/// Whether a Python file binds `os` by a plain `import os`.
fn imports_python_os(content: &[u8]) -> bool {
    content.split(|byte| *byte == b'\n').any(|line| {
        let line = line.trim_ascii();
        line == b"import os" || line.starts_with(b"import os,")
    })
}

/// Whether a Go file imports the `os` package.
fn imports_go_os(content: &[u8]) -> bool {
    content.windows(4).any(|window| window == b"\"os\"")
}

/// Whether the literal at `at` in `content` stands where the language of
/// `extension` takes only a constant: a `const` declaration on its line or
/// one whose statement (or Go `const (` block) opened before it, a `case`
/// label where cases are constants, or an annotation's or attribute's
/// argument.
fn constant_context(extension: &str, content: &[u8], at: usize) -> bool {
    let line = line_before(content, at);
    let statement = statement_before(content, at);
    match extension {
        "go" => has_word(line, b"const") || in_const_block(content, at),
        "java" | "scala" | "groovy" => has_word(line, b"case") || in_argument_of(line, b'@'),
        "kt" | "kts" => has_word(statement, b"const") || in_argument_of(line, b'@'),
        "cs" => {
            has_word(statement, b"const") || has_word(line, b"case") || in_argument_of(line, b'[')
        }
        "php" => has_word(statement, b"const"),
        _ => has_word(line, b"const"),
    }
}

/// Whether `bytes` holds `word` as a whole word.
fn has_word(bytes: &[u8], word: &[u8]) -> bool {
    let part =
        |byte: Option<&u8>| byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    bytes.windows(word.len()).enumerate().any(|(at, window)| {
        window == word
            && !part(at.checked_sub(1).and_then(|prior| bytes.get(prior)))
            && !part(bytes.get(at + word.len()))
    })
}

/// The bytes of the statement the literal at `at` stands in, up to it:
/// from the last `;`, `{` or `}` before it.
fn statement_before(content: &[u8], at: usize) -> &[u8] {
    let head = content.get(..at).unwrap_or_default();
    let start = head
        .iter()
        .rposition(|byte| matches!(byte, b';' | b'{' | b'}'))
        .map_or(0, |end| end + 1);
    head.get(start..).unwrap_or_default()
}

/// Whether the literal at `at` lies inside a Go `const (` block still open
/// there.
fn in_const_block(content: &[u8], at: usize) -> bool {
    let head = content.get(..at).unwrap_or_default();
    let Some(open) = head.windows(5).rposition(|window| window == b"const") else {
        return false;
    };
    let after = &head[open + 5..];
    let rest = after.trim_ascii_start();
    rest.first() == Some(&b'(') && !rest.contains(&b')') && has_word(&head[open..], b"const")
}

/// Whether the literal on `line` lies inside the argument list of an
/// annotation or attribute opened by `opener` (`@Name(`, `[Name(`) still
/// open at it.
fn in_argument_of(line: &[u8], opener: u8) -> bool {
    let Some(start) = line.iter().rposition(|byte| *byte == opener) else {
        return false;
    };
    let mut depth = 0_i32;
    for byte in &line[start..] {
        match byte {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
    }
    depth > 0
}
