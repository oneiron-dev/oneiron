//! The reference a remediation writes where a marked literal stood (FIX
//! 7608 slice 6): an expression in the file's own language that reads the
//! secret's environment variable, which a run is given (slice 7). It
//! replaces the whole quoted literal, so the code keeps its shape.
//!
//! CALL RENDERER-UNRESOLVED: a file form this renderer writes no reference
//! for (a structured config file, an unknown language, a constant context
//! whose language takes no runtime call there) answers `None`. The
//! remediation keeps that key as an explicit unresolved action naming its
//! path, never a guessed patch and never a refusal.

/// Writes the reference that stands for one secret's environment variable
/// in a file's code.
#[derive(Debug, Clone, Copy, Default)]
pub struct RepoSecretReferenceRenderer;

impl RepoSecretReferenceRenderer {
    /// The expression that replaces a quoted literal in the file at `path`
    /// whose bytes are `content`, reading the variable `env_name`. `before`
    /// is the literal's line up to its opening quote. `None` when the
    /// file's form has no reference this renderer writes (CALL
    /// RENDERER-UNRESOLVED).
    #[must_use]
    pub fn reference(path: &str, content: &[u8], before: &[u8], env_name: &str) -> Option<String> {
        let file = path.rsplit('/').next().unwrap_or(path);
        let extension = file.rsplit_once('.')?.1.to_ascii_lowercase();
        let identifier = env_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        // Each language below whose constants take no runtime call.
        let constant = declares_constant(before);
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
            "java" | "scala" | "groovy" => Some(format!("System.getenv(\"{env_name}\")")),
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

/// Whether `before` declares a constant: the word `const` on the line.
fn declares_constant(before: &[u8]) -> bool {
    let word =
        |byte: Option<&u8>| byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    before.windows(5).enumerate().any(|(at, window)| {
        window == b"const"
            && !word(at.checked_sub(1).and_then(|prior| before.get(prior)))
            && !word(before.get(at + 5))
    })
}
