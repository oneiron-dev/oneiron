//! An optional type check of code-mode programs before they run.
//!
//! A code-mode program is plain JavaScript that the guest runs as the body of
//! an async function. A check type-checks it against the declarations the
//! executor prompt teaches, the way `tsc` checks JavaScript (`allowJs`,
//! `checkJs`, strict, ES2022, no DOM or Node globals, no output), and returns
//! TypeScript's diagnostics in program coordinates.
//!
//! Two backends give the same diagnostics on the shared fixtures
//! (`tests/fixtures/golden.txt`):
//! - [`TscRsWasm`]: tsc-rs, a Rust port of TypeScript 7, as a pinned Wasm
//!   module run in process on Wasmtime. The default.
//! - [`MicrosoftTsc`]: Microsoft's TypeScript 7 as an external process, the
//!   correctness oracle and the fallback.
//!
//! Which one runs is configuration ([`BackendKind`]). Shadow mode is the only
//! mode that runs a check: the engine records what it found and blocks
//! nothing. `enforce` is a reserved name ([`CheckMode`]).

pub mod metrics;
mod microsoft;
mod output;
mod tsc_rs;

pub use self::metrics::{CheckMetrics, LatencySummary, MetricsSnapshot, StepThen};
pub use self::microsoft::{MICROSOFT_TS_VERSION, MicrosoftTsc};
pub use self::tsc_rs::{TSC_RS_COMMIT, TscRsBudget, TscRsWasm};

use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// What the engine does with a program's check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckMode {
    /// No check runs.
    #[default]
    Off,
    /// Every program is checked; its diagnostics are recorded and nothing is
    /// blocked.
    Shadow,
}

impl std::str::FromStr for CheckMode {
    type Err = CheckConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "off" => Ok(Self::Off),
            "shadow" => Ok(Self::Shadow),
            // Reserved: refusing a program on its check waits for an owner ruling.
            "enforce" => Err(CheckConfigError::EnforceReserved),
            _ => Err(CheckConfigError::UnknownMode),
        }
    }
}

/// Which checker runs a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendKind {
    /// tsc-rs in process.
    #[default]
    TscRs,
    /// Microsoft's TypeScript 7 as an external process.
    Microsoft,
}

impl std::str::FromStr for BackendKind {
    type Err = CheckConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "tsc-rs" => Ok(Self::TscRs),
            "microsoft" => Ok(Self::Microsoft),
            _ => Err(CheckConfigError::UnknownBackend),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CheckConfigError {
    #[error("code_check_enforce_reserved")]
    EnforceReserved,
    #[error("code_check_unknown_mode")]
    UnknownMode,
    #[error("code_check_unknown_backend")]
    UnknownBackend,
}

/// One declaration file a program is checked against.
#[derive(Debug, Clone, Copy)]
pub struct Declaration<'a> {
    /// A plain file name ending in `.d.ts`.
    pub name: &'a str,
    pub text: &'a str,
}

/// One check: a program as the model wrote it, and the declarations its run
/// serves.
#[derive(Debug, Clone, Copy)]
pub struct CheckInput<'a> {
    pub declarations: &'a [Declaration<'a>],
    pub program: &'a str,
}

/// The checker that answered, and what pins it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackendId {
    pub name: &'static str,
    pub pin: String,
}

/// One TypeScript diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    /// `program.js`, a declaration file, or none for a diagnostic about the
    /// whole check.
    pub file: Option<String>,
    /// 1-based, in the program as written (0 is the guest's async envelope).
    /// Declaration files keep their own lines.
    pub line: u32,
    pub column: u32,
    pub category: String,
    pub code: u32,
    pub message: String,
}

impl Diagnostic {
    /// The diagnostic as `tsc --pretty false` prints it, in program
    /// coordinates.
    #[must_use]
    pub fn render(&self) -> String {
        let place = self.file.as_ref().map_or_else(String::new, |file| {
            format!("{file}({},{}): ", self.line, self.column)
        });
        format!("{place}{} TS{}: {}", self.category, self.code, self.message)
    }
}

/// A finished check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    pub backend: BackendId,
    pub diagnostics: Vec<Diagnostic>,
    /// The largest linear memory the check grew to, when the backend can see it.
    pub peak_memory_bytes: Option<u64>,
}

/// Why a check gave no report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckFailure {
    /// Every check slot is in use.
    Busy,
    Timeout,
    /// The check outgrew its memory or output bound.
    OverBudget,
    /// The checker trapped, panicked or exited abnormally.
    Crashed,
    UnreadableOutput,
    InvalidInput,
    /// The checker is missing, fails its pin, or cannot start.
    Unavailable,
}

impl CheckFailure {
    /// The failure's stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Busy => "code_check_busy",
            Self::Timeout => "code_check_timeout",
            Self::OverBudget => "code_check_over_budget",
            Self::Crashed => "code_check_crashed",
            Self::UnreadableOutput => "code_check_unreadable_output",
            Self::InvalidInput => "code_check_invalid_input",
            Self::Unavailable => "code_check_unavailable",
        }
    }
}

impl std::fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for CheckFailure {}

/// A type checker for code-mode programs.
pub trait CodeCheck: Send + Sync {
    /// The checker this is when it answers.
    fn backend(&self) -> BackendId;

    /// Checks one program.
    ///
    /// # Errors
    ///
    /// A [`CheckFailure`] when the checker gives no diagnostics.
    fn check(&self, input: &CheckInput<'_>) -> Result<CheckReport, CheckFailure>;
}

/// Runs `then` when `first` gives no report.
pub struct Fallback {
    first: Box<dyn CodeCheck>,
    then: Box<dyn CodeCheck>,
}

impl Fallback {
    #[must_use]
    pub fn new(first: Box<dyn CodeCheck>, then: Box<dyn CodeCheck>) -> Self {
        Self { first, then }
    }
}

impl CodeCheck for Fallback {
    fn backend(&self) -> BackendId {
        self.first.backend()
    }

    fn check(&self, input: &CheckInput<'_>) -> Result<CheckReport, CheckFailure> {
        self.first.check(input).or_else(|_| self.then.check(input))
    }
}

/// Shadow mode as the engine holds it: the checker, and the counts of what
/// its checks found.
pub struct ShadowCheck {
    checker: Arc<dyn CodeCheck>,
    metrics: CheckMetrics,
}

impl ShadowCheck {
    #[must_use]
    pub fn new(checker: Arc<dyn CodeCheck>) -> Self {
        Self {
            checker,
            metrics: CheckMetrics::default(),
        }
    }

    #[must_use]
    pub fn checker(&self) -> &dyn CodeCheck {
        self.checker.as_ref()
    }

    #[must_use]
    pub fn metrics(&self) -> &CheckMetrics {
        &self.metrics
    }
}

/// The guest's envelope (`components/code-run-quickjs/guest.c`): a program
/// runs as the body of an async function, so top-level `await` and `return`
/// check as they run.
const ENVELOPE_PREFIX: &str = "(async () => {\n";
const ENVELOPE_SUFFIX: &str = "\n})()";
const PROGRAM_FILE: &str = "program.js";
const PROJECT_FILE: &str = "tsconfig.json";
/// The command line both backends run in the project's directory.
const TSC_ARGS: [&str; 4] = ["-p", PROJECT_FILE, "--pretty", "false"];

/// Every file of one check, by name: the declarations, the program in its
/// envelope, and the project that lists them.
fn project_files(input: &CheckInput<'_>) -> Result<Vec<(String, Vec<u8>)>, CheckFailure> {
    if input.declarations.len() > MAX_DECLARATIONS
        || input
            .declarations
            .iter()
            .any(|declaration| declaration.name.len() > MAX_NAME_BYTES)
    {
        return Err(CheckFailure::InvalidInput);
    }
    let size = input
        .declarations
        .iter()
        .map(|declaration| declaration.text.len())
        .try_fold(input.program.len(), usize::checked_add);
    if size.is_none_or(|size| size > DEFAULT_INPUT_BYTES) {
        return Err(CheckFailure::InvalidInput);
    }
    let mut names = Vec::with_capacity(input.declarations.len() + 1);
    let mut files = Vec::with_capacity(input.declarations.len() + 2);
    for declaration in input.declarations {
        let plain = declaration
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if !plain || !declaration.name.ends_with(".d.ts") || names.contains(&declaration.name) {
            return Err(CheckFailure::InvalidInput);
        }
        names.push(declaration.name);
        files.push((
            declaration.name.to_owned(),
            declaration.text.as_bytes().to_vec(),
        ));
    }
    names.push(PROGRAM_FILE);
    files.push((
        PROGRAM_FILE.to_owned(),
        format!("{ENVELOPE_PREFIX}{}{ENVELOPE_SUFFIX}", input.program).into_bytes(),
    ));
    // JavaScript checked as written: strict, ES2022 with no DOM or Node
    // globals, and no output.
    let project = serde_json::json!({
        "compilerOptions": {
            "allowJs": true,
            "checkJs": true,
            "noEmit": true,
            "strict": true,
            "target": "ES2022",
            "lib": ["ES2022"],
            "types": [],
            "skipLibCheck": false,
        },
        "files": names,
    });
    files.push((PROJECT_FILE.to_owned(), project.to_string().into_bytes()));
    Ok(files)
}

/// How one run of tsc ended.
struct Exited {
    status: i32,
    stdout: Vec<u8>,
    /// Whether anything reached stderr, where tsc prints only a crash.
    stderr: bool,
}

impl Exited {
    /// The run's report. tsc exits 0 clean, and 1 or 2 with diagnostics; a
    /// crash (an unrecovered Go panic also exits 2) tells its story on stderr
    /// or prints no diagnostic.
    fn report(
        self,
        backend: BackendId,
        peak_memory_bytes: Option<u64>,
    ) -> Result<CheckReport, CheckFailure> {
        if self.stderr || !(0..=2).contains(&self.status) {
            return Err(CheckFailure::Crashed);
        }
        let diagnostics = output::diagnostics(&self.stdout)?;
        if self.status != 0 && diagnostics.is_empty() {
            return Err(CheckFailure::Crashed);
        }
        Ok(CheckReport {
            backend,
            diagnostics,
            peak_memory_bytes,
        })
    }
}

/// The most declaration and program text one check takes.
const DEFAULT_INPUT_BYTES: usize = 4 << 20;
/// The most declaration files one check takes, and the longest name.
const MAX_DECLARATIONS: usize = 16;
const MAX_NAME_BYTES: usize = 64;
/// How long a check may take before it is abandoned.
const DEFAULT_WALL_TIME: Duration = Duration::from_secs(10);
/// The most diagnostic text a check may print.
const DEFAULT_OUTPUT_BYTES: usize = 1 << 20;
