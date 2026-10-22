//! A type check of code-mode programs, run beside them as feedback.
//!
//! A code-mode program is JavaScript, or TypeScript the host prepares into
//! JavaScript, that the guest runs as the body of an async function. A check
//! type-checks the program as its author wrote it, against the declarations
//! the executor prompt teaches: JavaScript the way `tsc` checks JavaScript
//! (`allowJs`, `checkJs`), a TypeScript original as TypeScript, both strict,
//! ES2022, with no DOM or Node globals and no output. It returns every
//! TypeScript diagnostic, whole, in program coordinates.
//!
//! Three backends give one output contract:
//! - [`TsrsWasm`]: tsrs, oxc's Rust port of TypeScript 7, as a pinned Wasm
//!   module run in process on Wasmtime. The default: it was the fastest of
//!   the three on the direction screen, with every diagnostic equal to
//!   Microsoft's (`examples/backend_screen.rs`, FIX 8255).
//! - [`TscRsWasm`]: tsc-rs, a Rust port of TypeScript 7, as a pinned Wasm
//!   module on the same runner.
//! - [`MicrosoftTsc`]: Microsoft's TypeScript 7 as an external process, the
//!   correctness oracle and the fallback.
//!
//! tsc-rs and Microsoft give the same diagnostics on the shared fixtures
//! (`tests/fixtures/golden.txt`).
//!
//! Which one runs is configuration ([`BackendKind`]). Feedback mode is the
//! only mode that runs a check: what it found goes back to the agent with
//! its step, and nothing waits on it or is refused for it. `enforce` is a
//! reserved name ([`CheckMode`]).

pub mod metrics;
mod microsoft;
mod output;
mod tsc_rs;
mod tsrs;
mod wasm;

pub use self::metrics::{CheckMetrics, LatencySummary, MetricsSnapshot, StepThen};
pub use self::microsoft::{MICROSOFT_TS_VERSION, MicrosoftTsc};
pub use self::tsc_rs::{TSC_RS_COMMIT, TscRsBudget, TscRsWasm};
pub use self::tsrs::{TSRS_COMMIT, TSRS_VERSION, TsrsWasm};

use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// What the engine does with a program's check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckMode {
    /// No check runs: each step's type feedback answers unavailable.
    Off,
    /// Every program is checked beside its run, the default: its diagnostics
    /// go back to the agent with the step, and nothing waits on the check or
    /// is refused for it.
    #[default]
    Feedback,
}

impl std::str::FromStr for CheckMode {
    type Err = CheckConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "off" => Ok(Self::Off),
            "feedback" => Ok(Self::Feedback),
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
    TscRs,
    /// Microsoft's TypeScript 7 as an external process.
    Microsoft,
    /// tsrs in process, the default.
    #[default]
    Tsrs,
}

impl std::str::FromStr for BackendKind {
    type Err = CheckConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "tsc-rs" => Ok(Self::TscRs),
            "microsoft" => Ok(Self::Microsoft),
            "tsrs" => Ok(Self::Tsrs),
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

/// The language a program is checked as: the language its run was prepared
/// from, never a guess at its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgramLanguage {
    /// Checked as `program.js` under `checkJs`, JSDoc types included.
    #[default]
    JavaScript,
    /// A TypeScript original, checked as written as `program.ts`.
    TypeScript,
}

impl ProgramLanguage {
    /// The file the program is checked as.
    #[must_use]
    pub const fn file(self) -> &'static str {
        match self {
            Self::JavaScript => "program.js",
            Self::TypeScript => "program.ts",
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
        }
    }
}

/// One check: a program as the model wrote it, the language its run was
/// prepared from, and the declarations its run serves.
#[derive(Debug, Clone, Copy)]
pub struct CheckInput<'a> {
    pub declarations: &'a [Declaration<'a>],
    pub program: &'a str,
    pub language: ProgramLanguage,
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
    /// `program.js` or `program.ts`, a declaration file, or none for a
    /// diagnostic about the whole check.
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

/// A check's report: every diagnostic it printed, each message whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    pub backend: BackendId,
    pub diagnostics: Vec<Diagnostic>,
    /// The largest linear memory the check grew to, when the backend can see it.
    pub peak_memory_bytes: Option<u64>,
    /// `None` for a check that finished. A check that stopped after it
    /// printed whole diagnostics is a partial report of them, with the
    /// failure that stopped it: never a complete one.
    pub incomplete: Option<CheckFailure>,
}

/// Why a check gave no report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckFailure {
    /// Every check slot is in use. The in-process backends queue a check
    /// for a slot until its deadline instead.
    Busy,
    Timeout,
    /// The check outgrew its memory bound.
    OverBudget,
    /// The checker trapped, panicked or exited abnormally.
    Crashed,
    UnreadableOutput,
    /// The program, or its declarations, past what one check takes, or a
    /// declaration file the project cannot name.
    InvalidInput,
    /// The checker does not check a program like this one.
    Unsupported,
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
            Self::Unsupported => "code_check_unsupported",
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
    /// The checker this is; a [`Fallback`] names the one it tries first.
    fn backend(&self) -> BackendId;

    /// Checks one program.
    ///
    /// # Errors
    ///
    /// A [`CheckFailure`] when the checker gives no diagnostics.
    fn check(&self, input: &CheckInput<'_>) -> Result<CheckReport, CheckFailure>;

    /// Checks one program, and names the checker whose report or failure the
    /// result is.
    fn check_attributed(
        &self,
        input: &CheckInput<'_>,
    ) -> (BackendId, Result<CheckReport, CheckFailure>) {
        (self.backend(), self.check(input))
    }
}

/// Runs `then` when `first` gives no complete report, whatever the failure:
/// a busy first checker could not check either.
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
        self.check_attributed(input).1
    }

    /// When `then` fails too, the failure is `then`'s own, under its name,
    /// unless only `first` printed a partial report: that report stands.
    fn check_attributed(
        &self,
        input: &CheckInput<'_>,
    ) -> (BackendId, Result<CheckReport, CheckFailure>) {
        match self.first.check_attributed(input) {
            (backend, Ok(report)) if report.incomplete.is_none() => (backend, Ok(report)),
            first => match self.then.check_attributed(input) {
                (_, Err(_)) if first.1.is_ok() => first,
                then => then,
            },
        }
    }
}

/// Feedback mode as the engine holds it: the checker, and the counts of
/// what its checks found.
pub struct FeedbackCheck {
    checker: Arc<dyn CodeCheck>,
    metrics: CheckMetrics,
}

impl FeedbackCheck {
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
/// The files a program is checked as, one per [`ProgramLanguage`].
const PROGRAM_FILES: [&str; 2] = [
    ProgramLanguage::JavaScript.file(),
    ProgramLanguage::TypeScript.file(),
];
const PROJECT_FILE: &str = "tsconfig.json";
/// The command line every backend runs in the project's directory.
const TSC_ARGS: [&str; 4] = ["-p", PROJECT_FILE, "--pretty", "false"];

/// Every file of one check, by name: the declarations, the program in its
/// envelope as the file of its language, and the project that lists them.
/// Past `input_bytes` of program and declarations, the check fails as
/// invalid input: the run never waits on it or is refused for it.
fn project_files(
    input: &CheckInput<'_>,
    input_bytes: usize,
) -> Result<Vec<(String, Vec<u8>)>, CheckFailure> {
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
    if size.is_none_or(|size| size > input_bytes) {
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
    let program = input.language.file();
    names.push(program);
    files.push((
        program.to_owned(),
        format!("{ENVELOPE_PREFIX}{}{ENVELOPE_SUFFIX}", input.program).into_bytes(),
    ));
    // The program checked as written, JavaScript under `checkJs` and a
    // TypeScript original as TypeScript: strict, ES2022 with no DOM or Node
    // globals, and no output. The program is these files alone: an import
    // adds no file, so a native checker reads nothing else it names.
    let project = serde_json::json!({
        "compilerOptions": {
            "allowJs": true,
            "checkJs": true,
            "noEmit": true,
            "noResolve": true,
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
    /// or prints no diagnostic. A crash or unreadable text after whole
    /// diagnostics keeps them, as a partial report.
    fn report(
        self,
        backend: BackendId,
        peak_memory_bytes: Option<u64>,
    ) -> Result<CheckReport, CheckFailure> {
        if self.stderr || !(0..=2).contains(&self.status) {
            return partial(
                backend,
                peak_memory_bytes,
                CheckFailure::Crashed,
                &self.stdout,
            );
        }
        let diagnostics = match output::diagnostics(&self.stdout) {
            Ok(diagnostics) => diagnostics,
            Err(failure) => return partial(backend, peak_memory_bytes, failure, &self.stdout),
        };
        if self.status != 0 && diagnostics.is_empty() {
            return Err(CheckFailure::Crashed);
        }
        Ok(CheckReport {
            backend,
            diagnostics,
            peak_memory_bytes,
            incomplete: None,
        })
    }
}

/// A run of tsc that stopped before it ended: why, and everything it had
/// printed by then.
pub(crate) struct Stopped {
    pub(crate) failure: CheckFailure,
    pub(crate) stdout: Vec<u8>,
}

impl From<CheckFailure> for Stopped {
    fn from(failure: CheckFailure) -> Self {
        Self {
            failure,
            stdout: Vec::new(),
        }
    }
}

impl Stopped {
    /// The whole diagnostics the run printed before it stopped, as a partial
    /// report; its failure alone when it printed none.
    fn report(
        self,
        backend: BackendId,
        peak_memory_bytes: Option<u64>,
    ) -> Result<CheckReport, CheckFailure> {
        partial(backend, peak_memory_bytes, self.failure, &self.stdout)
    }
}

/// What a check that `failure` stopped had printed: its whole diagnostics as
/// a partial report, or the failure when it printed none.
fn partial(
    backend: BackendId,
    peak_memory_bytes: Option<u64>,
    failure: CheckFailure,
    stdout: &[u8],
) -> Result<CheckReport, CheckFailure> {
    let diagnostics = output::partial_diagnostics(stdout);
    if diagnostics.is_empty() {
        return Err(failure);
    }
    Ok(CheckReport {
        backend,
        diagnostics,
        peak_memory_bytes,
        incomplete: Some(failure),
    })
}

/// The most declaration and program text one check takes by default
/// (`models.code_mode.check.max_input_bytes`).
pub const DEFAULT_INPUT_BYTES: usize = 4 << 20;
/// The most declaration files one check takes, and the longest name.
const MAX_DECLARATIONS: usize = 16;
const MAX_NAME_BYTES: usize = 64;
/// How long a check may take before it is abandoned.
const DEFAULT_WALL_TIME: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::{BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, Fallback};

    /// A checker that answers every program the same way.
    struct Fixed {
        name: &'static str,
        answer: Result<(), CheckFailure>,
    }

    impl CodeCheck for Fixed {
        fn backend(&self) -> BackendId {
            BackendId {
                name: self.name,
                pin: String::new(),
            }
        }

        fn check(&self, _: &CheckInput<'_>) -> Result<CheckReport, CheckFailure> {
            self.answer.map(|()| CheckReport {
                backend: self.backend(),
                diagnostics: Vec::new(),
                peak_memory_bytes: None,
            })
        }
    }

    fn fallback(first: Result<(), CheckFailure>, then: Result<(), CheckFailure>) -> Fallback {
        let first = Fixed {
            name: "first",
            answer: first,
        };
        let then = Fixed {
            name: "then",
            answer: then,
        };
        Fallback::new(Box::new(first), Box::new(then))
    }

    const PROGRAM: CheckInput<'static> = CheckInput {
        declarations: &[],
        program: "",
    };

    /// The fallback answers a program a busy first checker could not take,
    /// and is not asked when the first checker answers.
    #[test]
    fn the_fallback_answers_when_the_first_checker_is_busy() {
        let busy = fallback(Err(CheckFailure::Busy), Ok(()));
        let (backend, report) = busy.check_attributed(&PROGRAM);
        assert_eq!(backend.name, "then");
        assert_eq!(report.map(|report| report.backend.name), Ok("then"));
        let answered = busy.check(&PROGRAM);
        assert_eq!(answered.map(|report| report.backend.name), Ok("then"));

        let first = fallback(Ok(()), Err(CheckFailure::Unsupported));
        let (backend, report) = first.check_attributed(&PROGRAM);
        assert_eq!(backend.name, "first");
        assert_eq!(report.map(|report| report.backend.name), Ok("first"));
    }

    /// When the fallback fails too, the failure is the fallback's own, under
    /// the fallback's name.
    #[test]
    fn a_failed_fallback_keeps_its_own_failure_and_name() {
        let both = fallback(Err(CheckFailure::Busy), Err(CheckFailure::Unsupported));
        let (backend, failure) = both.check_attributed(&PROGRAM);
        assert_eq!(backend.name, "then");
        assert_eq!(failure, Err(CheckFailure::Unsupported));
        assert_eq!(both.check(&PROGRAM), Err(CheckFailure::Unsupported));
    }
}
