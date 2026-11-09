//! The SDK generator: writes every generated SDK output of the verb table (`scripts/sdk/verbs/`), the Rust types the
//! facade rows name, and the hand-written files listed in `INPUTS` (SDK-GENERATOR-RUST).
//!
//! It is a byte-for-byte port of the standard-library Python generator it replaced (main `e79eb76df3e`), so it keeps
//! that generator's rules: Python's `json`, `str` and `re` semantics where they reach an output (the `py` helpers),
//! dict insertion order, and the refusal texts (`GenerateError` carries the line Python printed last).
//!
//! The public API: `outputs` (every output, in the generator's order), `write_out_dir` (the `--out-dir` mode, which
//! crates/oneiron-sdk-build runs in-process), `CRATES` and `INPUTS` (what the generator reads, for the build crate's
//! input digest), `Outputs` and `GenerateError`. Both functions run the generator on a thread of its own with a
//! 256 MiB stack: the type walk recurses deeply on the engine's types.

mod catalog_fragment;
mod error;
mod facade_types;
mod generate;
#[cfg(all(test, unix))]
mod projection_rules;
mod py;
mod uniffi_types;
mod verb_table;

use std::path::{Path, PathBuf};

pub use error::GenerateError;
pub use facade_types::CRATES;
pub use generate::outputs::Outputs;

/// A digest of this crate's source files (set by its `build.rs`). `oneiron-sdk-build` mixes it into the digest that
/// names a build's shared run directory, so a change to the generator makes a new run.
pub const GENERATOR_SOURCE_DIGEST: &str = env!("GENERATOR_SOURCE_DIGEST");

/// The stack of the generator's thread (brief 2.2.2).
const STACK_BYTES: usize = 256 << 20;

/// Every fixed path the generator reads, relative to the repository root, beside the `CRATES` source directories
/// (brief 1.3), each with the functions that read it. A directory stands for every file under it.
pub const INPUTS: &[&str] = &[
    // verb_table::load_verbs (the verb table) and generate::docs::generated_artifacts (verbs.md).
    "scripts/sdk/verbs",
    // facade_types::type_names (read first, before any verb file).
    "scripts/sdk/type_names.json",
    // generate::common::hand_declared('ts'), generate::emit_ts::ts_facade_module, ts_native_module, and
    // generate::docs::generated_artifacts (types.md).
    "packages/oneiron/src/types.ts",
    // generate::common::hand_declared('ts') and generate::emit_ts::ts_facade_module.
    "packages/oneiron/src/key-value.ts",
    // generate::common::hand_declared('py') and generate::docs::generated_artifacts (types.md).
    "crates/oneiron-py/python/oneiron/__init__.pyi",
    // generate::uniffi::uniffi_taken (UNIFFI_HAND_WRITTEN).
    "crates/oneiron-uniffi/src/dto.rs",
    "crates/oneiron-uniffi/src/lib.rs",
    "crates/oneiron-uniffi/src/error.rs",
];

/// Runs `work` on a thread with the generator's stack, and returns its result.
fn on_generator_thread<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, GenerateError> + Send + 'static,
) -> Result<T, GenerateError> {
    let worker = std::thread::Builder::new()
        .name("generator".to_owned())
        .stack_size(STACK_BYTES)
        .spawn(work)
        .map_err(|error| {
            GenerateError::exception("RuntimeError", format!("can't start new thread: {error}"))
        })?;
    worker
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Every output for the repository at `root`, in the generator's order: each repository path with its text.
pub fn outputs(root: &Path) -> Result<Outputs, GenerateError> {
    let root = root.to_path_buf();
    on_generator_thread(move || generate::Generator::new(&root)?.outputs())
}

/// The `--out-dir <dir>` mode: every output under `<dir>/<repo path>`, and the three
/// generated agent-SDK docs under `<dir>/docs/agent-sdk/` (SDKGEN-DOCS = A). It writes into `dir` as given and runs
/// no other process.
pub fn write_out_dir(root: &Path, dir: &Path) -> Result<(), GenerateError> {
    let (root, dir): (PathBuf, PathBuf) = (root.to_path_buf(), dir.to_path_buf());
    on_generator_thread(move || generate::Generator::new(&root)?.write_out_dir(&dir))
}

/// The generator after its module level (the verb rows read and checked, the row sets built), for the binary's
/// modes: built once, on the thread that uses it (the type inventory is not `Send`), and run in one mode.
#[doc(hidden)]
pub struct Run {
    generator: generate::Generator,
}

#[doc(hidden)]
impl Run {
    /// The module level for the repository at `root`: the first refusal wins.
    pub fn new(root: &Path) -> Result<Self, GenerateError> {
        Ok(Self {
            generator: generate::Generator::new(root)?,
        })
    }

    /// `--package <name>...`; whether `docs` was among them.
    pub fn write_packages(&mut self, names: &[String]) -> Result<bool, GenerateError> {
        self.generator.write_packages(names)
    }

    /// `--out-dir <dir>`, the three generated docs included.
    pub fn write_out_dir(&mut self, dir: &Path) -> Result<(), GenerateError> {
        self.generator.write_out_dir(dir)
    }

    /// The default mode or `--check`; what the default mode prints on stdout.
    pub fn write_tree(&mut self, check: bool) -> Result<String, GenerateError> {
        self.generator.write_tree(check)
    }

    /// `print(text, end='')` and the flush before the next step: Python's `OSError` (`[Errno 28] No space left on
    /// device`, `BrokenPipeError: [Errno 32] Broken pipe`) when standard output cannot take it.
    pub fn print(&self, text: &str) -> Result<(), GenerateError> {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(text.as_bytes())
            .and_then(|()| stdout.flush())
            .map_err(|error| generate::outputs::stream_error(&error))
    }

    /// `subprocess.run([python, 'packages/oneiron/scripts/agent-docs.py', *flags], check=True)`.
    pub fn agent_docs(&self, flags: &[&str]) -> Result<(), GenerateError> {
        generate::outputs::agent_docs(&self.generator.root, flags)
    }

    /// The text of a `type=Path` argument as pathlib normalises it (`./out//` is `out`, the empty text `.`).
    pub fn command_line_path(text: &str) -> String {
        generate::outputs::pure_path(text)
    }
}

/// Python's `repr()` of a `str`, for the binary's argparse messages.
#[doc(hidden)]
pub fn py_repr(text: &str) -> String {
    py::text::repr_str(text)
}

/// Python's `\d` in a `str` pattern (`str.isdecimal()`), for the binary's argparse.
#[doc(hidden)]
pub fn py_is_decimal(c: char) -> bool {
    py::text::is_decimal(c)
}

/// Python's `str.isspace()`, for the binary's reading of `COLUMNS` (`int()` strips white space).
#[doc(hidden)]
pub fn py_is_space(c: char) -> bool {
    py::text::is_space(c)
}
