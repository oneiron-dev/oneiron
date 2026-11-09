//! The SDK generator: a port of `scripts/sdk/generate.py` and its sibling modules (SDK-GENERATOR-RUST).
//!
//! On the same inputs the port writes the same bytes to the same paths as the Python generator, and it refuses the
//! same inputs with the same message (`GenerateError` carries the text Python prints last). Until the stack's last
//! PR (G6) removes the Python, each ported function names the Python file and lines it ports, as of main
//! `e79eb76df3e`.
//!
//! The public API (brief 2.1): `outputs` (every output, in generate.py's order), `write_out_dir` (the `--out-dir`
//! mode, which crates/oneiron-sdk-build runs in-process), `CRATES` and `INPUTS` (what the generator reads, for the
//! build crate's input digest), `Outputs` and `GenerateError`. Both functions run the generator on a thread of its
//! own with a 256 MiB stack: the type walk recurses as deep as Python's raised limit (`facade_types.py:24`).

mod catalog_fragment;
mod error;
mod facade_types;
#[allow(
    dead_code,
    reason = "the module-level state; the emitters of later PRs of the port read it"
)]
mod generate;
mod harness;
#[allow(
    dead_code,
    reason = "the shared Python-behaviour helpers; later PRs of the port call the ones G1a does not"
)]
mod py;
mod uniffi_types;
mod verb_table;

use std::path::{Path, PathBuf};

pub use error::GenerateError;
pub use facade_types::CRATES;
pub use generate::outputs::Outputs;

/// The stack of the generator's thread (brief 2.2.2).
const STACK_BYTES: usize = 256 << 20;

/// Every fixed path the generator reads, relative to the repository root, beside the `CRATES` source directories
/// (brief 1.3), each with the functions that read it. A directory stands for every file under it.
pub const INPUTS: &[&str] = &[
    // verb_table::load_verbs (generate.py:17, the verb table) and generate::docs::generated_artifacts (verbs.md).
    "scripts/sdk/verbs",
    // facade_types::type_names (facade_types.py:372, read at import).
    "scripts/sdk/type_names.json",
    // generate::common::hand_declared('ts'), generate::emit_ts::ts_facade_module, ts_native_module, and
    // generate::docs::generated_artifacts (types.md).
    "packages/oneiron/src/types.ts",
    // generate::common::hand_declared('ts') and generate::emit_ts::ts_facade_module.
    "packages/oneiron/src/key-value.ts",
    // generate::common::hand_declared('py') and generate::docs::generated_artifacts (types.md).
    "crates/oneiron-py/python/oneiron/__init__.pyi",
    // generate::uniffi::uniffi_taken (generate.py:2750, UNIFFI_HAND_WRITTEN).
    "crates/oneiron-uniffi/src/dto.rs",
    "crates/oneiron-uniffi/src/lib.rs",
    "crates/oneiron-uniffi/src/error.rs",
    // generate::outputs (generate.py:2536): the dormant MCP dispatch host, read and set aside.
    "crates/oneiron-server/src/api/mcp_gateway/tasks_response.rs",
    // generate::outputs (generate.py:2554): the dormant board catalog host, read and set aside (it is under the
    // `oneiron` crate's source directory too).
    "crates/oneiron/src/board_verb.rs",
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

/// Every output of generate.py's `outputs()` for the repository at `root`, in its order: each path with its text,
/// and `None` for each of the sixteen old homes the default mode deletes.
pub fn outputs(root: &Path) -> Result<Outputs, GenerateError> {
    let root = root.to_path_buf();
    on_generator_thread(move || generate::Generator::new(&root)?.outputs())
}

/// generate.py's `--out-dir <dir>`: every output that is no deletion, under `<dir>/<repo path>`, and the three
/// generated agent-SDK docs under `<dir>/docs/agent-sdk/` (SDKGEN-DOCS = A). It writes into `dir` as given and runs
/// no other process.
pub fn write_out_dir(root: &Path, dir: &Path) -> Result<(), GenerateError> {
    let (root, dir): (PathBuf, PathBuf) = (root.to_path_buf(), dir.to_path_buf());
    on_generator_thread(move || generate::Generator::new(&root)?.write_out_dir(&dir))
}

/// generate.py after its module level, for the binary's modes: built once, on the thread that uses it (the type
/// inventory is not `Send`), and run in one mode.
#[doc(hidden)]
pub struct Run {
    generator: generate::Generator,
}

#[doc(hidden)]
impl Run {
    /// generate.py's module level (generate.py:4-343) for the repository at `root`.
    pub fn new(root: &Path) -> Result<Self, GenerateError> {
        Ok(Self {
            generator: generate::Generator::new(root)?,
        })
    }

    /// `--package <name>...` (generate.py:2934-2947); whether `docs` was among them.
    pub fn write_packages(&mut self, names: &[String]) -> Result<bool, GenerateError> {
        self.generator.write_packages(names)
    }

    /// `--out-dir <dir>` (generate.py:2950-2958, with the docs written here).
    pub fn write_out_dir(&mut self, dir: &Path) -> Result<(), GenerateError> {
        self.generator.write_out_dir(dir)
    }

    /// The default mode or `--check` (generate.py:2959-2979); what the default mode prints on stdout.
    pub fn write_tree(&mut self, check: bool) -> Result<String, GenerateError> {
        self.generator.write_tree(check)
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

/// The `port-harness` subcommand (DESIGN 6): dumps the port's state for comparison with
/// `scripts/sdk/port_harness.py`. Temporary: G6 deletes it with the Python.
#[doc(hidden)]
pub fn port_harness(args: &[String]) -> Result<(), GenerateError> {
    harness::run(args)
}
