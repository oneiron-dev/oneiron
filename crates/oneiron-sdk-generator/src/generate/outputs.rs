//! `BUILD_TIME_OUTPUTS`, `PACKAGE_OUTPUTS`, `PACKAGE_PATHS` and `outputs()`, which runs the emitters in a fixed
//! order: they share one `Inventory`, and the order they run in decides the names it allocates, so the order is part
//! of the output. Also the file operations of the binary's modes and agent-docs.py's `write`, with pathlib's errors.
//!
//! No rustfmt pass: every `.rs` output is a build-time output, which the tree modes neither write nor check.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;

use super::emit_http::http_facade;
use super::emit_py::python_facade_module;
use super::emit_ts::{row_of, ts_facade_module, ts_native_module, ts_native_signature, verb_tree};
use super::row_access::context_is;
use super::{Generator, RowId};
use crate::error::GenerateError;
use crate::py::read_text;
use crate::py::value::Dict;
use crate::verb_table::{VERBS_DIR, verb_files};

/// The outputs crates/oneiron-sdk-build produces at build time
/// (untangle slice 4.3); the default run neither writes nor checks them in the tree. A set, read for membership.
pub(crate) const BUILD_TIME_OUTPUTS: &[&str] = &[
    "crates/oneiron-py/src/generated/agent_verbs.rs",
    "crates/oneiron-napi/src/facade/client/generated/agent_verbs.rs",
    "crates/oneiron-remote/src/generated/agent_verbs.rs",
    "crates/oneiron-server/src/api/facade/generated/agent_verbs.rs",
    "crates/oneiron-server/src/api/facade/generated/dispatch.rs",
    "crates/oneiron-server/src/api/facade/generated/host_door_rows.rs",
    "crates/oneiron-server/src/api/mcp_gateway/generated/agent_verb_dispatch.rs",
    "crates/oneiron-uniffi/src/generated/facade_generated.rs",
    "crates/oneiron-uniffi/src/generated/facade_types_generated.rs",
    "crates/oneiron/src/verbs/generated/catalog_fragment.d.ts",
    "crates/oneiron/src/verbs/generated/catalog_fragment_revision.rs",
    "crates/oneiron/src/verbs/generated/code-mode.d.ts",
    "crates/oneiron/src/verbs/generated/run_verb_catalog.rs",
    "crates/oneiron/src/verbs/generated/sdk_generated.rs",
    "crates/oneiron/src/verbs/generated/verb_catalog.rs",
    "crates/oneiron/src/generated/core_verb_names.rs",
];

/// Each package's outputs, which its build writes in the tree
/// (`--package <name>`), by package name in the literal's order.
pub(crate) const PACKAGE_OUTPUTS: &[(&str, &[&str])] = &[
    (
        "oneiron",
        &[
            "packages/oneiron/src/facade-types.ts",
            "packages/oneiron/src/agent-verbs.ts",
            "packages/oneiron/src/facade-verbs.ts",
            "packages/oneiron/src/native-verbs.ts",
        ],
    ),
    (
        "oneiron-client",
        &[
            "packages/oneiron-client/src/facade.ts",
            "packages/oneiron-client/src/facade-types.ts",
        ],
    ),
    (
        "oneiron-py",
        &[
            "crates/oneiron-py/python/oneiron/_facade_verbs.py",
            "crates/oneiron-py/python/oneiron/_facade_verbs.pyi",
            "crates/oneiron-py/python/oneiron/facade_types.pyi",
        ],
    ),
    (
        "docs",
        &[
            "docs/agent-sdk/facade-types.md",
            "docs/agent-sdk/types.md",
            "docs/agent-sdk/verbs.md",
        ],
    ),
];

/// `PACKAGE_OUTPUTS[name]`.
pub(crate) fn package_outputs(name: &str) -> Option<&'static [&'static str]> {
    PACKAGE_OUTPUTS
        .iter()
        .find(|(package, _)| *package == name)
        .map(|(_, paths)| *paths)
}

/// `PACKAGE_PATHS`: whether `path` is a package output.
pub(crate) fn is_package_path(path: &str) -> bool {
    PACKAGE_OUTPUTS
        .iter()
        .any(|(_, paths)| paths.contains(&path))
}

/// The outputs of one run: each repository path (`/`-separated, relative to the root) with its text, in the order the
/// generator makes them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outputs {
    files: IndexMap<String, String>,
}

impl Outputs {
    /// `files[path] = text`: a new path goes last, a present one keeps its place (Python's dict).
    pub(crate) fn insert(&mut self, path: &str, text: String) {
        self.files.insert(path.to_owned(), text);
    }

    /// Every output in order: its path and its text.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str()))
    }

    /// The text of the output at `path`, if there is one.
    pub fn get(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(String::as_str)
    }

    /// How many outputs there are.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Python's `Path` of a command-line directory (`type=Path`): its text as `pathlib` normalises it, which the error
/// messages of the files under it print: repeated and trailing `/` and `.` parts dropped (but a leading `//`), and
/// the empty path is `.`.
pub(crate) fn pure_path(text: &str) -> String {
    let (anchor, rest) = if let Some(rest) = text.strip_prefix("//") {
        if rest.starts_with('/') {
            ("/", rest.trim_start_matches('/'))
        } else {
            ("//", rest)
        }
    } else if let Some(rest) = text.strip_prefix('/') {
        ("/", rest)
    } else {
        ("", text)
    };
    let parts: Vec<&str> = rest
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let joined = format!("{anchor}{}", parts.join("/"));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// `dir / path` as `pathlib` joins: a `.` (or empty) directory adds no part (`Path('.') / 'a/b'` is `a/b`), so an
/// error under `--out-dir .` names the path Python names.
pub(crate) fn join(dir: &Path, path: &str) -> PathBuf {
    if dir.as_os_str().is_empty() || dir == Path::new(".") {
        PathBuf::from(path)
    } else {
        dir.join(path)
    }
}

/// `path.parent.mkdir(parents=True, exist_ok=True)` (pathlib's `mkdir`): makes the directory and any missing parent;
/// an error names the directory whose own `mkdir` failed, as Python's does.
pub(crate) fn mkdir_parents(path: &Path) -> Result<(), GenerateError> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // `self.parent == self`: the root (or `.`) has no parent to make. A relative path's last parent is `.`.
            let parent = match path.parent() {
                Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
                Some(parent) => parent,
                None => path,
            };
            if parent == path {
                return Err(GenerateError::os(&error, path));
            }
            mkdir_parents(parent)?;
            // `self.mkdir(mode, parents=False, exist_ok=True)`.
            match fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() != io::ErrorKind::NotFound && path.is_dir() => Ok(()),
                Err(error) => Err(GenerateError::os(&error, path)),
            }
        }
        // `exist_ok`: any other failure is no error when the directory is there.
        Err(_) if path.is_dir() => Ok(()),
        Err(error) => Err(GenerateError::os(&error, path)),
    }
}

/// `path.write_text(text)`: UTF-8, `\n` as it is (Python on Linux and macOS), Python's `OSError` on a failure.
pub(crate) fn write_text(path: &Path, text: &str) -> Result<(), GenerateError> {
    fs::write(path, text).map_err(|error| GenerateError::os(&error, path))
}

/// The types no verb row reaches that a hand-written route serves, rooted last (OF-181, FIX 7968, 9891, 365), in this
/// order.
const EXTRA_ROOTS: [&str; 5] = [
    "crate::lens::GeneratedUiActionEvent",
    "crate::lens::GeneratedUiSegment",
    "crate::lens::GeneratedUiCatalogDescriptor",
    "crate::memory::TranscriptPage",
    "crate::memory::MessageResultAttachment",
];

/// The interpreter that runs agent-docs.py: `ONEIRON_PYTHON` when set, else `python3` (`python` on Windows).
fn python() -> String {
    std::env::var("ONEIRON_PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".to_owned()
        } else {
            "python3".to_owned()
        }
    })
}

/// Python's `OSError` for a failed write to a standard stream (`print`): the class its errno maps to and
/// `[Errno <n>] <strerror>`, with no path (`OSError: [Errno 28] No space left on device`, `BrokenPipeError: [Errno 32]
/// Broken pipe`).
pub(crate) fn stream_error(error: &io::Error) -> GenerateError {
    let kind = match error.kind() {
        io::ErrorKind::BrokenPipe => "BrokenPipeError",
        io::ErrorKind::ConnectionReset => "ConnectionResetError",
        io::ErrorKind::PermissionDenied => "PermissionError",
        io::ErrorKind::Interrupted => "InterruptedError",
        io::ErrorKind::WouldBlock => "BlockingIOError",
        _ => "OSError",
    };
    let message = match error.raw_os_error() {
        Some(errno) => {
            let text = io::Error::from_raw_os_error(errno).to_string();
            let strerror = text
                .strip_suffix(&format!(" (os error {errno})"))
                .unwrap_or(&text);
            format!("[Errno {errno}] {strerror}")
        }
        None => error.to_string(),
    };
    GenerateError::exception(kind, message)
}

/// `subprocess.CalledProcessError`'s text for a child that failed.
fn called_process_error(argv: &[String], status: std::process::ExitStatus) -> GenerateError {
    let cmd: Vec<String> = argv
        .iter()
        .map(|arg| crate::py::text::repr_str(arg))
        .collect();
    let cmd = format!("[{}]", cmd.join(", "));
    let message = match status.code() {
        Some(code) => format!("Command '{cmd}' returned non-zero exit status {code}."),
        None => signal_text(&cmd, status),
    };
    GenerateError::exception("subprocess.CalledProcessError", message)
}

/// Python's `signal.Signals` on Linux (x86-64 and AArch64 numbering): `sorted((s.value, s.name) for s in
/// signal.Signals)` on nelly (3.14.7). An alias (`SIGIOT`, `SIGCLD`, `SIGPOLL`) loses to the name that sorts first.
#[cfg(unix)]
const LINUX_SIGNALS: [(i32, &str); 33] = [
    (1, "SIGHUP"),
    (2, "SIGINT"),
    (3, "SIGQUIT"),
    (4, "SIGILL"),
    (5, "SIGTRAP"),
    (6, "SIGABRT"),
    (7, "SIGBUS"),
    (8, "SIGFPE"),
    (9, "SIGKILL"),
    (10, "SIGUSR1"),
    (11, "SIGSEGV"),
    (12, "SIGUSR2"),
    (13, "SIGPIPE"),
    (14, "SIGALRM"),
    (15, "SIGTERM"),
    (16, "SIGSTKFLT"),
    (17, "SIGCHLD"),
    (18, "SIGCONT"),
    (19, "SIGSTOP"),
    (20, "SIGTSTP"),
    (21, "SIGTTIN"),
    (22, "SIGTTOU"),
    (23, "SIGURG"),
    (24, "SIGXCPU"),
    (25, "SIGXFSZ"),
    (26, "SIGVTALRM"),
    (27, "SIGPROF"),
    (28, "SIGWINCH"),
    (29, "SIGIO"),
    (30, "SIGPWR"),
    (31, "SIGSYS"),
    (34, "SIGRTMIN"),
    (64, "SIGRTMAX"),
];

/// Python's `signal.Signals` on macOS: the same listing on the owner's Mac.
#[cfg(unix)]
const MACOS_SIGNALS: [(i32, &str); 31] = [
    (1, "SIGHUP"),
    (2, "SIGINT"),
    (3, "SIGQUIT"),
    (4, "SIGILL"),
    (5, "SIGTRAP"),
    (6, "SIGABRT"),
    (7, "SIGEMT"),
    (8, "SIGFPE"),
    (9, "SIGKILL"),
    (10, "SIGBUS"),
    (11, "SIGSEGV"),
    (12, "SIGSYS"),
    (13, "SIGPIPE"),
    (14, "SIGALRM"),
    (15, "SIGTERM"),
    (16, "SIGURG"),
    (17, "SIGSTOP"),
    (18, "SIGTSTP"),
    (19, "SIGCONT"),
    (20, "SIGCHLD"),
    (21, "SIGTTIN"),
    (22, "SIGTTOU"),
    (23, "SIGIO"),
    (24, "SIGXCPU"),
    (25, "SIGXFSZ"),
    (26, "SIGVTALRM"),
    (27, "SIGPROF"),
    (28, "SIGWINCH"),
    (29, "SIGINFO"),
    (30, "SIGUSR1"),
    (31, "SIGUSR2"),
];

/// `CalledProcessError.__str__` for a child a signal ended: `Command '...' died with <Signals.SIGTERM: 15>.`, or
/// `unknown signal <n>` for a number `signal.Signals` does not name (on another Unix, every number).
#[cfg(unix)]
fn signal_message(cmd: &str, signal: i32) -> String {
    let table: &[(i32, &str)] = if cfg!(target_os = "linux") {
        &LINUX_SIGNALS
    } else if cfg!(target_os = "macos") {
        &MACOS_SIGNALS
    } else {
        &[]
    };
    match table.iter().find(|(number, _)| *number == signal) {
        Some((_, name)) => format!("Command '{cmd}' died with <Signals.{name}: {signal}>."),
        None => format!("Command '{cmd}' died with unknown signal {signal}."),
    }
}

#[cfg(unix)]
fn signal_text(cmd: &str, status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    signal_message(cmd, status.signal().unwrap_or(0))
}

#[cfg(not(unix))]
fn signal_text(cmd: &str, _status: std::process::ExitStatus) -> String {
    format!("Command '{cmd}' died with unknown signal 0.")
}

/// `subprocess.run([python, 'packages/oneiron/scripts/agent-docs.py', *flags], check=True)`, inheriting the standard
/// streams: the docs mirror's `--check` and `--generated`, which stay Python (SDKGEN-DOCS = A). The `--out-dir` mode,
/// the build's, never comes here.
#[allow(
    clippy::disallowed_methods,
    reason = "the default mode, --check and --package docs run agent-docs.py, a Python CI and developer \
              step; oneiron_spawn is the server's, and the build's mode (--out-dir) never spawns"
)]
pub(crate) fn agent_docs(root: &Path, flags: &[&str]) -> Result<(), GenerateError> {
    let script = root.join("packages/oneiron/scripts/agent-docs.py");
    let interpreter = python();
    let mut argv = vec![interpreter.clone(), script.to_string_lossy().into_owned()];
    argv.extend(flags.iter().map(|flag| (*flag).to_owned()));
    let status = std::process::Command::new(&interpreter)
        .arg(&script)
        .args(flags)
        .status()
        .map_err(|error| GenerateError::os(&error, Path::new(&interpreter)))?;
    if status.success() {
        Ok(())
    } else {
        Err(called_process_error(&argv, status))
    }
}

impl Generator {
    /// Every output, in the `files` dict's order, each emitter run at its fixed place in the order (the emitters
    /// share the inventory, and the order they run in names its types).
    pub(crate) fn outputs(&mut self) -> Result<Outputs, GenerateError> {
        let facade_rows = local_facade_rows(self);
        // sdk_generated.rs.
        let core = super::emit_core::core(self, &facade_rows)?;
        let super::emit_server::FacadeDispatch {
            routes: server,
            dispatch,
        } = super::emit_server::facade_dispatch(self, &facade_rows)?;
        // The remote client's typed methods.
        let remote = super::emit_remote::remote(self, &facade_rows)?;
        // The napi and PyO3 methods, one row at a time.
        let super::emit_native::NativeTexts { napi, py } =
            super::emit_native::napi_py(self, &facade_rows)?;
        let ts = format!("{}{}", super::HEADER, super::common::AGENT_VERBS_TS);
        let ts_native = ts_native(self, &facade_rows)?;
        // verb_catalog.rs and the custody rows.
        let super::emit_core::Catalog {
            text: catalog,
            custody,
        } = super::emit_core::catalog(self)?;
        // UniFFI before the HTTP facade.
        let (uniffi, uniffi_types) = super::uniffi::uniffi_facade(self, &facade_rows)?;
        let http = http_facade(self)?;
        // The files dict, its values evaluated left to right.
        let mut files = Outputs::default();
        files.insert("packages/oneiron-client/src/facade.ts", http);
        files.insert(
            "crates/oneiron/src/verbs/generated/run_verb_catalog.rs",
            super::emit_core::run_catalog(self)?,
        );
        files.insert(
            "crates/oneiron-uniffi/src/generated/facade_generated.rs",
            uniffi,
        );
        files.insert(
            "crates/oneiron-uniffi/src/generated/facade_types_generated.rs",
            uniffi_types,
        );
        files.insert("crates/oneiron/src/verbs/generated/sdk_generated.rs", core);
        files.insert(
            "crates/oneiron/src/verbs/generated/verb_catalog.rs",
            catalog,
        );
        files.insert(
            super::CORE_VERB_NAMES_PATH,
            super::emit_core::core_verb_names(self, &custody)?,
        );
        files.insert(
            "crates/oneiron-server/src/api/facade/generated/agent_verbs.rs",
            server,
        );
        files.insert(
            "crates/oneiron-server/src/api/facade/generated/dispatch.rs",
            dispatch,
        );
        files.insert(
            "crates/oneiron-server/src/api/facade/generated/host_door_rows.rs",
            super::emit_server::host_door_rows(self, &facade_rows)?,
        );
        files.insert("crates/oneiron-remote/src/generated/agent_verbs.rs", remote);
        files.insert(
            "crates/oneiron-napi/src/facade/client/generated/agent_verbs.rs",
            napi,
        );
        // FIX 8907: the MCP dispatch is a whole-file child of tasks_response.
        files.insert(
            "crates/oneiron-server/src/api/mcp_gateway/generated/agent_verb_dispatch.rs",
            format!(
                "{}use super::*;\n{}",
                super::HEADER,
                super::emit_mcp::mcp_dispatch(self)?
            ),
        );
        files.insert("packages/oneiron/src/agent-verbs.ts", ts);
        // Untangle slice 4.3 (S4-3): what were marked blocks are whole files their hosts import.
        let tree = verb_tree(self, &facade_rows)?;
        files.insert(
            "packages/oneiron/src/facade-verbs.ts",
            ts_facade_module(self, &tree)?,
        );
        let tree = verb_tree(self, &facade_rows)?;
        files.insert(
            "crates/oneiron-py/python/oneiron/_facade_verbs.py",
            python_facade_module(self, &tree, false)?,
        );
        let tree = verb_tree(self, &facade_rows)?;
        files.insert(
            "crates/oneiron-py/python/oneiron/_facade_verbs.pyi",
            python_facade_module(self, &tree, true)?,
        );
        files.insert(
            "crates/oneiron-py/src/generated/agent_verbs.rs",
            format!(
                "{}#[pymethods]\nimpl NativeClient {{\n{py}}}\n",
                super::HEADER
            ),
        );
        // Rooted last, once every emitter above has named the types it uses.
        for text in EXTRA_ROOTS {
            self.inventory_mut()?.root_ir(text)?;
        }
        let rows: Vec<Dict> = self
            .facade_rows
            .iter()
            .map(|&id| row_of(self, id))
            .collect();
        let refs: Vec<&Dict> = rows.iter().collect();
        let census = self.inventory_mut()?.census(&refs)?;
        let facade_types = self.inventory_mut()?.typescript(&census)?;
        files.insert("packages/oneiron/src/facade-types.ts", facade_types.clone());
        files.insert(
            "packages/oneiron/src/native-verbs.ts",
            ts_native_module(self, &ts_native, &facade_types)?,
        );
        files.insert("packages/oneiron-client/src/facade-types.ts", facade_types);
        let stubs = self.inventory_mut()?.python(&census)?;
        files.insert("crates/oneiron-py/python/oneiron/facade_types.pyi", stubs);
        // The code-mode catalog fragment over every row code mode serves, with its own inventory.
        let code_mode: Vec<Dict> = self
            .code_mode_rows
            .iter()
            .map(|&id| row_of(self, id))
            .collect();
        let code_mode: Vec<&Dict> = code_mode.iter().collect();
        for (path, text) in crate::catalog_fragment::catalog_fragment(
            &self.root,
            &code_mode,
            super::HEADER,
            &self.type_names,
            &mut self.fragment_dependencies,
        )? {
            files.insert(path, text);
        }
        Ok(files)
    }

    /// The `--out-dir` mode: every output under `dir/<path>`; then the three generated docs (SDKGEN-DOCS = A: the text
    /// of agent-docs.py's `generated_artifacts`, written here, no process spawned).
    pub(crate) fn write_out_dir(&mut self, dir: &Path) -> Result<(), GenerateError> {
        let files = self.outputs()?;
        for (path, text) in files.iter() {
            let target = join(dir, path);
            if let Some(parent) = target.parent() {
                mkdir_parents(parent)?;
            }
            write_text(&target, text)?;
        }
        // As `agent-docs.py --from <dir> --out <dir>` would: its two outputs read back from `dir`.
        let docs = super::docs::generated_artifacts(&self.root, dir)?;
        super::docs::write(&docs, dir)
    }

    /// Every file the outputs depend on, as paths from the repository root, sorted: the fixed inputs (`INPUTS`' files),
    /// each verb file, and the crate source files the two type inventories' lookups read (`INVENTORY`'s and the
    /// catalog fragment's; see `facade_types::index`). Read after `outputs()`.
    pub(crate) fn dependencies(&self) -> BTreeSet<String> {
        let mut paths: BTreeSet<String> = crate::INPUTS
            .iter()
            .filter(|path| **path != VERBS_DIR)
            .map(|path| (*path).to_owned())
            .collect();
        for file in verb_files(&self.root.join(VERBS_DIR)) {
            if let Some(name) = file.file_name() {
                paths.insert(format!("{VERBS_DIR}/{}", name.to_string_lossy()));
            }
        }
        if let Some(inventory) = &self.inventory {
            paths.extend(inventory.index.dependency_paths());
        }
        paths.extend(self.fragment_dependencies.iter().cloned());
        paths
    }

    /// The `--package` mode: each named package's outputs written in the tree where they differ (the docs mirror's
    /// need the TypeScript and Python packages' too). Whether `docs` was named: the caller then runs
    /// `agent-docs.py --generated`.
    pub(crate) fn write_packages(&mut self, names: &[String]) -> Result<bool, GenerateError> {
        let files = self.outputs()?;
        let mut packages: std::collections::BTreeSet<&str> =
            names.iter().map(String::as_str).collect();
        let docs = packages.contains("docs");
        if docs {
            packages.insert("oneiron");
            packages.insert("oneiron-py");
        }
        for name in packages {
            for path in package_outputs(name).unwrap_or_default() {
                if path.starts_with("docs/") {
                    continue;
                }
                let target = self.root.join(path);
                // `files[path]`: every package path is an output.
                let text = files.get(path).ok_or_else(|| GenerateError::key(path))?;
                if !target.exists() || read_text(&target)? != text {
                    if let Some(parent) = target.parent() {
                        mkdir_parents(parent)?;
                    }
                    write_text(&target, text)?;
                }
            }
        }
        Ok(docs)
    }

    /// The default mode and `--check`: the tree's outputs that are no build-time output written where they differ
    /// (`--check`: none written, and the package outputs not compared), then `SDK-GENERATED-STALE` for `--check`.
    /// Returns what the default mode prints on stdout: the census, each opaque leaf and each unread shape.
    pub(crate) fn write_tree(&mut self, check: bool) -> Result<String, GenerateError> {
        let files = self.outputs()?;
        let mut stale: Vec<&str> = Vec::new();
        for (path, text) in files.iter() {
            if BUILD_TIME_OUTPUTS.contains(&path) || (check && is_package_path(path)) {
                continue;
            }
            let target = self.root.join(path);
            if target.exists() && read_text(&target)? == text {
                continue;
            }
            stale.push(path);
            if !check {
                if let Some(parent) = target.parent() {
                    mkdir_parents(parent)?;
                }
                write_text(&target, text)?;
            }
        }
        if check && !stale.is_empty() {
            return Err(GenerateError::exit(format!(
                "SDK-GENERATED-STALE: {}",
                stale.join(", ")
            )));
        }
        if check {
            return Ok(String::new());
        }
        // OF-246: how many row types read fully, and each leaf that did not.
        let rows: Vec<Dict> = self
            .facade_rows
            .iter()
            .map(|&id| row_of(self, id))
            .collect();
        let refs: Vec<&Dict> = rows.iter().collect();
        let inventory = self.inventory_mut()?;
        let mut out = inventory.census(&refs)?.join("\n");
        out.push('\n');
        for (place, text) in &inventory.opaques {
            out += &format!("  opaque: {place} ({text})\n");
        }
        for (place, text, reason) in &inventory.fallbacks {
            out += &format!("  unread: {place} ({text}): {reason}\n");
        }
        Ok(out)
    }
}

// ---- outputs()'s locals

/// `outputs()`'s `facade_rows`: `[r for r in ROWS if r.get("context", "memory") == "memory"] + BOARD_HOST_ROWS`,
/// recomputed as `outputs()` does (the same rows as `FACADE_ROWS`).
pub(crate) fn local_facade_rows(generator: &Generator) -> Vec<RowId> {
    generator
        .callable_rows
        .iter()
        .copied()
        .filter(|&id| context_is(&generator.rows[id], "memory"))
        .chain(generator.board_host_rows.iter().copied())
        .collect()
}

/// `'\n'.join(ts_native_signature(r) for r in facade_rows)`.
fn ts_native(generator: &mut Generator, facade_rows: &[RowId]) -> Result<String, GenerateError> {
    let mut signatures = Vec::new();
    for &id in facade_rows {
        signatures.push(ts_native_signature(generator, id)?);
    }
    Ok(signatures.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // python3 -c "from pathlib import Path; print([str(Path(p)) for p in P])" on nelly.
    #[test]
    fn pure_path_is_pathlibs() {
        let cases = [
            ("", "."),
            (".", "."),
            ("./", "."),
            ("out", "out"),
            ("out/", "out"),
            ("./out//x/./y/", "out/x/y"),
            ("/", "/"),
            ("/a/../b", "/a/../b"),
            ("//a", "//a"),
            ("///a", "/a"),
            ("a/./.", "a"),
            ("..", ".."),
        ];
        for (text, expected) in cases {
            assert_eq!(pure_path(text), expected, "{text:?}");
        }
    }

    // python3 -c "from pathlib import Path; print([str(Path(d) / 'a/b.ts') for d in ['.', '', 'out', '/']])"
    #[test]
    fn join_is_pathlibs() {
        for (dir, expected) in [
            (".", "a/b.ts"),
            ("", "a/b.ts"),
            ("out", "out/a/b.ts"),
            ("/", "/a/b.ts"),
        ] {
            assert_eq!(
                join(Path::new(dir), "a/b.ts"),
                Path::new(expected),
                "{dir:?}"
            );
        }
    }

    #[test]
    fn package_tables() {
        assert!(is_package_path("docs/agent-sdk/types.md"));
        assert!(!is_package_path(
            "crates/oneiron/src/verbs/generated/verb_catalog.rs"
        ));
        assert_eq!(
            package_outputs("oneiron-client").map(<[&str]>::len),
            Some(2)
        );
        assert_eq!(package_outputs("nope"), None);
        assert_eq!(BUILD_TIME_OUTPUTS.len(), 16);
    }

    // python3 -c "import subprocess; print(subprocess.CalledProcessError(-N, ['x']))" on nelly (3.14.7).
    #[cfg(target_os = "linux")]
    #[test]
    fn signals_are_named_as_python_names_them() {
        let cmd = "['x']";
        for (signal, expected) in [
            (15, "Command '['x']' died with <Signals.SIGTERM: 15>."),
            (24, "Command '['x']' died with <Signals.SIGXCPU: 24>."),
            (6, "Command '['x']' died with <Signals.SIGABRT: 6>."),
            (64, "Command '['x']' died with <Signals.SIGRTMAX: 64>."),
            (35, "Command '['x']' died with unknown signal 35."),
        ] {
            assert_eq!(signal_message(cmd, signal), expected);
        }
    }

    // python3 -c "print('x' * 9000)" with stdout on /dev/full, and into a closed pipe, on nelly: the last line.
    #[cfg(target_os = "linux")]
    #[test]
    fn stream_errors_are_pythons() {
        assert_eq!(
            stream_error(&io::Error::from_raw_os_error(28)).to_string(),
            "OSError: [Errno 28] No space left on device"
        );
        assert_eq!(
            stream_error(&io::Error::from_raw_os_error(32)).to_string(),
            "BrokenPipeError: [Errno 32] Broken pipe"
        );
    }
}
