//! Port of generate.py:2194-2604: `BUILD_TIME_OUTPUTS`, `PACKAGE_OUTPUTS`, `PACKAGE_PATHS` and `outputs()`, in
//! Python's call order (brief H10: the emitters share one `Inventory`, and the order they run in names its types);
//! and the file operations of generate.py:2928-2983 (`main`) and agent-docs.py's `write`, with pathlib's errors.
//!
//! Not ported, both by the lane's design (DESIGN 9.1, CHECK-4.3 C2): `FORMAT`'s rustfmt pass (generate.py:2586-2589;
//! no committed `.rs` output remains, so its text reaches no file), and the two dormant rewrites of generate.py:
//! 2533-2557 (the MCP dispatch and board catalog markers, absent on main). Their two hosts are still read, as Python
//! reads them, so a missing or undecodable host fails here as it does there.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;

use super::emit_http::http_facade;
use super::emit_py::python_facade_module;
use super::emit_ts::{
    VerbTree, row_of, ts_facade_module, ts_native_module, ts_native_signature, verb_tree,
};
use super::row_access::context_is;
use super::{Generator, RowId};
use crate::error::GenerateError;
use crate::py::read_text;
use crate::py::value::{Dict, Value};

/// Port of generate.py:2194-2211 (BUILD_TIME_OUTPUTS): the outputs crates/oneiron-sdk-build produces at build time
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

/// Port of generate.py:2215-2236 (PACKAGE_OUTPUTS): each package's outputs, which its build writes in the tree
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

/// Port of generate.py:2237 (PACKAGE_PATHS): every package output path (a set, read for membership).
pub(crate) fn is_package_path(path: &str) -> bool {
    PACKAGE_OUTPUTS
        .iter()
        .any(|(_, paths)| paths.contains(&path))
}

/// The outputs of one run, as generate.py's `outputs()` returns them: each repository path (`/`-separated, relative
/// to the root) with its text, or `None` for an old home the default mode deletes, in the `files` dict's order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outputs {
    files: IndexMap<String, Option<String>>,
}

impl Outputs {
    /// `files[path] = text`: a new path goes last, a present one keeps its place (Python's dict).
    pub(crate) fn insert(&mut self, path: &str, text: Option<String>) {
        self.files.insert(path.to_owned(), text);
    }

    /// Every output in order: its path, and its text or `None` for a deletion.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_deref()))
    }

    /// The output at `path`: `None` when there is none, `Some(None)` for a deletion.
    pub fn get(&self, path: &str) -> Option<Option<&str>> {
        self.files.get(path).map(Option::as_deref)
    }

    /// How many outputs there are, deletions included.
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

/// generate.py:2590-2603: the outputs' old homes, which the default mode deletes, in the literal's order.
pub(crate) const DELETIONS: [&str; 16] = [
    "crates/oneiron/src/workspace_roster/rooms/verb_catalog.rs",
    "crates/oneiron-server/src/mcp/agent_catalog.rs",
    "crates/oneiron-py/python/oneiron/agent_verbs.py",
    "crates/oneiron-py/python/oneiron/agent_verbs.pyi",
    // FIX 8907: the whole-file outputs' homes before generated/.
    "crates/oneiron/src/task_verb/verb_catalog.rs",
    "crates/oneiron/src/task_verb/run_verb_catalog.rs",
    "crates/oneiron/src/task_verb/sdk_generated.rs",
    "crates/oneiron/src/task_verb/catalog_fragment_revision.rs",
    "crates/oneiron-server/src/api/facade/agent_verbs.rs",
    "crates/oneiron-server/src/api/facade/dispatch.rs",
    "crates/oneiron-remote/src/agent_verbs.rs",
    "crates/oneiron-napi/src/facade/client/agent_verbs.rs",
    "crates/oneiron-uniffi/src/facade_generated.rs",
    "crates/oneiron-uniffi/src/facade_types_generated.rs",
    "crates/oneiron/src/task_verb/catalog_fragment.d.ts",
    "crates/oneiron/src/task_verb/code-mode.d.ts",
];

/// generate.py:2563-2575: the types no verb row reaches that a hand-written route serves, rooted last (OF-181, FIX
/// 7968, 9891, 365), in Python's order.
const EXTRA_ROOTS: [&str; 5] = [
    "crate::lens::GeneratedUiActionEvent",
    "crate::lens::GeneratedUiSegment",
    "crate::lens::GeneratedUiCatalogDescriptor",
    "crate::memory::TranscriptPage",
    "crate::memory::MessageResultAttachment",
];

/// The interpreter generate.py's spawn of agent-docs.py names (`sys.executable`): `ONEIRON_PYTHON` when set, else
/// `python3` (`python` on Windows), as crates/oneiron-sdk-build chose one.
fn python() -> String {
    std::env::var("ONEIRON_PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".to_owned()
        } else {
            "python3".to_owned()
        }
    })
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

/// `Command '...' died with <Signals.SIGTERM: 15>.` (Linux's signal numbers).
#[cfg(unix)]
fn signal_text(cmd: &str, status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    let Some(signal) = status.signal() else {
        return format!("Command '{cmd}' died with unknown signal 0.");
    };
    let names = [
        "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE",
        "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM",
    ];
    match usize::try_from(signal - 1)
        .ok()
        .and_then(|at| names.get(at))
    {
        Some(name) if cfg!(target_os = "linux") => {
            format!("Command '{cmd}' died with <Signals.{name}: {signal}>.")
        }
        _ => format!("Command '{cmd}' died with unknown signal {signal}."),
    }
}

#[cfg(not(unix))]
fn signal_text(cmd: &str, _status: std::process::ExitStatus) -> String {
    format!("Command '{cmd}' died with unknown signal 0.")
}

/// generate.py:2948 and 2982-2983: `subprocess.run([sys.executable, 'packages/oneiron/scripts/agent-docs.py',
/// *flags], check=True)`, inheriting the standard streams. The script stays Python (SDKGEN-DOCS = A keeps its
/// `--check` and `--generated`); the `--out-dir` mode, the build's, never comes here.
#[allow(
    clippy::disallowed_methods,
    reason = "generate.py's default mode, --check and --package docs run agent-docs.py, a Python CI and developer \
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
    /// Port of generate.py:2241-2604 (outputs): every output, in the `files` dict's order, each emitter run where
    /// Python runs it (brief H10), then the sixteen deletions as `None`.
    pub(crate) fn outputs(&mut self) -> Result<Outputs, GenerateError> {
        // generate.py:2242
        let facade_rows = local_facade_rows(self);
        // generate.py:2243-2385: sdk_generated.rs (G4a's segment).
        let core = super::emit_core::core(self, &facade_rows)?;
        // generate.py:2386
        let super::emit_server::FacadeDispatch {
            routes: server,
            dispatch,
        } = super::emit_server::facade_dispatch(self, &facade_rows)?;
        // generate.py:2387-2449: the remote client's typed methods (G4a's segment).
        let remote = super::emit_remote::remote(self, &facade_rows)?;
        // generate.py:2450-2459: the napi and PyO3 methods, one row at a time (G4a's segment).
        let super::emit_native::NativeTexts { napi, py } =
            super::emit_native::napi_py(self, &facade_rows)?;
        // generate.py:2460-2461
        let ts = format!("{}{}", super::HEADER, super::common::AGENT_VERBS_TS);
        let ts_native = ts_native(self, &facade_rows)?;
        // generate.py:2462-2508: verb_catalog.rs and the custody rows (G4a's segment).
        let super::emit_core::Catalog {
            text: catalog,
            custody,
        } = super::emit_core::catalog(self)?;
        // generate.py:2509-2510: UniFFI before the HTTP facade.
        let (uniffi, uniffi_types) = super::uniffi::uniffi_facade(self, &facade_rows)?;
        let http = http_facade(self)?;
        // generate.py:2511-2532: the files dict, its values evaluated left to right.
        let mut files = Outputs::default();
        files.insert("packages/oneiron-client/src/facade.ts", Some(http));
        files.insert(
            "crates/oneiron/src/verbs/generated/run_verb_catalog.rs",
            Some(super::emit_core::run_catalog(self)?),
        );
        files.insert(
            "crates/oneiron-uniffi/src/generated/facade_generated.rs",
            Some(uniffi),
        );
        files.insert(
            "crates/oneiron-uniffi/src/generated/facade_types_generated.rs",
            Some(uniffi_types),
        );
        files.insert(
            "crates/oneiron/src/verbs/generated/sdk_generated.rs",
            Some(core),
        );
        files.insert(
            "crates/oneiron/src/verbs/generated/verb_catalog.rs",
            Some(catalog),
        );
        files.insert(
            super::CORE_VERB_NAMES_PATH,
            Some(super::emit_core::core_verb_names(self, &custody)?),
        );
        files.insert(
            "crates/oneiron-server/src/api/facade/generated/agent_verbs.rs",
            Some(server),
        );
        files.insert(
            "crates/oneiron-server/src/api/facade/generated/dispatch.rs",
            Some(dispatch),
        );
        files.insert(
            "crates/oneiron-server/src/api/facade/generated/host_door_rows.rs",
            Some(super::emit_server::host_door_rows(self, &facade_rows)?),
        );
        files.insert(
            "crates/oneiron-remote/src/generated/agent_verbs.rs",
            Some(remote),
        );
        files.insert(
            "crates/oneiron-napi/src/facade/client/generated/agent_verbs.rs",
            Some(napi),
        );
        // FIX 8907: the MCP dispatch is a whole-file child of tasks_response.
        files.insert(
            "crates/oneiron-server/src/api/mcp_gateway/generated/agent_verb_dispatch.rs",
            Some(format!(
                "{}use super::*;\n{}",
                super::HEADER,
                super::emit_mcp::mcp_dispatch(self)?
            )),
        );
        files.insert("packages/oneiron/src/agent-verbs.ts", Some(ts));
        // Untangle slice 4.3 (S4-3): what were marked blocks are whole files their hosts import.
        let tree = verb_tree(self, &facade_rows)?;
        files.insert(
            "packages/oneiron/src/facade-verbs.ts",
            Some(ts_facade_module(self, &tree)?),
        );
        let tree = verb_tree(self, &facade_rows)?;
        files.insert(
            "crates/oneiron-py/python/oneiron/_facade_verbs.py",
            Some(python_facade_module(self, &tree, false)?),
        );
        let tree = verb_tree(self, &facade_rows)?;
        files.insert(
            "crates/oneiron-py/python/oneiron/_facade_verbs.pyi",
            Some(python_facade_module(self, &tree, true)?),
        );
        files.insert(
            "crates/oneiron-py/src/generated/agent_verbs.rs",
            Some(format!(
                "{}#[pymethods]\nimpl NativeClient {{\n{py}}}\n",
                super::HEADER
            )),
        );
        // generate.py:2533-2557: the two dormant rewrites are not ported (their begin markers are absent on main);
        // their hosts are read, as Python reads them whether or not a marker is there.
        read_text(
            &self
                .root
                .join("crates/oneiron-server/src/api/mcp_gateway/tasks_response.rs"),
        )?;
        read_text(&self.root.join("crates/oneiron/src/board_verb.rs"))?;
        // generate.py:2563-2575: rendered last, once every emitter above has named the types it uses.
        for text in EXTRA_ROOTS {
            self.inventory_mut()?.root_ir(text)?;
        }
        // generate.py:2576-2581
        let rows: Vec<Dict> = self
            .facade_rows
            .iter()
            .map(|&id| row_of(self, id))
            .collect();
        let refs: Vec<&Dict> = rows.iter().collect();
        let census = self.inventory_mut()?.census(&refs)?;
        let facade_types = self.inventory_mut()?.typescript(&census)?;
        files.insert(
            "packages/oneiron/src/facade-types.ts",
            Some(facade_types.clone()),
        );
        files.insert(
            "packages/oneiron/src/native-verbs.ts",
            Some(ts_native_module(self, &ts_native, &facade_types)?),
        );
        files.insert(
            "packages/oneiron-client/src/facade-types.ts",
            Some(facade_types),
        );
        let stubs = self.inventory_mut()?.python(&census)?;
        files.insert(
            "crates/oneiron-py/python/oneiron/facade_types.pyi",
            Some(stubs),
        );
        // generate.py:2585: the code-mode catalog fragment over every row code mode serves, with its own inventory.
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
        )? {
            files.insert(path, Some(text));
        }
        // generate.py:2586-2589: rustfmt (`FORMAT`) is not ported: no committed `.rs` output remains (CHECK-4.3 C2).
        for path in DELETIONS {
            files.insert(path, None);
        }
        Ok(files)
    }

    /// Port of generate.py:2950-2958 (main's `--out-dir` mode): every output that is no deletion, under
    /// `dir/<path>`; then the three generated docs (SDKGEN-DOCS = A: agent-docs.py's `generated_artifacts`, written
    /// here rather than by a spawned `agent-docs.py --from <dir> --out <dir>`).
    pub(crate) fn write_out_dir(&mut self, dir: &Path) -> Result<(), GenerateError> {
        let files = self.outputs()?;
        for (path, text) in files.iter() {
            let Some(text) = text else { continue };
            let target = join(dir, path);
            if let Some(parent) = target.parent() {
                mkdir_parents(parent)?;
            }
            write_text(&target, text)?;
        }
        let output = |path: &str| files.get(path).flatten().unwrap_or_default();
        let docs = super::docs::generated_artifacts(
            &self.root,
            output("crates/oneiron-py/python/oneiron/_facade_verbs.pyi"),
            output("packages/oneiron/src/facade-types.ts"),
        )?;
        super::docs::write(&docs, dir)
    }

    /// Port of generate.py:2934-2947 (main's `--package` mode): each named package's outputs written in the tree
    /// where they differ (the docs mirror's need the TypeScript and Python packages' too). Whether `docs` was named:
    /// the caller then runs `agent-docs.py --generated` (generate.py:2948).
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
                let text = files
                    .get(path)
                    .ok_or_else(|| GenerateError::key(path))?
                    .unwrap_or_default();
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

    /// Port of generate.py:2959-2979 (main's default mode and `--check`): the tree's outputs that are no build-time
    /// output written where they differ (`--check`: none written, and the package outputs not compared), each old
    /// home deleted (`--check`: reported), then `SDK-GENERATED-STALE` for `--check`. Returns what the default mode
    /// prints on stdout: the census, each opaque leaf and each unread shape.
    pub(crate) fn write_tree(&mut self, check: bool) -> Result<String, GenerateError> {
        let files = self.outputs()?;
        let mut stale: Vec<&str> = Vec::new();
        for (path, text) in files.iter() {
            if BUILD_TIME_OUTPUTS.contains(&path) || (check && is_package_path(path)) {
                continue;
            }
            let target = self.root.join(path);
            let Some(text) = text else {
                if target.exists() {
                    stale.push(path);
                    if !check {
                        fs::remove_file(&target)
                            .map_err(|error| GenerateError::os(&error, &target))?;
                    }
                }
                continue;
            };
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

// ---- outputs()'s locals, and the replay entry points of the ported emitters (DESIGN 9.3)

/// generate.py:2242 `facade_rows`: `[r for r in ROWS if r.get("context", "memory") == "memory"] + BOARD_HOST_ROWS`,
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

/// generate.py:2461: `'\n'.join(ts_native_signature(r) for r in facade_rows)`.
fn ts_native(generator: &mut Generator, facade_rows: &[RowId]) -> Result<String, GenerateError> {
    let mut signatures = Vec::new();
    for &id in facade_rows {
        signatures.push(ts_native_signature(generator, id)?);
    }
    Ok(signatures.join("\n"))
}

/// The verb tree as Python's dicts: `{name: {'row': row, 'children': {...}}}` (the replay's logged value).
fn tree_value(generator: &Generator, tree: &VerbTree) -> Value {
    let mut out = Dict::new();
    for (name, node) in tree {
        let mut entry = Dict::new();
        entry.insert(
            "row".to_owned(),
            node.row
                .map_or(Value::None, |id| Value::Dict(row_of(generator, id))),
        );
        entry.insert("children".to_owned(), tree_value(generator, &node.children));
        out.insert(name.clone(), Value::Dict(entry));
    }
    Value::Dict(out)
}

/// The replay's `ts_native_signature#n`: the nth facade row's signature (generate.py:2461).
pub(crate) fn replay_ts_native_signature(
    generator: &mut Generator,
    n: usize,
) -> Result<Value, GenerateError> {
    let facade_rows = local_facade_rows(generator);
    let id = n
        .checked_sub(1)
        .and_then(|at| facade_rows.get(at))
        .copied()
        .ok_or_else(|| GenerateError::exit(format!("port-harness replay: no facade row {n}")))?;
    ts_native_signature(generator, id).map(Value::Str)
}

/// The replay's `http_facade#1` (generate.py:2510).
pub(crate) fn replay_http_facade(
    generator: &mut Generator,
    _n: usize,
) -> Result<Value, GenerateError> {
    http_facade(generator).map(Value::Str)
}

/// The replay's `verb_tree#n`: the first call is `http_facade`'s over `FACADE_ROWS` (generate.py:1534), the next
/// three `outputs()`'s over its `facade_rows` (2528-2530).
pub(crate) fn replay_verb_tree(
    generator: &mut Generator,
    n: usize,
) -> Result<Value, GenerateError> {
    let rows = if n == 1 {
        generator.facade_rows.clone()
    } else {
        local_facade_rows(generator)
    };
    let tree = verb_tree(generator, &rows)?;
    Ok(tree_value(generator, &tree))
}

/// The replay's `ts_facade_module#1` (generate.py:2528).
pub(crate) fn replay_ts_facade_module(
    generator: &mut Generator,
    _n: usize,
) -> Result<Value, GenerateError> {
    let rows = local_facade_rows(generator);
    let tree = verb_tree(generator, &rows)?;
    ts_facade_module(generator, &tree).map(Value::Str)
}

/// The replay's `python_facade_module#n`: the runtime module first (generate.py:2529), then the stub (2530).
pub(crate) fn replay_python_facade_module(
    generator: &mut Generator,
    n: usize,
) -> Result<Value, GenerateError> {
    let rows = local_facade_rows(generator);
    let tree = verb_tree(generator, &rows)?;
    python_facade_module(generator, &tree, n == 2).map(Value::Str)
}

/// The replay's `ts_native_module#1` (generate.py:2579). Its arguments are recomputed at the call: by then every
/// type the signatures and the census name is rooted, so neither call changes the inventory, and each gives the text
/// `outputs()` passed.
pub(crate) fn replay_ts_native_module(
    generator: &mut Generator,
    _n: usize,
) -> Result<Value, GenerateError> {
    let rows = local_facade_rows(generator);
    let signatures = ts_native(generator, &rows)?;
    let facade_rows: Vec<Dict> = generator
        .facade_rows
        .iter()
        .map(|&id| row_of(generator, id))
        .collect();
    let refs: Vec<&Dict> = facade_rows.iter().collect();
    let inventory = generator.inventory_mut()?;
    let census = inventory.census(&refs)?;
    let facade_types = inventory.typescript(&census)?;
    ts_native_module(generator, &signatures, &facade_types).map(Value::Str)
}

/// The output a `python_facade_module` value is: the stub holds its `typing` import line.
pub(crate) fn python_facade_module_path(text: &str) -> &'static str {
    if text.contains("\nfrom typing import Any, overload\n") {
        "crates/oneiron-py/python/oneiron/_facade_verbs.pyi"
    } else {
        "crates/oneiron-py/python/oneiron/_facade_verbs.py"
    }
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
}
