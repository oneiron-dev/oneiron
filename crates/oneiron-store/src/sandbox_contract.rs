//! Guest tier, runtime, language, import classes and the linked-import boundary contract.

use crate::sandbox_credential::SandboxCredentialEffect;

pub const SANDBOX_WIT_WORLD_NAME: &str = "oneiron:code-run/guest@1.0.0";

pub const SANDBOX_JS_COMPONENT_NAME: &str = "oneiron.plain-js.quickjs-component";

pub const PLAIN_JS_HOST_VERB_DTS: &str = include_str!("../../wit/generated/code-run.d.ts");

/// Trust tier selected by the host before linking a guest program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxGuestTier {
    /// First-party Dreamer code. Public writes link as per-op typed traps.
    FirstPartyDreamer,
    /// Imported or externally-authored code.
    Foreign,
    /// Explicitly untrusted code.
    Untrusted,
}

impl SandboxGuestTier {
    /// Stable tier label for diagnostics and proposal metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstPartyDreamer => "first_party_dreamer",
            Self::Foreign => "foreign",
            Self::Untrusted => "untrusted",
        }
    }

    /// Foreign and untrusted guests cannot link host write imports.
    #[must_use]
    pub const fn requires_zero_write_imports(self) -> bool {
        matches!(self, Self::Foreign | Self::Untrusted)
    }
}

/// Guest language accepted by the code-mode authoring surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxGuestLanguage {
    /// Full plain JavaScript interpreted inside the sandbox component.
    PlainJavaScript,
}

impl SandboxGuestLanguage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlainJavaScript => "plain_javascript",
        }
    }
}

/// Stable execution boundary used to host the guest runtime component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxComponentBoundary {
    /// Wasmtime Component Model + WIT-linked host imports.
    WasmtimeWit,
}

impl SandboxComponentBoundary {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WasmtimeWit => "wasmtime_wit",
        }
    }
}

/// Runtime component selected for code-mode execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxGuestRuntime {
    /// QuickJS-class plain-JS interpreter embedded as a WASM component.
    PlainJsQuickJsComponent,
}

impl SandboxGuestRuntime {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlainJsQuickJsComponent => SANDBOX_JS_COMPONENT_NAME,
        }
    }

    #[must_use]
    pub const fn language(self) -> SandboxGuestLanguage {
        match self {
            Self::PlainJsQuickJsComponent => SandboxGuestLanguage::PlainJavaScript,
        }
    }

    #[must_use]
    pub const fn boundary(self) -> SandboxComponentBoundary {
        match self {
            Self::PlainJsQuickJsComponent => SandboxComponentBoundary::WasmtimeWit,
        }
    }

    #[must_use]
    pub const fn wit_world(self) -> &'static str {
        match self {
            Self::PlainJsQuickJsComponent => SANDBOX_WIT_WORLD_NAME,
        }
    }

    #[must_use]
    pub const fn prompt_side_dts(self) -> &'static str {
        match self {
            Self::PlainJsQuickJsComponent => PLAIN_JS_HOST_VERB_DTS,
        }
    }

    /// The dotted host verbs this runtime's prompt-side `d.ts` ADVERTISES.
    ///
    /// Structural, not textual: `namespace` nesting supplies the prefix and
    /// each `function name(` line contributes one dotted verb, so the set the
    /// prompt teaches a model can be compared against the imports a boundary
    /// actually links. The dangerous direction is the one only this makes
    /// checkable: an advertised verb with no linked import teaches the model
    /// to call a host effect that does not exist, and speech is the sharpest
    /// case, since [`SandboxImportClass::Speech`] is deliberately kept apart
    /// from [`SandboxImportClass::WriteTrap`] and carries its own gated
    /// witness path.
    #[must_use]
    pub fn advertised_prompt_verbs(self) -> Vec<String> {
        advertised_host_verbs(self.prompt_side_dts())
    }
}

/// Extracts every dotted verb a prompt-side `d.ts` declares.
///
/// One pass over the lines: `declare namespace x {` / `namespace x {` pushes a
/// prefix, a line that is exactly `}` pops it, and `function name(` emits the
/// prefixed name. A multi-line parameter object closes on `}): ...`, never on
/// a bare `}`, so it cannot pop a namespace it never opened.
fn advertised_host_verbs(dts: &str) -> Vec<String> {
    let mut namespaces: Vec<&str> = Vec::new();
    let mut verbs = Vec::new();
    for line in dts.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("declare namespace ")
            .or_else(|| line.strip_prefix("namespace "))
        {
            if let Some(name) = rest.split_whitespace().next() {
                namespaces.push(name);
            }
        } else if let Some(rest) = line
            .strip_prefix("declare function ")
            .or_else(|| line.strip_prefix("function "))
        {
            let name = rest.split('(').next().unwrap_or_default().trim();
            if !name.is_empty() {
                let mut verb = namespaces.join(".");
                if !verb.is_empty() {
                    verb.push('.');
                }
                verb.push_str(name);
                verbs.push(verb);
            }
        } else if line == "}" {
            namespaces.pop();
        }
    }
    verbs
}

pub use crate::sandbox_import::SandboxImportClass;

