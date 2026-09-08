//! Guest tier, runtime, language, import classes and the linked-import boundary contract.

use super::credential::SandboxCredentialEffect;
use crate::code_run::SelfEffect;

pub const SANDBOX_WIT_WORLD_NAME: &str = "oneiron:code-run/guest@1.0.0";

pub const SANDBOX_JS_COMPONENT_NAME: &str = "oneiron.plain-js.quickjs-component";

pub const PLAIN_JS_HOST_VERB_DTS: &str = r#"declare namespace self {
  namespace memory {
    function search(input: { query: string; limit?: number }): Promise<{ results: unknown[] }>;
    function put_claim(input: {
      id: string;
      predicate: string;
      subject: unknown;
      value: unknown;
      confidence?: number;
      occurred?: { start: number; end: number };
      learnedAt?: number;
    }): Promise<{ id: string }>;
    function supersede_claim(input: { newId: string; oldId: string; now: number }): Promise<{ id: string }>;
    function put_edge(input: { src: string; kind: string; tgt: string; weight?: number }): Promise<{ src: string; kind: string; tgt: string }>;
  }

  function askHuman(input: { prompt: string }): Promise<{ waitId: string }>;
  function ask_human(input: { prompt: string }): Promise<{ waitId: string }>;

  function speak(input: { text: string }): Promise<{ order: number; isVisible: boolean }>;
  function think(input: { text: string }): Promise<{ order: number; isVisible: boolean }>;
  function express(input: { text: string }): Promise<{ order: number; isVisible: boolean }>;
}

declare namespace oneiron {
  namespace clock {
    function now_unix_ms(): number;
  }

  namespace random {
    function bytes(length: number): Uint8Array;
  }
}
"#;

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
}

/// Class of a host import linked into a guest program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxImportClass {
    ReadOnly,
    CredentialHandle,
    Determinism,
    DurableWait,
    WriteTrap,
    /// The `self.speak` family (ONE-1686): an explicit host effect that emits
    /// one durable MESSAGE bubble through the run's bound witness route.
    ///
    /// Deliberately NOT `WriteTrap`. A write trap is a gated MEMORY verb —
    /// claim, supersede, edge — and OF-060 P3 pins that set closed. Speech
    /// writes a transcript row, not memory, and it is gated on the witness
    /// path instead; giving it its own class is what keeps the two ceilings
    /// from being confused for one.
    Speech,
}

impl SandboxImportClass {
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(self, Self::WriteTrap)
    }
}

/// One host import exposed at link time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SandboxLinkedImport {
    name: &'static str,
    class: SandboxImportClass,
}

impl SandboxLinkedImport {
    #[must_use]
    pub const fn new(name: &'static str, class: SandboxImportClass) -> Self {
        Self { name, class }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn class(self) -> SandboxImportClass {
        self.class
    }

    #[must_use]
    pub fn write_trap_effect(self) -> Option<SelfEffect> {
        match (self.class, self.name) {
            (SandboxImportClass::WriteTrap, "self.memory.put_claim") => {
                Some(SelfEffect::MemoryPutClaim)
            }
            (SandboxImportClass::WriteTrap, "self.memory.supersede_claim") => {
                Some(SelfEffect::MemorySupersedeClaim)
            }
            (SandboxImportClass::WriteTrap, "self.memory.put_edge") => {
                Some(SelfEffect::MemoryPutEdge)
            }
            _ => None,
        }
    }
}

const READ_FILE_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("sandbox.fs.read_file", SandboxImportClass::ReadOnly);

const CREDENTIAL_CALL_IMPORT: SandboxLinkedImport = SandboxLinkedImport::new(
    "sandbox.credential.call",
    SandboxImportClass::CredentialHandle,
);

const CLOCK_NOW_UNIX_MS_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.clock.now_unix_ms", SandboxImportClass::Determinism);

const RANDOM_BYTES_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.random.bytes", SandboxImportClass::Determinism);

const SELF_MEMORY_SEARCH_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.memory.search", SandboxImportClass::ReadOnly);

const SELF_MEMORY_PUT_CLAIM_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.memory.put_claim", SandboxImportClass::WriteTrap);

const SELF_MEMORY_SUPERSEDE_CLAIM_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.memory.supersede_claim", SandboxImportClass::WriteTrap);

const SELF_MEMORY_PUT_EDGE_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.memory.put_edge", SandboxImportClass::WriteTrap);

const SELF_ASK_HUMAN_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.ask_human", SandboxImportClass::DurableWait);

const SELF_ASK_HUMAN_CAMEL_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.askHuman", SandboxImportClass::DurableWait);

const SELF_SPEAK_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.speak", SandboxImportClass::Speech);

const SELF_THINK_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.think", SandboxImportClass::Speech);

const SELF_EXPRESS_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.express", SandboxImportClass::Speech);

const NON_WRITE_IMPORTS: &[SandboxLinkedImport] = &[
    READ_FILE_IMPORT,
    CREDENTIAL_CALL_IMPORT,
    CLOCK_NOW_UNIX_MS_IMPORT,
    RANDOM_BYTES_IMPORT,
];

const FIRST_PARTY_IMPORTS: &[SandboxLinkedImport] = &[
    READ_FILE_IMPORT,
    CREDENTIAL_CALL_IMPORT,
    CLOCK_NOW_UNIX_MS_IMPORT,
    RANDOM_BYTES_IMPORT,
    SELF_MEMORY_SEARCH_IMPORT,
    SELF_MEMORY_PUT_CLAIM_IMPORT,
    SELF_MEMORY_SUPERSEDE_CLAIM_IMPORT,
    SELF_MEMORY_PUT_EDGE_IMPORT,
    SELF_ASK_HUMAN_IMPORT,
    SELF_ASK_HUMAN_CAMEL_IMPORT,
    SELF_SPEAK_IMPORT,
    SELF_THINK_IMPORT,
    SELF_EXPRESS_IMPORT,
];

/// Link-time contract for one guest tier.
///
/// First-party write traps are immediate typed host calls; foreign and
/// untrusted guests link no write imports and use proposal deltas only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxBoundaryContract {
    tier: SandboxGuestTier,
    runtime: SandboxGuestRuntime,
    linked_imports: &'static [SandboxLinkedImport],
    proposal_delta_channel: bool,
    credential_call_effect: SandboxCredentialEffect,
}

impl SandboxBoundaryContract {
    /// Returns the currently implemented contract for `tier`.
    #[must_use]
    pub const fn for_tier(tier: SandboxGuestTier) -> Self {
        match tier {
            SandboxGuestTier::FirstPartyDreamer => Self {
                tier,
                runtime: SandboxGuestRuntime::PlainJsQuickJsComponent,
                linked_imports: FIRST_PARTY_IMPORTS,
                proposal_delta_channel: false,
                credential_call_effect: SandboxCredentialEffect::ReadOnly,
            },
            SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted => Self {
                tier,
                runtime: SandboxGuestRuntime::PlainJsQuickJsComponent,
                linked_imports: NON_WRITE_IMPORTS,
                proposal_delta_channel: true,
                credential_call_effect: SandboxCredentialEffect::ReadOnly,
            },
        }
    }

    #[must_use]
    pub const fn tier(self) -> SandboxGuestTier {
        self.tier
    }

    #[must_use]
    pub const fn runtime(self) -> SandboxGuestRuntime {
        self.runtime
    }

    #[must_use]
    pub const fn guest_language(self) -> SandboxGuestLanguage {
        self.runtime.language()
    }

    #[must_use]
    pub const fn component_boundary(self) -> SandboxComponentBoundary {
        self.runtime.boundary()
    }

    #[must_use]
    pub const fn wit_world(self) -> &'static str {
        self.runtime.wit_world()
    }

    #[must_use]
    pub const fn prompt_side_dts(self) -> &'static str {
        self.runtime.prompt_side_dts()
    }

    #[must_use]
    pub const fn linked_imports(self) -> &'static [SandboxLinkedImport] {
        self.linked_imports
    }

    /// Whether this tier emits write intents through the proposal-delta channel.
    #[must_use]
    pub const fn has_proposal_delta_channel(self) -> bool {
        self.proposal_delta_channel
    }

    /// Credential-backed imports are handle-only and read-only at this boundary.
    #[must_use]
    pub const fn credential_call_effect(self) -> SandboxCredentialEffect {
        self.credential_call_effect
    }

    /// True if any linked import can commit or trap a host write.
    #[must_use]
    pub fn links_write_imports(self) -> bool {
        self.linked_imports
            .iter()
            .any(|import| import.class().is_write())
    }
}
