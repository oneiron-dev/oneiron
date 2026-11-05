//! Core half of `store::sandbox_contract`: its store-layer items live in `oneiron_store::sandbox_contract` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::sandbox_contract::*;

use crate::store::sandbox_credential::SandboxCredentialEffect;
pub use crate::store::sandbox_import::{SandboxImportClass, SandboxLinkedImport};

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

const OUTPUT_TEXT_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.output.text", SandboxImportClass::Output);

const OUTPUT_BYTES_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.output.bytes", SandboxImportClass::Output);

// The byte twin of the streamed "store" text target (FIX 829): frames land
// in the step's store sink and take effect only when the `store` verb row
// binds them, so the class is Output as the text target's is.
const STORE_BYTES_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.store.bytes", SandboxImportClass::Output);

const VAULT_AGENTS_PUT_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("vault.agents.put", SandboxImportClass::AgentAuthoring);

const SELF_JSON_VALIDATE_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.json.validate", SandboxImportClass::ReadOnly);

const SELF_VERBS_NAMES_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.verbs.names", SandboxImportClass::VerbTable);

const SELF_VERBS_CALL_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.verbs.call", SandboxImportClass::VerbTable);

const SELF_REPORT_BLOCKED_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.report_blocked", SandboxImportClass::WriteTrap);

const SELF_ASK_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("ask", SandboxImportClass::DurableWait);

const SELF_SPEAK_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.speak", SandboxImportClass::Speech);

const SELF_THINK_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.think", SandboxImportClass::Speech);

const SELF_EXPRESS_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("self.express", SandboxImportClass::Speech);

const PROPOSAL_OPEN_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.propose.open", SandboxImportClass::Proposal);

const PROPOSAL_CHUNK_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.propose.chunk", SandboxImportClass::Proposal);

const PROPOSAL_CLOSE_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("oneiron.propose.close", SandboxImportClass::Proposal);

const NON_WRITE_IMPORTS: &[SandboxLinkedImport] = &[
    READ_FILE_IMPORT,
    CREDENTIAL_CALL_IMPORT,
    CLOCK_NOW_UNIX_MS_IMPORT,
    RANDOM_BYTES_IMPORT,
    OUTPUT_TEXT_IMPORT,
    OUTPUT_BYTES_IMPORT,
    STORE_BYTES_IMPORT,
    PROPOSAL_OPEN_IMPORT,
    PROPOSAL_CHUNK_IMPORT,
    PROPOSAL_CLOSE_IMPORT,
];

const FIRST_PARTY_IMPORTS: &[SandboxLinkedImport] = &[
    READ_FILE_IMPORT,
    CREDENTIAL_CALL_IMPORT,
    CLOCK_NOW_UNIX_MS_IMPORT,
    RANDOM_BYTES_IMPORT,
    OUTPUT_TEXT_IMPORT,
    OUTPUT_BYTES_IMPORT,
    STORE_BYTES_IMPORT,
    VAULT_AGENTS_PUT_IMPORT,
    SELF_JSON_VALIDATE_IMPORT,
    SELF_VERBS_NAMES_IMPORT,
    SELF_VERBS_CALL_IMPORT,
    SELF_REPORT_BLOCKED_IMPORT,
    SELF_ASK_IMPORT,
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
    host_services: bool,
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
                host_services: true,
            },
            SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted => Self {
                tier,
                runtime: SandboxGuestRuntime::PlainJsQuickJsComponent,
                linked_imports: NON_WRITE_IMPORTS,
                proposal_delta_channel: true,
                credential_call_effect: SandboxCredentialEffect::ReadOnly,
                host_services: true,
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

    /// The same contract with the file and credential imports cut off from
    /// any host-attached service adapter. They stay linked, because the
    /// component imports them, and refuse every call; only the reserved
    /// recoverable-output reads the host answers itself still resolve.
    #[must_use]
    pub const fn without_host_services(self) -> Self {
        Self {
            host_services: false,
            ..self
        }
    }

    /// Whether the file and credential imports may reach a host-attached
    /// service adapter.
    #[must_use]
    pub const fn links_host_services(self) -> bool {
        self.host_services
    }

    /// True if any linked import can commit or trap a host write.
    #[must_use]
    pub fn links_write_imports(self) -> bool {
        self.linked_imports
            .iter()
            .any(|import| import.class().is_write())
    }
}
