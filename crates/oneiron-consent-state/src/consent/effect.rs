//! Moved from `crates/oneiron/src/consent/effect.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_store::consent_bound::normalized_ref;

// ---------------------------------------------------------------------------
// Catastrophe floor — invariant 7
// ---------------------------------------------------------------------------

/// Members of the closed catastrophe floor.
///
/// This set is engine-owned and **non-rememberable**: it is evaluated before
/// trust and grants, always Asks, and is rejected from standing-grant minting.
/// It is not an owner-overridable deny — the owner may still approve the op in
/// the moment, but may never make it automatic.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub enum CatastropheClass {
    /// An actor raising its own ceiling.
    WidenOwnAuthority,
    /// Key rotation or recovery-path change.
    KeyRecovery,
    /// Mass or whole-vault deletion.
    VaultWideDestruction,
    /// Turning off a guard or gate.
    SecurityControlDisable,
    /// Bulk export of secrets or private scoped content.
    MassSecretExport,
    /// Widening a world's privacy settings (FIX 4480): irreversible in
    /// effect, since what reached a wider place cannot be called back. Like
    /// erase, no bypass covers it, and no standing grant makes it automatic:
    /// an agent's widen always asks a holder in the moment.
    WorldPrivacyWiden,
    /// A force-push, history rewrite or delete of a protected ref (ARCH-0068
    /// RC4; DEC-0006 names it one-way). The owner's scoped bypass covers it
    /// (L8-51).
    ProtectedRefRewriteOrDelete,
}

impl CatastropheClass {
    /// The pinned stable string for receipts and reason codes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WidenOwnAuthority => "widen_own_authority",
            Self::KeyRecovery => "key_recovery",
            Self::VaultWideDestruction => "vault_wide_destruction",
            Self::SecurityControlDisable => "security_control_disable",
            Self::MassSecretExport => "mass_secret_export",
            Self::WorldPrivacyWiden => "world_privacy_widen",
            Self::ProtectedRefRewriteOrDelete => "protected_ref_rewrite_or_delete",
        }
    }

    /// Whether a scoped bypass grant may cover this class. Erase is no class
    /// but is excluded the same way (`ComposedEffect::as_erase`); a world's
    /// widen is excluded here (FIX 4480): like erase, no bypass covers it.
    #[must_use]
    pub const fn bypassable(self) -> bool {
        !matches!(self, Self::WorldPrivacyWiden)
    }

    /// Parses a pinned catastrophe-class string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "widen_own_authority" => Some(Self::WidenOwnAuthority),
            "key_recovery" => Some(Self::KeyRecovery),
            "vault_wide_destruction" => Some(Self::VaultWideDestruction),
            "security_control_disable" => Some(Self::SecurityControlDisable),
            "mass_secret_export" => Some(Self::MassSecretExport),
            "world_privacy_widen" => Some(Self::WorldPrivacyWiden),
            "protected_ref_rewrite_or_delete" => Some(Self::ProtectedRefRewriteOrDelete),
            _ => None,
        }
    }
}

/// The engine-owned fact set reversibility is computed from.
///
/// Every field is a FACT the host observed, not a verdict anyone asserted:
/// there is no `reversible` field here, and no public request, generated-code
/// call, connector manifest, grant, or guard proposal can inject one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EffectFacts {
    /// What kind of operation this is (e.g. `claim.put`, `channel.send`).
    pub operation_kind: String,
    /// The op fires hooks whose effects the engine does not own.
    pub fires_hooks: bool,
    /// The op triggers a publish or deploy.
    pub triggers_publish: bool,
    /// The op is observable by parties outside this vault.
    pub external_observers: bool,
    /// Whether a faithful undo exists for the op's full effect.
    pub undo_fidelity: UndoFidelity,
    /// How many entities the op mutates, cumulatively.
    pub blast_radius: u64,
    /// The catastrophe classes the host matched, if any.
    pub catastrophe: Option<CatastropheClass>,
}

impl EffectFacts {
    /// Builds a fact set for one operation kind, defaulted to the quiet,
    /// local, fully-undoable case.
    pub fn new(operation_kind: impl Into<String>) -> Result<Self> {
        Ok(Self {
            operation_kind: normalized_ref("operation kind", operation_kind.into())?,
            fires_hooks: false,
            triggers_publish: false,
            external_observers: false,
            undo_fidelity: UndoFidelity::Full,
            blast_radius: 1,
            catastrophe: None,
        })
    }

    /// Marks the op as firing engine-external hooks.
    #[must_use]
    pub const fn with_hooks(mut self, fires_hooks: bool) -> Self {
        self.fires_hooks = fires_hooks;
        self
    }

    /// Marks the op as triggering a publish or deploy.
    #[must_use]
    pub const fn with_publish_trigger(mut self, triggers_publish: bool) -> Self {
        self.triggers_publish = triggers_publish;
        self
    }

    /// Marks the op as observable outside this vault.
    #[must_use]
    pub const fn with_external_observers(mut self, external_observers: bool) -> Self {
        self.external_observers = external_observers;
        self
    }

    /// Records the host's undo-fidelity finding.
    #[must_use]
    pub const fn with_undo_fidelity(mut self, undo_fidelity: UndoFidelity) -> Self {
        self.undo_fidelity = undo_fidelity;
        self
    }

    /// Records the cumulative blast radius.
    #[must_use]
    pub const fn with_blast_radius(mut self, blast_radius: u64) -> Self {
        self.blast_radius = blast_radius;
        self
    }

    /// Records a matched catastrophe class.
    #[must_use]
    pub const fn with_catastrophe(mut self, catastrophe: CatastropheClass) -> Self {
        self.catastrophe = Some(catastrophe);
        self
    }
}

/// The host's undo-fidelity finding for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UndoFidelity {
    /// A faithful undo exists inside the engine's own window.
    Full,
    /// Undo exists but does not restore the full effect.
    Partial,
    /// No undo exists.
    None,
    /// The host could not determine undo fidelity for this op.
    Unknown,
}
