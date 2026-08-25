use crate::error::{Error, Result};

use super::bound::{ConsentDomain, GrantBound, covers};
use super::grant::StandingConsentGrant;
use super::support::{hash_field, invalid_bound, normalized_ref, undo_fidelity_byte};

/// Domain-separated BLAKE3 label for [`EffectDigest`].
const EFFECT_DIGEST_DOMAIN: &[u8] = b"oneiron.consent.effect_digest.v1\0";

// ---------------------------------------------------------------------------
// Catastrophe floor — invariant 7
// ---------------------------------------------------------------------------

/// Members of the closed catastrophe floor.
///
/// This set is engine-owned and **non-rememberable**: it is evaluated before
/// trust and grants, always Asks, and is rejected from standing-grant minting.
/// It is not an owner-overridable deny — the owner may still approve the op in
/// the moment, but may never make it automatic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        }
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
            _ => None,
        }
    }
}

// CONTRACT-EDGE: `CATASTROPHE_FLOOR_V1` is a versioned public contract
// imported across the GOV belt — adding, removing, or reordering members bumps
// `CATASTROPHE_FLOOR_VERSION` and lands as a reviewed contract change in
// consent.rs alone; the floor itself survives unchanged (catastrophe verbs sit
// outside every ⊤ per OF-453 L9).
/// Version of the closed catastrophe floor.
pub const CATASTROPHE_FLOOR_VERSION: u16 = 1;

/// The closed catastrophe floor, version 1 — the only always-gate.
pub const CATASTROPHE_FLOOR_V1: [CatastropheClass; 5] = [
    CatastropheClass::WidenOwnAuthority,
    CatastropheClass::KeyRecovery,
    CatastropheClass::VaultWideDestruction,
    CatastropheClass::SecurityControlDisable,
    CatastropheClass::MassSecretExport,
];

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// Engine-computed digest of one composed effect.
///
/// There is no public constructor from caller bytes on the ask path: a digest
/// is derived by [`ComposedEffect::digest`] over engine-owned facts, so a
/// caller cannot forge the identity of the op an approve-once receipt covers.
/// [`EffectDigest::from_bytes`] exists only to rehydrate a digest the engine
/// already emitted (e.g. from a receipt row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectDigest(pub(super) [u8; 32]);

impl EffectDigest {
    /// Rehydrates a previously engine-emitted digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding, used in receipts and registry rows.
    #[must_use]
    pub fn to_hex(&self) -> String {
        crate::entity_id::bytes_to_hex_lower(&self.0)
    }
}

/// Store-attested proof that one approve-once marker is available to spend.
///
/// Fields are private: raw caller input cannot construct this proof. The only
/// constructor reads the marker on the write transaction that will either
/// authorize and spend the effect or abort without consuming the tap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApproveOnceAuthorization {
    pub(super) effect_digest: EffectDigest,
}

// ---------------------------------------------------------------------------
// Host-owned reversibility classification — invariant 6
// ---------------------------------------------------------------------------

/// The reversibility verdict the HOST computes. Never caller-supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReversibilityClass {
    /// Effect-reversible: undo is the net, so the op runs automatically.
    Reversible,
    /// Irreversible in effect — an outbound send or a deploy, even though the
    /// ledger records it.
    Irreversible,
    /// A sub-axis is genuinely unknown, with no irreversible or catastrophe
    /// evidence. Biased toward Auto.
    Unknown,
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

/// The blast-radius count above which an op stops being "one write".
pub const BULK_BLAST_RADIUS_FLOOR: u64 = 100;

/// Classifies the composed effect's reversibility — invariant 6.
///
/// Biased-permissive: a valid unknown sub-axis with no irreversible or
/// catastrophe evidence resolves [`ReversibilityClass::Unknown`], which the
/// evaluator treats as auto-eligible. Concrete irreversible evidence — an
/// external observer, a publish/deploy trigger, an engine-external hook, a
/// missing/partial undo, or bulk blast radius — resolves
/// [`ReversibilityClass::Irreversible`].
///
/// # Errors
///
/// Returns [`Error::InvalidConsentEffectFacts`] when a required write fact is
/// malformed (an empty operation kind), so the caller takes the invariant-8
/// domain fail-safe rather than a fabricated verdict.
pub(crate) fn classify_composed_effect(facts: &EffectFacts) -> Result<ReversibilityClass> {
    if facts.operation_kind.trim().is_empty() {
        return Err(Error::InvalidConsentEffectFacts(
            "composed effect has no operation kind",
        ));
    }
    // A catastrophe-shaped effect is irreversible regardless of undo claims;
    // the floor check runs before this in the evaluator either way.
    if facts.catastrophe.is_some() {
        return Ok(ReversibilityClass::Irreversible);
    }
    if facts.external_observers
        || facts.triggers_publish
        || facts.fires_hooks
        || facts.blast_radius >= BULK_BLAST_RADIUS_FLOOR
    {
        return Ok(ReversibilityClass::Irreversible);
    }
    Ok(match facts.undo_fidelity {
        UndoFidelity::Full => ReversibilityClass::Reversible,
        UndoFidelity::Partial | UndoFidelity::None => ReversibilityClass::Irreversible,
        // Unknown-and-NOT-irreversible-and-NOT-catastrophe: biased to auto.
        UndoFidelity::Unknown => ReversibilityClass::Unknown,
    })
}

// ---------------------------------------------------------------------------
// The composed effect + the evaluator
// ---------------------------------------------------------------------------

/// One operation as the engine composed it, ready for evaluation.
///
/// A MIXED operation — a `channel_send` of private content — carries BOTH a
/// disclosure requirement and an action requirement. The evaluator applies
/// logical AND across them: both must be covered or the op does not auto-run.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComposedEffect {
    facts: EffectFacts,
    disclosure_requirement: Option<GrantBound>,
    action_requirement: Option<GrantBound>,
}

impl ComposedEffect {
    /// Builds a composed effect from engine-owned facts, with no requirements
    /// attached yet.
    #[must_use]
    pub const fn new(facts: EffectFacts) -> Self {
        Self {
            facts,
            disclosure_requirement: None,
            action_requirement: None,
        }
    }

    /// Attaches the disclosure requirement this op must satisfy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConsentBound`] when the bound is not a
    /// disclosure bound.
    pub fn with_disclosure_requirement(mut self, bound: GrantBound) -> Result<Self> {
        if bound.domain() != ConsentDomain::Disclosure {
            return Err(invalid_bound(
                "disclosure requirement needs a disclosure-domain bound",
            ));
        }
        self.disclosure_requirement = Some(bound);
        Ok(self)
    }

    /// Attaches the action requirement this op must satisfy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConsentBound`] when the bound is not an action
    /// bound.
    pub fn with_action_requirement(mut self, bound: GrantBound) -> Result<Self> {
        if bound.domain() != ConsentDomain::Action {
            return Err(invalid_bound(
                "action requirement needs an action-domain bound",
            ));
        }
        self.action_requirement = Some(bound);
        Ok(self)
    }

    /// The engine-owned facts.
    #[must_use]
    pub const fn facts(&self) -> &EffectFacts {
        &self.facts
    }

    /// The disclosure requirement, when this op discloses.
    #[must_use]
    pub const fn disclosure_requirement(&self) -> Option<&GrantBound> {
        self.disclosure_requirement.as_ref()
    }

    /// The action requirement, when this op acts.
    #[must_use]
    pub const fn action_requirement(&self) -> Option<&GrantBound> {
        self.action_requirement.as_ref()
    }

    /// Whether this op spans both domains.
    #[must_use]
    pub const fn is_mixed(&self) -> bool {
        self.disclosure_requirement.is_some() && self.action_requirement.is_some()
    }

    /// The catastrophe class this op matched, if any.
    #[must_use]
    pub const fn catastrophe(&self) -> Option<CatastropheClass> {
        self.facts.catastrophe
    }

    /// The domain whose fail-safe applies when classification fails.
    ///
    /// A pure disclosure op hides; anything that writes asks — invariant 8. A
    /// mixed op writes, so it asks.
    #[must_use]
    pub const fn fail_safe_domain(&self) -> ConsentDomain {
        if self.action_requirement.is_some() {
            ConsentDomain::Action
        } else if self.disclosure_requirement.is_some() {
            ConsentDomain::Disclosure
        } else {
            // A requirement-free op is still a write path by default.
            ConsentDomain::Action
        }
    }

    /// The engine-computed digest identifying this exact op.
    #[must_use]
    pub fn digest(&self) -> EffectDigest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EFFECT_DIGEST_DOMAIN);
        hash_field(&mut hasher, self.facts.operation_kind.as_bytes());
        hasher.update(&[
            u8::from(self.facts.fires_hooks),
            u8::from(self.facts.triggers_publish),
            u8::from(self.facts.external_observers),
            undo_fidelity_byte(self.facts.undo_fidelity),
        ]);
        hasher.update(&self.facts.blast_radius.to_be_bytes());
        hash_field(
            &mut hasher,
            self.facts
                .catastrophe
                .map(CatastropheClass::as_str)
                .unwrap_or_default()
                .as_bytes(),
        );
        for requirement in [&self.disclosure_requirement, &self.action_requirement] {
            match requirement {
                Some(bound) => hash_field(&mut hasher, bound.digest().as_bytes()),
                None => hash_field(&mut hasher, &[]),
            }
        }
        EffectDigest(*hasher.finalize().as_bytes())
    }
}

/// The evaluator's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsentDecision {
    /// Run it; a standing reuse also writes a quiet use receipt.
    Auto,
    /// Raise the in-moment ask.
    Ask,
    /// Withhold the disclosure (the disclosure-domain fail-safe).
    Hide,
}

/// Evaluates one composed effect against the owner's remembered state.
///
/// The order is exactly the DEC-0006 order, and each step is load-bearing:
///
/// 1. **Catastrophe first.** The closed floor is evaluated before trust and
///    grants and always Asks — no standing grant, preference, or high-trust
///    actor reaches past it (invariant 7).
/// 2. **An exact store-attested approve-once authorization, or a covering
///    standing grant.** For a mixed op, "covering" means BOTH conjuncts are
///    covered (invariant 4).
/// 3. **Host reversibility.** An effect-reversible op runs automatically —
///    undo is the net (invariant 1); classification is host-owned and
///    biased-permissive (invariant 6).
///
/// Only an irreversible, ungranted, non-catastrophe operation enters the ask
/// lane. A classification failure takes the effect's domain fail-safe
/// (invariant 8) rather than guessing.
pub(crate) fn evaluate_consent(
    effect: &ComposedEffect,
    approve_once: Option<&ApproveOnceAuthorization>,
    grants: &[StandingConsentGrant],
) -> ConsentDecision {
    // 1. The only always-gate.
    if effect.catastrophe().is_some() {
        return ConsentDecision::Ask;
    }

    // 2a. Only a store-attested, still-available approve-once marker can
    // authorize exactly this op. Raw caller-supplied digest equality is not
    // authority.
    if approve_once.is_some_and(|authorization| authorization.effect_digest == effect.digest()) {
        return ConsentDecision::Auto;
    }

    // 2b. Standing coverage. Both conjuncts must be covered for a mixed op; a
    // single-domain op needs only its own conjunct. An op carrying NO
    // requirement at all has nothing to be covered — it falls through to the
    // classifier, so an unattached IRREVERSIBLE write asks (invariant 1's
    // floor: undo is the net ONLY when the classifier says the effect is
    // reversible). A vacuous double-`None` is NOT "covered".
    let has_requirement =
        effect.disclosure_requirement().is_some() || effect.action_requirement().is_some();
    let disclosure_covered = effect
        .disclosure_requirement()
        .is_none_or(|required| covers(grants, required));
    let action_covered = effect
        .action_requirement()
        .is_none_or(|required| covers(grants, required));
    if has_requirement && disclosure_covered && action_covered {
        return ConsentDecision::Auto;
    }

    // 3. Host reversibility. Anything still ungranted rides the classifier.
    match classify_composed_effect(&effect.facts) {
        Ok(ReversibilityClass::Reversible | ReversibilityClass::Unknown) => ConsentDecision::Auto,
        Ok(ReversibilityClass::Irreversible) => {
            // An irreversible DISCLOSURE that is not covered hides; an
            // irreversible write asks.
            effect.fail_safe_domain().fail_safe()
        }
        // Malformed or absent required write facts: the invariant-8 fallback.
        Err(_) => effect.fail_safe_domain().fail_safe(),
    }
}
