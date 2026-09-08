//! SKILL lifecycle machine and governance-tier axis.

/// SKILL lifecycle machine (ARCH-0053 §6, ONE-1735) — ONE machine for every
/// skill, whatever its birth path (Dreamer distill, conversation convert
/// [ONE-1446], hub import [OF-201]).
///
/// ```text
/// candidate ──admission gate──▶ active ──┬─▶ stale        (source deleted; visible, reversible)
///   (scan + held-out where scorable,     ├─▶ quarantined  (soft-retired: out of packs,
///    ONE-1449 — that gate ARMS the       │                 evidence kept, revivable,
///    candidate→active transition)        │                 ALWAYS PROPOSED, never automatic)
///                                        └─▶ superseded   (new revision admitted; this rev
///                                                          never loads as canon again)
/// ```
///
/// Laws pinned here:
/// - **Terminal delete never happens.** There is no deleted/retracted state;
///   the strictest exit is `Quarantined`, which keeps evidence and stays
///   revivable. The pre-ONE-1735 reuse of the claim lifecycle exposed a
///   `retracted` string for skills; that string no longer parses (fail
///   closed) — soft retirement is `quarantined`.
/// - **`Stale` folds ONE-1447's semantics** into the one machine instead of
///   a bespoke flag: the skill's source messages were deleted, the record
///   stays visible, and the state is reversible (`Stale → Active`) when the
///   evidence situation recovers.
/// - **`Quarantined` is outcome-driven and consent-gated**: a reliability
///   floor-crossing (SK-05) may only PROPOSE quarantine — the update door
///   rejects a transition into `Quarantined` stamped `approval = auto`.
/// - **`Superseded` is terminal for the revision** (not for the skill): the
///   old revision is frozen and never loads as canon; continuing the skill
///   means admitting a new revision ([`Vault::supersede_skill_record`]).
/// - **Identity/alignment-tier skills never enter the auto-edit loop** at
///   all (ratified with the SKILL-CONV/SKILL-OPT wave, ONE-1446..1449); the
///   auto-edit loop is SKILL-OPT machinery and enforces that law at its own
///   door — the lifecycle machine carries no bypass for it.
///
/// `AgentDefinition` (OF-334, ONE-1443) deliberately rides `SkillRecord`'s
/// lifecycle machinery; migrating its lifecycle field onto this enum is
/// ONE-1443 follow-up, not part of ONE-1735.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkillLifecycle {
    /// Born, not yet admitted. All three birth paths start here.
    Candidate,
    /// Admitted through the gate; the only state that loads as canon.
    Active,
    /// Source evidence deleted (ONE-1447). Visible and reversible.
    Stale,
    /// Outcome-driven soft retirement: excluded from packs, evidence kept,
    /// revivable. Entering this state is ALWAYS PROPOSED, never automatic.
    Quarantined,
    /// A newer revision was admitted; this revision is frozen and never
    /// loads as canon again.
    Superseded,
}

impl SkillLifecycle {
    /// The pinned on-disk string for this state.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
        }
    }

    /// Parses a pinned on-disk state string. `retracted` (the pre-ONE-1735
    /// claim-lifecycle leak) deliberately does not parse: terminal delete
    /// never happens, soft retirement is `quarantined`.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "candidate" => Some(Self::Candidate),
            "active" => Some(Self::Active),
            "stale" => Some(Self::Stale),
            "quarantined" => Some(Self::Quarantined),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }

    /// The legal-transition table of the one lifecycle machine. Self-loops
    /// are allowed (state-preserving updates); everything else is exactly
    /// the ARCH-0053 §6 diagram plus its two documented reversals
    /// (`Stale → Active`, `Quarantined → Active`). `Superseded` has no
    /// exits: an old revision never loads as canon again.
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        if self == to {
            return true;
        }
        matches!(
            (self, to),
            (Self::Candidate, Self::Active)
                | (Self::Active, Self::Stale)
                | (Self::Active, Self::Quarantined)
                | (Self::Active, Self::Superseded)
                | (Self::Stale, Self::Active)
                | (Self::Quarantined, Self::Active)
        )
    }

    /// Whether a record in this state may load as canon (pack assembly,
    /// dependency resolution, tier-1 index). `Active` only: candidates are
    /// pre-admission, stale lost its evidence (reversibly), quarantined is
    /// excluded-but-revivable, superseded is frozen history.
    #[must_use]
    pub fn loads_as_canon(self) -> bool {
        self == Self::Active
    }
}

/// Governance TIER of a skill (ONE-1448): what the AUTOMATED edit loop is
/// allowed to touch.
///
/// A NEW axis, deliberately not the existing one. `skill_hub`'s
/// [`SkillGovernance`](crate::skill_hub::SkillGovernance)
/// (recommended|discouraged|prohibited) is a POLICY opinion a scan receipt
/// carries ABOUT bytes — the one axis on that row that is not the scanner's
/// opinion. This is a property of the SKILL's ROLE in the system, asserted by
/// its owner, and the two do not substitute for each other: a `recommended`
/// skill can be identity-tier, and a `standard` skill can be `prohibited`.
///
/// - [`Self::Identity`] — who the agent is. Never an optimization target.
/// - [`Self::Alignment`] — what the agent may and may not do. Never an
///   optimization target.
/// - [`Self::Standard`] — ordinary capability content; the only tier the
///   automated edit loop may draft against.
///
/// The mark is OPTIONAL on the wire (elide-the-default, like `contentHash`):
/// records minted before this key existed carry none. Absence is NOT
/// `standard` — resolving an absent mark is a fail-closed provenance question
/// the optimization job answers
/// ([`crate::skill_optimize::skill_governance_tier`]), and an answer it cannot
/// ground excludes the record from the loop rather than admitting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillGovernanceTier {
    Identity,
    Alignment,
    Standard,
}

impl SkillGovernanceTier {
    /// The pinned on-disk string for this tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Alignment => "alignment",
            Self::Standard => "standard",
        }
    }

    /// Parses a pinned on-disk tier string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "identity" => Some(Self::Identity),
            "alignment" => Some(Self::Alignment),
            "standard" => Some(Self::Standard),
            _ => None,
        }
    }

    /// True for the tiers no automated edit loop may ever target.
    ///
    /// Stated as a property of the TIER rather than re-derived at each door,
    /// so a later tier addition has to answer this question explicitly.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        matches!(self, Self::Identity | Self::Alignment)
    }
}
