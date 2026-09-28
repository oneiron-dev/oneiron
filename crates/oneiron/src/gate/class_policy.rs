//! Vault-resident CLASS policy: waits and act postures, with holder narrowing.
//!
//! DEC-0005 puts floors and ceilings in manifest rows the engine resolves in
//! the same snapshot as the data they govern, and the owner rule of
//! 2026-09-27 says the same thing about a WAIT and about whether an act CLASS
//! may run at all: both are shipped policy defaults, not engine invariants.
//!
//! Two tables, both keyed by a CLASS string the engine never interprets:
//!
//! * [`WaitPolicyTable`] — how long a named wait must run. One row carries a
//!   `min_secs` floor and an optional `max_secs` ceiling.
//! * [`ActPolicyTable`] — whether a named act may run for a named subject
//!   class. One row carries an [`ActPosture`].
//!
//! Both resolve the same way, and both keep the substrate OUT of policy: a row
//! says how long to wait or whether the class is permitted, never whether the
//! payload is coherent, whether custody names its subject, or whether a grant
//! actually carries the capability the act needs. Those stay code.
//!
//! # Precedence
//!
//! A row is either VAULT-scoped (`holder_ref` absent) or HOLDER-scoped
//! (`holder_ref` naming the actor that holds the governed thing). The vault row
//! is the cap; a holder row may only narrow inside it, and
//! [`ClassPolicyPrecedence::VaultOnly`] on the vault row turns holder rows off
//! for that class entirely. Merge across packs is most-restrictive-wins, so a
//! second pack can tighten a class and never open it.

use crate::entity_id::EntityId;

/// How a holder-scoped row composes with its vault-scoped row.
///
/// Declared on the VAULT row, because the question is what the vault permits a
/// holder to do — a holder row that named its own precedence would be naming
/// its own widener, which `manifest:vault:AUTH` forbids.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ClassPolicyPrecedence {
    /// A holder row narrows inside the vault row; anything it asks for outside
    /// the vault's bounds is clamped back to them. The default.
    #[default]
    NestedNarrowing,
    /// Holder rows are ignored for this class: the vault row is the answer.
    VaultOnly,
}

impl ClassPolicyPrecedence {
    /// Manifest token for this arm. The parse direction is [`Self::parse`]; the
    /// two stay exact inverses.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::VaultOnly => "vault_only",
        }
    }

    #[must_use]
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "vault_only" => Some(Self::VaultOnly),
            _ => None,
        }
    }

    /// Restrictive composition across packs: `VaultOnly` wins, because it is
    /// the arm that grants a holder less.
    #[must_use]
    pub(crate) fn restrict(self, other: Self) -> Self {
        match (self, other) {
            (Self::NestedNarrowing, Self::NestedNarrowing) => Self::NestedNarrowing,
            _ => Self::VaultOnly,
        }
    }
}

/// One `wait_policy` row: how long the named wait must run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WaitPolicyRow {
    /// Opaque wait class, e.g. `channel_identity.quarantine`.
    pub(crate) wait_class: String,
    /// Actor that holds the governed thing, or `None` for the vault row.
    pub(crate) holder_ref: Option<EntityId>,
    /// Shortest admissible wait. The restrictive pole is LONGER, so this is
    /// the number a caller cannot go under.
    pub(crate) min_secs: u64,
    /// Longest admissible wait, when the vault bounds it. Also the cap on how
    /// far a holder row may raise `min_secs`.
    pub(crate) max_secs: Option<u64>,
    /// Vault-row-only: what holder rows may do for this class.
    pub(crate) precedence: ClassPolicyPrecedence,
}

/// The resolved window for one wait class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedWait {
    pub(crate) min_secs: u64,
    pub(crate) max_secs: Option<u64>,
}

/// The resolved `wait_policy` table. Empty means no class is governed, which is
/// the bootstrap posture: the caller keeps its own shipped default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WaitPolicyTable {
    rows: Vec<WaitPolicyRow>,
}

impl WaitPolicyTable {
    pub(crate) fn from_rows(rows: Vec<WaitPolicyRow>) -> Self {
        Self { rows }
    }

    pub(crate) fn extend_rows(&mut self, other: Self) {
        self.rows.extend(other.rows);
    }

    #[must_use]
    pub(crate) fn rows(&self) -> &[WaitPolicyRow] {
        &self.rows
    }

    /// The window for `wait_class`, as the vault row bounds it and the holder
    /// row narrows it.
    ///
    /// `holder` is the actor that holds the governed thing, when the caller
    /// knows one. A holder row is consulted only when the vault row leaves
    /// [`ClassPolicyPrecedence::NestedNarrowing`] in force.
    #[must_use]
    pub(crate) fn resolve(&self, wait_class: &str, holder: Option<EntityId>) -> WaitResolution {
        let mut min_secs = None;
        let mut max_secs: Option<u64> = None;
        let mut precedence = None;
        for row in self
            .rows
            .iter()
            .filter(|row| row.wait_class == wait_class && row.holder_ref.is_none())
        {
            // Most-restrictive-wins on both bounds: the longest floor and the
            // tightest ceiling any pack declared.
            min_secs = Some(min_secs.map_or(row.min_secs, |seen: u64| seen.max(row.min_secs)));
            if let Some(row_max) = row.max_secs {
                max_secs = Some(max_secs.map_or(row_max, |seen: u64| seen.min(row_max)));
            }
            precedence = Some(
                precedence.map_or(row.precedence, |seen: ClassPolicyPrecedence| {
                    seen.restrict(row.precedence)
                }),
            );
        }
        let Some(vault_min) = min_secs else {
            return WaitResolution::Ungoverned;
        };
        // Two packs that each parsed fine can still leave a floor above a
        // ceiling. No window satisfies that, and picking either bound would be
        // inventing policy, so it fails closed.
        if max_secs.is_some_and(|max| vault_min > max) {
            return WaitResolution::Contradictory;
        }
        let mut resolved = ResolvedWait {
            min_secs: vault_min,
            max_secs,
        };
        if precedence.unwrap_or_default() == ClassPolicyPrecedence::VaultOnly {
            return WaitResolution::Resolved(resolved);
        }
        let Some(holder) = holder else {
            return WaitResolution::Resolved(resolved);
        };
        for row in self
            .rows
            .iter()
            .filter(|row| row.wait_class == wait_class && row.holder_ref == Some(holder))
        {
            // Narrowing only, and capped by the vault: a holder may hold the
            // thing longer than the vault asks, never shorter, and never past
            // the ceiling the vault set.
            let asked = row.min_secs.max(resolved.min_secs);
            resolved.min_secs = resolved.max_secs.map_or(asked, |max| asked.min(max));
            if let Some(row_max) = row.max_secs {
                let narrowed = resolved.max_secs.map_or(row_max, |max| max.min(row_max));
                resolved.max_secs = Some(narrowed.max(resolved.min_secs));
            }
        }
        WaitResolution::Resolved(resolved)
    }
}

/// What the manifest says about one wait class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitResolution {
    /// No row names this class: the caller keeps its own shipped default.
    Ungoverned,
    /// Rows contradict each other. The caller refuses; it never guesses.
    Contradictory,
    Resolved(ResolvedWait),
}

/// Whether an act CLASS may run at all for one subject class.
///
/// `Deny` is the restrictive pole and the default for an absent row, so a
/// misread or unnamed pairing never resolves to the permissive arm.
///
/// `RequireCapability` is NOT permission to act. It says the class is not
/// barred, and hands the question to the substrate check that owns it: the
/// caller must still prove the subject holds the capability the act needs. A
/// read-only grant fails that check exactly as before — the difference is that
/// the refusal now names the missing capability instead of the subject's class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ActPosture {
    /// The class may not run, whatever capabilities the subject holds.
    #[default]
    Deny,
    /// The class may run when the substrate check finds the capability.
    RequireCapability,
}

impl ActPosture {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::RequireCapability => "require_capability",
        }
    }

    #[must_use]
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "deny" => Some(Self::Deny),
            "require_capability" => Some(Self::RequireCapability),
            _ => None,
        }
    }

    /// Restrictive composition: any `Deny` wins.
    #[must_use]
    pub(crate) fn restrict(self, other: Self) -> Self {
        match (self, other) {
            (Self::RequireCapability, Self::RequireCapability) => Self::RequireCapability,
            _ => Self::Deny,
        }
    }
}

/// One `act_policy` row: whether `act_class` may run for `subject_class`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActPolicyRow {
    /// Opaque act class, e.g. `channel_identity.outbound_send`.
    pub(crate) act_class: String,
    /// Opaque subject class, e.g. `delegated_grant`.
    pub(crate) subject_class: String,
    /// Actor that holds the subject, or `None` for the vault row.
    pub(crate) holder_ref: Option<EntityId>,
    pub(crate) posture: ActPosture,
    /// Vault-row-only: what holder rows may do for this pairing.
    pub(crate) precedence: ClassPolicyPrecedence,
}

/// The resolved `act_policy` table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActPolicyTable {
    rows: Vec<ActPolicyRow>,
}

impl ActPolicyTable {
    pub(crate) fn from_rows(rows: Vec<ActPolicyRow>) -> Self {
        Self { rows }
    }

    pub(crate) fn extend_rows(&mut self, other: Self) {
        self.rows.extend(other.rows);
    }

    #[must_use]
    pub(crate) fn rows(&self) -> &[ActPolicyRow] {
        &self.rows
    }

    /// The posture for `(act_class, subject_class)`, or `None` when no row
    /// names the pairing.
    ///
    /// `None` is deliberately not `Deny`: "the manifest is silent" and "the
    /// manifest bars this class" are different facts, and only the caller knows
    /// whether its own shipped default or a refusal is the honest answer to
    /// silence. Every engine caller here takes the restrictive arm.
    #[must_use]
    pub(crate) fn resolve(
        &self,
        act_class: &str,
        subject_class: &str,
        holder: Option<EntityId>,
    ) -> Option<ActPosture> {
        let matches =
            |row: &&ActPolicyRow| row.act_class == act_class && row.subject_class == subject_class;
        let mut posture = None;
        let mut precedence = None;
        for row in self
            .rows
            .iter()
            .filter(matches)
            .filter(|row| row.holder_ref.is_none())
        {
            posture =
                Some(posture.map_or(row.posture, |seen: ActPosture| seen.restrict(row.posture)));
            precedence = Some(
                precedence.map_or(row.precedence, |seen: ClassPolicyPrecedence| {
                    seen.restrict(row.precedence)
                }),
            );
        }
        let vault_posture = posture?;
        if precedence.unwrap_or_default() == ClassPolicyPrecedence::VaultOnly {
            return Some(vault_posture);
        }
        let holder = match holder {
            Some(holder) => holder,
            None => return Some(vault_posture),
        };
        // Narrowing only: the holder row composes restrictively against the
        // vault row, so it can reach `Deny` and can never leave it.
        let resolved = self
            .rows
            .iter()
            .filter(matches)
            .filter(|row| row.holder_ref == Some(holder))
            .fold(vault_posture, |seen, row| seen.restrict(row.posture));
        Some(resolved)
    }
}
