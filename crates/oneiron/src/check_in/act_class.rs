//! The shipped act table (ARCH-0082 #act-table and #catastrophe-floor).

use serde::{Deserialize, Serialize};

use crate::consent::CatastropheClass;

/// The classes of act that check in. The order is the order of
/// [`ACT_CLASS`] and of [`ActClass::ALL`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActClass {
    /// Work an undo restores.
    ReversibleWork,
    /// Starting other agents' work: a fan-out of consults or a spawn. The
    /// `spawn` power is in every agent's grant (SPAWN-KNOB).
    Spawn,
    /// Spend above the spend cap. Raising the cap is the act that checks in.
    SpendOverCap,
    /// A send under a delegated identity. A send from the actor's own
    /// identity is reversible work.
    OutboundSend,
    /// An agent adding someone else to a room or thread; the add is from now
    /// (ARCH-0082 #agent-room-add, SCOPE-JOIN = A).
    RoomAdd,
    /// Adding a member, or raising a member's role.
    MemberAdd,
    /// Removing a member, or lowering a member's role.
    MemberRemove,
    /// Preparing a legal document and sending it for signature.
    LegalSend,
    /// Signing as the vault's principal. Anyone signs in their own name.
    Sign,
    /// Billing changes.
    Billing,
    /// Deleting items; restorable from backup for 90 days.
    Delete,
    /// Deleting the whole vault.
    VaultDelete,
    /// Erasing data for good.
    Erase,
    /// Transferring the vault's ownership.
    OwnershipTransfer,
    /// Key rotation or a recovery-path change.
    KeyRecovery,
    /// Turning off a guard or gate.
    SecurityControlDisable,
    /// Bulk export of secrets or private scoped content.
    MassSecretExport,
    /// An agent widening a world's privacy settings.
    WorldWiden,
    /// Widening another actor's grant.
    GrantWiden,
    /// Widening one's own grant: never answered by the actor itself.
    GrantWidenOwn,
}

impl ActClass {
    /// Every act class, in table order.
    pub const ALL: [Self; 20] = [
        Self::ReversibleWork,
        Self::Spawn,
        Self::SpendOverCap,
        Self::OutboundSend,
        Self::RoomAdd,
        Self::MemberAdd,
        Self::MemberRemove,
        Self::LegalSend,
        Self::Sign,
        Self::Billing,
        Self::Delete,
        Self::VaultDelete,
        Self::Erase,
        Self::OwnershipTransfer,
        Self::KeyRecovery,
        Self::SecurityControlDisable,
        Self::MassSecretExport,
        Self::WorldWiden,
        Self::GrantWiden,
        Self::GrantWidenOwn,
    ];

    /// The stable token for receipts and policy rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReversibleWork => "reversible_work",
            Self::Spawn => "spawn",
            Self::SpendOverCap => "spend_over_cap",
            Self::OutboundSend => "outbound_send",
            Self::RoomAdd => "room_add",
            Self::MemberAdd => "member_add",
            Self::MemberRemove => "member_remove",
            Self::LegalSend => "legal_send",
            Self::Sign => "sign",
            Self::Billing => "billing",
            Self::Delete => "delete",
            Self::VaultDelete => "vault_delete",
            Self::Erase => "erase",
            Self::OwnershipTransfer => "ownership_transfer",
            Self::KeyRecovery => "key_recovery",
            Self::SecurityControlDisable => "security_control_disable",
            Self::MassSecretExport => "mass_secret_export",
            Self::WorldWiden => "world_widen",
            Self::GrantWiden => "grant_widen",
            Self::GrantWidenOwn => "grant_widen_own",
        }
    }

    /// The class `token` names; `None` for any other text, the tokens the
    /// classes had before the verb-surface rename included (VS-OLD-NAMES = A).
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|act| act.as_str() == token)
    }

    /// This class's row of [`ACT_CLASS`].
    #[must_use]
    pub fn row(self) -> &'static ActClassRow {
        &ACT_CLASS[self as usize]
    }

    /// Whether the act takes the owner-checked preview and confirm
    /// (DEC-0006 #undo-class): its row is one-way and it is not [`Self::Sign`].
    /// Sign is one-way but its H is the signer's own (ARCH-0082:205;
    /// L8-49-SIGN = A), so it keeps its own preview. Today this is true for
    /// exactly [`Self::Erase`] and [`Self::VaultDelete`].
    #[must_use]
    pub fn owner_confirms(self) -> bool {
        self.row().undo.is_one_way() && self != Self::Sign
    }
}

/// How far an act can be undone. Canon fills no missing class by default, so
/// an act with an [`UndoClass::Unstated`] class holds on silence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UndoClass {
    /// An undo restores it.
    Undoable,
    /// A revoke undoes it.
    UndoableByRevoke,
    /// Restorable from backup for 90 days.
    BackupOnly,
    /// One-way once the send window closes.
    OneWayAfterSendWindow,
    /// One-way.
    OneWay,
    /// Canon states no undo class.
    Unstated,
    /// Not an act with an effect of its own.
    NotApplicable,
}

impl UndoClass {
    /// Whether the class is one-way.
    #[must_use]
    pub const fn is_one_way(self) -> bool {
        matches!(self, Self::OneWay)
    }
}

/// A proof an act accepts. The names are the settlement's `proof_kind`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    /// A person's authenticated confirm (H). Step-up waits on MFA, which is
    /// not built; until then it is an authenticated session confirm.
    HumanConfirm,
    /// A signature by the holder's key over the effect digest (K).
    Key,
    /// A quorum of holders (Q).
    Quorum,
    /// A delay window with notice (D); silence at its end is the proof.
    DelayWindow,
}

/// What the decision-model check (M) may do for an act.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCheck {
    /// The model audits a sample after the fact; it gates nothing.
    SampledAudit,
    /// The unsure test of `AskWhenUnsure` decides go or ask.
    UnsureTest,
    /// The model is asked only after an explicit Owner row opens it.
    AfterOwnerRow,
    /// The model never decides this act.
    Never,
}

/// One row of the act table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActClassRow {
    pub act: ActClass,
    pub undo: UndoClass,
    /// The proofs a check-in ask for this act accepts.
    pub accepted_proofs: &'static [ProofKind],
    pub model_check: ModelCheck,
    /// A C row: `AlwaysAsk` for every role but Owner, moved only by an
    /// explicit Owner row (the bypass grant).
    pub catastrophe: bool,
    /// The F row: fixed, not a default. Nobody answers their own ask.
    pub fixed: bool,
    /// The built catastrophe-floor class this row is, where one exists
    /// ([`crate::consent::CATASTROPHE_FLOOR_V2`]).
    pub floor_class: Option<CatastropheClass>,
}

use ProofKind::{DelayWindow, HumanConfirm, Key, Quorum};

const NO_PROOF: &[ProofKind] = &[];
const CONFIRM_OR_KEY: &[ProofKind] = &[HumanConfirm, Key];
const CONFIRM_KEY_QUORUM: &[ProofKind] = &[HumanConfirm, Key, Quorum];
const CONFIRM_KEY_DELAY: &[ProofKind] = &[HumanConfirm, Key, DelayWindow];
const EVERY_PROOF: &[ProofKind] = &[HumanConfirm, Key, Quorum, DelayWindow];

const fn row(
    act: ActClass,
    undo: UndoClass,
    accepted_proofs: &'static [ProofKind],
    model_check: ModelCheck,
) -> ActClassRow {
    ActClassRow {
        act,
        undo,
        accepted_proofs,
        model_check,
        catastrophe: false,
        fixed: false,
        floor_class: None,
    }
}

const fn catastrophe(
    act: ActClass,
    undo: UndoClass,
    accepted_proofs: &'static [ProofKind],
    model_check: ModelCheck,
    floor_class: Option<CatastropheClass>,
) -> ActClassRow {
    ActClassRow {
        catastrophe: true,
        floor_class,
        ..row(act, undo, accepted_proofs, model_check)
    }
}

/// The shipped act table, in [`ActClass::ALL`] order. The four floor rows
/// canon lists outside the main table (key and recovery, security-control
/// disable, mass secret export, an agent's widen of a world) state no undo
/// class, so they hold on silence.
pub static ACT_CLASS: [ActClassRow; 20] = [
    row(
        ActClass::ReversibleWork,
        UndoClass::Undoable,
        NO_PROOF,
        ModelCheck::SampledAudit,
    ),
    row(
        ActClass::Spawn,
        UndoClass::Undoable,
        CONFIRM_OR_KEY,
        ModelCheck::UnsureTest,
    ),
    row(
        ActClass::SpendOverCap,
        UndoClass::Unstated,
        CONFIRM_KEY_QUORUM,
        ModelCheck::UnsureTest,
    ),
    // H per send or per batch; K for a standing envelope; D is undo-send.
    row(
        ActClass::OutboundSend,
        UndoClass::OneWayAfterSendWindow,
        CONFIRM_KEY_DELAY,
        ModelCheck::UnsureTest,
    ),
    // Canon has no table row: an agent's add checks in, in AskWhenUnsure, and
    // the decision model weighs who is there, the room's purpose and the
    // newcomer's role. What the newcomer saw from now cannot be taken back,
    // so canon states no undo class and an unsure add holds on silence.
    row(
        ActClass::RoomAdd,
        UndoClass::Unstated,
        CONFIRM_OR_KEY,
        ModelCheck::UnsureTest,
    ),
    row(
        ActClass::MemberAdd,
        UndoClass::Unstated,
        CONFIRM_KEY_QUORUM,
        ModelCheck::UnsureTest,
    ),
    row(
        ActClass::MemberRemove,
        UndoClass::Unstated,
        CONFIRM_KEY_QUORUM,
        ModelCheck::UnsureTest,
    ),
    row(
        ActClass::LegalSend,
        UndoClass::OneWayAfterSendWindow,
        CONFIRM_OR_KEY,
        ModelCheck::UnsureTest,
    ),
    // H is the signer's own; K only after the Owner opens the dial.
    catastrophe(
        ActClass::Sign,
        UndoClass::OneWay,
        CONFIRM_KEY_QUORUM,
        ModelCheck::AfterOwnerRow,
        None,
    ),
    row(
        ActClass::Billing,
        UndoClass::Unstated,
        CONFIRM_OR_KEY,
        ModelCheck::UnsureTest,
    ),
    // The Grant is the consent.
    row(
        ActClass::Delete,
        UndoClass::BackupOnly,
        CONFIRM_OR_KEY,
        ModelCheck::UnsureTest,
    ),
    // D: 7 days with two or more Owners (the veto window).
    catastrophe(
        ActClass::VaultDelete,
        UndoClass::OneWay,
        EVERY_PROOF,
        ModelCheck::AfterOwnerRow,
        Some(CatastropheClass::VaultWideDestruction),
    ),
    // D: 7 days with two or more Owners; a person's own statutory request
    // skips it. The built floor handles erase apart from its classes.
    catastrophe(
        ActClass::Erase,
        UndoClass::OneWay,
        EVERY_PROOF,
        ModelCheck::AfterOwnerRow,
        None,
    ),
    // D is optional ("owner changes wait N days").
    catastrophe(
        ActClass::OwnershipTransfer,
        UndoClass::Unstated,
        EVERY_PROOF,
        ModelCheck::AfterOwnerRow,
        None,
    ),
    catastrophe(
        ActClass::KeyRecovery,
        UndoClass::Unstated,
        CONFIRM_KEY_QUORUM,
        ModelCheck::AfterOwnerRow,
        Some(CatastropheClass::KeyRecovery),
    ),
    catastrophe(
        ActClass::SecurityControlDisable,
        UndoClass::Unstated,
        CONFIRM_KEY_QUORUM,
        ModelCheck::AfterOwnerRow,
        Some(CatastropheClass::SecurityControlDisable),
    ),
    catastrophe(
        ActClass::MassSecretExport,
        UndoClass::Unstated,
        CONFIRM_KEY_QUORUM,
        ModelCheck::AfterOwnerRow,
        Some(CatastropheClass::MassSecretExport),
    ),
    // No bypass covers an agent's widen of a world (DEC-0006 #widen-world-floor).
    catastrophe(
        ActClass::WorldWiden,
        UndoClass::Unstated,
        CONFIRM_OR_KEY,
        ModelCheck::Never,
        Some(CatastropheClass::WorldPrivacyWiden),
    ),
    row(
        ActClass::GrantWiden,
        UndoClass::UndoableByRevoke,
        CONFIRM_KEY_QUORUM,
        ModelCheck::Never,
    ),
    // A holder's proof, never the actor's. The built floor names it
    // `widen_own_authority`.
    ActClassRow {
        fixed: true,
        floor_class: Some(CatastropheClass::WidenOwnAuthority),
        ..row(
            ActClass::GrantWidenOwn,
            UndoClass::NotApplicable,
            CONFIRM_OR_KEY,
            ModelCheck::Never,
        )
    },
];
