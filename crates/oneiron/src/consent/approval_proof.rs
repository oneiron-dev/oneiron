//! Gate-attested owner approval carriers and retained proof families.

use crate::receipt::intent_id::IntentId;

/// Gate-attested one-send owner approval, minted only while the Gate spends
/// that tap and the Pending row is inserted on the same write transaction.
/// It is admission metadata, never a caller-supplied transport payload field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmittedApproval {
    intent_id: IntentId,
    effect_digest: crate::consent::EffectDigest,
}

impl AdmittedApproval {
    pub(crate) const fn from_gate(
        intent_id: IntentId,
        effect_digest: crate::consent::EffectDigest,
    ) -> Self {
        Self {
            intent_id,
            effect_digest,
        }
    }
    pub(crate) const fn intent_id(self) -> IntentId {
        self.intent_id
    }
    pub(crate) const fn effect_digest(self) -> crate::consent::EffectDigest {
        self.effect_digest
    }
}

/// The family a kept press is filed under, named by the pinned target of the
/// effect whose admission spent it, never by the row's connector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PinnedApprovalFamily {
    /// A Linear issue mutation through the outbound dispatch door.
    LinearDispatch,
    /// A campaign enrollment's outbound leg.
    CampaignLeg,
    /// A scoped-MCP tool call on a catalogued connector (FIX 6424 part 3).
    ScopedMcp,
    /// An ordinary dispatch with a frozen Communication, Calendar or HttpBundle target.
    ConnectorSlate,
}

impl PinnedApprovalFamily {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::LinearDispatch => 1,
            Self::CampaignLeg => 2,
            Self::ScopedMcp => 3,
            Self::ConnectorSlate => 4,
        }
    }
}

/// One spent press of a pinned family, as its admission selected it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PinnedApproval {
    pub(crate) family: PinnedApprovalFamily,
    pub(crate) proof: AdmittedApproval,
}

impl PinnedApproval {
    pub(crate) const fn new(family: PinnedApprovalFamily, proof: AdmittedApproval) -> Self {
        Self { family, proof }
    }
}
