//! Campaign-local MACRO home-node election, designation persistence, and admission checks.

use serde::{Deserialize, Serialize};

use super::storage::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, from_row, invalid, pin_schema, read_meta, to_row,
};
use crate::Vault;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Home-node designation
// ---------------------------------------------------------------------------

/// Campaign-local home-node designation key. Deliberately NOT the Dreamer's
/// `dreamer:home_node_macro:v1`.
const CAMPAIGN_HOME_NODE_META_KEY: &[u8] = b"campaign:home_node_macro:v1";

/// Candidate node signals for the campaign MACRO home-node election.
///
/// `attached` is authority-bearing only for cloud candidates: a detached cloud
/// node is not eligible at all, while local candidates are elected from the
/// caller-supplied current candidate set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CampaignHomeNodeCandidate {
    /// Stable node identity; zero is rejected.
    pub node_id: u64,
    /// Whether this candidate is the attached cloud node.
    pub cloud: bool,
    /// Sync attachment signal.
    pub attached: bool,
    /// Whether this candidate is an always-on local node.
    pub always_on_local: bool,
    /// Whether this candidate is the owner's primary device.
    pub primary_device: bool,
}

impl CampaignHomeNodeCandidate {
    /// Cloud candidate; eligible only while attached.
    #[must_use]
    pub const fn cloud(node_id: u64, attached: bool) -> Self {
        Self {
            node_id,
            cloud: true,
            attached,
            always_on_local: false,
            primary_device: false,
        }
    }

    /// Always-on local candidate.
    #[must_use]
    pub const fn always_on_local(node_id: u64) -> Self {
        Self {
            node_id,
            cloud: false,
            attached: true,
            always_on_local: true,
            primary_device: false,
        }
    }

    /// Primary-device candidate.
    #[must_use]
    pub const fn primary_device(node_id: u64) -> Self {
        Self {
            node_id,
            cloud: false,
            attached: true,
            always_on_local: false,
            primary_device: true,
        }
    }

    const fn designation_class(self) -> Option<CampaignHomeNodeClass> {
        if self.cloud {
            // A detached cloud node is INELIGIBLE, not demoted: it cannot be a
            // local or primary device, so it simply drops out of the election.
            if self.attached {
                Some(CampaignHomeNodeClass::CloudAttached)
            } else {
                None
            }
        } else if self.always_on_local {
            Some(CampaignHomeNodeClass::AlwaysOnLocal)
        } else if self.primary_device {
            Some(CampaignHomeNodeClass::PrimaryDevice)
        } else {
            None
        }
    }
}

/// Election class that made a node the campaign MACRO home node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CampaignHomeNodeClass {
    /// Attached cloud node — the strongest tier.
    CloudAttached,
    /// Always-on local node.
    AlwaysOnLocal,
    /// The owner's primary device — the weakest eligible tier.
    PrimaryDevice,
}

impl CampaignHomeNodeClass {
    /// Stable wire token persisted in the designation row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudAttached => "cloud_attached",
            Self::AlwaysOnLocal => "always_on_local",
            Self::PrimaryDevice => "primary_device",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "cloud_attached" => Some(Self::CloudAttached),
            "always_on_local" => Some(Self::AlwaysOnLocal),
            "primary_device" => Some(Self::PrimaryDevice),
            _ => None,
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::CloudAttached => 0,
            Self::AlwaysOnLocal => 1,
            Self::PrimaryDevice => 2,
        }
    }
}

/// The single persisted campaign MACRO home-node designation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CampaignHomeNodeDesignation {
    /// Row schema version.
    pub schema_version: u32,
    /// Designated node.
    pub node_id: u64,
    /// Tier that won the election.
    pub class: CampaignHomeNodeClass,
    /// Election instant supplied by the caller.
    pub elected_at: u64,
}

/// Whether the local node may act as the campaign home node right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignHomeNodeAdmission {
    /// The local node holds the designation.
    Designated(CampaignHomeNodeDesignation),
    /// Another node holds it.
    NotHomeNode(CampaignHomeNodeDesignation),
    /// No node holds it.
    NoHomeNode,
}

/// Builds a local candidate from the vault's stable sync device identity.
///
/// # Errors
///
/// Storage errors propagate from the device-identity read.
pub fn local_campaign_home_node_candidate(
    vault: &Vault,
    attached: bool,
    always_on_local: bool,
    primary_device: bool,
) -> Result<CampaignHomeNodeCandidate> {
    Ok(CampaignHomeNodeCandidate {
        node_id: crate::identity::load_or_mint_client_id(vault)?,
        cloud: false,
        attached,
        always_on_local,
        primary_device,
    })
}

/// Elects and persists the campaign home-node designation.
///
/// Deterministic over the CURRENT candidate set: attached cloud beats always-on
/// local beats primary device, with the lowest stable node id resolving ties
/// inside a tier. An empty or all-ineligible set CLEARS the designation rather
/// than leaving a stale leader behind.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a zero or duplicated node id; storage errors
/// propagate.
pub fn elect_campaign_home_node_designation(
    vault: &Vault,
    candidates: &[CampaignHomeNodeCandidate],
    now: u64,
) -> Result<Option<CampaignHomeNodeDesignation>> {
    let designation = select_campaign_home_node(candidates, now)?;
    let encoded = designation.map(encode_designation).transpose()?;
    vault.with_write_txn(|wtxn| {
        match encoded.as_ref() {
            Some(bytes) => vault
                .store
                .vault_meta
                .put(wtxn, CAMPAIGN_HOME_NODE_META_KEY, bytes)?,
            None => {
                vault
                    .store
                    .vault_meta
                    .delete(wtxn, CAMPAIGN_HOME_NODE_META_KEY)?;
            }
        }
        Ok(())
    })?;
    Ok(designation)
}

/// Reads the persisted campaign home-node designation, if one exists.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_home_node_designation(
    vault: &Vault,
) -> Result<Option<CampaignHomeNodeDesignation>> {
    read_meta(vault, CAMPAIGN_HOME_NODE_META_KEY)?
        .map(|raw| decode_designation(&raw))
        .transpose()
}

/// Admission check for the local node.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a zero node id; storage errors propagate.
pub fn require_campaign_home_node(
    vault: &Vault,
    local_node_id: u64,
) -> Result<CampaignHomeNodeAdmission> {
    if local_node_id == 0 {
        return Err(invalid("campaign home node_id must be nonzero"));
    }
    Ok(match campaign_home_node_designation(vault)? {
        None => CampaignHomeNodeAdmission::NoHomeNode,
        Some(designation) if designation.node_id == local_node_id => {
            CampaignHomeNodeAdmission::Designated(designation)
        }
        Some(designation) => CampaignHomeNodeAdmission::NotHomeNode(designation),
    })
}

/// Pure selector. Kept separate from persistence so the ordering law is
/// testable without a vault, and so the write path has exactly one decision.
pub(super) fn select_campaign_home_node(
    candidates: &[CampaignHomeNodeCandidate],
    now: u64,
) -> Result<Option<CampaignHomeNodeDesignation>> {
    let mut best: Option<(u8, u64, CampaignHomeNodeClass)> = None;
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.node_id == 0 {
            return Err(invalid("campaign home node_id must be nonzero"));
        }
        if candidates[..index]
            .iter()
            .any(|seen| seen.node_id == candidate.node_id)
        {
            return Err(invalid("duplicate campaign home node candidate"));
        }
        let Some(class) = candidate.designation_class() else {
            continue;
        };
        let rank = class.rank();
        let better = best.is_none_or(|(best_rank, best_node_id, _)| {
            rank < best_rank || (rank == best_rank && candidate.node_id < best_node_id)
        });
        if better {
            best = Some((rank, candidate.node_id, class));
        }
    }
    Ok(best.map(|(_, node_id, class)| CampaignHomeNodeDesignation {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        node_id,
        class,
        elected_at: now,
    }))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesignationRow {
    schema_version: u32,
    node_id: u64,
    class: String,
    elected_at: u64,
}

fn encode_designation(record: CampaignHomeNodeDesignation) -> Result<Vec<u8>> {
    to_row(&DesignationRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        node_id: record.node_id,
        class: record.class.as_str().to_owned(),
        elected_at: record.elected_at,
    })
}

pub(super) fn decode_designation(raw: &[u8]) -> Result<CampaignHomeNodeDesignation> {
    const CONTEXT: &str = "campaign home-node designation";
    let row: DesignationRow = from_row(raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    if row.node_id == 0 {
        return Err(Error::CorruptedIndex(CONTEXT));
    }
    Ok(CampaignHomeNodeDesignation {
        schema_version: row.schema_version,
        node_id: row.node_id,
        class: CampaignHomeNodeClass::parse(&row.class).ok_or(Error::CorruptedIndex(CONTEXT))?,
        elected_at: row.elected_at,
    })
}
