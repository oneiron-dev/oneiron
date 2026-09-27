//! One durable proactivity digest per vault cadence, with intent-bound urgent wakes.
use super::invalid;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
const CADENCE_KEY: &[u8] = b"settings:dreamer:proactivity:cadence:v1";
const STATE_KEY: &[u8] = b"dreamer:proactivity:state:v1";
const DIGEST_PREFIX: &[u8] = b"dreamer:proactivity:digest:v1:";
const PRESENTATION_KEY: &[u8] = b"settings:dreamer:proactivity:presentation:v1";
const POLICY_CONFIRMED_PREFIX: &[u8] = b"settings:dreamer:proactivity:confirmed:v1:";
/// Generic proposed claim written through the existing gated agent memory
/// verb. It changes NO settings until the owner confirms its exact revision.
pub const PROACTIVITY_POLICY_REQUEST_PREDICATE: &str = "dreamer.proactivity.policy_request";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityCadence {
    pub period_secs: u64,
    pub group_by_facet: bool,
    pub urgent_breakthrough: bool,
}
/// Agent-authored, owner-confirmed presentation row. Templates and voice are
/// data, not engine-owned prompt or persona text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityPresentation {
    /// Maps the derived facet group to a display group.
    pub group_aliases: BTreeMap<String, String>,
    /// Uses `{group}` for the display group.
    pub group_template: String,
    /// Uses `{summary}` and `{ref}` for each item.
    pub item_template: String,
    /// A host-facing style hint; the host owns voice rendering.
    pub voice_style: String,
    /// Derived groups eligible for a pre-cadence urgent delivery.
    pub urgent_groups: Vec<String>,
}
impl ProactivityPresentation {
    fn validate(&self) -> Result<()> {
        if self.group_template.len() > 1024
            || !self.group_template.contains("{group}")
            || self.item_template.len() > 1024
            || !self.item_template.contains("{summary}")
            || !self.item_template.contains("{ref}")
            || self.voice_style.len() > 1024
            || self.group_aliases.len() > 64
            || self.urgent_groups.len() > 64
            || self.group_aliases.iter().any(|(key, value)| {
                key.trim().is_empty()
                    || key.len() > 128
                    || value.trim().is_empty()
                    || value.len() > 128
            })
            || self
                .urgent_groups
                .iter()
                .any(|group| group.trim().is_empty() || group.len() > 128)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
/// Typed request payload for the existing `self.memory.put_claim` agent verb.
/// The host may build it from a chat request; no natural-language parser or
/// product persona is embedded in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityPolicyRequest {
    pub cadence: ProactivityCadence,
    pub presentation: ProactivityPresentation,
}
impl ProactivityPolicyRequest {
    pub fn claim_value(&self) -> Result<String> {
        if self.cadence.period_secs == 0 {
            return Err(invalid());
        }
        self.presentation.validate()?;
        serde_json::to_string(self).map_err(|_| invalid())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProactivityPolicyProposal {
    pub request: ProactivityPolicyRequest,
    pub revision: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrgentDigestWake {
    pub intent_ref: EntityId,
    pub needed_before: u64,
    pub waiting_harms_intent: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestProposal {
    #[serde(with = "crate::serialize::entity_ref")]
    pub claim_ref: EntityId,
    pub revision: [u8; 32],
    pub summary: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactivityDigest {
    pub id: [u8; 32],
    pub created_at: u64,
    pub urgent: bool,
    pub groups: BTreeMap<String, Vec<DigestProposal>>,
    pub rendered: String,
    pub voice_style: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestState {
    last_regular: Option<u64>,
    last_digest_id: Option<[u8; 32]>,
    seen: BTreeMap<String, [u8; 32]>,
}
impl Vault {
    pub fn set_proactivity_cadence(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        row: &ProactivityCadence,
    ) -> Result<()> {
        if row.period_secs == 0 {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(row).map_err(|_| invalid())?;
        self.with_write_txn(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            self.store.vault_meta.put(txn, CADENCE_KEY, &bytes)?;
            Ok(())
        })?;
        self.store.notify_proactivity_changes();
        Ok(())
    }
    /// An agent may draft this row in chat; only the authenticated owner's
    /// confirmation writes it. Edits affect the next digest, not past rows.
    pub fn set_proactivity_presentation(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        row: &ProactivityPresentation,
    ) -> Result<()> {
        row.validate()?;
        let bytes = serde_json::to_vec(row).map_err(|_| invalid())?;
        self.with_write_txn(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            self.store.vault_meta.put(txn, PRESENTATION_KEY, &bytes)?;
            Ok(())
        })?;
        self.store.notify_proactivity_changes();
        Ok(())
    }

    /// Resolve an agent-authored, still-pending policy claim for exact owner
    /// review. An ordinary claim alone has no settings authority.
    pub fn proactivity_policy_proposal(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        claim_ref: EntityId,
    ) -> Result<ProactivityPolicyProposal> {
        let txn = self.store.env.read_txn()?;
        super::validate_owner_in_txn(self, &txn, owner)?;
        load_policy_proposal(self, &txn, owner.actor(), claim_ref)
    }

    /// Confirm the exact proposal the host showed the authenticated owner.
    /// Both policy rows and a replay marker commit together; an agent claim
    /// cannot edit either row directly, nor replay an old confirmation.
    pub fn confirm_proactivity_policy_proposal(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        claim_ref: EntityId,
        expected_revision: [u8; 32],
    ) -> Result<()> {
        let confirmed_key = [POLICY_CONFIRMED_PREFIX, claim_ref.as_bytes()].concat();
        self.with_write_txn(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            if self.store.vault_meta.get(&*txn, &confirmed_key)?.is_some() {
                return Err(invalid());
            }
            let proposal = load_policy_proposal(self, &*txn, owner.actor(), claim_ref)?;
            if proposal.revision != expected_revision {
                return Err(invalid());
            }
            self.store.vault_meta.put(
                txn,
                CADENCE_KEY,
                &serde_json::to_vec(&proposal.request.cadence).map_err(|_| invalid())?,
            )?;
            self.store.vault_meta.put(
                txn,
                PRESENTATION_KEY,
                &serde_json::to_vec(&proposal.request.presentation).map_err(|_| invalid())?,
            )?;
            self.store
                .vault_meta
                .put(txn, &confirmed_key, &expected_revision)?;
            Ok(())
        })?;
        self.store.notify_proactivity_changes();
        Ok(())
    }

    /// Subscribe before the first deadline read. Every notification means
    /// "re-read committed state", never "deliver a wake".
    pub fn subscribe_proactivity_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.store.proactivity_updates.subscribe()
    }

    /// Next armed cadence, only while there is unseen pending work. The host
    /// arms its existing deadline timer from this row; no engine poll exists.
    pub fn next_proactivity_digest_at(&self) -> Result<Option<u64>> {
        let authority = self.dreamer_authority()?.entity_ref();
        let txn = self.store.env.read_txn()?;
        let cadence = load_cadence(self, &txn)?;
        let state = load_state(self, &txn)?;
        if pending_proposals(self, &txn, authority, &state, &cadence)?.is_empty() {
            return Ok(None);
        }
        Ok(Some(state.last_regular.map_or(0, |last| {
            last.saturating_add(cadence.period_secs)
        })))
    }

    /// The deadline source calls this on a timer wake. No owner credential is
    /// minted by the background job: this is a projection, not a policy edit.
    pub fn emit_due_proactivity_digest(
        &self,
        now: u64,
        local_node_id: u64,
    ) -> Result<Option<ProactivityDigest>> {
        let store = crate::dreamer_runner::DreamerRunnerStore::new(self);
        if store
            .home_node_designation()?
            .is_none_or(|home| home.node_id != local_node_id)
            || store
                .local_home_node_candidate(false, false, false)?
                .node_id
                != local_node_id
        {
            return Ok(None);
        }
        self.assemble_proactivity_digest(None, now, None)
    }

    /// Builds a display projection only. Pending decisions remain pending.
    /// The urgent assessment comes from the host, but must name a live,
    /// approved intent whose deadline is before the next cadence boundary.
    pub fn proactivity_digest(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        now: u64,
        urgent: Option<&UrgentDigestWake>,
    ) -> Result<Option<ProactivityDigest>> {
        self.assemble_proactivity_digest(Some(owner), now, urgent)
    }

    fn assemble_proactivity_digest(
        &self,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        now: u64,
        urgent: Option<&UrgentDigestWake>,
    ) -> Result<Option<ProactivityDigest>> {
        let authority = self.dreamer_authority()?.entity_ref();
        self.with_write_txn(|txn| {
            if let Some(owner) = owner {
                super::validate_owner_in_txn(self, txn, owner)?;
            }
            let cadence = load_cadence(self, &*txn)?;
            let presentation = load_presentation(self, &*txn)?;
            let mut state = load_state(self, &*txn)?;
            let next = state
                .last_regular
                .map(|last| last.saturating_add(cadence.period_secs));
            let due = next.is_none_or(|next| now >= next);
            let breakthrough = if let (Some(wake), Some(next), Some(owner)) = (urgent, next, owner)
            {
                if cadence.urgent_breakthrough
                    && wake.waiting_harms_intent
                    && wake.needed_before < next
                {
                    self.get_claim_in_txn(&*txn, &wake.intent_ref)?
                        .is_some_and(|body| {
                            body.predicate == "profile.intent"
                                && body.subject == crate::ClaimSubject::Entity(owner.actor())
                                && body.source == Some(ClaimSource::UserStated)
                                && body
                                    .value
                                    .as_str()
                                    .is_some_and(|text| !text.trim().is_empty())
                                && body.approval == ClaimApprovalStatus::Approved
                                && body.lifecycle == ClaimLifecycleStatus::Active
                                && !body.stale
                        })
                } else {
                    false
                }
            } else {
                false
            };
            if !due && !breakthrough {
                return Ok(None);
            }
            let mut groups: BTreeMap<String, Vec<DigestProposal>> = BTreeMap::new();
            for (group, proposal) in pending_proposals(self, txn, authority, &state, &cadence)? {
                if !due && !presentation.urgent_groups.contains(&group) {
                    continue;
                }
                let display_group = presentation
                    .group_aliases
                    .get(&group)
                    .cloned()
                    .unwrap_or(group);
                groups.entry(display_group).or_default().push(proposal);
            }
            if groups.is_empty() {
                return Ok(None);
            }
            let mut rendered = String::new();
            for (group, proposals) in &mut groups {
                proposals.sort_by_key(|p| p.claim_ref);
                rendered.push_str(&presentation.group_template.replace("{group}", group));
                for proposal in proposals {
                    rendered.push_str(
                        &presentation
                            .item_template
                            .replace("{summary}", &proposal.summary)
                            .replace("{ref}", &proposal.claim_ref.to_hex()),
                    );
                    state
                        .seen
                        .insert(proposal.claim_ref.to_hex(), proposal.revision);
                }
            }
            let is_urgent = !due && breakthrough;
            let identity = serde_json::to_vec(&(
                now,
                &groups,
                is_urgent,
                &rendered,
                &presentation.voice_style,
            ))
            .map_err(|_| invalid())?;
            let digest = ProactivityDigest {
                id: *blake3::hash(&identity).as_bytes(),
                created_at: now,
                urgent: is_urgent,
                groups,
                rendered,
                voice_style: presentation.voice_style,
            };
            let bytes = serde_json::to_vec(&digest).map_err(|_| invalid())?;
            self.store
                .vault_meta
                .put(txn, &[DIGEST_PREFIX, &digest.id].concat(), &bytes)?;
            if due {
                state.last_regular = Some(now);
            }
            state.last_digest_id = Some(digest.id);
            self.store.vault_meta.put(
                txn,
                STATE_KEY,
                &serde_json::to_vec(&state).map_err(|_| invalid())?,
            )?;
            Ok(Some(digest))
        })
    }
    /// Test-only fault seam: a corrupt digest row must not block independent
    /// due attempts in the host supervisor.
    #[cfg(feature = "test-support")]
    pub fn corrupt_proactivity_state_for_test(&self) -> Result<()> {
        self.with_write_txn(|txn| {
            self.store
                .vault_meta
                .put(txn, STATE_KEY, b"invalid digest state")?;
            Ok(())
        })
    }

    /// The latest scheduled or urgent output for the host's inbox/board read
    /// plane. The ID still verifies the persisted digest on every read.
    pub fn latest_proactivity_digest(&self) -> Result<Option<ProactivityDigest>> {
        let id = {
            let txn = self.store.env.read_txn()?;
            load_state(self, &txn)?.last_digest_id
        };
        id.map(|id| self.read_proactivity_digest(id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn read_proactivity_digest(&self, id: [u8; 32]) -> Result<Option<ProactivityDigest>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &[DIGEST_PREFIX, &id].concat())?
            .map(|bytes| {
                let digest: ProactivityDigest =
                    serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                let identity = serde_json::to_vec(&(
                    digest.created_at,
                    &digest.groups,
                    digest.urgent,
                    &digest.rendered,
                    &digest.voice_style,
                ))
                .map_err(|_| invalid())?;
                if digest.id != id || blake3::hash(&identity).as_bytes() != &id {
                    return Err(invalid());
                }
                Ok(digest)
            })
            .transpose()
    }
}
#[cfg(test)]
mod tests;

fn load_cadence(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProactivityCadence> {
    let row: ProactivityCadence = match vault.store.vault_meta.get(txn, CADENCE_KEY)? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| invalid())?,
        None => {
            serde_json::from_str(include_str!("digest_defaults.json")).map_err(|_| invalid())?
        }
    };
    if row.period_secs == 0 {
        return Err(invalid());
    }
    Ok(row)
}
fn load_state(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<DigestState> {
    vault
        .store
        .vault_meta
        .get(txn, STATE_KEY)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| invalid()))
        .transpose()
        .map(Option::unwrap_or_default)
}
fn load_presentation(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProactivityPresentation> {
    let row: ProactivityPresentation = match vault.store.vault_meta.get(txn, PRESENTATION_KEY)? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| invalid())?,
        None => serde_json::from_str(include_str!("digest_presentation_defaults.json"))
            .map_err(|_| invalid())?,
    };
    row.validate()?;
    Ok(row)
}
fn pending_proposals(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: EntityId,
    state: &DigestState,
    cadence: &ProactivityCadence,
) -> Result<Vec<(String, DigestProposal)>> {
    let mut pending = Vec::new();
    // Stream the producer index rather than using its capped 10k-ID query:
    // previously displayed proposals remain Proposed and still occupy index
    // slots. A full tray must not disable the scheduler's other deadlines.
    let prefix = crate::claim::producer_prefix(authority);
    for row in vault.store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        let id = EntityId::from_bytes(
            key[prefix.len()..]
                .try_into()
                .map_err(|_| crate::Error::CorruptedIndex("claim projection index"))?,
        )?;
        let Some(bytes) = vault.store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&bytes).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || bytes.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&bytes[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.predicate == PROACTIVITY_POLICY_REQUEST_PREDICATE
            || body.approval != ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.source != Some(ClaimSource::Generated)
            || body.stale
            || crate::claim::session_claim_producer(&body) != Some(authority)
        {
            continue;
        }
        let revision = *blake3::hash(&bytes[ENTITY_METADATA_HEADER_LEN..]).as_bytes();
        if state.seen.get(&id.to_hex()) == Some(&revision) {
            continue;
        }
        let group = if cadence.group_by_facet {
            body.predicate
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".")
        } else {
            "proposals".into()
        };
        pending.push((
            group,
            DigestProposal {
                claim_ref: id,
                revision,
                summary: format!("{}: {}", body.predicate, body.value),
            },
        ));
    }
    Ok(pending)
}

impl crate::store::Store {
    /// Only post-commit callers signal; the watch value carries no user data.
    pub(crate) fn notify_proactivity_changes(&self) {
        self.proactivity_updates.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }
}

fn load_policy_proposal(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
    claim_ref: EntityId,
) -> Result<ProactivityPolicyProposal> {
    let raw = vault
        .store
        .entities
        .get(txn, claim_ref.as_bytes())?
        .ok_or_else(invalid)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Err(invalid());
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.predicate != PROACTIVITY_POLICY_REQUEST_PREDICATE
        || body.subject != crate::ClaimSubject::Entity(owner)
        || body.source != Some(ClaimSource::Generated)
        || body.approval != ClaimApprovalStatus::Proposed
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || crate::claim::session_claim_producer(&body).is_none()
    {
        return Err(invalid());
    }
    let value = body.value.as_str().ok_or_else(invalid)?;
    if value.len() > 16_384 {
        return Err(invalid());
    }
    let request: ProactivityPolicyRequest = serde_json::from_str(value).map_err(|_| invalid())?;
    request.claim_value()?;
    Ok(ProactivityPolicyProposal {
        request,
        revision: *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes(),
    })
}
