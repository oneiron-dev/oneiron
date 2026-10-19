//! A mention's saved resolution, separate from the tagger's original suggestion.
//! The answer and its owner evidence land in the same writer as the link.

use serde::{Deserialize, Serialize};

use super::{IdentityAnswerRequest, IdentityAsk, MentionProvenance, ask_key, key_hex};
use crate::claim::ClaimSource;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::tagging::{DerivationEnvelopeView, MentionLink, TaggedMentionView};
use crate::{EntityId, Error, Result, Vault};

const RESOLUTIONS: SideTable<(EntityId, [u8; 32]), IdentityResolutionView, Named> =
    SideTable::new(&side_table::DREAMER_IDENTITY_RESOLUTION);

/// The existing owner choice, with the later records that support it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityAnswerEvidenceRequest {
    pub ask: String,
    pub choice: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMentionState {
    Unresolved,
    Candidates,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityResolutionView {
    /// The ask answered, or the same span key for a saved context-hint resolution.
    pub ask: String,
    pub target_ref: String,
    pub source: String,
    /// Present only when the resolution's transaction revalidated an owner proof.
    pub owner_ref: Option<String>,
    pub owner_evidence_refs: Vec<String>,
    pub resolved_at: u64,
    /// The mention before resolution: its span, candidates and model confidences.
    pub original: TaggedMentionView,
    pub original_provenance: DerivationEnvelopeView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityMentionView {
    pub mention: MentionProvenance,
    pub name: String,
    pub state: IdentityMentionState,
    pub candidate_refs: Vec<String>,
    pub target_ref: Option<String>,
    pub current: TaggedMentionView,
    pub provenance: DerivationEnvelopeView,
    pub resolution: Option<IdentityResolutionView>,
}

pub(super) fn snapshot_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<(TaggedMentionView, DerivationEnvelopeView)> {
    let tags = crate::tagging::current_tags_in_txn(vault, txn, &ask.turn)?.0
        .ok_or(Error::EntityNotFound)?;
    let (index, mention) = tags.mentions.iter().enumerate().find(|(_, mention)| {
        mention.message == ask.message && mention.start == ask.start && mention.end == ask.end
    }).ok_or(Error::EntityNotFound)?;
    Ok((crate::tagging::mention_view(index, mention), crate::tagging::envelope_view(&tags.envelope)))
}

pub(super) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: &IdentityAsk,
    target: EntityId,
    source: ClaimSource,
    now: u64,
    original: (TaggedMentionView, DerivationEnvelopeView),
) -> Result<()> {
    let key = ask_key(&ask.turn, &ask.message, ask.start, ask.end);
    RESOLUTIONS.put(&vault.store, txn, &(ask.turn, key), &IdentityResolutionView {
        ask: key_hex(&key),
        target_ref: target.to_hex(),
        source: source.as_str().to_owned(),
        owner_ref: None,
        owner_evidence_refs: Vec::new(),
        resolved_at: now,
        original: original.0,
        original_provenance: original.1,
    })
}

pub(super) fn prove_owner_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    ask: &IdentityAsk,
    evidence: &[EntityId],
) -> Result<()> {
    let owner = owner.revalidate_in_txn(vault, txn)?;
    crate::memory::identity_doors::require_identity_evidence_in_txn(vault, txn, evidence)?;
    let key = (ask.turn, ask_key(&ask.turn, &ask.message, ask.start, ask.end));
    let mut resolution = RESOLUTIONS.get(&vault.store, txn, &key)?
        .ok_or(Error::InvariantViolation("identity answer lacks resolution provenance"))?;
    resolution.owner_ref = Some(owner.to_hex());
    resolution.owner_evidence_refs = evidence.iter().map(EntityId::to_hex).collect();
    RESOLUTIONS.put(&vault.store, txn, &key, &resolution)
}

pub(crate) fn clear_mention_resolutions_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    RESOLUTIONS.delete_from(store, txn, turn.as_bytes())?;
    Ok(())
}

/// Erasure drops the projection too, including its copy of the original candidate refs.
pub(crate) fn erase_mention_resolutions_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let reference = id.to_hex();
    let mut erased = false;
    for (key, resolution) in RESOLUTIONS.scan(store, txn)? {
        let original_refs: Vec<_> = match &resolution.original.link {
            crate::tagging::MentionLinkView::Tag => Vec::new(),
            crate::tagging::MentionLinkView::Candidates { entity_refs, .. } => entity_refs.iter().collect(),
            crate::tagging::MentionLinkView::Minted { entity_ref, .. } => vec![entity_ref],
        };
        if key.0 == *id || resolution.original.message_ref == reference
            || resolution.target_ref == reference || resolution.owner_ref.as_ref() == Some(&reference)
            || resolution.owner_evidence_refs.contains(&reference)
            || original_refs.contains(&&reference)
        {
            RESOLUTIONS.delete(store, txn, &key)?;
            erased = true;
        }
    }
    Ok(erased)
}

impl Memory<'_> {
    /// An owner-only projection over the saved span, not an opaque TURN body.
    pub fn identity_mention_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &MentionProvenance,
    ) -> MemoryResult<IdentityMentionView> {
        let turn = crate::memory::resolve_entity_ref(self.vault(), &input.turn)?;
        let message = crate::memory::resolve_entity_ref(self.vault(), &input.message)?;
        for reference in [&input.turn, &input.message] {
            self.get_entity(reference)?.value.ok_or_else(|| MemoryError::not_found("mention text is not readable"))?;
        }
        let start = usize::try_from(input.start).map_err(|_| MemoryError::bad_request("invalid mention start"))?;
        let end = usize::try_from(input.end).map_err(|_| MemoryError::bad_request("invalid mention end"))?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        owner.revalidate_in_txn(self.vault(), &txn)?;
        let tags = crate::tagging::current_tags_in_txn(self.vault(), &txn, &turn)?.0
            .ok_or_else(|| MemoryError::not_found("no current saved mention at that span"))?;
        let (index, mention) = tags.mentions.iter().enumerate().find(|(_, mention)| {
            mention.message == message && mention.start == start && mention.end == end
        }).ok_or_else(|| MemoryError::not_found("no saved mention at that span"))?;
        let text = crate::tagging::message_text_in_txn(self.vault(), &txn, &turn, &message)?
            .ok_or_else(|| MemoryError::not_found("mention text is not readable"))?;
        let name = text.get(start..end).ok_or_else(|| MemoryError::not_found("mention span no longer reads"))?.to_owned();
        let provenance = crate::tagging::envelope_view(&tags.envelope);
        let resolution = RESOLUTIONS.get(&self.vault().store, &txn, &(turn, ask_key(&turn, &message, start, end)))?
            .filter(|record| record.original_provenance == provenance
                && mention.link.entities().iter().any(|id| id.to_hex() == record.target_ref));
        let state = if resolution.is_some() {
            IdentityMentionState::Resolved
        } else {
            match &mention.link {
                MentionLink::Candidates { entities, .. } if !entities.is_empty() => IdentityMentionState::Candidates,
                _ => IdentityMentionState::Unresolved,
            }
        };
        let candidate_refs = mention.link.entities().iter().map(EntityId::to_hex).collect();
        let target_ref = resolution.as_ref().map(|record| record.target_ref.clone());
        self.produced_from([turn, message]);
        if let Some(record) = &resolution {
            self.produced_from(record.owner_ref.iter().chain(&record.owner_evidence_refs)
                .filter_map(|reference| EntityId::from_hex(reference).ok()));
        }
        Ok(IdentityMentionView {
            mention: MentionProvenance { turn: turn.to_hex(), message: message.to_hex(), start: input.start, end: input.end },
            name, state, candidate_refs, target_ref,
            current: crate::tagging::mention_view(index, mention),
            provenance, resolution,
        })
    }

    pub fn identity_answer_with_evidence_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &IdentityAnswerEvidenceRequest,
    ) -> MemoryResult<super::IdentitySettled> {
        let evidence = self.identity_evidence_refs(&input.evidence_refs)?;
        self.identity_answer_guarded(&IdentityAnswerRequest {
            ask: input.ask.clone(), choice: input.choice.clone(),
        }, Some(owner), &evidence)
    }
}
