//! Doors for `tests/side_key_pins.rs` (UC-06 K-proofs of PRs 2 to 5): one fixture key of
//! each crate-private side-table key type that those PRs derive, with the reader of its type.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::artifact_hosting::ArtifactPointerChannel;
use crate::attempt_queue::AttemptId;
use crate::compaction::EpochScope;
use crate::critic::CritiqueArtifactKey;
use crate::deletion::PendingTombstoneKey;
use crate::dreamer_tournament::DreamerTournamentBranchVerdict;
use crate::entity_id::EntityId;
use crate::ports::{DocumentSlot, DocumentUpdateKey, UpdateSeq};
use crate::side_table::SideKey;
use crate::store::ChannelIdentityLifecycleReceiptId;
use crate::store::RetrievalRunId;
use crate::store::vad_annotation::VadAnnotationMetaKey;

/// One fixture key: the bytes it spells after its table prefix, and what its type reads from
/// any bytes (the key read, spelled again; `None` where the type refuses them).
pub struct Pin {
    pub spelled: Vec<u8>,
    pub read: fn(&[u8]) -> Option<Vec<u8>>,
}

impl Pin {
    pub fn of<K: SideKey>(key: &K) -> Self {
        Self {
            spelled: spell(key),
            read: |bytes: &[u8]| K::decode_key(bytes).map(|key| spell(&key)),
        }
    }
}

fn spell<K: SideKey>(key: &K) -> Vec<u8> {
    let mut out = Vec::new();
    key.encode_into(&mut out);
    out
}

/// `workspace_roster::codec::MemberIntentKey`: the workspace ref, NUL, the raw person id.
pub fn member_intent_key(workspace_ref: &str, person_ref: EntityId) -> Pin {
    crate::workspace_roster::member_intent_key_pin_for_test(workspace_ref, person_ref)
}

/// `workspace_roster::records::RosterMemberKey`: the workspace ref, NUL, the person id in hex.
pub fn roster_member_key(workspace_ref: &str, person_ref: EntityId) -> Pin {
    crate::workspace_roster::roster_member_key_pin_for_test(workspace_ref, person_ref)
}

/// `workspace_roster::rooms::participation::FactKey`: room, thread, subject kind and id, cause
/// kind and id. `subject` is a kind byte and id that `FactSubject` reads.
pub fn fact_key(
    room: EntityId,
    branch: [u8; 16],
    subject: (u8, [u8; 16]),
    cause: (u8, [u8; 16]),
) -> Pin {
    crate::workspace_roster::fact_key_pin_for_test(room, branch, subject, cause)
}

/// `origin::document_ingress::ProvenanceRefKey`: the provenance id, `:`, the ref name hash.
pub fn provenance_ref_key(provenance: EntityId, ref_name_hash: [u8; 32]) -> Pin {
    crate::origin::provenance_ref_key_pin_for_test(provenance, ref_name_hash)
}

/// `origin::export::RepoRevisionKey`: the repo identity hex, `:`, the raw revision id.
pub fn repo_revision_key(repo_hex: &str, revision: EntityId) -> Pin {
    crate::origin::export::repo_revision_key_pin_for_test(repo_hex, revision)
}

/// `origin::lfs::store::LfsRefKey`: the repo id, NUL, the ref name, NUL, the object id.
pub fn lfs_ref_key(repo_id: EntityId, ref_name: &str, oid: [u8; 32]) -> Pin {
    crate::origin::lfs::lfs_ref_key_pin_for_test(repo_id, ref_name, oid)
}

/// `origin::smart_http::intent::ReceivePackIntentKey`: the repo identity hex, then the raw
/// operation id, with no separator.
pub fn receive_pack_intent_key(repo_identity_hex: &str, operation_id: EntityId) -> Pin {
    crate::origin::smart_http::receive_pack_intent_key_pin_for_test(repo_identity_hex, operation_id)
}

/// `origin::smart_http::intent::ReceivePackProgressKey`: an intent key, then the batch number
/// as eight big-endian bytes.
pub fn receive_pack_progress_key(
    repo_identity_hex: &str,
    operation_id: EntityId,
    batch: u64,
) -> Pin {
    crate::origin::smart_http::receive_pack_progress_key_pin_for_test(
        repo_identity_hex,
        operation_id,
        batch,
    )
}

/// `llm::decision::questions::ask_history::AskHistoryKey`: the question id, then the sequence as
/// eight big-endian bytes.
pub fn ask_history_key(question: EntityId, sequence: u64) -> Pin {
    crate::llm::decision::questions::ask_history_key_pin_for_test(question, sequence)
}

/// `llm::step::step_index::StepIndexKey`: the raw attempt id, then the 32-byte step hash.
pub fn step_index_key(attempt_id: [u8; 16], step_hash: [u8; 32]) -> Pin {
    let attempt_id = AttemptId::from_bytes(&attempt_id).expect("an attempt id is any 16 bytes");
    crate::llm::step_index_key_pin_for_test(attempt_id, step_hash)
}

/// `llm::step::step_index::StepIndexClaimKey`: `i:`, then the raw claim id.
pub fn step_index_claim_key(claim: EntityId) -> Pin {
    crate::llm::step_index_claim_key_pin_for_test(claim)
}

/// `ports::DocumentSlot`: the document id as 32 lower-case hex characters.
pub fn document_slot(document: EntityId) -> Pin {
    Pin::of(&DocumentSlot::of(document))
}

/// `ports::DocumentUpdateKey` of an appended update: the slot, `:`, the sequence as 8 lower-case
/// hex digits.
pub fn document_update_key_of_sequence(document: EntityId, sequence: u32) -> Pin {
    Pin::of(&DocumentUpdateKey {
        slot: DocumentSlot::of(document),
        seq: UpdateSeq::Sequence(sequence),
    })
}

/// `ports::DocumentUpdateKey` of an entity-document commit: the slot, `:`, the head's generation
/// as 20 decimal digits.
pub fn document_update_key_of_generation(document: EntityId, generation: u64) -> Pin {
    Pin::of(&DocumentUpdateKey {
        slot: DocumentSlot::of(document),
        seq: UpdateSeq::Generation(generation),
    })
}

/// `artifact_hosting::ArtifactPointerRowKey`: the channel byte, the artifact id's length as a
/// big-endian `u16`, the artifact id.
pub fn artifact_pointer_row_key(channel: ArtifactPointerChannel, artifact: &str) -> Pin {
    crate::artifact_hosting::artifact_pointer_row_key_pin_for_test(channel, artifact)
}

/// `codebase::store::TextIndexKey`: the text, NUL, the raw id.
pub fn text_index_key(value: &str, id: EntityId) -> Pin {
    crate::codebase::text_index_key_pin_for_test(value, id)
}

/// `codebase::store::HashIndexKey`: the 32-byte hash, NUL, the raw id.
pub fn hash_index_key(value: [u8; 32], id: EntityId) -> Pin {
    crate::codebase::hash_index_key_pin_for_test(value, id)
}

/// `compaction::EpochScope`: the session id, then the conversation id when the scope names one.
pub fn epoch_scope(session: EntityId, conversation: Option<EntityId>) -> Pin {
    Pin::of(&match conversation {
        Some(conversation) => EpochScope::of_conversation(session, conversation),
        None => EpochScope::of_session(session),
    })
}

/// `connector_key::txn::ConnectorIndexKey`: the connector, NUL, the raw key id.
pub fn connector_index_key(connector: &str, id: EntityId) -> Pin {
    crate::connector_key::connector_index_key_pin_for_test(connector, id)
}

/// `consent::owner_reason::RuleKey`: the grant ref, `:`, the 16-byte decision id.
pub fn rule_key(grant_ref: &str, decision_id: [u8; 16]) -> Pin {
    crate::consent::rule_key_pin_for_test(grant_ref, decision_id)
}

/// `context_board::plugin::state::BlockKey`: the actor id, the section id's length as a
/// big-endian `u64`, the section id, the 16-byte block ref.
pub fn block_key(actor: EntityId, section_id: &str, block_ref: [u8; 16]) -> Pin {
    crate::context_board::block_key_pin_for_test(actor, section_id, block_ref)
}

/// `critic::CritiqueArtifactKey`: the raw branch attempt id, the artifact id's length as a
/// big-endian `u16`, the artifact id.
pub fn critique_artifact_key(branch_attempt: [u8; 16], artifact_id: &str) -> Pin {
    Pin::of(&CritiqueArtifactKey {
        branch_attempt: attempt(branch_attempt),
        artifact_id: artifact_id.to_owned(),
    })
}

/// `deletion::PendingTombstoneKey`: the window label, `:`, the entity id in lower-case hex.
pub fn pending_tombstone_key(window: &str, id: EntityId) -> Pin {
    Pin::of(&PendingTombstoneKey {
        window: window.to_owned(),
        id,
    })
}

/// `dreamer_consolidation::gap::BranchGapKey`: the scope text, then the 32-byte gap hash, with no
/// separator.
pub fn branch_gap_key(scope_text: &str, gap_hash: [u8; 32]) -> Pin {
    crate::dreamer_consolidation::branch_gap_key_pin_for_test(scope_text, gap_hash)
}

/// `dreamer_consolidation::neighbourhood::ListingPin`: the raw attempt id, then the NOTE id when
/// the pin names one.
pub fn listing_pin(attempt_id: [u8; 16], note: Option<EntityId>) -> Pin {
    crate::dreamer_consolidation::listing_pin_key_pin_for_test(attempt(attempt_id), note)
}

/// `dreamer_prefilter::supersession::MemberKey`: the attempt-kind text, `:`, the raw turn id.
pub fn member_key(attempt_kind: &str, turn: EntityId) -> Pin {
    crate::dreamer_prefilter::member_key_pin_for_test(attempt_kind, turn)
}

/// `dreamer_runner::admission::BudgetReservationKey`: the budget id's length as a big-endian
/// `u16`, the budget id, the raw attempt id.
pub fn budget_reservation_key(budget_id: &str, attempt_id: [u8; 16]) -> Pin {
    crate::dreamer_runner::budget_reservation_key_pin_for_test(budget_id, attempt(attempt_id))
}

/// `dreamer_runner::milestone::MilestoneCandidateKey`: the raw attempt id, `at` and `learned_at`
/// as eight big-endian bytes each, the raw claim id.
pub fn milestone_candidate_key(
    attempt_id: [u8; 16],
    at: u64,
    learned_at: u64,
    claim_id: EntityId,
) -> Pin {
    crate::dreamer_runner::milestone_candidate_key_pin_for_test(
        attempt(attempt_id),
        at,
        learned_at,
        claim_id,
    )
}

/// `dreamer_tournament::evidence::TournamentEvidenceKey`: the run id with a big-endian `u16`
/// length, the raw branch attempt id, the round as a big-endian `u16`, the verdict byte, the
/// candidate ref with a big-endian `u16` length.
pub fn tournament_evidence_key(
    run_id: &str,
    branch_attempt: [u8; 16],
    round: u16,
    verdict: DreamerTournamentBranchVerdict,
    candidate_ref: &str,
) -> Pin {
    crate::dreamer_tournament::tournament_evidence_key_pin_for_test(
        run_id,
        attempt(branch_attempt),
        round,
        verdict,
        candidate_ref,
    )
}

/// `gate::proposal_observation::ProposalKey`: the raw actor id, `:`, the proposal ref.
pub fn proposal_key(actor: EntityId, proposal_ref: &str) -> Pin {
    crate::gate::proposal_observation::proposal_key_pin_for_test(actor, proposal_ref)
}

/// `gate::proposal_observation::HistoryKey`: the raw actor id, `:`, the count as eight
/// big-endian bytes.
pub fn history_key(actor: EntityId, count: u64) -> Pin {
    crate::gate::proposal_observation::history_key_pin_for_test(actor, count)
}

/// `note::side_keys::HexPair`: two ids in lower-case hex, `:`-joined.
pub fn hex_pair(a: EntityId, b: EntityId) -> Pin {
    crate::note::hex_pair_pin_for_test(a, b)
}

/// `note::side_keys::HexTriple`: three ids in lower-case hex, `:`-joined.
pub fn hex_triple(a: EntityId, b: EntityId, c: EntityId) -> Pin {
    crate::note::hex_triple_pin_for_test(a, b, c)
}

/// `note::side_keys::HexHexHash`: two ids in lower-case hex and a hash's hex text, `:`-joined.
pub fn hex_hex_hash(a: EntityId, b: EntityId, hash: &str) -> Pin {
    crate::note::hex_hex_hash_pin_for_test(a, b, hash)
}

/// `outbound_intent_ledger::store::AttemptCallKey`: the raw attempt id, then the call sequence
/// as eight big-endian bytes.
pub fn attempt_call_key(attempt_id: [u8; 16], call_seq: u64) -> Pin {
    crate::outbound_intent_ledger::attempt_call_key_pin_for_test(attempt(attempt_id), call_seq)
}

/// `receipt::dispatch_observation::DispatchObservationKey`: the raw attempt id, then the attempt
/// count as four big-endian bytes.
pub fn dispatch_observation_key(attempt_id: [u8; 16], attempt_count: u32) -> Pin {
    crate::receipt::dispatch_observation_key_pin_for_test(attempt(attempt_id), attempt_count)
}

/// `recovery::document::DocKey`: the note id and the head id in lower-case hex, `:`-joined.
pub fn doc_key(note: EntityId, head: EntityId) -> Pin {
    crate::recovery::doc_key_pin_for_test(note, head)
}

/// `repo_mutation::proposal::OpKey`: the 64-byte repo key hash, `:`, the sequence as eight
/// big-endian bytes.
pub fn op_key(repo_key_hash: [u8; 64], seq: u64) -> Pin {
    crate::repo_mutation::proposal::op_key_pin_for_test(repo_key_hash, seq)
}

/// `store::ChannelIdentityLifecycleReceiptId`: its 16 bytes.
pub fn channel_identity_lifecycle_receipt_id(bytes: [u8; 16]) -> Pin {
    Pin::of(&ChannelIdentityLifecycleReceiptId::from_bytes(bytes))
}

/// `store::RetrievalRunId`: its 16 bytes.
pub fn retrieval_run_id(bytes: [u8; 16]) -> Pin {
    Pin::of(&RetrievalRunId::from_bytes(bytes))
}

/// `store::skill_resident::LoadedSkillKey`: the receipt id's length as a big-endian `u64`, the
/// receipt id, the raw skill id.
pub fn loaded_skill_key(receipt: &str, skill: EntityId) -> Pin {
    crate::store::skill_resident::loaded_skill_key_pin_for_test(receipt, skill)
}

/// `store::vad_annotation::VadAnnotationMetaKey`: the entity type byte, then the raw id.
pub fn vad_annotation_meta_key(entity_type: u8, id: EntityId) -> Pin {
    Pin::of(&VadAnnotationMetaKey { entity_type, id })
}

/// `sync::lease::LeaseKey`: the vault id and the client id as 16 lower-case hex digits each,
/// `:`-joined.
pub fn lease_key(vault_id: u64, client_id: u64) -> Pin {
    crate::sync::lease::lease_key_pin_for_test(vault_id, client_id)
}

/// `sync::note::workflows::NoteForkKey`: the note id and the fork id in lower-case hex,
/// `:`-joined.
pub fn note_fork_key(note: EntityId, fork: EntityId) -> Pin {
    crate::sync::note::note_fork_key_pin_for_test(note, fork)
}

/// `task_verb::ask_band::BandKey`: the raw owner id, the class's length as a big-endian `u16`,
/// the class.
pub fn band_key(owner: EntityId, class: &str) -> Pin {
    crate::task_verb::band_key_pin_for_test(owner, class)
}

/// `task_verb::ask_band::MarkerKey`: a band key, `:`, the raw word id.
pub fn marker_key(owner: EntityId, class: &str, word: EntityId) -> Pin {
    crate::task_verb::marker_key_pin_for_test(owner, class, word)
}

/// `task_verb::follow_up::TaskFollowUpKey`: the raw task id, NUL, the stage.
pub fn task_follow_up_key(task_ref: EntityId, stage: &str) -> Pin {
    crate::task_verb::task_follow_up_key_pin_for_test(task_ref, stage)
}

/// `vault_cleanup::attempt_retention::TaskAttemptKey`: the 32-byte task digest, then the raw
/// 16-byte attempt.
pub fn task_attempt_key(task_digest: [u8; 32], attempt: [u8; 16]) -> Pin {
    crate::vault_cleanup::task_attempt_key_pin_for_test(task_digest, attempt)
}

fn attempt(bytes: [u8; 16]) -> AttemptId {
    AttemptId::from_bytes(&bytes).expect("an attempt id is any 16 bytes")
}
