//! The inputs and answers of the owner's embedding-space rows (OF-370):
//! `vault.embedding_spaces.*`, each a host door over the engine fns that
//! `/v1/owner/embedding-spaces` (L05) runs. Every input and answer is that
//! route's JSON, and the route answers with these types and fns (FIX 1951):
//! one definition the generated SDK, remote and binding code name too. A
//! route-only piece stays the route's: its `running` answer to a check still
//! going, and its refused-document reads.
//!
//! The proof each fn here asks for is the door's admission: a server mints it
//! from the request, as `/v1/owner` does, and an embedded handle acts as the
//! vault's embedded owner. Each space change hands it to its engine fn, which
//! checks it again inside the write that commits the change (FIX 8200), so a
//! proof revoked while the request waited changes nothing. A move's check runs a server's own probe towers, so it has no fn
//! here: its server door calls `SyncServer::check_space_move`.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::embed::{
    EmbeddingSpace, InputKind, PendingEmbedderBinding, SpaceMove, SpaceMoveCheck, SpaceMoveOutcome,
    SpaceProbe, SpaceRef,
};
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};

/// Every declared space, where each kind slot reads, and every move: what
/// `GET /v1/owner/embedding-spaces` and each space change answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EmbeddingSpacesView {
    pub spaces: Vec<EmbeddingSpace>,
    /// The vault's own text vector index, which an unbound text slot reads.
    pub text_index: EmbeddingSpace,
    /// Kind to declared space id; an absent text kind reads the text index.
    pub slots: BTreeMap<InputKind, String>,
    pub moves: Vec<SpaceMove>,
    /// Stored probes per kind.
    pub probes: BTreeMap<InputKind, usize>,
    /// Documents each space's model refused by their content, by space id; a
    /// space with none is absent.
    pub refused: BTreeMap<String, usize>,
    /// Each owner-approved embedder binding a space move stages: waiting,
    /// filling, applied, not applied or undone.
    pub binding_moves: Vec<PendingEmbedderBinding>,
}

/// `vault.embedding_spaces.declare`'s input: one space, the body
/// `PUT /v1/owner/embedding-spaces` takes, `{id, dimensions, accepts,
/// query_towers, evidence?}`. A new width is a new space.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct EmbeddingSpaceDeclareRequest(
    #[schemars(with = "serde_json::Map<String, serde_json::Value>")] pub EmbeddingSpace,
);

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::embedding_space::{
    EmbeddingSpaceBindRequest, EmbeddingSpaceCandidateRequest, EmbeddingSpaceMoveOutcome,
    EmbeddingSpaceMoveRequest, EmbeddingSpaceProbeDeleteRequest, EmbeddingSpaceProbeDeleted,
    EmbeddingSpaceProbePutRequest, EmbeddingSpaceRequest,
};

/// `vault.embedding_spaces.move_check`'s answer, as
/// `POST /v1/owner/embedding-spaces/move/check` gives it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EmbeddingSpaceMoveChecked {
    pub outcome: EmbeddingSpaceMoveOutcome,
    /// The paired probe run, unless the candidate is still filling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<SpaceMoveCheck>,
}

impl From<SpaceMoveOutcome> for EmbeddingSpaceMoveChecked {
    fn from(outcome: SpaceMoveOutcome) -> Self {
        let (outcome, check) = match outcome {
            SpaceMoveOutcome::Filling => (EmbeddingSpaceMoveOutcome::Filling, None),
            SpaceMoveOutcome::SwappedIn(check) => {
                (EmbeddingSpaceMoveOutcome::SwappedIn, Some(check))
            }
            SpaceMoveOutcome::Kept(check) => (EmbeddingSpaceMoveOutcome::Kept, Some(check)),
            SpaceMoveOutcome::Undecided(check) => {
                (EmbeddingSpaceMoveOutcome::Undecided, Some(check))
            }
        };
        Self { outcome, check }
    }
}

/// One stored probe with its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EmbeddingSpaceProbe {
    /// 32 hex.
    pub id: String,
    #[serde(flatten)]
    pub probe: SpaceProbe,
}

/// `vault.embedding_spaces.probes.list`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EmbeddingSpaceProbes {
    pub probes: Vec<EmbeddingSpaceProbe>,
}

/// An engine refusal of a space change, a bad request as the route answers
/// it; an owner's proof the change's write no longer admits keeps the owner
/// door's own refusal (FIX 8200).
fn refused(error: crate::error::Error) -> MemoryError {
    if error.kind() == crate::error::ErrorKind::ConsentOwnerNotAuthenticated {
        return error.into();
    }
    MemoryError::bad_request(error.to_string())
}

/// The view each space change answers with.
pub fn embedding_spaces_view(vault: &Vault) -> MemoryResult<EmbeddingSpacesView> {
    let bindings = vault.kind_slot_bindings()?;
    let slots = InputKind::ALL
        .into_iter()
        .filter_map(|kind| Some((kind, bindings.space_for(kind)?.to_owned())))
        .collect();
    let mut probes = BTreeMap::new();
    for (_, probe) in vault.space_probes()? {
        *probes.entry(probe.kind).or_insert(0) += 1;
    }
    Ok(EmbeddingSpacesView {
        spaces: vault.embedding_spaces()?,
        text_index: vault.text_index_space(),
        slots,
        moves: vault.space_moves()?,
        probes,
        refused: vault.media_refusal_counts()?,
        binding_moves: vault.embedder_binding_moves()?,
    })
}

/// `vault.embedding_spaces.list`.
pub fn read_embedding_spaces(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
) -> MemoryResult<EmbeddingSpacesView> {
    embedding_spaces_view(vault)
}

/// `vault.embedding_spaces.declare`: declares or widens one space.
pub fn declare_embedding_space_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceDeclareRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .declare_embedding_space(owner, input.0)
        .map_err(refused)?;
    embedding_spaces_view(vault)
}

/// `vault.embedding_spaces.bind`: binds one kind slot, or returns it to its
/// default.
pub fn bind_embedding_slot_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceBindRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    match &input.space {
        Some(space) => vault.bind_kind_slot(owner, input.kind, space),
        None => vault.unbind_kind_slot(owner, input.kind),
    }
    .map_err(refused)?;
    embedding_spaces_view(vault)
}

/// `vault.embedding_spaces.one_space`: the one-space preset.
pub fn bind_one_embedding_space_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .bind_one_space_for_all(owner, &input.space)
        .map_err(refused)?;
    embedding_spaces_view(vault)
}

/// `vault.embedding_spaces.retire`: drops a space no slot binds and no open
/// move names, with its rows.
pub fn retire_embedding_space_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .retire_embedding_space(owner, &input.space)
        .map_err(refused)?;
    embedding_spaces_view(vault)
}

/// `vault.embedding_spaces.move`: starts moving every slot the incumbent
/// serves to the candidate. It answers the move, as the route does.
pub fn begin_embedding_space_move_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceMoveRequest,
) -> MemoryResult<SpaceMove> {
    let incumbent = input
        .incumbent
        .map_or(SpaceRef::TextIndex, SpaceRef::Declared);
    vault
        .begin_space_move(owner, &input.candidate, incumbent, input.margin)
        .map_err(refused)
}

/// The move to `candidate`, for a server's check of it; not found when no
/// move names it.
pub fn find_embedding_space_move(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    candidate: &str,
) -> MemoryResult<SpaceMove> {
    vault
        .space_moves()?
        .into_iter()
        .find(|moving| moving.candidate == candidate)
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                format!("no embedding space move to {candidate}"),
                &["List the moves with vault.embedding_spaces.list."],
            )
        })
}

/// `vault.embedding_spaces.move_approve`: the owner's yes over a check that
/// did not read not worse.
pub fn approve_embedding_space_move_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    approve_embedding_space_move_admitted_as(vault, owner, input, None)
}

/// [`approve_embedding_space_move_as`] behind the host's media egress gate
/// on the candidate's third-party model (FIX 6907): what the gate withholds
/// never fills the candidate, so it does not keep the move filling.
pub fn approve_embedding_space_move_admitted_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceCandidateRequest,
    egress: Option<&dyn crate::embed::EgressPredicate>,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .approve_space_move_admitted(owner, &input.candidate, egress)
        .map_err(refused)?;
    embedding_spaces_view(vault)
}

/// `vault.embedding_spaces.move_undo`: binds a swapped-in move's incumbent
/// again.
pub fn undo_embedding_space_move_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .undo_space_move(owner, &input.candidate)
        .map_err(refused)?;
    embedding_spaces_view(vault)
}

/// `vault.embedding_spaces.move_abandon`: ends an open move with no swap.
pub fn abandon_embedding_space_move_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .abandon_space_move(owner, &input.candidate)
        .map_err(refused)?;
    embedding_spaces_view(vault)
}

/// `vault.embedding_spaces.probes.list`.
pub fn read_embedding_space_probes(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
) -> MemoryResult<EmbeddingSpaceProbes> {
    Ok(EmbeddingSpaceProbes {
        probes: vault
            .space_probes()?
            .into_iter()
            .map(|(id, probe)| EmbeddingSpaceProbe {
                id: crate::entity_id::bytes_to_hex_lower(&id),
                probe,
            })
            .collect(),
    })
}

/// `vault.embedding_spaces.probes.put`: stores one probe, written now.
pub fn put_embedding_space_probe_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceProbePutRequest,
) -> MemoryResult<EmbeddingSpaceProbe> {
    let mut targets = BTreeSet::from([input.family]);
    targets.extend(input.targets);
    let probe = SpaceProbe {
        kind: input.kind,
        query: input.query,
        query_media: input.query_media,
        family: input.family,
        written_from: None,
        source_refs: input.source_refs.into_iter().collect(),
        targets,
        author: input.author,
        written_at: vault.now_recorded_at(),
        cohort: None,
    };
    let id = vault
        .put_space_probe(owner, probe.clone())
        .map_err(refused)?;
    Ok(EmbeddingSpaceProbe {
        id: crate::entity_id::bytes_to_hex_lower(&id),
        probe,
    })
}

/// `vault.embedding_spaces.probes.delete`.
pub fn delete_embedding_space_probe_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EmbeddingSpaceProbeDeleteRequest,
) -> MemoryResult<EmbeddingSpaceProbeDeleted> {
    let id = probe_id(&input.id)?;
    Ok(EmbeddingSpaceProbeDeleted {
        ok: vault.delete_space_probe(owner, &id)?,
    })
}

/// A probe id from its 32 hex.
fn probe_id(hex: &str) -> MemoryResult<[u8; 16]> {
    let malformed = || MemoryError::bad_request("id must be 32 hex");
    if hex.len() != 32 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    let mut id = [0_u8; 16];
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| malformed())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
    }
    Ok(id)
}
