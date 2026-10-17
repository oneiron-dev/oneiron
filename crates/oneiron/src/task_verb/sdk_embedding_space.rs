//! The inputs and answers of the owner's embedding-space rows (OF-370):
//! `vault.embedding_spaces.*`, each a host door over the engine fns that
//! `/v1/owner/embedding-spaces` (L05) runs. Every input and answer is that
//! route's JSON. The route's own structs live in the server crate, which the
//! generated SDK, remote and binding code cannot name, so the shapes are
//! spelled here; the engine fns and their order are the route's.
//!
//! None of these engine fns takes the owner's proof. The proof each fn here
//! asks for is the door's admission: a server mints it from the request, as
//! `/v1/owner` does, and an embedded handle acts as the vault's embedded
//! owner. A move's check runs a server's own probe towers, so it has no fn
//! here: its server door calls `SyncServer::check_space_move`.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::embed::{
    EmbeddingSpace, InputKind, SpaceMove, SpaceMoveCheck, SpaceMoveOutcome, SpaceProbe, SpaceRef,
};
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

/// Every declared space, where each kind slot reads, and every move: what
/// `GET /v1/owner/embedding-spaces` and each space change answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingSpacesView {
    pub spaces: Vec<EmbeddingSpace>,
    /// The vault's own text vector index, which an unbound text slot reads.
    pub text_index: EmbeddingSpace,
    /// Kind to declared space id; an absent text kind reads the text index.
    pub slots: BTreeMap<InputKind, String>,
    pub moves: Vec<SpaceMove>,
    /// Stored probes per kind.
    pub probes: BTreeMap<InputKind, usize>,
}

/// `vault.embedding_spaces.declare`'s input: one space, the body
/// `PUT /v1/owner/embedding-spaces` takes, `{id, dimensions, accepts,
/// query_towers, evidence?}`. A new width is a new space.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct EmbeddingSpaceDeclareRequest(
    #[schemars(with = "serde_json::Map<String, serde_json::Value>")] pub EmbeddingSpace,
);

/// `vault.embedding_spaces.bind`'s input: one kind slot and its space.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceBindRequest {
    /// `text`, `image` or `audio`.
    #[schemars(with = "String")]
    pub kind: InputKind,
    /// The declared space; absent returns the slot to its default.
    #[serde(default)]
    pub space: Option<String>,
}

/// One declared space, by id: `vault.embedding_spaces.one_space` and
/// `.retire`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceRequest {
    pub space: String,
}

/// `vault.embedding_spaces.move`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceMoveRequest {
    pub candidate: String,
    /// A declared space id, or absent for the vault's text index.
    #[serde(default)]
    pub incumbent: Option<String>,
    /// A tolerance stricter than the measured retest noise.
    #[serde(default)]
    pub margin: Option<f32>,
}

/// One move, by its candidate: `vault.embedding_spaces.move_check`,
/// `.move_approve`, `.move_undo` and `.move_abandon`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceCandidateRequest {
    pub candidate: String,
}

/// What a move's check did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingSpaceMoveOutcome {
    /// The candidate still lacks a vector of some moving document; no probe
    /// ran.
    Filling,
    /// Every kind read not worse: the candidate serves now.
    SwappedIn,
    /// A kind read worse: the incumbent keeps serving and the move is closed.
    Kept,
    /// A kind read unknown: the incumbent keeps serving and the move stays
    /// open.
    Undecided,
}

/// `vault.embedding_spaces.move_check`'s answer, as
/// `POST /v1/owner/embedding-spaces/move/check` gives it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingSpaceProbe {
    /// 32 hex.
    pub id: String,
    #[serde(flatten)]
    pub probe: SpaceProbe,
}

/// `vault.embedding_spaces.probes.list`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingSpaceProbes {
    pub probes: Vec<EmbeddingSpaceProbe>,
}

/// `vault.embedding_spaces.probes.put`'s input: one probe the owner, or
/// another model, wrote.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceProbePutRequest {
    /// `text`, `image` or `audio`: the kind of the documents it finds.
    #[schemars(with = "String")]
    pub kind: InputKind,
    pub query: String,
    /// The document the query was written from, as 32 hex.
    pub family: EntityId,
    /// Every document that answers it, as 32 hex; the family's when absent.
    #[serde(default)]
    pub targets: Vec<EntityId>,
    /// Who wrote the query.
    pub author: String,
}

/// `vault.embedding_spaces.probes.delete`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceProbeDeleteRequest {
    /// The probe's id, 32 hex.
    pub id: String,
}

/// `vault.embedding_spaces.probes.delete`'s answer: whether a probe went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingSpaceProbeDeleted {
    pub ok: bool,
}

/// An engine refusal of a space change, a bad request as the route answers
/// it.
fn refused(error: crate::error::Error) -> MemoryError {
    MemoryError::bad_request(error.to_string())
}

/// The view each space change answers with.
fn view(vault: &Vault) -> MemoryResult<EmbeddingSpacesView> {
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
    })
}

/// `vault.embedding_spaces.list`.
pub fn read_embedding_spaces(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
) -> MemoryResult<EmbeddingSpacesView> {
    view(vault)
}

/// `vault.embedding_spaces.declare`: declares or widens one space.
pub fn declare_embedding_space_as(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceDeclareRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault.declare_embedding_space(input.0).map_err(refused)?;
    view(vault)
}

/// `vault.embedding_spaces.bind`: binds one kind slot, or returns it to its
/// default.
pub fn bind_embedding_slot_as(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceBindRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    match &input.space {
        Some(space) => vault.bind_kind_slot(input.kind, space),
        None => vault.unbind_kind_slot(input.kind),
    }
    .map_err(refused)?;
    view(vault)
}

/// `vault.embedding_spaces.one_space`: the one-space preset.
pub fn bind_one_embedding_space_as(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .bind_one_space_for_all(&input.space)
        .map_err(refused)?;
    view(vault)
}

/// `vault.embedding_spaces.retire`: drops a space no slot binds and no open
/// move names, with its rows.
pub fn retire_embedding_space_as(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .retire_embedding_space(&input.space)
        .map_err(refused)?;
    view(vault)
}

/// `vault.embedding_spaces.move`: starts moving every slot the incumbent
/// serves to the candidate. It answers the move, as the route does.
pub fn begin_embedding_space_move_as(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceMoveRequest,
) -> MemoryResult<SpaceMove> {
    let incumbent = input
        .incumbent
        .map_or(SpaceRef::TextIndex, SpaceRef::Declared);
    vault
        .begin_space_move(&input.candidate, incumbent, input.margin)
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
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .approve_space_move(&input.candidate)
        .map_err(refused)?;
    view(vault)
}

/// `vault.embedding_spaces.move_undo`: binds a swapped-in move's incumbent
/// again.
pub fn undo_embedding_space_move_as(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault.undo_space_move(&input.candidate).map_err(refused)?;
    view(vault)
}

/// `vault.embedding_spaces.move_abandon`: ends an open move with no swap.
pub fn abandon_embedding_space_move_as(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    vault
        .abandon_space_move(&input.candidate)
        .map_err(refused)?;
    view(vault)
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
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceProbePutRequest,
) -> MemoryResult<EmbeddingSpaceProbe> {
    let mut targets = BTreeSet::from([input.family]);
    targets.extend(input.targets);
    let probe = SpaceProbe {
        kind: input.kind,
        query: input.query,
        family: input.family,
        targets,
        author: input.author,
        written_at: vault.now_recorded_at(),
    };
    let id = vault.put_space_probe(probe.clone()).map_err(refused)?;
    Ok(EmbeddingSpaceProbe {
        id: crate::entity_id::bytes_to_hex_lower(&id),
        probe,
    })
}

/// `vault.embedding_spaces.probes.delete`.
pub fn delete_embedding_space_probe_as(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    input: EmbeddingSpaceProbeDeleteRequest,
) -> MemoryResult<EmbeddingSpaceProbeDeleted> {
    let id = probe_id(&input.id)?;
    Ok(EmbeddingSpaceProbeDeleted {
        ok: vault.delete_space_probe(&id)?,
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
