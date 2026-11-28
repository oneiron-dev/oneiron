//! The owner's project mint (FIX [OWNER-PROJECT-MINT-DOOR]; Engine ACCEPT
//! 28 Nov 14:48): `vault.projects.mint {name, parent?, intent_key}` mints one
//! project under a parent the owner holds, and `vault.projects.minted` reads
//! the projects it minted back. A GPU line needs a lane project and each of
//! its families a child of it; before this door only the house drafting
//! agent's card and the owner's tap minted a project, and always under the
//! root.
//!
//! - Owner proof only, chosen by the Engine 28 Nov (not an owner ruling):
//!   [`admit_caller_in_txn`] is the one caller check of both doors. No Grant
//!   is checked, minted or narrowed; the project's leader is the owner.
//! - Idempotent by intent key, through the lane-economy intent table
//!   ([`IntentAsk`]): the same key with the same name and parent answers the
//!   same project and writes nothing; the same key with another name or
//!   parent is refused; a refused mint keeps no intent.
//! - The parent: absent, the root. Present, it must be a project the fold
//!   serves (an Unsigned root serves, as the card tap parents under it), and
//!   one of its parent chains must reach the root, through which the owner
//!   sits on every board.
//! - The birth is the card tap's owner birth without the parts a card brings
//!   (a source message, a leader agent and its Grant, skills, a goal, a
//!   budget share): the local depth birth, the host's owner signature, the
//!   history landing, the born setting rows, and a commit only when the fold
//!   installs the signed state. No home room is born.
//! - The record: one `PROJECT_OWNER_MINT` row per project, keyed by the
//!   project, in the birth's own write. It leaves with the project
//!   ([`deindex_owner_mint_in_txn`], from `deindex_project_room`).
use super::owner_signer::owner_signed_at;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::GateError;
use crate::gpu_line::{IntentAsk, IntentStand};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

#[doc(hidden)]
pub use oneiron_verb_wire::workspace_roster::project::owner_mint::{
    OwnerMintedProject, OwnerMintedProjectsPage, OwnerMintedProjectsRequest,
    OwnerProjectMintAnswer, OwnerProjectMintRequest,
};

/// The owner mints a project.
pub const VAULT_PROJECTS_MINT: &str = "vault.projects.mint";
/// The projects the owner minted.
pub const VAULT_PROJECTS_MINTED: &str = "vault.projects.minted";

/// A project name's byte cap once trimmed: the machine-name rule
/// (`machine_names::MACHINE_NAME_MAX_BYTES`, `crates/oneiron/src/machine_names/mod.rs`).
pub const PROJECT_NAME_MAX_BYTES: usize = crate::machine_names::MACHINE_NAME_MAX_BYTES;
/// Rows of a `vault.projects.minted` page when the ask names no limit
/// (chosen by OPUS-RSI-MARKET, PLAN-OWNER-PROJECT-MINT-DOOR).
const MINTED_PAGE_DEFAULT: u32 = 100;
/// The most rows one page answers (chosen by OPUS-RSI-MARKET, same plan).
const MINTED_PAGE_MAX: u32 = 500;

/// One owner mint of one project. Key: id16 (project).
const OWNER_MINTS: SideTable<EntityId, OwnerProjectMint, Named> =
    SideTable::new(&side_table::PROJECT_OWNER_MINT);

/// What the door recorded at the birth: the name the owner gave and the
/// parent it was minted under. It holds no actor: the door is the vault
/// owner's alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerProjectMint {
    name: String,
    parent: EntityId,
    minted_at_ms: u64,
}

fn refusal(code: &str, message: &str, suggestion: &str) -> MemoryError {
    MemoryError::new(code, message.to_owned(), &[suggestion])
}

/// The one caller check of both doors: the vault owner's proof, revalidated
/// in the door's own transaction. Owner proof only was chosen by the Engine
/// (28 Nov), not ruled by the owner; opening the doors to a Grant changes
/// this function and the two verb rows' proof.
fn admit_caller_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Result<EntityId> {
    owner.revalidate_as_vault_owner_in_txn(vault, txn)
}

/// The trimmed name, or why it is refused.
fn project_name(name: &str) -> std::result::Result<&str, MemoryError> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.len() > PROJECT_NAME_MAX_BYTES
        || trimmed.contains(['\n', '\r', '\0'])
    {
        return Err(refusal(
            MEMORY_CODE_BAD_REQUEST,
            "a project name is one line without NUL, 1 to 128 bytes once trimmed",
            "Name the project in one short line.",
        ));
    }
    Ok(trimmed)
}

/// Whether one of `start`'s served parent chains reaches `root`. Each
/// project is read once, so a cycle of parents ends the walk.
fn reaches_root(reader: &ProjectReader<'_, '_>, start: EntityId, root: EntityId) -> Result<bool> {
    let mut seen = BTreeSet::new();
    let mut next = vec![start];
    while let Some(id) = next.pop() {
        if id == root {
            return Ok(true);
        }
        if !seen.insert(id) {
            continue;
        }
        let Some(view) = reader.effective(id)? else {
            continue;
        };
        for parent in &view.parents {
            next.push(EntityId::from_hex(parent).map_err(|_| invalid())?);
        }
    }
    Ok(false)
}

/// The answer row of `project`'s mint, with its parents as served now;
/// `None` when the fold no longer serves the project.
fn minted_row(
    reader: &ProjectReader<'_, '_>,
    project: EntityId,
    mint: OwnerProjectMint,
) -> Result<Option<OwnerMintedProject>> {
    let Some(view) = reader.effective(project)? else {
        return Ok(None);
    };
    let parents = view
        .parents
        .iter()
        .map(|parent| EntityId::from_hex(parent).map_err(|_| invalid()))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(OwnerMintedProject {
        project,
        name: mint.name,
        parent: mint.parent,
        parents,
        minted_at_ms: mint.minted_at_ms,
        minted_by: VAULT_PROJECTS_MINT.to_owned(),
    }))
}

/// Drops `project`'s mint row: the project's delete and erase both run it,
/// so no name outlives its project.
pub(super) fn deindex_owner_mint_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
) -> Result<()> {
    OWNER_MINTS.delete(store, txn, &project).map(drop)
}

impl Vault {
    /// `vault.projects.mint`: the owner mints one project under `parent`, or
    /// the root, signed with the host's owner project signer. The project,
    /// its depth birth, its born setting rows, the mint row and the intent
    /// commit in one write, and only once the fold installs the signed
    /// state. An exact replay answers the project its key minted.
    ///
    /// # Errors
    ///
    /// The door's refusals as typed [`MemoryError`]s: a bad name or intent
    /// key (bad request); a parent the fold does not serve (not found); a
    /// parent outside the root's tree (forbidden); a key that names another
    /// ask, or whose project is gone, or a parent whose slices contradict
    /// (invalid state). Storage errors, and a signed state the fold refuses.
    pub fn mint_owner_project(
        &self,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        request: &OwnerProjectMintRequest,
    ) -> MemoryResult<OwnerProjectMintAnswer> {
        let name = project_name(&request.name)?.to_owned();
        let kind = self.project_type_byte()?;
        let answered = self.with_write_txn(|txn| {
            let actor = admit_caller_in_txn(self, txn, owner)?;
            let ask = match IntentAsk::new(
                actor,
                VAULT_PROJECTS_MINT,
                &request.intent_key,
                &(&request.name, &request.parent),
            ) {
                Ok(ask) => ask,
                Err(refused) => return Ok(Err(refused.into())),
            };
            let root = ROOT.get(&self.store, txn, &())?.ok_or_else(invalid)?;
            let (id, mut record, parent) = {
                let reader = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                    .ok_or_else(invalid)?;
                match Ok::<IntentStand, crate::gpu_line::IntentRefused>(IntentStand::New) {
                    Err(refused) => return Ok(Err(refused.into())),
                    Ok(IntentStand::Replayed(written)) => {
                        let project = <[u8; 16]>::try_from(written.as_slice())
                            .ok()
                            .and_then(|bytes| EntityId::from_bytes(bytes).ok())
                            .ok_or_else(invalid)?;
                        let row = match OWNER_MINTS.get(&self.store, txn, &project)? {
                            Some(mint) => minted_row(&reader, project, mint)?,
                            None => None,
                        };
                        return Ok(row
                            .map(|project| OwnerProjectMintAnswer {
                                project,
                                replayed: true,
                            })
                            .ok_or_else(|| {
                                refusal(
                                    MEMORY_CODE_INVALID_STATE,
                                    "the project this intent key minted is gone",
                                    "Ask under a new intent key.",
                                )
                            }));
                    }
                    Ok(IntentStand::New) => {}
                }
                let parent = request.parent.unwrap_or(root);
                let Some(view) = reader.effective(parent)? else {
                    return Ok(Err(refusal(
                        MEMORY_CODE_NOT_FOUND,
                        "no such project: the parent names no project the vault serves",
                        "Name a parent from vault.projects.minted, or none for the root.",
                    )));
                };
                if !reaches_root(&reader, parent, root)? {
                    return Ok(Err(refusal(
                        MEMORY_CODE_FORBIDDEN,
                        "not the owner's own: the parent does not descend from this vault's root",
                        "Name a parent under the root, or none for the root.",
                    )));
                }
                let Some(slice) = view.slice.clone() else {
                    return Ok(Err(refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "the parent's slices contradict, so nothing fits under it",
                        "Resolve the parent's slices first.",
                    )));
                };
                let id = EntityId::now();
                if EntityStoreRead::port_entity_present(&self.store, txn, &id)? {
                    return Err(invalid());
                }
                let mut record = ProjectRecord::new(
                    id,
                    Some(parent),
                    EntityId::from_hex(&view.claims_scope_ref).map_err(|_| invalid())?,
                    actor,
                )?;
                record.slice = slice;
                // The owner is held to the card tap's rule, not an agent
                // spawn's: a parent with no levels left mints a child with
                // none.
                record.depth_limit = view.depth_limit;
                record.depth_remaining =
                    view.depth_remaining.min(view.depth_limit).saturating_sub(1);
                (id, record, parent)
            };
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            // The authenticated owner act births the project as the card tap
            // does: the creation-default depth birth this replica resolves.
            crate::gate::project_depth::put_local_birth_in_txn(self, txn, id, at)?;
            let signed_at = owner_signed_at(self, txn)?;
            self.sign_owner_project_in_txn(txn, owner, signer, id, &mut record, None, signed_at)?;
            self.land_owner_project_birth_in_txn(
                txn,
                id,
                kind,
                TimeRange { start: at, end: at },
                at,
                &record,
            )?;
            crate::setting::write_born_rows_in_txn(self, txn, id)?;
            self.require_owner_head_in_txn(txn, id, &record)?;
            let mint = OwnerProjectMint {
                name: name.clone(),
                parent,
                minted_at_ms: self.now_recorded_ms(),
            };
            OWNER_MINTS.put(&self.store, txn, &id, &mint)?;
            ask.keep_in_txn(self, txn, id.as_bytes().to_vec(), mint.minted_at_ms)?;
            Ok(Ok(OwnerProjectMintAnswer {
                project: OwnerMintedProject {
                    project: id,
                    name: mint.name,
                    parent,
                    parents: vec![parent],
                    minted_at_ms: mint.minted_at_ms,
                    minted_by: VAULT_PROJECTS_MINT.to_owned(),
                },
                replayed: false,
            }))
        })?;
        answered
    }

    /// `vault.projects.minted`: one page of the projects the owner minted
    /// through `vault.projects.mint` that the fold still serves, in mint
    /// order, each with its parents as served now.
    ///
    /// # Errors
    ///
    /// A limit outside 1..=500 (bad request); a proof that is not the live
    /// owner's; storage errors.
    pub fn owner_minted_projects(
        &self,
        owner: &AuthenticatedOwner,
        request: &OwnerMintedProjectsRequest,
    ) -> MemoryResult<OwnerMintedProjectsPage> {
        let limit = request.limit.unwrap_or(MINTED_PAGE_DEFAULT);
        if !(1..=MINTED_PAGE_MAX).contains(&limit) {
            return Err(refusal(
                MEMORY_CODE_BAD_REQUEST,
                "a page of minted projects holds 1 to 500 rows",
                "Ask for at most 500 rows, or name no limit for 100.",
            ));
        }
        let txn = self.store.env.read_txn()?;
        admit_caller_in_txn(self, &txn, owner)?;
        let reader =
            ProjectReader::new(&self.store, &txn, self.privacy_posture())?.ok_or_else(invalid)?;
        let mut projects = Vec::new();
        let mut next_after = None;
        for row in OWNER_MINTS.iter_from(&self.store, &txn, &[])? {
            let (project, mint) = row?;
            if request.after.is_some_and(|after| project <= after) {
                continue;
            }
            let Some(row) = minted_row(&reader, project, mint)? else {
                continue;
            };
            if projects.len() == limit as usize {
                next_after = projects.last().map(|last| last.project);
                break;
            }
            projects.push(row);
        }
        Ok(OwnerMintedProjectsPage {
            projects,
            next_after,
        })
    }
}

impl Memory<'_> {
    /// `vault.projects.mint` on the embedded handle: refused. The owner
    /// project signer works under the host's slip issuer, which only the
    /// host holds, so only the host's door mints a project.
    pub fn projects_mint(
        &self,
        _input: &OwnerProjectMintRequest,
    ) -> MemoryResult<OwnerProjectMintAnswer> {
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "a project mint needs the host's authenticated owner and owner signer",
        ))
        .into())
    }
}
