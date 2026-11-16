//! The owner's door for the facets a project's home room reads through
//! (L7-39: Engine RULINGS L7-39-ROOM-FACET-SET = A and L7-39-OLDER-PEER = A,
//! 14 Nov 17:03 and 17:31). The set is a signed field of the project's
//! authority, and only a v4 proof signs it. The fold judges every state that
//! carries one, whoever signs it; this door refuses early what the fold
//! would not install.
//!
//! The owner reaches it through `vault.projects.room_facets.set` (L7-39
//! PR 3), a host door: the host signs with the owner's project signer under
//! its slip issuer, so the embedded handle refuses. A leader or board holder
//! signs its own set in the record it writes through
//! `vault.projects.roster.write`.
use super::fold::ProjectDisposition;
use super::owner_signer::owner_signed_at;
use super::read::{ProjectReader, stored};
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::GateError;
use crate::memory::{Memory, MemoryResult};

/// `vault.projects.room_facets.set`: the project, and the facets its home
/// room reads through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoomFacetsSetRequest {
    pub project: EntityId,
    /// The set: it holds the project's own slice facet and reads no facet a
    /// parent project's room does not. Absent or null drops the set, so the
    /// room reads the slice's facet again.
    #[serde(default)]
    pub room_facets: Option<BTreeSet<EntityId>>,
}

/// A project's room facet set as the owner's verb left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoomFacetsState {
    pub project: EntityId,
    /// The set the home room reads through; none when it reads the slice's
    /// facet.
    pub room_facets: Option<BTreeSet<EntityId>>,
    /// The signed project state the set landed in, as hex.
    pub revision: String,
}

/// [`Vault::set_project_room_facets`] from the owner verb's request, signed
/// with the host's owner project signer.
///
/// # Errors
///
/// The door's refusals.
pub fn set_project_room_facets_from_request_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    signer: &OwnerProjectSigner<'_>,
    input: ProjectRoomFacetsSetRequest,
) -> MemoryResult<ProjectRoomFacetsState> {
    let revision =
        vault.set_project_room_facets(owner, signer, input.project, input.room_facets.clone())?;
    Ok(ProjectRoomFacetsState {
        project: input.project,
        room_facets: input.room_facets,
        revision: blake3::Hash::from(revision.0).to_hex().to_string(),
    })
}

impl Memory<'_> {
    /// `vault.projects.room_facets.set` on the embedded handle: refused. The
    /// owner's project signer works under the host's slip issuer, which only
    /// the host holds, so only the host's door sets a room facet set.
    pub fn projects_set_room_facets(
        &self,
        _input: &ProjectRoomFacetsSetRequest,
    ) -> MemoryResult<ProjectRoomFacetsState> {
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "a room facet set needs the host's authenticated owner and owner signer",
        ))
        .into())
    }
}

fn unresolved(project: EntityId, reason: &'static str) -> Error {
    RecordError::ProjectAuthorityUnresolved { project, reason }.into()
}

impl Vault {
    /// Sets the facets `id`'s home room reads through, or with `None` drops
    /// the set, so the room reads the project's slice facet again. The host
    /// signs the state for the owner over the settled head (v4 with a set,
    /// v3 without), it lands as history, and the act commits only once the
    /// fold installs it as the head.
    ///
    /// The set holds the project's own slice facet, which then stays put
    /// while the set exists, and reads no facet a parent's room does not.
    /// The head must carry a signed roster: an unsigned project takes the
    /// owner's first signature ([`Self::sign_owner_project`]) before a set.
    pub fn set_project_room_facets(
        &self,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        id: EntityId,
        facets: Option<BTreeSet<EntityId>>,
    ) -> Result<ProjectRevisionHash> {
        let kind = self.project_type_byte()?;
        self.with_write_txn(|txn| {
            let (witness, authority) = {
                let reader = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                    .ok_or_else(invalid)?;
                let frontier = reader.frontier(id)?.ok_or(Error::EntityNotFound)?;
                if frontier.disposition != ProjectDisposition::Settled {
                    return Err(unresolved(
                        id,
                        "a room facet set needs the project's settled head",
                    ));
                }
                let witness = frontier.witness.ok_or_else(invalid)?;
                let authority = witness.authority()?.clone();
                if let Some(set) = &facets {
                    if !(authority.slice.facet).is_some_and(|anchor| set.contains(&anchor)) {
                        return Err(RecordError::InvalidProjectBody(
                            "a room facet set holds its project's own facet",
                        )
                        .into());
                    }
                    for parent in &authority.parents {
                        let parent = EntityId::from_hex(parent)?;
                        let Some(view) = reader.effective(parent)? else {
                            return Err(unresolved(id, "a parent project serves no authority"));
                        };
                        if view.slice.is_none()
                            || room_widens(view.room_facet_reach(), Some(set.clone()))
                        {
                            return Err(RecordError::InvalidProjectBody(
                                "a room facet set stays inside its parents' rooms",
                            )
                            .into());
                        }
                    }
                }
                // Narrowing or dropping the set leaves no child's set reading
                // a facet this room no longer reads.
                let reach = facets
                    .clone()
                    .or_else(|| (authority.slice.facet).map(|anchor| BTreeSet::from([anchor])));
                let parent = id.to_hex();
                for row in crate::ports::EntityStoreRead::port_entity_ids_by_type(
                    reader.store(),
                    reader.txn(),
                    kind,
                    None,
                )? {
                    let child = row?;
                    if child == id {
                        continue;
                    }
                    if let Some(view) = reader.effective(child)?
                        && view.room_facets.is_some()
                        && view.parents.contains(&parent)
                        && room_widens(reach.clone(), view.room_facet_reach())
                    {
                        return Err(RecordError::InvalidProjectBody(
                            "a room facet set leaves no child's set outside it",
                        )
                        .into());
                    }
                }
                (witness, authority)
            };
            let Some(signed) = &authority.roster else {
                return Err(unresolved(
                    id,
                    "a room facet set needs a head that signs its roster",
                ));
            };
            let mut next = stored(&self.store, txn, id, kind)?.ok_or(Error::EntityNotFound)?;
            // The head's seats, in the stored row's order where it agrees.
            let mut roster: Vec<String> = next
                .roster
                .iter()
                .filter(|seat| signed.contains(*seat))
                .chain(signed)
                .cloned()
                .collect();
            let mut seated = BTreeSet::new();
            roster.retain(|seat| seated.insert(seat.clone()));
            next.parents = authority.parents.clone();
            next.parent_heads = authority.parent_heads.clone();
            next.claims_scope_ref = authority.claims_scope_ref.clone();
            next.slice = authority.slice.clone();
            next.depth_limit = authority.depth_limit;
            next.depth_remaining = authority.depth_remaining;
            next.leader = authority.leader.clone();
            next.board = authority.board.clone();
            next.roster = roster;
            next.room_facets = facets;
            let signed_at = owner_signed_at(self, txn)?;
            self.sign_owner_project_in_txn(
                txn,
                owner,
                signer,
                id,
                &mut next,
                Some(witness.anchor),
                signed_at,
            )?;
            self.batch_in()
                .put_engine_history(
                    &id,
                    kind,
                    TimeRange {
                        start: signed_at,
                        end: signed_at,
                    },
                    signed_at,
                    &encode(&next)?,
                )
                .apply(txn)?;
            self.require_owner_head_in_txn(txn, id, &next)
        })
    }
}
