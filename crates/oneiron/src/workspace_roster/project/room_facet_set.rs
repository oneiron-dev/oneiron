//! The owner's door for the facets a project's home room reads through
//! (L7-39: Engine RULINGS L7-39-ROOM-FACET-SET = A and L7-39-OLDER-PEER = A,
//! 14 Nov 17:03 and 17:31). The set is a signed field of the project's
//! authority, and only a v4 proof signs it. The fold judges every state that
//! carries one, whoever signs it; this door refuses early what the fold
//! would not install.
use super::fold::ProjectDisposition;
use super::owner_signer::owner_signed_at;
use super::read::{ProjectReader, stored};
use super::*;
use crate::consent::AuthenticatedOwner;

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
