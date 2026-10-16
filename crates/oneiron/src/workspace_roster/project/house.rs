//! The house mind leads the root project (ONEIRON-ARCH-0063: the vault is the
//! root project, its house mind leads and its owners form its board; the
//! house mind is the ORG given a pen).
//!
//! The vault seeds its root with the `sys.team_lead` row as leader, before
//! any workspace exists. Once a workspace names its house, the owner's door
//! signs the root's next state with that house as leader: a host-signed v3
//! state over the root's current head, landed as history, the board and every
//! earlier revision kept. Nothing writes a projection around the door, and a
//! root that already follows its house is left as it is.
use super::fold::ProjectDisposition;
use super::owner_signer::{OwnerProjectSigner, owner_signed_at};
use super::read::stored;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::workspace_roster::WorkspaceRosterPreset;

impl Vault {
    /// Makes `preset`'s house mind the root project's leader.
    ///
    /// `preset` must be the workspace's stored preset, so the house is the
    /// one its onboarding anchored to the ORG, never one a caller names. The
    /// owner is revalidated and the host signs in the writing transaction,
    /// over the root's current head; the act commits only once the fold
    /// installs the new state. The seat the old leader held as leader goes
    /// with the lead (a board seat stays), and the house takes one.
    pub fn bind_house_leader(
        &self,
        preset: &WorkspaceRosterPreset,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
    ) -> Result<()> {
        let kind = self.project_type_byte()?;
        let house = preset.house_actor_ref.to_hex();
        self.with_write_txn(|txn| {
            let stored_preset = crate::workspace_roster::PRESET
                .get(&self.store, txn, &preset.workspace_ref)?
                .map(|row| row.preset);
            if stored_preset.as_ref() != Some(preset) {
                return Err(RecordError::InvalidProjectBody(
                    "the house leads the root only as its workspace's stored preset names it",
                )
                .into());
            }
            if self.get_entity_type_in_txn(txn, &preset.house_actor_ref)?
                != Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
            {
                return Err(invalid());
            }
            let root = root_project_in(&self.store, txn)?.ok_or(Error::EntityNotFound)?;
            let witness = {
                let frontier = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                    .ok_or_else(invalid)?
                    .frontier(root)?
                    .ok_or(Error::EntityNotFound)?;
                if !matches!(
                    frontier.disposition,
                    ProjectDisposition::Unsigned | ProjectDisposition::Settled
                ) {
                    return Err(RecordError::ProjectAuthorityUnresolved {
                        project: root,
                        reason: "the root's authority must be settled before its house leads it",
                    }
                    .into());
                }
                frontier.witness.ok_or_else(invalid)?
            };
            let authority = witness.anchor.authority.clone();
            if authority.leader == house {
                return Ok(());
            }
            let mut next = stored(&self.store, txn, root, kind)?.ok_or(Error::EntityNotFound)?;
            // The head's seats: its signed roster, else the leader and board
            // an unsigned or older head seats, with the stored roster.
            let mut roster: Vec<String> = Vec::new();
            match &authority.roster {
                Some(signed) => {
                    roster.extend(
                        next.roster
                            .iter()
                            .filter(|seat| signed.contains(*seat))
                            .cloned(),
                    );
                    roster.extend(signed.iter().cloned());
                }
                None => {
                    roster.extend(next.roster.iter().cloned());
                    roster.push(authority.leader.clone());
                    roster.extend(authority.board.iter().cloned());
                }
            }
            let mut seated = BTreeSet::new();
            roster.retain(|seat| seated.insert(seat.clone()));
            if !authority.board.contains(&authority.leader) {
                roster.retain(|seat| *seat != authority.leader);
            }
            if !roster.contains(&house) {
                roster.push(house.clone());
            }
            next.parents = authority.parents.clone();
            next.parent_heads = authority.parent_heads.clone();
            next.claims_scope_ref = authority.claims_scope_ref.clone();
            next.slice = authority.slice.clone();
            next.depth_limit = authority.depth_limit;
            next.depth_remaining = authority.depth_remaining;
            next.board = authority.board.clone();
            next.leader = house;
            next.roster = roster;
            let signed_at = owner_signed_at(self, txn)?;
            self.sign_owner_project_in_txn(
                txn,
                owner,
                signer,
                root,
                &mut next,
                Some(witness.anchor),
                signed_at,
            )?;
            self.batch_in()
                .put_engine_history(
                    &root,
                    kind,
                    TimeRange {
                        start: signed_at,
                        end: signed_at,
                    },
                    signed_at,
                    &encode(&next)?,
                )
                .apply(txn)?;
            self.require_owner_head_in_txn(txn, root, &next)?;
            Ok(())
        })
    }
}
