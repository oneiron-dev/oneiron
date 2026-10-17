//! The house mind leads the root project (ONEIRON-ARCH-0063: the vault is the
//! root project, its house mind leads and its owners form its board; the
//! house mind is the ORG given a pen).
//!
//! The vault seeds its root with the `sys.team_lead` row as leader, before
//! any workspace exists. Once a workspace names its house, the owner's door
//! signs the root's next state with that house as leader: a host-signed v3
//! state over the root's current head, landed as history, the board and every
//! earlier revision kept. Nothing writes a projection around the door, and a
//! root that already follows its house is left as it is. Either way the
//! house then joins the root's home room through the three consents
//! (OF-531), as an agent on its institutional standing and its roster seat,
//! with the owner as filer.
//!
//! Two doors reach it (FIX 700/911): the owner's finish of a stored
//! workspace, and the host's start, which binds the one stored workspace's
//! house only while the root still follows its seeded leader, so a leader
//! the board chose is never replaced.
use super::fold::ProjectDisposition;
use super::owner_signer::{OwnerProjectSigner, owner_signed_at};
use super::read::stored;
use super::*;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::workspace_roster::WorkspaceRosterPreset;
use crate::{EdgeActorClass, WriteActor};

impl Vault {
    /// Makes the house mind `workspace_ref`'s stored preset names the root
    /// project's leader: [`Self::bind_house_leader`] over that preset, the
    /// owner's finish of the workspace. No stored preset is `EntityNotFound`.
    pub fn bind_workspace_house_leader(
        &self,
        workspace_ref: &str,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
    ) -> Result<()> {
        let preset = crate::workspace_roster::read_preset(self, workspace_ref)?
            .ok_or(Error::EntityNotFound)?;
        self.bind_house_leader(&preset, owner, signer)
    }

    /// The house a host binds at start: when exactly one workspace preset is
    /// stored and the root still follows its seeded leader, that preset's
    /// house takes the lead as [`Self::bind_house_leader`] makes it, signed
    /// with `issuer`'s owner-project slip. `Ok(false)` when no preset or
    /// several are stored, or the root follows any other leader; the lead is
    /// re-read in the writing transaction, so a leader the board chose is
    /// never replaced.
    pub fn bind_default_house_leader(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
    ) -> Result<bool> {
        let Some(seeded) = crate::agent_def::legacy_logical_id_row(ROOT_SEED_LEADER)? else {
            return Ok(false);
        };
        let seeded = seeded.to_hex();
        let preset = {
            let txn = self.store.env.read_txn()?;
            let presets = crate::workspace_roster::PRESET
                .iter_from(&self.store, &txn, &[])?
                .take(2)
                .collect::<Result<Vec<_>>>()?;
            let [(_, row)] = presets.as_slice() else {
                return Ok(false);
            };
            let Some(root) = root_project_in(&self.store, &txn)? else {
                return Ok(false);
            };
            if self
                .effective_project_in_txn(&txn, root)?
                .is_none_or(|(_, effective)| effective.leader != seeded)
            {
                return Ok(false);
            }
            row.preset.clone()
        };
        let signer = self.owner_project_signer(issuer)?;
        self.lead_root(&preset, owner, &signer, Some(seeded.as_str()))
    }

    /// Makes `preset`'s house mind the root project's leader.
    ///
    /// `preset` must be the workspace's stored preset, so the house is the
    /// one its onboarding anchored to the ORG, never one a caller names. The
    /// owner is revalidated and the host signs in the writing transaction,
    /// over the root's current head; the act commits only once the fold
    /// installs the new state. The seat the old leader held as leader goes
    /// with the lead (a board seat stays), and the house takes one. In the
    /// same transaction the house files its join of the root's home room,
    /// with the revalidated owner as filer; a join that holds or is refused
    /// is no participation, and the lead stands either way.
    pub fn bind_house_leader(
        &self,
        preset: &WorkspaceRosterPreset,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
    ) -> Result<()> {
        self.lead_root(preset, owner, signer, None)?;
        Ok(())
    }

    /// [`Self::bind_house_leader`], leaving the root as it is and answering
    /// `false` when `only_from` names a leader other than the one the root
    /// follows now. The house's anchor to the workspace's ORG is filled in
    /// the same transaction when the preset was stored without one; a house
    /// anchored to another subject is refused, never re-anchored.
    fn lead_root(
        &self,
        preset: &WorkspaceRosterPreset,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        only_from: Option<&str>,
    ) -> Result<bool> {
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
            if only_from.is_some_and(|leader| authority.leader != leader) {
                return Ok(false);
            }
            let filer = WriteActor::new(owner.revalidate_in_txn(self, txn)?, EdgeActorClass::Human);
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            crate::subject_model::ensure_actor_subject_in_txn(
                self,
                txn,
                preset.house_actor_ref,
                preset.org_ref,
                filer,
                now,
            )?;
            if authority.leader == house {
                self.house_joins_root_in_txn(txn, owner, root, preset.house_actor_ref)?;
                return Ok(true);
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
            self.house_joins_root_in_txn(txn, owner, root, preset.house_actor_ref)?;
            Ok(true)
        })
    }

    /// The house's join of the root's home room, once the root's head and
    /// room are installed, filed by the revalidated owner (OF-417).
    fn house_joins_root_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        root: EntityId,
        house: EntityId,
    ) -> Result<()> {
        let caller = WriteActor::new(owner.revalidate_in_txn(self, txn)?, EdgeActorClass::Human);
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        crate::workspace_roster::workplace_join::file_house_join_in_txn(
            self,
            txn,
            super::home_room_id(root)?,
            house,
            caller,
            now,
        )?;
        Ok(())
    }
}
