//! The house mind leads the root project (ONEIRON-ARCH-0063: the vault is the
//! root project, its house mind leads and its owners form its board; the
//! house mind runs the ORG).
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
//!
//! The bind changes no subject anchor (HOUSE-BIND = A): the house agent keeps
//! its own model PERSON, and its link to the org is its role there, one
//! membership grant at the role its binder names, with a receipt
//! (`workspace_roster::house_link`). A house that loses the lead to another
//! loses that grant in the same write. The owner's unbind gives the lead back
//! to `sys.team_lead` in a new signed state and removes the grant. Both check,
//! in their own write, that the owner may assign the role they set or clear
//! by the role table; `Vault::set_house_role` and `Vault::clear_house_role`
//! change the role alone, under that rule, and never the leader.
//!
//! The house reads a person's unscoped MESSAGE for its project question
//! through one policy row (`gate::house_grant`). The shipped manifest carries
//! it for the seeded house; for a house that takes the lead, the same write
//! re-seeds an untouched seeded default with that house's row, and the unbind
//! takes it out again. The row is an engine default, installed as a seeded
//! upgrade is and never as the owner's policy write; a default the owner
//! authored is left as it is.
use super::fold::ProjectDisposition;
use super::owner_signer::{OwnerProjectSigner, owner_signed_at};
use super::read::stored;
use super::*;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::federation::FederationGrantRole;
use crate::workspace_roster::WorkspaceRosterPreset;
use crate::workspace_roster::house_link::{
    house_links_in_txn, link_house_in_txn, unlink_house_in_txn,
};
use crate::{EdgeActorClass, WriteActor};

/// The root's settled frontier in `txn`: its id, its witness and the
/// authority that witness signs.
fn settled_root_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<(EntityId, ProjectWitness, ProjectAuthority)> {
    let root = root_project_in(&vault.store, txn)?.ok_or(Error::EntityNotFound)?;
    let frontier = ProjectReader::new(&vault.store, txn, vault.privacy_posture())?
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
    let witness = frontier.witness.ok_or_else(invalid)?;
    let authority = witness.authority()?.clone();
    Ok((root, witness, authority))
}

impl Vault {
    /// Makes the house mind `workspace_ref`'s stored preset names the root
    /// project's leader at `role` in its org: [`Self::bind_house_leader`] over
    /// that preset, the owner's finish of the workspace. No stored preset is
    /// `EntityNotFound`.
    pub fn bind_workspace_house_leader(
        &self,
        workspace_ref: &str,
        role: FederationGrantRole,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
    ) -> Result<()> {
        let preset = crate::workspace_roster::read_preset(self, workspace_ref)?
            .ok_or(Error::EntityNotFound)?;
        self.bind_house_leader(&preset, role, owner, signer)
    }

    /// The house a host binds at start: when exactly one workspace preset is
    /// stored and the root still follows its seeded leader, that preset's
    /// house takes the lead at `role` as [`Self::bind_house_leader`] makes
    /// it, signed with `issuer`'s owner-project slip. `Ok(false)` when no
    /// preset or several are stored, or the root follows any other leader;
    /// the lead is re-read in the writing transaction, so a leader the board
    /// chose is never replaced.
    pub fn bind_default_house_leader(
        &self,
        role: FederationGrantRole,
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
        self.lead_root(&preset, role, owner, &signer, Some(seeded.as_str()))
    }

    /// Makes `preset`'s house mind the root project's leader, running its
    /// org at `role` (member up to owner; the binder names it).
    ///
    /// `preset` must be the workspace's stored preset, so the house is the
    /// one its workspace names, never one a caller names. The owner is
    /// revalidated and the host signs in the writing transaction, over the
    /// root's current head; the act commits only once the fold installs the
    /// new state. The seat the old leader held as leader goes with the lead
    /// (a board seat stays), and the house takes one. In the same transaction
    /// the house takes its role in the org (`house_link`, the owner able to
    /// assign it by the role table), a house that led before it loses its
    /// own, and an untouched seeded policy default takes
    /// the house's read row (`gate::house_grant`), as an engine default. Then
    /// the house files its join of the root's home room, with the revalidated
    /// owner as filer; a join that holds or is refused is no participation,
    /// and the lead stands either way. No subject anchor changes.
    pub fn bind_house_leader(
        &self,
        preset: &WorkspaceRosterPreset,
        role: FederationGrantRole,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
    ) -> Result<()> {
        self.lead_root(preset, role, owner, signer, None)?;
        Ok(())
    }

    /// The owner's unbind of the root's house mind: in one transaction the
    /// house's grant in its org goes, with its receipt, the root's leader
    /// goes back to `sys.team_lead` in a new owner-signed state over the
    /// current head (every earlier state kept), and an untouched seeded
    /// policy default loses the house's read row. The seeded house, when a
    /// workspace names it, keeps the lead and loses only its role.
    /// `Ok(false)`, changing nothing, when the root's leader is no house a
    /// stored workspace names and holds no role. No subject anchor changes,
    /// and nothing the house wrote is rewritten.
    pub fn unbind_house_leader(
        &self,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
    ) -> Result<bool> {
        let kind = self.project_type_byte()?;
        let seeded =
            crate::agent_def::legacy_logical_id_row(ROOT_SEED_LEADER)?.ok_or_else(invalid)?;
        let (unbound, reseeded) = self.with_write_txn(|txn| {
            let (root, witness, authority) = settled_root_in_txn(self, txn)?;
            let Ok(house) = EntityId::from_hex(&authority.leader) else {
                return Ok((false, false));
            };
            // The seeded house can run a workspace's org too: it keeps the
            // lead and gives up only its role.
            let moves = house != seeded
                && crate::workspace_roster::PRESET
                    .scan(&self.store, txn)?
                    .iter()
                    .any(|(_, row)| row.preset.house_actor_ref == house);
            if !moves && house_links_in_txn(self, txn, house)?.is_empty() {
                return Ok((false, false));
            }
            let binder = owner.revalidate_in_txn(self, txn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            unlink_house_in_txn(self, txn, house, binder, now)?;
            if moves {
                self.sign_root_leader_in_txn(
                    txn,
                    owner,
                    signer,
                    (root, kind),
                    witness,
                    seeded.to_hex(),
                )?;
            }
            let reseeded = self.reseed_policy_manifest_in_txn(txn, now)?.is_some();
            Ok((true, reseeded))
        })?;
        if reseeded {
            // A floor this commit moved is judged again at once (FIX 5505).
            self.apply_pending_rebinds_after_commit();
        }
        Ok(unbound)
    }

    /// [`Self::bind_house_leader`], leaving the root as it is and answering
    /// `false` when `only_from` names a leader other than the one the root
    /// follows now.
    fn lead_root(
        &self,
        preset: &WorkspaceRosterPreset,
        role: FederationGrantRole,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        only_from: Option<&str>,
    ) -> Result<bool> {
        let kind = self.project_type_byte()?;
        let house = preset.house_actor_ref.to_hex();
        let (led, reseeded) = self.with_write_txn(|txn| {
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
            let (root, witness, authority) = settled_root_in_txn(self, txn)?;
            if only_from.is_some_and(|leader| authority.leader != leader) {
                return Ok((false, false));
            }
            let binder = owner.revalidate_in_txn(self, txn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            if authority.leader != house {
                // The house that led before gives up its role in its org.
                if let Ok(before) = EntityId::from_hex(&authority.leader) {
                    unlink_house_in_txn(self, txn, before, binder, now)?;
                }
                self.sign_root_leader_in_txn(txn, owner, signer, (root, kind), witness, house)?;
            }
            link_house_in_txn(self, txn, preset, role, binder, now)?;
            let reseeded = self.reseed_policy_manifest_in_txn(txn, now)?.is_some();
            self.house_joins_root_in_txn(txn, owner, root, preset.house_actor_ref)?;
            Ok((true, reseeded))
        })?;
        if reseeded {
            // A floor this commit moved is judged again at once (FIX 5505).
            self.apply_pending_rebinds_after_commit();
        }
        Ok(led)
    }

    /// Signs the root's next state over `witness` with `leader` as its
    /// leader, as the owner's door does: a host-signed v3 state landed as
    /// history, which the fold must install as the head. The seat the old
    /// leader held as leader goes with the lead (a board seat stays), and
    /// `leader` takes one; the board and every earlier state are kept.
    fn sign_root_leader_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        (root, kind): (EntityId, u8),
        witness: ProjectWitness,
        leader: String,
    ) -> Result<()> {
        let authority = witness.authority()?.clone();
        let mut next = stored(&self.store, txn, root, kind)?.ok_or(Error::EntityNotFound)?;
        // The head's seats: its signed roster, else the leader and board an
        // unsigned or older head seats, with the stored roster.
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
        if !roster.contains(&leader) {
            roster.push(leader.clone());
        }
        next.parents = authority.parents.clone();
        next.parent_heads = authority.parent_heads.clone();
        next.claims_scope_ref = authority.claims_scope_ref.clone();
        next.slice = authority.slice.clone();
        next.depth_limit = authority.depth_limit;
        next.depth_remaining = authority.depth_remaining;
        next.board = authority.board.clone();
        next.leader = leader;
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
