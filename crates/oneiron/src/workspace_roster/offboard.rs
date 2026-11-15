//! Member offboarding (ARCH-0063 [INB-07]): the leaver rule applied to what
//! onboarding assembled in the company vault.
//!
//! Canon: "offboarding: revoke the actor, keep the person — fire the agency,
//! keep the memories" (ARCH-0063:152); "The member seat and the inquiry edge
//! end together ... A leaver takes their vault" (ARCH-0043:166); what they
//! wrote in the shared vault stays (ARCH-0043:159). Engine rulings, 15 Nov:
//! INB-07-OFFBOARD = A1 + B1, OFFBOARD-ROOMS = A, OFFBOARD-PENDING-ASKS = A,
//! OFFBOARD-SEAT-AUTHORITY = A, OFFBOARD-CUSTODY-AUTHORITY = A,
//! OFFBOARD-CHECK-INS = B.
//!
//! # One writer
//!
//! Every effect commits in one write transaction, so no half-offboarded
//! member exists. When the member still holds a seat, that writer is
//! `vault.members.remove`'s own ([`Vault::remove_shared_member_then`]): its
//! named power, its check-in (a Deputy's offboard waits on an Owner and
//! applies nothing until the check-in is spent), its `MemberRemoved`
//! receipt, notice, slips and Connect detach. The workspace half then asks
//! the ruled authority in the same writer: the vault's owner, or an admin
//! holding the workspace-settings power.
//!
//! # What ends and what stays
//!
//! * The member's actor and a work companion born here are switched off;
//!   their PERSONs, anchors and every word they wrote stay. What they made
//!   keeps running (ARCH-0053 #author-off-no-cascade) and is listed.
//! * The access grants and the capability slips those actors held, and the
//!   companion-profile grant minted for a born companion, are revoked: a
//!   switched-off actor keeps no credential to read with.
//! * A brought companion is her member's own: she is detached from her work
//!   facet here, never switched off.
//! * The delegated mailbox is released and closed (a tombstone): no send can
//!   use it. Mail already landed stays under its audience. The owner's
//!   offboard revokes its custody in the same writer, as its last step,
//!   since the revoke tears down lease files no rollback restores; an
//!   admin's names it for the owner, since only the owner signs a custody
//!   revoke.
//! * The member and their companion leave every room they stand in; the
//!   room keeps its history.
//! * The leaver's open member asks are declined and the check-ins they
//!   asked let go; check-ins waiting on them are left to the ladder.
//! * The member's personal vault, when her roster row links one, is
//!   handed over (ARCH-0063:359 "A matching offboarding verb hands the vault
//!   over"; RULING INB-07-VAULT-LINK = A): the link goes with the row, the
//!   seat's inquiry route to the vault ends with the seat, and the outcome
//!   names the vault and its origin for the host, which moves a minted one
//!   out of the org account.
//! * The roster row and the onboarding reservations go; a journal row
//!   answers a replay of the same offboarding id.

use serde::{Deserialize, Serialize};

use super::work_companion::require_settings_authority_in_txn;
use super::*;
use crate::agent_def::AgentMadeBy;
use crate::authority::{ActSurface, HostSlipIssuer};
use crate::channel_identity::ChannelIdentityStep;
use crate::check_in::{LeaverCheckIns, settle_leaver_check_ins_in_txn};
use crate::edge::EdgeActorClass;
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_CONVERSATION};
use crate::secret_custody::{SecretCustodyStatus, SecretCustodyWork};
use crate::store::EngineScan;
use crate::store::scan_count::ScanCount;

/// The refusal of an offboarding by someone without the workspace power.
const OFFBOARD_REFUSAL: &str = "offboarding is a workspace act: owner or admin settings power";

/// One member offboarding. The caller names the workspace and the member;
/// everything the offboarding ends is read from the roster row onboarding
/// wrote, never from the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberOffboardingIntent {
    /// Caller-chosen idempotency key for this offboarding.
    pub offboarding_id: String,
    /// The workspace the member leaves.
    pub workspace_ref: String,
    /// The leaving member's `PERSON`.
    pub person_ref: EntityId,
    /// The settled check-in a Deputy's re-call spends: ending a standing
    /// seat waits on an Owner, as a Deputy's removal does. Not part of the
    /// request's identity.
    #[serde(default)]
    pub check_in_ref: Option<EntityId>,
}

impl MemberOffboardingIntent {
    fn validate(&self) -> Result<()> {
        validate_name(
            &self.offboarding_id,
            "offboarding_id must be 1..=256 bytes and contain no NUL",
        )?;
        validate_name(
            &self.workspace_ref,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )
    }

    /// The digest a replay must match: the workspace and the member.
    fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.workspace-offboarding.intent.v1");
        hasher.update(self.workspace_ref.as_bytes());
        hasher.update(&[ROSTER_KEY_SEPARATOR]);
        hasher.update(self.person_ref.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Where the leaver's companion came from, as onboarding recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OffboardedCompanionKind {
    /// A work companion born in this workspace: switched off, PERSON kept.
    Work,
    /// Her member's own companion: detached, never switched off.
    Brought,
    /// A roster row written before onboarding recorded the origin: treated
    /// as brought. The owner may switch her off with `vault.agents.update`.
    Unrecorded,
}

/// What the offboarding did to the leaver's companion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffboardedCompanion {
    pub person_ref: EntityId,
    pub actor_ref: EntityId,
    pub kind: OffboardedCompanionKind,
    /// Her actor was switched off here.
    pub switched_off: bool,
    /// Her work-facet association was removed here.
    pub facet_detached: bool,
}

/// One room membership the offboarding ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffboardedRoomLeave {
    pub room: EntityId,
    /// The member or their companion.
    pub person: EntityId,
}

/// What one offboarding did, and what it left for the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MemberOffboardingOutcome {
    /// Echo of the idempotency key.
    pub offboarding_id: String,
    pub workspace_ref: String,
    /// The leaving member's `PERSON`, kept.
    pub person_ref: EntityId,
    /// The `MemberRemoved` receipt id when this offboarding ended a standing
    /// seat; `None` when the seat had already ended.
    pub seat_receipt: Option<String>,
    /// The actors switched off here: the member's, and a born companion's.
    pub actors_switched_off: Vec<EntityId>,
    pub companion: Option<OffboardedCompanion>,
    /// The access grants revoked here.
    pub access_grants_revoked: Vec<EntityId>,
    /// The capability slips the switched-off actors held, revoked here by
    /// this install's live host issuer (hex ids); none when this install
    /// holds no live host issuer, as a member removal then revokes none.
    pub actor_slips_revoked: Vec<String>,
    /// The delegated mailbox identity, when the member had one, and the
    /// state it was left in (`tombstone` once retired).
    pub identity_ref: Option<EntityId>,
    pub identity_state: Option<String>,
    /// The mailbox custody revoked here, by the owner's offboarding.
    pub custody_revoked: Option<String>,
    /// The live mailbox custody an admin's offboarding left for the owner
    /// to revoke (`vault.secrets.revoke`); its identity is retired, so no
    /// send can use it.
    pub custody_left_for_owner: Option<String>,
    pub rooms_left: Vec<OffboardedRoomLeave>,
    /// The member's personal vault her roster row linked, handed over
    /// (ARCH-0063:359 [INB-07]): it is hers, the company keeps no route to
    /// it (the seat's inquiry route ends with the seat) and never reads it.
    /// A `minted` one leaves the org account through the host, which owns
    /// the account and the billing. `None` when the row linked none.
    pub personal_vault: Option<PersonalVaultLinkView>,
    /// The leaver's open member asks, declined.
    pub member_asks_declined: Vec<String>,
    /// The open check-ins the leaver's person or actors asked, let go.
    pub check_ins_let_go: Vec<EntityId>,
    /// Open check-ins whose current rung pins the leaver, left to the
    /// ladder: the leaver may no longer answer, and the ask climbs.
    pub check_ins_waiting_on_leaver: Vec<EntityId>,
    /// What the switched-off actors made, still running, as
    /// `vault.agents.made_by` lists it (the agents they saved, branches,
    /// watchers, hooks and scheduled sends): one answer per actor that made
    /// anything. The owner pauses it with `vault.agents.pause_tree` if it
    /// should stop.
    pub made_by: Vec<AgentMadeBy>,
    /// The recorded time the offboarding committed.
    pub completed_at: u64,
    /// This answer is a replay of an offboarding that already completed:
    /// only the echo fields and `completed_at` are filled.
    pub replayed: bool,
}

impl MemberOffboardingOutcome {
    fn new(intent: &MemberOffboardingIntent, completed_at: u64, replayed: bool) -> Self {
        Self {
            offboarding_id: intent.offboarding_id.clone(),
            workspace_ref: intent.workspace_ref.clone(),
            person_ref: intent.person_ref,
            seat_receipt: None,
            actors_switched_off: Vec::new(),
            companion: None,
            access_grants_revoked: Vec::new(),
            actor_slips_revoked: Vec::new(),
            identity_ref: None,
            identity_state: None,
            custody_revoked: None,
            custody_left_for_owner: None,
            rooms_left: Vec::new(),
            personal_vault: None,
            member_asks_declined: Vec::new(),
            check_ins_let_go: Vec::new(),
            check_ins_waiting_on_leaver: Vec::new(),
            made_by: Vec::new(),
            completed_at,
            replayed,
        }
    }
}

/// What the offboarding writer hands back for after its commit.
struct Settled {
    outcome: MemberOffboardingOutcome,
    custody: Option<SecretCustodyWork>,
    count: ScanCount,
}

/// Who offboards in the writer, and with what: the offboarder's PERSON, the
/// live host issuer that revokes the actors' slips (`None` when this install
/// holds none), the custody revoke's audit surface, and the writer's
/// recorded time.
struct Leaver<'a> {
    offboarder: EntityId,
    issuer: Option<&'a HostSlipIssuer>,
    surface: ActSurface,
    now: u64,
}

impl Vault {
    /// Offboards `intent.person_ref` from `intent.workspace_ref`, as
    /// `owner`: the vault's owner, or an admin holding the
    /// workspace-settings power over the workspace's vault. A seat that
    /// still stands ends in the same writer under `vault.members.remove`'s
    /// own law (its RemoveMember power and check-in). `surface` is the
    /// custody revoke's audit surface. A replay of a completed offboarding
    /// id answers its completion; the same id with another workspace or
    /// member fails with [`Error::InvalidClaimBody`].
    ///
    /// # Errors
    /// [`Error::InvalidClaimBody`] for a malformed request, an unknown
    /// workspace, a member not on its roster, a reused id, or an offboarding
    /// of oneself (a member leaves through `vault.members.leave`); the
    /// authority refusals of the workspace power and of the removal door;
    /// [`Error::CheckInPending`] when the seat end waits on an Owner; the
    /// refusals of the doors it composes. Every refusal writes nothing.
    pub fn offboard_workspace_member(
        &self,
        intent: MemberOffboardingIntent,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
    ) -> Result<MemberOffboardingOutcome> {
        intent.validate()?;
        let digest = intent.digest();
        let preset = read_preset(self, &intent.workspace_ref)?
            .ok_or_else(|| invalid("workspace_ref names no established workspace"))?;
        let vault_id = preset.workspace_vault_id;
        // Read first, so an offboarding the workspace power refuses opens
        // no check-in at the seat door.
        let (seat_stands, owner_offboards) = {
            let rtxn = self.store.env.read_txn()?;
            require_settings_authority_in_txn(self, &rtxn, vault_id, owner, OFFBOARD_REFUSAL)?;
            let offboarder = owner.revalidate_person_in_txn(self, &rtxn)?;
            if let Some(done) = OFFBOARDING.get(&self.store, &rtxn, &intent.offboarding_id)? {
                return replay(&intent, &digest, &done);
            }
            refuse_self_offboard(offboarder, &intent)?;
            roster_member_in_txn(self, &rtxn, &intent)?;
            (
                self.member_role_in_txn(&rtxn, vault_id, intent.person_ref)?
                    .is_some(),
                crate::policy_model::is_live_vault_owner_in_txn(self, &rtxn, &offboarder)?,
            )
        };
        if owner_offboards {
            // The owner door's order: the install key loads before the
            // writer that carries the custody revoke.
            self.load_signing_for_revoke()?;
        }
        let settle = |txn: &mut heed::RwTxn<'_>,
                      offboarder: EntityId,
                      now: u64,
                      issuer: Option<&HostSlipIssuer>| {
            self.settle_offboarding_in_txn(
                txn,
                &intent,
                &digest,
                vault_id,
                owner,
                Leaver {
                    offboarder,
                    issuer,
                    surface,
                    now,
                },
            )
        };
        let (seat_receipt, settled) = if seat_stands {
            // The workspace power and the roster row are judged again in the
            // removal's writer before its check-in, so a caller who lost the
            // power since the read above, or a seat with no roster row here,
            // commits nothing, not even a pending check-in.
            let guard = |txn: &heed::RoTxn<'_>| {
                require_settings_authority_in_txn(self, txn, vault_id, owner, OFFBOARD_REFUSAL)?;
                roster_member_in_txn(self, txn, &intent).map(|_| ())
            };
            let (receipt, settled) = self.remove_shared_member_then(
                owner,
                vault_id,
                intent.person_ref,
                intent.check_in_ref,
                guard,
                settle,
            )?;
            (Some(receipt.id), settled)
        } else {
            // The seat ended earlier; the actors' slips still go, under the
            // same live host issuer a removal's writer uses.
            let loaded = self.membership_issuer(None);
            let settled = self.with_write_txn(|txn| {
                let offboarder = owner.revalidate_person_in_txn(self, txn)?;
                if self
                    .member_role_in_txn(txn, vault_id, intent.person_ref)?
                    .is_some()
                {
                    return Err(Error::ConcurrentWrite(
                        "the member's seat changed during offboarding; retry",
                    ));
                }
                let issuer = self.executing_host_issuer_in_txn(txn, loaded)?;
                let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                settle(txn, offboarder, now, issuer.as_ref())
            })?;
            (None, settled)
        };
        let Settled {
            mut outcome,
            custody,
            count,
        } = settled;
        count.finish(self);
        if !outcome.actor_slips_revoked.is_empty() {
            self.store.notify_credential_revocations();
        }
        if let Some(custody) = &custody {
            self.mirror_custody_change(custody);
        }
        outcome.seat_receipt = seat_receipt;
        Ok(outcome)
    }

    /// The workspace half of an offboarding, in the writer that ends (or
    /// found ended) the seat, as `leaver` names it.
    fn settle_offboarding_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        intent: &MemberOffboardingIntent,
        digest: &[u8; 32],
        vault_id: u64,
        owner: &AuthenticatedOwner,
        leaver: Leaver<'_>,
    ) -> Result<Settled> {
        let Leaver {
            offboarder,
            issuer,
            surface,
            now,
        } = leaver;
        require_settings_authority_in_txn(self, txn, vault_id, owner, OFFBOARD_REFUSAL)?;
        refuse_self_offboard(offboarder, intent)?;
        if OFFBOARDING
            .get(&self.store, txn, &intent.offboarding_id)?
            .is_some()
        {
            return Err(Error::ConcurrentWrite(
                "the offboarding completed in another writer; retry for its answer",
            ));
        }
        let (key, row) = roster_member_in_txn(self, txn, intent)?;
        let mut outcome = MemberOffboardingOutcome::new(intent, now, false);

        // The actors: the member's, and a work companion born here.
        let born_grant = match row.companion_origin {
            CompanionOrigin::Born { profile_grant_ref } => Some(profile_grant_ref),
            CompanionOrigin::Brought | CompanionOrigin::Unrecorded => None,
        };
        let mut actors = vec![row.actor_ref];
        if born_grant.is_some()
            && let Some(companion_actor) = row.companion_actor_ref
        {
            actors.push(companion_actor);
        }
        for actor in &actors {
            let version = |current: &str| offboard_version(digest, &intent.offboarding_id, current);
            if self.switch_off_agent_definition_in_txn(txn, actor, version, now)? {
                outcome.actors_switched_off.push(*actor);
            }
        }
        let mut count = ScanCount::start(
            &self.store,
            txn,
            EngineScan::TypeIndexRows,
            &[crate::registry::ENTITY_TYPE_AGENT_DEF],
        )?;
        for actor in &actors {
            let made = self.agent_made_by_in_txn(txn, actor, &mut count)?;
            if made.count > 0 {
                outcome.made_by.push(made);
            }
        }
        outcome.access_grants_revoked =
            revoke_leaver_access_grants_in_txn(self, txn, &actors, born_grant, now)?;
        // "Revoke the actor" (ARCH-0063:152): a slip the actor holds would
        // still read under its owner-minted agent Grants, which judge the
        // Grant and its pact, not the definition switched off above.
        if let Some(issuer) = issuer {
            for actor in &actors {
                for slip in
                    self.revoke_held_capability_slips_in_txn(txn, issuer, &actor.to_hex(), None)?
                {
                    outcome
                        .actor_slips_revoked
                        .push(crate::entity_id::bytes_to_hex_lower(&slip));
                }
            }
        }

        // The companion: a brought one is detached; the binding ends.
        if let (Some(person), Some(actor)) = (row.companion_person_ref, row.companion_actor_ref) {
            let kind = match row.companion_origin {
                CompanionOrigin::Born { .. } => OffboardedCompanionKind::Work,
                CompanionOrigin::Brought => OffboardedCompanionKind::Brought,
                CompanionOrigin::Unrecorded => OffboardedCompanionKind::Unrecorded,
            };
            let mut facet_detached = false;
            if kind != OffboardedCompanionKind::Work
                && let Some(facet) = row.companion_facet_ref
            {
                facet_detached = crate::ports::EdgeStore::port_edge_delete(
                    self,
                    txn,
                    &person,
                    EdgeKind::HasFacet,
                    &facet,
                )?;
            }
            if COMPANION_PRINCIPAL.get(&self.store, txn, &person)? == Some(intent.person_ref) {
                COMPANION_PRINCIPAL.delete(&self.store, txn, &person)?;
            }
            outcome.companion = Some(OffboardedCompanion {
                person_ref: person,
                actor_ref: actor,
                kind,
                switched_off: outcome.actors_switched_off.contains(&actor),
                facet_detached,
            });
        }

        // The delegated mailbox: retired; its custody the owner's to revoke,
        // which this writer does last.
        let mut owner_revokes = None;
        if let Some(identity) = row.identity_ref {
            let (state, custody_name) = self.retire_leaver_mailbox_in_txn(txn, &identity, now)?;
            outcome.identity_ref = Some(identity);
            outcome.identity_state = Some(state);
            if let Some(name) = custody_name
                && custody_live_in_txn(self, txn, &name)?
            {
                if crate::policy_model::is_live_vault_owner_in_txn(self, txn, &offboarder)? {
                    owner_revokes = Some(name);
                } else {
                    outcome.custody_left_for_owner = Some(name);
                }
            }
        }

        // Rooms: the member and their companion leave every room.
        let mut leavers = vec![intent.person_ref];
        leavers.extend(row.companion_person_ref);
        outcome.rooms_left = leave_every_room_in_txn(
            self,
            txn,
            &leavers,
            WriteActor::new(offboarder, EdgeActorClass::Human),
            now,
        )?;

        // Asks: declined; check-ins asked let go, check-ins waiting listed.
        outcome.member_asks_declined =
            self.decline_member_asks_of_in_txn(txn, vault_id, intent.person_ref, offboarder, now)?;
        let mut askers = vec![intent.person_ref];
        askers.extend(actors.iter().copied());
        let LeaverCheckIns {
            let_go,
            waiting_on_leaver,
        } = settle_leaver_check_ins_in_txn(
            self,
            txn,
            &askers,
            intent.person_ref,
            offboarder,
            &format!("workspace_offboarding:{}", intent.offboarding_id),
            now,
        )?;
        outcome.check_ins_let_go = let_go;
        outcome.check_ins_waiting_on_leaver = waiting_on_leaver;

        // The roster row and the onboarding reservation go, and the
        // personal-vault link with the row; the journal answers a replay.
        outcome.personal_vault = row.personal_vault.as_ref().map(PersonalVaultLink::view);
        MEMBER.delete(&self.store, txn, &key)?;
        MEMBER_INTENT.delete(
            &self.store,
            txn,
            &MemberIntentKey {
                workspace_ref: intent.workspace_ref.clone(),
                person_ref: intent.person_ref,
            },
        )?;
        OFFBOARDING.put(
            &self.store,
            txn,
            &intent.offboarding_id,
            &OffboardingJournalRow {
                offboarding_id: intent.offboarding_id.clone(),
                intent_digest: *digest,
                completed_at: now,
            },
        )?;

        // Last: the owner's custody revoke tears down the custody's lease
        // files, which a rollback of this writer would not restore, so it
        // runs after every step here that can refuse.
        let mut custody = None;
        if let Some(name) = owner_revokes {
            self.revoke_secret_in_txn(
                txn,
                &name,
                crate::secret_rotation::RevokeCause::Revoked,
                now,
            )?;
            custody = Some(self.carry_custody_revoke_in_txn(txn, offboarder, surface, &name, now)?);
            outcome.custody_revoked = Some(name);
        }
        Ok(Settled {
            outcome,
            custody,
            count,
        })
    }

    /// Releases, then closes, the leaver's delegated mailbox at `identity`,
    /// from whichever retirement stop it stands at: the answer is the state
    /// it was left in and its custody name. A row on another machine, or one
    /// that never went live, is left as it is.
    fn retire_leaver_mailbox_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        identity: &EntityId,
        now: u64,
    ) -> Result<(String, Option<String>)> {
        let current = self
            .get_channel_identity_in_txn(txn, identity)?
            .ok_or(Error::EntityNotFound)?;
        let Some(grant) = current.grant() else {
            return Ok((current.state().as_str().to_owned(), None));
        };
        let custody = grant.custody_record_ref.clone();
        let mut state = current.state();
        if state == ChannelIdentityState::Active {
            state = self
                .step_channel_identity_in_writer(txn, identity, ChannelIdentityStep::Release, now)?
                .state();
        }
        if state == ChannelIdentityState::Released {
            state = self
                .step_channel_identity_in_writer(txn, identity, ChannelIdentityStep::Close, now)?
                .state();
        }
        Ok((state.as_str().to_owned(), Some(custody)))
    }
}

/// The answer to a replay of completed offboarding `done`.
fn replay(
    intent: &MemberOffboardingIntent,
    digest: &[u8; 32],
    done: &OffboardingJournalRow,
) -> Result<MemberOffboardingOutcome> {
    if done.intent_digest != *digest {
        return Err(invalid(
            "offboarding_id was already used with different inputs",
        ));
    }
    Ok(MemberOffboardingOutcome::new(
        intent,
        done.completed_at,
        true,
    ))
}

/// A member leaves on their own through `vault.members.leave`; an
/// offboarding is another person's act.
fn refuse_self_offboard(offboarder: EntityId, intent: &MemberOffboardingIntent) -> Result<()> {
    if offboarder == intent.person_ref {
        return Err(invalid(
            "a member leaves through vault.members.leave; offboarding is another person's act",
        ));
    }
    Ok(())
}

/// The version an offboarding writes on a definition it switches off:
/// derived from the offboarding (its workspace and member `digest`, and its
/// id) and the version `current` the definition stands at, so it is never
/// the version it replaces, and no two offboardings write the same one.
/// The id holds no NUL ([`MemberOffboardingIntent::validate`]).
fn offboard_version(digest: &[u8; 32], offboarding_id: &str, current: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron.workspace-offboarding.version.v1");
    hasher.update(digest);
    hasher.update(offboarding_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(current.as_bytes());
    format!("offboard-{}", hasher.finalize().to_hex())
}

/// The leaver's roster row, keyed as the roster files it: an offboarding
/// names a member of this workspace's roster.
fn roster_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: &MemberOffboardingIntent,
) -> Result<(RosterMemberKey, RosterMemberRow)> {
    let key = RosterMemberKey {
        workspace_ref: intent.workspace_ref.clone(),
        person_ref: intent.person_ref,
    };
    let row = MEMBER
        .get(&vault.store, txn, &key)?
        .ok_or_else(|| invalid("person_ref is not on this workspace's roster"))?;
    Ok((key, row))
}

/// Whether custody record `name` is held here and still active.
fn custody_live_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, name: &str) -> Result<bool> {
    let Some(id) =
        crate::store::secret_name_index::resolve_secret_ref_in_txn(&vault.store, txn, name)?
    else {
        return Ok(false);
    };
    Ok(
        crate::secret_custody::read_secret_custody_meta_in_txn(&vault.store, txn, &id)?
            .is_some_and(|record| record.status == SecretCustodyStatus::Active),
    )
}

/// Revokes every live access grant one of `actors` holds, and the
/// companion-profile grant `born_grant` minted for a born companion: the
/// revoked ids.
fn revoke_leaver_access_grants_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actors: &[EntityId],
    born_grant: Option<EntityId>,
    now: u64,
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for row in vault
        .store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_ACCESS_GRANT])?
    {
        let (key, _) = row?;
        let id: [u8; 16] = key[1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("access grant type index key"))?;
        ids.push(EntityId::from_bytes(id)?);
    }
    let mut doomed = Vec::new();
    for id in ids {
        let crate::vault::LiveEntityRow::Live { body, .. } =
            crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?
        else {
            continue;
        };
        // An erased grant is no grant left to revoke.
        let Ok(grant) = crate::access_grant::decode_access_grant_body(&body) else {
            continue;
        };
        if grant.status == crate::access_grant::AccessGrantStatus::Active
            && (actors.contains(&grant.principal_ref) || born_grant == Some(id))
        {
            doomed.push(id);
        }
    }
    for id in &doomed {
        vault.revoke_admitted_access_grant_in_txn(txn, id, now, |_| Ok(()))?;
    }
    Ok(doomed)
}

/// Ends the membership of each of `leavers` in every live room they stand
/// in, through the room leave door's own ledger write: each gets a Leave
/// row, the room keeps its history, and a later join opens a new
/// membership (OFFBOARD-ROOMS = A).
fn leave_every_room_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    leavers: &[EntityId],
    writer: WriteActor,
    now: u64,
) -> Result<Vec<OffboardedRoomLeave>> {
    let mut rooms = Vec::new();
    for row in vault
        .store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_CONVERSATION])?
    {
        let (key, _) = row?;
        let id: [u8; 16] = key[1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("conversation type index key"))?;
        rooms.push(EntityId::from_bytes(id)?);
    }
    let mut left = Vec::new();
    for room in rooms {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &room)?.is_live() {
            continue;
        }
        let members = vault.members_in_txn(txn, room)?;
        for person in leavers {
            if members.contains(person) {
                vault.leave_member_in_txn(txn, room, *person, writer, now)?;
                left.push(OffboardedRoomLeave {
                    room,
                    person: *person,
                });
            }
        }
    }
    Ok(left)
}
