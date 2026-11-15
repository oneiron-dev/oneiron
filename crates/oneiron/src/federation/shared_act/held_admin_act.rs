//! The org two-admin rule (UNBUILT-06 PR 2; canon identity.md:223, ORG-1 A;
//! lead ORG-TWO-ADMIN-SCOPE, 15 Nov 20:1x; Engine RULING UNBUILT06-SHAPE
//! Q1, Q2 and Q4 = A). Opt in: while an Owner keeps the shared vault's
//! `org.two_admin` key on, an Admin's or a Deputy's power act counts for
//! nothing alone and becomes a question (Fable pass 26, act rule 1.3). The
//! shared-vault write gate and the delegate mint refuse it with
//! [`TWO_ADMIN_HOLD_REFUSAL`]; the verb that fronts it stores it here as
//! written, as one [`HeldAdminAct`], and asks each other live Owner, Admin
//! and Deputy in the inbox. A second, distinct live admin's approve re-runs
//! the same verb with the same input under that admin's own proof: the
//! approve door sets this module's per-thread approval around its
//! synchronous run, and the gate lets only that admin's write in that vault
//! through. The receipt names the approver as `actor` and the first admin
//! as `proposer`. The first admin may withdraw the act while it waits; past
//! `org.two_admin_lapse_secs` (default 7 days) the housekeeping pass marks
//! it lapsed and tells the first admin. An Owner's own act is never held.
//! Stored change: keep (a new table; `proposer` is an existing optional
//! receipt field).
use super::{Role, check_vault, invalid};
use crate::consent::AuthenticatedOwner;
use crate::error::{ClaimError, Error, Result};
use crate::federation::setting_keys::{ORG_TWO_ADMIN, ORG_TWO_ADMIN_LAPSE_SECS};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::memory::TWO_ADMIN_HOLD_REFUSAL;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};
use sha2::Digest as _;
use std::cell::Cell;

/// The inbox producer of a held act's ask to another admin; its event is
/// `<held act id>:<recipient id>` and its result the held act's id.
pub const NOTIFICATION_PRODUCER_ADMIN_ACT_HELD: &str = "shared_vault.admin_act_held";

/// The inbox producer of a lapsed act's notice to its first admin; its event
/// is `<held act id>:<first admin id>` and its result the held act's id.
pub const NOTIFICATION_PRODUCER_ADMIN_ACT_LAPSED: &str = "shared_vault.admin_act_lapsed";

/// Every held admin act, by id.
const HELD_ADMIN_ACT: SideTable<EntityId, HeldAdminAct, Named> =
    SideTable::new(&side_table::SHARED_ACT_HELD_ADMIN);

/// Where a held act stands.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HeldAdminActStatus {
    /// Waiting for a second admin.
    Open,
    /// The admin `approver` approved it, and its re-run under their proof is
    /// under way. It lands, or goes back to `Open` when the re-run refuses.
    Approving { approver: String },
    /// The re-run under `approver`'s proof ran.
    Landed { approver: String },
    /// Its first admin took it back.
    Withdrawn,
    /// No second admin approved it before `lapses_at`.
    Lapsed,
}

/// One Admin's or Deputy's power act, held as written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldAdminAct {
    pub id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    /// The verb the first admin called, by its dotted name.
    pub verb: String,
    /// The verb's input as the first admin wrote it.
    pub input: serde_json::Value,
    /// SHA-256 of the input's RFC 8785 form, 64 hex.
    pub input_digest: String,
    /// The first admin's PERSON id, hex.
    pub first_admin: String,
    pub held_at: u64,
    pub lapses_at: u64,
    pub status: HeldAdminActStatus,
    pub closed_at: Option<u64>,
}

/// The approved re-run of one held act: only [`Vault::claim_held_admin_act`]
/// builds one, for the approve door to run its verb under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldAdminApproval {
    vault_id: u64,
    held: EntityId,
    first_admin: EntityId,
    approver: EntityId,
}

thread_local! {
    static APPROVAL: Cell<Option<HeldAdminApproval>> = const { Cell::new(None) };
}

/// The approval this thread runs under. A write door reads it on its calling
/// thread, because the group commit may run the write's closure on another
/// member's thread (FIX 11607), and enters it again in the closure.
pub(crate) fn current_held_admin_approval() -> Option<HeldAdminApproval> {
    APPROVAL.with(Cell::get)
}

/// Gives the thread back the approval it ran under before, when dropped.
pub(crate) struct HeldAdminApprovalScope(Option<HeldAdminApproval>);

impl Drop for HeldAdminApprovalScope {
    fn drop(&mut self) {
        APPROVAL.with(|cell| cell.set(self.0));
    }
}

/// Runs the rest of the scope under `approval`, or under none: a write's
/// closure runs under the approval its caller captured, on any thread.
pub(crate) fn enter_held_admin_approval(
    approval: Option<HeldAdminApproval>,
) -> HeldAdminApprovalScope {
    HeldAdminApprovalScope(APPROVAL.with(|cell| cell.replace(approval)))
}

/// Runs `run` as the approved re-run of `approval`'s held act.
pub(crate) fn run_approved_admin_act<T>(approval: HeldAdminApproval, run: impl FnOnce() -> T) -> T {
    let _scope = enter_held_admin_approval(Some(approval));
    run()
}

/// The first admin of the held act whose approved re-run this thread runs,
/// PERSON hex, when `actor` is its approver in shared vault `vault_id`: the
/// receipt's `proposer`.
pub(crate) fn approved_admin_act_proposer(vault_id: u64, actor: EntityId) -> Option<String> {
    current_held_admin_approval()
        .filter(|approval| approval.vault_id == vault_id && approval.approver == actor)
        .map(|approval| approval.first_admin.to_hex())
}

/// The refusal of a held power act.
pub(crate) fn two_admin_hold_refusal() -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority {
        reason: TWO_ADMIN_HOLD_REFUSAL,
    })
}

/// Whether `role` holds the admin powers the rule holds or approves with.
fn is_admin_role(role: Role) -> bool {
    matches!(role, Role::Owner | Role::Admin | Role::Deputy)
}

fn digest(input: &serde_json::Value) -> Result<String> {
    let canonical = serde_json_canonicalizer::to_vec(input)
        .map_err(|_| Error::InvalidConfig("held admin act input is not canonical JSON".into()))?;
    Ok(crate::entity_id::bytes_to_hex_lower(&sha2::Sha256::digest(
        &canonical,
    )))
}

impl Vault {
    /// The org two-admin rule at a door, in the door's snapshot: a power act
    /// in shared vault `vault_id` that only an Admin or Deputy grant of
    /// `writer` admits refuses with [`TWO_ADMIN_HOLD_REFUSAL`] while an Owner
    /// has turned `org.two_admin` on, unless it is the approved re-run of a
    /// held act whose approver is `writer`, in this vault. The caller judged
    /// the grants first: an Owner's own act never comes here.
    pub(crate) fn two_admin_hold_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        writer: EntityId,
    ) -> Result<()> {
        if current_held_admin_approval()
            .is_some_and(|approval| approval.vault_id == vault_id && approval.approver == writer)
        {
            return Ok(());
        }
        if ORG_TWO_ADMIN.read_in_txn(self, txn, &[], None)?.value {
            return Err(two_admin_hold_refusal());
        }
        Ok(())
    }

    /// Holds the power act `verb` with `input` that the gate refused to
    /// `first_admin`, a live Admin or Deputy of this shared vault: one
    /// durable held act and an inbox ask to each other live Owner, Admin and
    /// Deputy; nothing else changes. The same act held again by the same
    /// admin while it waits answers that act.
    pub(crate) fn hold_admin_act(
        &self,
        first_admin: EntityId,
        verb: &str,
        input: serde_json::Value,
    ) -> Result<HeldAdminAct> {
        let input_digest = digest(&input)?;
        let mut txn = self.store.env.write_txn()?;
        let vault_id = self
            .shared_vault_creation_in_txn(&txn)?
            .ok_or_else(invalid)?
            .vault_id;
        check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        if !holders.iter().any(|holder| {
            holder.member == first_admin && matches!(holder.role, Role::Admin | Role::Deputy)
        }) {
            return Err(invalid());
        }
        let first_hex = first_admin.to_hex();
        if let Some((_, open)) =
            HELD_ADMIN_ACT
                .scan(&self.store, &txn)?
                .into_iter()
                .find(|(_, act)| {
                    act.vault_id == vault_id
                        && act.status == HeldAdminActStatus::Open
                        && act.first_admin == first_hex
                        && act.verb == verb
                        && act.input_digest == input_digest
                        && now < act.lapses_at
                })
        {
            return Ok(open);
        }
        let lapse = ORG_TWO_ADMIN_LAPSE_SECS
            .read_in_txn(self, &txn, &[], None)?
            .value;
        let id = self.store.clock.entity_id()?;
        let act = HeldAdminAct {
            id: id.to_hex(),
            vault_id,
            verb: verb.to_owned(),
            input,
            input_digest,
            first_admin: first_hex,
            held_at: now,
            lapses_at: now.saturating_add(lapse),
            status: HeldAdminActStatus::Open,
            closed_at: None,
        };
        HELD_ADMIN_ACT.put(&self.store, &mut txn, &id, &act)?;
        let recipients: std::collections::BTreeSet<EntityId> = holders
            .iter()
            .filter(|holder| is_admin_role(holder.role) && holder.member != first_admin)
            .map(|holder| holder.member)
            .collect();
        for recipient in recipients {
            self.record_notification_in_txn(
                &mut txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_ADMIN_ACT_HELD.to_owned(),
                        event: format!("{}:{}", act.id, recipient.to_hex()),
                        result: Some(act.id.clone()),
                        detail: Some(format!(
                            "{} by {} waits for a second admin's approve",
                            act.verb, act.first_admin
                        )),
                        ..NotificationSource::default()
                    },
                    subject_refs: vec![first_admin],
                    recipient: Some(recipient),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        txn.commit()?;
        Ok(act)
    }

    /// A second, distinct live Owner, Admin or Deputy of shared vault
    /// `vault_id` approves open held act `held` before it lapses: the act
    /// stands as theirs to run, and the answer is the approval their re-run
    /// of its verb runs under ([`run_approved_admin_act`]). The caller then
    /// settles it ([`Self::settle_held_admin_act`]).
    pub(crate) fn claim_held_admin_act(
        &self,
        approver: &AuthenticatedOwner,
        vault_id: u64,
        held: &str,
    ) -> Result<(HeldAdminAct, HeldAdminApproval)> {
        let id = EntityId::from_hex(held)?;
        let mut txn = self.store.env.write_txn()?;
        let approver = approver.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let mut act = HELD_ADMIN_ACT
            .get(&self.store, &txn, &id)?
            .ok_or_else(invalid)?;
        let first_admin = EntityId::from_hex(&act.first_admin)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        if act.vault_id != vault_id
            || act.status != HeldAdminActStatus::Open
            || now >= act.lapses_at
            || approver == first_admin
            || !holders
                .iter()
                .any(|holder| holder.member == approver && is_admin_role(holder.role))
        {
            return Err(invalid());
        }
        act.status = HeldAdminActStatus::Approving {
            approver: approver.to_hex(),
        };
        HELD_ADMIN_ACT.put(&self.store, &mut txn, &id, &act)?;
        txn.commit()?;
        Ok((
            act,
            HeldAdminApproval {
                vault_id,
                held: id,
                first_admin,
                approver,
            },
        ))
    }

    /// Settles the approved act `approval` names after its re-run: landed
    /// when the re-run ran, open again when it refused.
    pub(crate) fn settle_held_admin_act(
        &self,
        approval: HeldAdminApproval,
        landed: bool,
    ) -> Result<HeldAdminAct> {
        let mut txn = self.store.env.write_txn()?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let mut act = HELD_ADMIN_ACT
            .get(&self.store, &txn, &approval.held)?
            .ok_or_else(invalid)?;
        let approver = approval.approver.to_hex();
        if act.status
            != (HeldAdminActStatus::Approving {
                approver: approver.clone(),
            })
        {
            return Err(invalid());
        }
        if landed {
            act.status = HeldAdminActStatus::Landed { approver };
            act.closed_at = Some(now);
        } else {
            act.status = HeldAdminActStatus::Open;
        }
        HELD_ADMIN_ACT.put(&self.store, &mut txn, &approval.held, &act)?;
        txn.commit()?;
        Ok(act)
    }

    /// The first admin of open held act `held` in shared vault `vault_id`
    /// takes it back; it lands no more.
    pub fn withdraw_held_admin_act(
        &self,
        first_admin: &AuthenticatedOwner,
        vault_id: u64,
        held: &str,
    ) -> Result<HeldAdminAct> {
        let id = EntityId::from_hex(held)?;
        let mut txn = self.store.env.write_txn()?;
        let actor = first_admin.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let mut act = HELD_ADMIN_ACT
            .get(&self.store, &txn, &id)?
            .ok_or_else(invalid)?;
        if act.vault_id != vault_id
            || act.status != HeldAdminActStatus::Open
            || act.first_admin != actor.to_hex()
        {
            return Err(invalid());
        }
        act.status = HeldAdminActStatus::Withdrawn;
        act.closed_at = Some(now);
        HELD_ADMIN_ACT.put(&self.store, &mut txn, &id, &act)?;
        txn.commit()?;
        Ok(act)
    }

    /// Every held act of shared vault `vault_id`, for a reader who is a live
    /// Owner, Admin or Deputy there: the people the rule asks.
    pub fn held_admin_acts(
        &self,
        reader: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<HeldAdminAct>> {
        let txn = self.store.env.read_txn()?;
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let holders = self.live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?;
        if !holders
            .iter()
            .any(|holder| holder.member == reader && is_admin_role(holder.role))
        {
            return Err(invalid());
        }
        Ok(HELD_ADMIN_ACT
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, act)| act)
            .filter(|act| act.vault_id == vault_id)
            .collect())
    }

    /// The housekeeping pass's lapse (run from
    /// [`Self::notify_matured_shared_acts`]): each open held act past its
    /// `lapses_at` on the store clock is marked lapsed, and its first admin
    /// gets one inbox notice. A read pass goes first, so a vault with none
    /// due opens no writer. Answers the number of acts it lapsed.
    pub(crate) fn lapse_held_admin_acts(&self) -> Result<usize> {
        let due = |act: &HeldAdminAct, now: u64| {
            act.status == HeldAdminActStatus::Open && act.lapses_at <= now
        };
        {
            let txn = self.store.env.read_txn()?;
            let now = self.store.clock.now_recorded_at();
            if !HELD_ADMIN_ACT
                .scan(&self.store, &txn)?
                .iter()
                .any(|(_, act)| due(act, now))
            {
                return Ok(0);
            }
        }
        let mut txn = self.store.env.write_txn()?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let mut lapsed = 0;
        for (id, mut act) in HELD_ADMIN_ACT.scan(&self.store, &txn)? {
            if !due(&act, now) {
                continue;
            }
            act.status = HeldAdminActStatus::Lapsed;
            act.closed_at = Some(now);
            HELD_ADMIN_ACT.put(&self.store, &mut txn, &id, &act)?;
            let first_admin = EntityId::from_hex(&act.first_admin)?;
            self.record_notification_in_txn(
                &mut txn,
                &NotificationEvent {
                    kind: NotificationKind::EventReceived,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_ADMIN_ACT_LAPSED.to_owned(),
                        event: format!("{}:{}", act.id, act.first_admin),
                        result: Some(act.id.clone()),
                        detail: Some(format!(
                            "Your {} in shared vault {} lapsed: no second admin approved it in time, \
                             so it did not run.",
                            act.verb, act.vault_id
                        )),
                        ..NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient: Some(first_admin),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
            lapsed += 1;
        }
        txn.commit()?;
        Ok(lapsed)
    }

    /// The held-act table's actor scrub: a hard erase of `actor` deletes
    /// every held act that names it, as its first admin, as its approver, or
    /// in its input, open or closed. A deleted act can be neither approved
    /// nor withdrawn, so no held act outlives the person it names.
    pub(crate) fn erase_held_admin_act_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, txn, actor)? {
            return Ok(());
        }
        let written = actor.to_hex();
        let names = |hex: &str| {
            hex.eq_ignore_ascii_case(&written)
                || EntityId::from_hex(hex).is_ok_and(|named| named == *actor)
        };
        for (id, act) in HELD_ADMIN_ACT.scan(&self.store, txn)? {
            let approver = match &act.status {
                HeldAdminActStatus::Approving { approver }
                | HeldAdminActStatus::Landed { approver } => names(approver),
                HeldAdminActStatus::Open
                | HeldAdminActStatus::Withdrawn
                | HeldAdminActStatus::Lapsed => false,
            };
            let in_input = act
                .input
                .to_string()
                .to_ascii_lowercase()
                .contains(&written);
            if names(&act.first_admin) || approver || in_input {
                HELD_ADMIN_ACT.delete(&self.store, txn, &id)?;
            }
        }
        Ok(())
    }
}
