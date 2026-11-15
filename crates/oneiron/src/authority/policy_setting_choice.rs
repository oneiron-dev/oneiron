//! Folds every signed act on a vault setting (FIX 4624, FIX 5660): the
//! owner's catalogue settings and the settings whose own doors still sign
//! (the dreamer wake policy, inference defaults, room-thread admin switches,
//! ...), and each agent's free-time policy, set by the owner or by an agent
//! whose Grant names it.
//!
//! The setting itself is a local row of the install that changed it; the
//! signed act is the account every machine the owner admits folds and
//! checks. The acts keep the shared owner-choice register
//! ([`super::owner_choice`]) under their own revision domain
//! ([`POLICY_SETTING_REVISION_CONTEXT`]), one frontier per target (a
//! vault-wide setting's reserved target, or the agent a free-time policy is
//! for), each act's choice the digest of the value it left (none for a
//! clear). An act supersedes exactly its target's live acts its parents
//! carry, which its `seen` must name, or it is no valid entry. A carrier the
//! one rule did not admit, or an owner the parents hold removed, leaves the
//! act valid and without effect. An agent's act is the free-time policy's
//! alone (the record's shape); its Grant row is no authority-log row, so the
//! fold keeps the act's agent and Grant, and a view holds it back where this
//! install holds that Grant refused, trusting the carrier where it holds
//! none (contract §4, [`super::carried_act`]).
//!
//! The doors ([`Vault::record_policy_setting_op_in_txn`]) sign the act in
//! the setting's own write, best effort ([`super::carried_act`]): the
//! setting primitive's `set_setting` for an owner's change that names its
//! act surface, and each older setting's own door.
//!
//! The act is the write (stage 7a-2): an owner's change of a row that
//! travels names its row and carries its value, and its door appends it in
//! the change's own write or refuses the change
//! ([`Vault::append_setting_slot_act_in_txn`]). Each row then has a frontier
//! of its own, and the setting projection reads it back with the heads' ops
//! ([`Vault::setting_slot_fold_in_txn`]).
//!
//! A batch is one act (stage 7a-3): one entry lists several rows, each on its
//! own target with its own `seen`, under one decider. It lands once per row,
//! on that row's frontier, and in all of them or none: a `seen` that is wrong
//! on any row makes the entry invalid. A refused or held-back batch is so in
//! every row, since both sets are keyed by the entry's hash.
//!
//! A move's carried rows are one copy (stage 7a-4): one `SettingCopy`
//! entry, signed by the mover's install key alone, lists each carried row
//! with the acts it copies. Each row lands on its own target's frontier as
//! the setting acts do, as an engine statement: its carrier must be admitted
//! and its `seen` right, and no owner is tested, since none decided it. Its
//! choice is the entry's own hash, so two copies on one row always differ
//! and the projection meets them. A row must name every live act it
//! replaces, or the entry is invalid, as for a wrong `seen`: a copy adds
//! bounds and never drops one. The projection reads what it names
//! ([`Vault::setting_slot_head_in_txn`]).

use std::collections::{BTreeMap, BTreeSet};

use oneiron_setting_contract::RowKey;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    ChoiceAt, FoldedOwnerChoice, OwnerChoiceOp, OwnerChoiceState, choice_landing,
    folded_owner_choices, owner_choice_landing, refused_owner_choices,
};
use super::*;

/// Every setting's acts in one fold state, each keyed by its target.
pub(super) type PolicySettingChoiceState = OwnerChoiceState<[u8; 32]>;

/// Every setting's folded acts.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedPolicySettings {
    /// Each target's acts, keyed by the target; a target no act names has no
    /// entry.
    pub(crate) targets: BTreeMap<EntityId, FoldedOwnerChoice<[u8; 32]>>,
    /// Well-signed acts without effect: their carrier was not admitted, or
    /// their owner not live, at their parents.
    pub(crate) refused: BTreeSet<AuthorityEntryHash>,
}

impl FoldedPolicySettings {
    /// Whether no setting act folded: a projection an image need not carry.
    pub(super) fn is_empty(&self) -> bool {
        self.targets.is_empty() && self.refused.is_empty()
    }

    /// Whether any target's live act rests on how this install counts
    /// machines.
    pub(super) fn rests_on_counting(&self) -> bool {
        self.targets.values().any(|folded| !folded.live.is_empty())
    }

    /// `target`'s revision: what the next act on it names as `seen`, zero
    /// while no act names it.
    pub(crate) fn revision(&self, target: EntityId) -> [u8; 32] {
        self.targets.get(&target).map_or([0; 32], |folded| {
            folded.revision(POLICY_SETTING_REVISION_CONTEXT)
        })
    }

    /// The live acts `machine` carried, for its next profile revision's
    /// acknowledged set ([`super::world_privacy::live_edits_by`]).
    pub(super) fn live_choices_by(
        &self,
        machine: EntityId,
    ) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
        self.targets
            .values()
            .flat_map(move |folded| super::owner_choice::live_choices_by(folded, machine))
    }
}

/// The `PolicySettingSet` transition ([`owner_choice_landing`]), under its
/// own revision domain, on its target's frontier, and for a batch on each
/// row's (stage 7a-3): every row is judged against the state before the
/// entry, and only then do they all land.
pub(super) fn apply_policy_setting(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    set: &PolicySettingSet,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let acts = set
        .row_acts()
        .map_err(|_| AuthorityFoldIssue::InvalidEntry(hash))?;
    let mut landings = Vec::with_capacity(acts.len());
    for (act, value) in &acts {
        let op = OwnerChoiceOp {
            act,
            machine: set.machine,
            choice: value.as_ref(),
            context: POLICY_SETTING_REVISION_CONTEXT,
        };
        landings.push(owner_choice_landing(
            state,
            &state.policy_settings,
            entry,
            op,
            hash,
            counting,
            restriction_only,
        )?);
    }
    for landing in landings {
        state.policy_settings.land(landing);
    }
    if let Some(agent) = super::carried_act::AgentCarriedAct::of(&set.act, entry.ts) {
        state.agent_carried_acts.insert(hash, agent);
    }
    Ok(())
}

/// The `SettingCopy` transition (stage 7a-4; module doc): each carried row
/// lands on its target's frontier as an engine statement
/// ([`choice_landing`] with no owner), its choice the entry's own hash. A row
/// that leaves out a live act of its target, which it would replace, makes
/// the entry invalid. Every row is judged against the state before the
/// entry, and only then do they all land.
pub(super) fn apply_setting_copy(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    copy: &SettingCopy,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let mut landings = Vec::with_capacity(copy.rows.len());
    for row in &copy.rows {
        let target = row
            .target()
            .map_err(|_| AuthorityFoldIssue::InvalidEntry(hash))?;
        let named: BTreeSet<AuthorityEntryHash> = row
            .names
            .iter()
            .filter(|name| name.slot == row.slot)
            .map(|name| name.act)
            .collect();
        if state
            .policy_settings
            .live_choices(target)
            .any(|live| !named.contains(&live))
        {
            return Err(AuthorityFoldIssue::InvalidEntry(hash));
        }
        let at = ChoiceAt {
            target,
            seen: row.seen,
            owner: None,
            machine: copy.machine,
            choice: Some(&hash),
            context: POLICY_SETTING_REVISION_CONTEXT,
        };
        landings.push(choice_landing(
            state,
            &state.policy_settings,
            entry,
            at,
            hash,
            counting,
            restriction_only,
        )?);
    }
    for landing in landings {
        state.policy_settings.land(landing);
    }
    Ok(())
}

/// The fold's view of every setting's acts, under this install's pin and
/// holds.
pub(super) fn folded_policy_settings(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedPolicySettings {
    FoldedPolicySettings {
        targets: folded_owner_choices(state, &state.policy_settings, pin, counted),
        refused: refused_owner_choices(&state.policy_settings).clone(),
    }
}

/// One act on a setting as its door passes it: everything its signed record
/// carries but the carrier, which the signing install names.
pub(crate) struct PolicySettingAct {
    /// The act, its `seen` read by [`Vault::policy_setting_revision_in_txn`]
    /// in the same write.
    pub(crate) act: OwnerAct,
    /// The setting's wire name: a catalogue key's name, or a
    /// [`PolicySetting`]'s [`PolicySetting::wire`] text.
    pub(crate) setting: String,
    /// BLAKE3 over the value the act replaced, as JSON.
    pub(crate) prior: [u8; 32],
    /// BLAKE3 over the value it left, as JSON; `None` for a clear.
    pub(crate) value: Option<[u8; 32]>,
}

impl Vault {
    /// `target`'s setting revision in `txn`: the `seen` an act on it names.
    pub(crate) fn policy_setting_revision_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
    ) -> Result<[u8; 32]> {
        Ok(self
            .authority_view_readonly_in_txn(txn)?
            .policy_settings
            .revision(target))
    }

    /// Records `act` as a signed `PolicySettingSet` in the write `txn` that
    /// changed the setting, best effort ([`super::carried_act`]): the
    /// setting and the door's own record stand whatever this meets.
    pub(crate) fn record_policy_setting_op_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: PolicySettingAct,
    ) -> Option<AuthorityEntryHash> {
        let PolicySettingAct {
            act,
            setting,
            prior,
            value,
        } = act;
        self.record_carried_act_in_txn(txn, "policy setting", |machine| {
            AuthorityOp::PolicySettingSet(PolicySettingSet {
                act,
                machine,
                setting,
                prior,
                value,
                slot: None,
                inline: None,
                more: Vec::new(),
            })
        })
    }

    /// Appends `act`, an owner's change of setting rows that travel, as one
    /// signed `PolicySettingSet` in the change's write `txn` (stage 7a-2; a
    /// batch of rows stage 7a-3): each row named by its slot, with its value
    /// inline and the `seen` of its own target, read in `txn`. Not best
    /// effort: the act is the write, so whatever stops it (no live machine
    /// profile to carry it, a fold that does not count it, a storage fault)
    /// fails the change, and the savepoint it ran in is rolled back with it.
    /// The entry's hash.
    ///
    /// # Errors
    ///
    /// The typed refusal of the act's append ([`super::carried_act`]), an act
    /// with no row, or a storage error.
    pub(crate) fn append_setting_slot_act_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: SettingSlotAct,
    ) -> Result<AuthorityEntryHash> {
        let SettingSlotAct {
            owner,
            surface,
            rows,
        } = act;
        let rows = {
            let view = self.authority_view_readonly_in_txn(txn)?;
            rows.into_iter()
                .map(|row| {
                    let seen = view
                        .policy_settings
                        .revision(setting_slot_target(&row.slot)?);
                    slot_row(row.slot, seen, row.prior, row.inline)
                })
                .collect::<Result<Vec<_>>>()?
        };
        let carried_by = setting_act_of((owner, surface), rows)?;
        self.append_carried_act_in_savepoint(txn, |machine| {
            AuthorityOp::PolicySettingSet(carried_by(machine))
        })
    }

    /// Whether the fold in `txn` holds the setting act `hash` valid and
    /// without effect: its carrier was not admitted, or its owner not live,
    /// at its parents.
    pub(crate) fn policy_setting_act_refused_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        hash: AuthorityEntryHash,
    ) -> Result<bool> {
        Ok(self
            .authority_view_readonly_in_txn(txn)?
            .policy_settings
            .refused
            .contains(&hash))
    }

    /// Whether this install can carry an owner's act in `txn`: it has a
    /// machine identity and install key, and a live profile of it stands
    /// under that key ([`super::carried_act`]).
    pub(crate) fn can_carry_owner_act_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        self.owner_act_carrier_in_txn(txn, &fold)
            .map(|carrier| carrier.is_some())
    }

    /// Appends a move's carried rows as one signed `SettingCopy` in the
    /// mover's write `txn` (stage 7a-4): each carried row with the acts it
    /// copies, and the `seen` of its own target, read in `txn`. Not best
    /// effort here: whatever stops it fails the call, and its savepoint is
    /// rolled back; the carry keeps its rows on this install whatever this
    /// meets. The entry's hash.
    ///
    /// # Errors
    ///
    /// The typed refusal of the append ([`super::carried_act`]), or a
    /// storage error.
    pub(crate) fn append_setting_copy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        rows: Vec<(RowKey, Vec<SettingCopyName>)>,
    ) -> Result<AuthorityEntryHash> {
        let rows = {
            let view = self.authority_view_readonly_in_txn(txn)?;
            rows.into_iter()
                .map(|(slot, names)| {
                    Ok(SettingCopyRow {
                        seen: view.policy_settings.revision(setting_slot_target(&slot)?),
                        slot,
                        names,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };
        self.append_carried_act_in_savepoint(txn, |machine| {
            AuthorityOp::SettingCopy(SettingCopy { machine, rows })
        })
    }

    /// `target`'s live setting acts in `txn`, a copy among them: what a copy
    /// of its row names (stage 7a-4). Empty when no act names the target.
    pub(crate) fn setting_slot_live_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
    ) -> Result<Vec<AuthorityEntryHash>> {
        Ok(self
            .authority_view_readonly_in_txn(txn)?
            .policy_settings
            .targets
            .get(&target)
            .map(|folded| folded.live.keys().copied().collect())
            .unwrap_or_default())
    }

    /// Every setting target the fold names in `txn`, each with its
    /// revision: what the setting projection compares with the revision it
    /// last projected (stage 7a-2).
    pub(crate) fn policy_setting_revisions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<(EntityId, [u8; 32])>> {
        Ok(self
            .authority_view_readonly_in_txn(txn)?
            .policy_settings
            .targets
            .iter()
            .map(|(target, folded)| (*target, folded.revision(POLICY_SETTING_REVISION_CONTEXT)))
            .collect())
    }

    /// `target`'s acts as the setting projection reads them (stage 7a-2):
    /// its revision, each live head with its op read back from the log, and,
    /// when the heads conflict, the last act every one of them descends from.
    /// `None` when no act names the target.
    pub(crate) fn setting_slot_fold_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
    ) -> Result<Option<SettingSlotFold>> {
        let view = self.authority_view_readonly_in_txn(txn)?;
        let Some(folded) = view.policy_settings.targets.get(&target) else {
            return Ok(None);
        };
        let live = folded
            .live
            .keys()
            .map(|hash| self.setting_slot_head_in_txn(txn, target, *hash))
            .collect::<Result<Vec<_>>>()?;
        let conflict = !folded.conflict.is_empty();
        let in_force = match (&folded.in_force, conflict) {
            (Some(head), true) => Some(self.setting_slot_head_in_txn(txn, target, head.act)?),
            _ => None,
        };
        Ok(Some(SettingSlotFold {
            revision: folded.revision(POLICY_SETTING_REVISION_CONTEXT),
            live,
            in_force,
            conflict,
        }))
    }

    /// The setting act `hash` names, read back from the log in `txn`, as it
    /// bears on `target` (a batch's row on it, stage 7a-3; a copy's row on
    /// it, stage 7a-4).
    pub(crate) fn setting_slot_head_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
        hash: AuthorityEntryHash,
    ) -> Result<SettingSlotHead> {
        let mut head = SettingSlotHead {
            act: hash,
            set: None,
            copy: None,
        };
        let id = authority_log_entity_id_from_hash(&hash)?;
        let Some(raw) = self
            .store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
        else {
            return Ok(head);
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(crate::error::Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Ok(head);
        }
        let entry = super::readonly_fold::decode_stored_authority_log_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?;
        if authority_entry_hash(&entry)? != hash {
            return Ok(head);
        }
        match &entry.op {
            AuthorityOp::PolicySettingSet(set) => head.set = set.on_target(target)?,
            AuthorityOp::SettingCopy(copy) => head.copy = copy.on_target(target)?.cloned(),
            _ => {}
        }
        Ok(head)
    }
}

/// An owner's change of setting rows that travel, as its door passes it
/// (stage 7a-2; several rows stage 7a-3): everything its signed record
/// carries but the carrier, each row's target and `seen`, and the values'
/// digests, which follow from the signing install, the slots, the fold in the
/// write and `inline`.
pub(crate) struct SettingSlotAct {
    /// The owner who decided.
    pub(crate) owner: EntityId,
    /// Where his say-so reached this install.
    pub(crate) surface: ActSurface,
    /// The rows, at least one, no two on one slot.
    pub(crate) rows: Vec<SettingSlotRow>,
}

/// One row of a [`SettingSlotAct`].
pub(crate) struct SettingSlotRow {
    /// The row.
    pub(crate) slot: RowKey,
    /// BLAKE3 over the value the act replaced, as JSON.
    pub(crate) prior: [u8; 32],
    /// The value it left, as its JSON bytes; `None` for a clear.
    pub(crate) inline: Option<Vec<u8>>,
}

/// The row `slot` of an act, on `seen`: no slot for the key's vault value row
/// (the target every act on it has named since stage 7a-1), and the value's
/// digest from its inline bytes.
fn slot_row(
    slot: RowKey,
    seen: [u8; 32],
    prior: [u8; 32],
    inline: Option<Vec<u8>>,
) -> Result<PolicySettingRow> {
    let vault_row = setting_slot_target(&slot)? == policy_setting_target(&slot.name)?;
    Ok(PolicySettingRow {
        setting: slot.name.clone(),
        slot: (!vault_row).then_some(slot),
        seen,
        prior,
        value: inline.as_deref().map(setting_value_digest),
        inline,
    })
}

/// The owner's act on `rows`, given its carrier: the first row is the op's
/// own, on the act's target and `seen`, and the rest are its `more` (stage
/// 7a-3).
fn setting_act_of(
    (owner, surface): (EntityId, ActSurface),
    mut rows: Vec<PolicySettingRow>,
) -> Result<impl FnOnce(EntityId) -> PolicySettingSet> {
    if rows.is_empty() {
        return Err(crate::error::Error::InvariantViolation(
            "a setting act names at least one row",
        ));
    }
    let first = rows.remove(0);
    let act = OwnerAct::by_owner(
        owner,
        OwnerActKind::PolicySetting,
        first.target()?,
        surface,
        first.seen,
    );
    Ok(move |machine| PolicySettingSet {
        act,
        machine,
        setting: first.setting,
        prior: first.prior,
        value: first.value,
        slot: first.slot,
        inline: first.inline,
        more: rows,
    })
}

/// One setting row's acts, as the setting projection reads them (stage
/// 7a-2).
pub(crate) struct SettingSlotFold {
    /// The target's revision: the basis a projection of it records.
    pub(crate) revision: [u8; 32],
    /// Each live head.
    pub(crate) live: Vec<SettingSlotHead>,
    /// When the heads conflict, the last act every one of them descends
    /// from; `None` when they agree or no such act exists.
    pub(crate) in_force: Option<SettingSlotHead>,
    /// Whether the live heads left different values.
    pub(crate) conflict: bool,
}

/// One setting act the projection reads: its hash, and its op when the
/// log here holds it.
pub(crate) struct SettingSlotHead {
    pub(crate) act: AuthorityEntryHash,
    /// `None` where the entry is not stored here (an adopted image covers
    /// it) or is not a setting act.
    pub(crate) set: Option<PolicySettingSet>,
    /// The copy's row on the target where the entry is a move's setting copy
    /// (stage 7a-4); `None` otherwise.
    pub(crate) copy: Option<SettingCopyRow>,
}

/// Where some rows' acts stood when a test read them (stage 7a-2 tests; several rows 7a-3): the
/// main-log heads and the rows' live acts, and each row's revision by its target. An act signed
/// on it later is concurrent with every act appended since.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) struct SettingFrontier {
    parents: BTreeSet<AuthorityEntryHash>,
    seen: BTreeMap<EntityId, [u8; 32]>,
}

#[cfg(all(oneiron_test_support, feature = "test-support"))]
impl SettingFrontier {
    /// The revision `slot`'s target had when the frontier read it; zero for a row it did not.
    fn seen_of(&self, slot: &RowKey) -> Result<[u8; 32]> {
        Ok(self
            .seen
            .get(&setting_slot_target(slot)?)
            .copied()
            .unwrap_or([0; 32]))
    }
}

#[cfg(all(oneiron_test_support, feature = "test-support"))]
impl Vault {
    /// The frontier of the rows `slots`' acts now.
    pub(crate) fn setting_frontier(&self, slots: &[RowKey]) -> Result<SettingFrontier> {
        let fold = self.authority_fold()?;
        let mut parents = fold.append_heads.clone();
        let mut seen = BTreeMap::new();
        for slot in slots {
            let target = setting_slot_target(slot)?;
            if let Some(folded) = fold.policy_settings.targets.get(&target) {
                parents.extend(folded.live.keys().copied());
            }
            seen.insert(target, fold.policy_settings.revision(target));
        }
        Ok(SettingFrontier { parents, seen })
    }

    /// The owner `owner`'s change of each row of `rows` to its JSON bytes (`None` clears), as
    /// the machine `machine`'s own door signs it with its install key `key`, on `frontier`, at
    /// `ts`: one act that names its rows and carries their values (a batch for more than one
    /// row, stage 7a-3). A row `frontier` did not read names `seen` zero.
    pub(crate) fn sign_setting_act_as(
        &self,
        (machine, key): (EntityId, &ed25519_dalek::SigningKey),
        owner: EntityId,
        frontier: &SettingFrontier,
        rows: Vec<(RowKey, Option<Vec<u8>>)>,
        ts: u64,
    ) -> Result<AuthorityLogEntry> {
        let rows = rows
            .into_iter()
            .map(|(slot, inline)| {
                let seen = frontier.seen_of(&slot)?;
                slot_row(slot, seen, setting_value_digest(b"null"), inline)
            })
            .collect::<Result<Vec<_>>>()?;
        let op = AuthorityOp::PolicySettingSet(setting_act_of(
            (owner, ActSurface::ThisInstall),
            rows,
        )?(machine));
        self.sign_on_frontier_as(key, frontier, op, ts)
    }

    /// A move's copy of each carried row of `rows`, naming its acts, as the machine `machine`'s
    /// own carry signs it with its install key `key`, on `frontier`, at `ts` (stage 7a-4 tests).
    /// A row `frontier` did not read names `seen` zero.
    pub(crate) fn sign_setting_copy_as(
        &self,
        (machine, key): (EntityId, &ed25519_dalek::SigningKey),
        frontier: &SettingFrontier,
        rows: Vec<(RowKey, Vec<SettingCopyName>)>,
        ts: u64,
    ) -> Result<AuthorityLogEntry> {
        let rows = rows
            .into_iter()
            .map(|(slot, names)| {
                Ok(SettingCopyRow {
                    seen: frontier.seen_of(&slot)?,
                    slot,
                    names,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let op = AuthorityOp::SettingCopy(SettingCopy { machine, rows });
        self.sign_on_frontier_as(key, frontier, op, ts)
    }

    /// `op` signed with the install key `key` on `frontier`'s parents at `ts`, at the key's next
    /// sequence.
    fn sign_on_frontier_as(
        &self,
        key: &ed25519_dalek::SigningKey,
        frontier: &SettingFrontier,
        op: AuthorityOp,
        ts: u64,
    ) -> Result<AuthorityLogEntry> {
        use ed25519_dalek::Signer;

        let fold = self.authority_fold()?;
        let signer = AuthorityKey::Ed25519(key.verifying_key().to_bytes());
        let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: fold.vault_id,
            seq,
            parent_hashes: frontier.parents.iter().copied().collect(),
            op,
            signer: AuthoritySignature {
                suite: signer.suite(),
                public_key: signer,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts,
        };
        let transcript = authority_transcript(&entry)?;
        entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
        Ok(entry)
    }
}
