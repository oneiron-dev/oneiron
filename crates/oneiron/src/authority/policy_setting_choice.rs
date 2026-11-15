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
    FoldedOwnerChoice, OwnerChoiceOp, OwnerChoiceState, folded_owner_choices, owner_choice_landing,
    refused_owner_choices,
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
/// own revision domain, on its target's frontier.
pub(super) fn apply_policy_setting(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    set: &PolicySettingSet,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let op = OwnerChoiceOp {
        act: &set.act,
        machine: set.machine,
        choice: set.value.as_ref(),
        context: POLICY_SETTING_REVISION_CONTEXT,
    };
    let landing = owner_choice_landing(
        state,
        &state.policy_settings,
        entry,
        op,
        hash,
        counting,
        restriction_only,
    )?;
    state.policy_settings.land(landing);
    if let Some(agent) = super::carried_act::AgentCarriedAct::of(&set.act, entry.ts) {
        state.agent_carried_acts.insert(hash, agent);
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
            })
        })
    }

    /// Appends `act`, an owner's change of a setting row that travels, as a
    /// signed `PolicySettingSet` in the change's write `txn` (stage 7a-2):
    /// named by its row, with its value inline. Not best effort: the act is
    /// the write, so whatever stops it (no live machine profile to carry it,
    /// a fold that does not count it, a storage fault) fails the change, and
    /// the savepoint it ran in is rolled back with it. The entry's hash.
    ///
    /// # Errors
    ///
    /// The typed refusal of the act's append ([`super::carried_act`]), or a
    /// storage error.
    pub(crate) fn append_setting_slot_act_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: SettingSlotAct,
    ) -> Result<AuthorityEntryHash> {
        let SettingSlotAct {
            act,
            slot,
            prior,
            inline,
        } = act;
        let value = inline.as_ref().map(|bytes| *blake3::hash(bytes).as_bytes());
        let setting = slot.name.clone();
        let vault_row = setting_slot_target(&slot)? == policy_setting_target(&setting)?;
        self.append_carried_act_in_savepoint(txn, |machine| {
            AuthorityOp::PolicySettingSet(PolicySettingSet {
                act,
                machine,
                setting,
                prior,
                value,
                slot: (!vault_row).then_some(slot),
                inline,
            })
        })
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
            .map(|hash| self.setting_slot_head_in_txn(txn, *hash))
            .collect::<Result<Vec<_>>>()?;
        let conflict = !folded.conflict.is_empty();
        let in_force = match (&folded.in_force, conflict) {
            (Some(head), true) => Some(self.setting_slot_head_in_txn(txn, head.act)?),
            _ => None,
        };
        Ok(Some(SettingSlotFold {
            revision: folded.revision(POLICY_SETTING_REVISION_CONTEXT),
            live,
            in_force,
            conflict,
        }))
    }

    /// The setting act `hash` names, read back from the log in `txn`.
    fn setting_slot_head_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        hash: AuthorityEntryHash,
    ) -> Result<SettingSlotHead> {
        let id = authority_log_entity_id_from_hash(&hash)?;
        let Some(raw) = self
            .store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
        else {
            return Ok(SettingSlotHead {
                act: hash,
                set: None,
            });
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(crate::error::Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Ok(SettingSlotHead {
                act: hash,
                set: None,
            });
        }
        let entry = super::readonly_fold::decode_stored_authority_log_body(
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?;
        let set = match entry.op {
            AuthorityOp::PolicySettingSet(set) if authority_entry_hash(&entry)? == hash => {
                Some(set)
            }
            _ => None,
        };
        Ok(SettingSlotHead { act: hash, set })
    }
}

/// An owner's change of a setting row that travels, as its door passes it
/// (stage 7a-2): everything its signed record carries but the carrier and
/// the value's digest, which follow from the signing install and `inline`.
pub(crate) struct SettingSlotAct {
    /// The act on the row's target ([`setting_slot_target`]), its `seen`
    /// read by [`Vault::policy_setting_revision_in_txn`] in the same write.
    pub(crate) act: OwnerAct,
    /// The row.
    pub(crate) slot: RowKey,
    /// BLAKE3 over the value the act replaced, as JSON.
    pub(crate) prior: [u8; 32],
    /// The value it left, as its JSON bytes; `None` for a clear.
    pub(crate) inline: Option<Vec<u8>>,
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
}

/// Where a row's acts stood when a test read them (stage 7a-2 tests): the main-log heads and
/// the row's live acts, and its revision. An act signed on it later is concurrent with every
/// act appended since.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) struct SettingFrontier {
    parents: BTreeSet<AuthorityEntryHash>,
    seen: [u8; 32],
}

#[cfg(all(oneiron_test_support, feature = "test-support"))]
impl Vault {
    /// The frontier of the row `slot`'s acts now.
    pub(crate) fn setting_frontier(&self, slot: &RowKey) -> Result<SettingFrontier> {
        let fold = self.authority_fold()?;
        let target = setting_slot_target(slot)?;
        let mut parents = fold.append_heads.clone();
        if let Some(folded) = fold.policy_settings.targets.get(&target) {
            parents.extend(folded.live.keys().copied());
        }
        Ok(SettingFrontier {
            parents,
            seen: fold.policy_settings.revision(target),
        })
    }

    /// The owner `owner`'s change of the row `slot` to the JSON bytes `inline` (`None`
    /// clears), as the machine `machine`'s own door signs it with its install key `key`, on
    /// `frontier`, at `ts`: one act that names the row and carries its value.
    pub(crate) fn sign_setting_act_as(
        &self,
        (machine, key): (EntityId, &ed25519_dalek::SigningKey),
        owner: EntityId,
        frontier: &SettingFrontier,
        (slot, inline): (RowKey, Option<Vec<u8>>),
        ts: u64,
    ) -> Result<AuthorityLogEntry> {
        use ed25519_dalek::Signer;

        let fold = self.authority_fold()?;
        let signer = AuthorityKey::Ed25519(key.verifying_key().to_bytes());
        let seq = fold.append_sequences.get(&signer).map_or(1, |seq| seq + 1);
        let target = setting_slot_target(&slot)?;
        let vault_row = target == policy_setting_target(&slot.name)?;
        let op = AuthorityOp::PolicySettingSet(PolicySettingSet {
            act: OwnerAct::by_owner(
                owner,
                OwnerActKind::PolicySetting,
                target,
                ActSurface::ThisInstall,
                frontier.seen,
            ),
            machine,
            setting: slot.name.clone(),
            prior: *blake3::hash(b"null").as_bytes(),
            value: inline.as_ref().map(|bytes| *blake3::hash(bytes).as_bytes()),
            slot: (!vault_row).then_some(slot),
            inline,
        });
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
