//! Folds every signed act on a vault setting (FIX 4624, FIX 5660): the
//! owner's dreamer wake policy, inference defaults and room-thread admin
//! switches, and each agent's free-time policy, set by the owner or by an
//! agent whose Grant names it.
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
//! the setting's own write, best effort ([`super::carried_act`]).
//!
//! One setting is the fold's own to read: web sign-in
//! ([`PolicySetting::WebSignIn`], the owner's ruling AUTH-5). No install
//! keeps a row of it. Its act is the switch back when its value is the one
//! over the owner keys its parents hold
//! ([`super::owner_proof::web_sign_in_switch`]): it then counts only with an
//! owner key's proof and is kept under that value. An act of the setting
//! with any other value asks for an owner key again and is kept as a clear,
//! so no value a carrier picked stays in the register to speak for keys
//! enrolled later. The register keys an act by its target alone and a
//! free-time policy act names any target, so an act of another setting that
//! names the web sign-in target is valid and without effect there.
//!
//! A second setting is the fold's own: the recovery box's kit-only switch
//! ([`PolicySetting::RecoveryBoxKitOnly`], WAYBACK-BOX-HOLD-FROM-DEVICE-SWITCH
//! = A), which the owner's device signs in its preset write for the managed
//! node that holds the box. It speaks for the owner's way back, so its act
//! counts only with an owner key's proof, whoever carries it, and an act of
//! another setting that names its target is without effect there too.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    FoldedOwnerChoice, OwnerChoiceLanding, OwnerChoiceOp, OwnerChoiceState, folded_owner_choices,
    owner_choice_landing, refused_owner_choices,
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
    /// their owner not live, at their parents; and each act of another
    /// setting that named the web sign-in or the kit-only setting's target.
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
    // The web sign-in and kit-only frontiers are judged by their target,
    // whatever setting an act on them names: the register keys an act by its
    // target alone.
    let on_web_sign_in = super::owner_proof::is_web_sign_in_target(set.act.target);
    let web_sign_in = on_web_sign_in && set.setting == PolicySetting::WebSignIn;
    let on_kit_only = is_recovery_box_kit_only_target(set.act.target);
    let kit_only = on_kit_only && set.setting == PolicySetting::RecoveryBoxKitOnly;
    let switches_back = web_sign_in
        && set.value.is_some()
        && set.value == super::owner_proof::web_sign_in_switch(state);
    let op = OwnerChoiceOp {
        act: &set.act,
        machine: set.machine,
        choice: if on_web_sign_in && !switches_back {
            None
        } else {
            set.value.as_ref()
        },
        context: POLICY_SETTING_REVISION_CONTEXT,
        persons_own_narrowing: false,
        owner_key_only: switches_back || on_kit_only,
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
    // Another setting's act on the web sign-in or kit-only target lands
    // nothing there.
    let landing = match landing {
        OwnerChoiceLanding::Recorded { hash, .. } | OwnerChoiceLanding::Waiting { hash, .. }
            if (on_web_sign_in && !web_sign_in) || (on_kit_only && !kit_only) =>
        {
            OwnerChoiceLanding::Refused(hash)
        }
        landing => landing,
    };
    // A waiting act is no agent's act in force: the owner's confirm is his
    // own act (row CARRIER-OWNER-PROOF).
    let waits = matches!(landing, OwnerChoiceLanding::Waiting { .. });
    state.policy_settings.land(landing);
    if !waits && let Some(agent) = super::carried_act::AgentCarriedAct::of(&set.act, entry.ts) {
        state.agent_carried_acts.insert(hash, agent);
    }
    Ok(())
}

/// Whether `target` is the recovery box kit-only setting's reserved target.
fn is_recovery_box_kit_only_target(target: EntityId) -> bool {
    matches!(
        PolicySetting::RecoveryBoxKitOnly.reserved_target(),
        Ok(Some(reserved)) if reserved == target
    )
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
    pub(crate) setting: PolicySetting,
    /// BLAKE3 over the value the act replaced, as JSON.
    pub(crate) prior: [u8; 32],
    /// BLAKE3 over the value it left, as JSON; `None` for a clear.
    pub(crate) value: Option<[u8; 32]>,
}

impl Vault {
    /// Signs, appends and folds `act` as a `PolicySettingSet` in `txn`, the
    /// write that made the choice, and fails that write when it cannot: for a
    /// setting the fold reads with no row of its own, where the signed act is
    /// the setting itself. The entry hash once the fold in `txn` counted it
    /// as a valid entry; whether it landed or waits for an owner key's proof
    /// is the caller's to read.
    ///
    /// # Errors
    /// No live machine profile of this install to carry the act, more heads
    /// than one entry may name, a fold that did not count it, and storage
    /// errors.
    pub(crate) fn append_policy_setting_op_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: PolicySettingAct,
    ) -> Result<AuthorityEntryHash> {
        let PolicySettingAct {
            act,
            setting,
            prior,
            value,
        } = act;
        self.append_carried_act_in_txn(txn, |machine| {
            AuthorityOp::PolicySettingSet(PolicySettingSet {
                act,
                machine,
                setting,
                prior,
                value,
            })
        })
    }

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
            })
        })
    }
}
