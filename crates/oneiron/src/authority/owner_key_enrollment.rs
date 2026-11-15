//! The fold's judge of the owner's enrollment of one of his devices' own
//! owner signing keys (FIX 4920; Engine 10-20 00:5x, rulings B and C).
//!
//! An `OwnerKeyEnroll` entry puts one fresh key on the roster as an owner
//! root of its own (`ROLE_OWNER`, Software tier), revocable like any owner
//! root: a device's Ed25519 key, or a passkey's P-256 key (row
//! WEB-PASSKEY-OWNER-KEY), whose signatures are its WebAuthn assertions. Two signatures carry it, the enrollment's one exception to the
//! owner-act contract's carrier-alone rule (CALLS "FIX 4920 enrollment
//! signatures"):
//! - its primary signer is an existing owner root, live and consenting in the
//!   entry's parents: a root change is signed by an existing root (the
//!   predecessor-authorized handoff). An incoming key never authorizes itself:
//!   the shape check refuses the new key as a signer, and this judge reads the
//!   roster before the key enters it;
//! - its one cosign is the install key of the carrier of the owner's act,
//!   judged by the one carrier rule every owner act shares
//!   ([`super::owner_act_signer_admits`]) and by the owner's liveness at the
//!   act's causal point (`owner_live_at`), both as they stand. The carrier is
//!   no roster key, so it never joins the roster's participants.
//!
//! The key's proof of possession, the act's kind, target and zero `seen`, and
//! the device's one shape are the wire shape check's
//! (`OwnerKeyEnroll::validate_entry`), which runs before this judge.
//!
//! Validity here reads the parents' fold state alone, pin-free and
//! install-free: counting changes no entry's validity (`install_fold`), and a
//! roster key is the same on every replica. A sequence floor still refuses
//! the entry as it refuses any roster-signed row (it never lands restriction
//! only). A carrier removed later does not unenrol the key: the owner revokes
//! it with an ordinary `RevokeDevice`, as he revokes any owner root. A resumed
//! fold refolds in full past an enrollment (`fold_resume::admits_past` takes
//! none), and a checkpoint image carries its body.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The policy hook of CALLS "FIX 5896 enrolled key custody" (Engine 10-20
/// 08:0x): an owner's enrolled device key starts its own custody line. Its
/// predecessor authorizes it but is not its custody ancestor, so a key a
/// hosted vault's custodial root signed in is still the owner's: the
/// dispatcher upserts it with no admitter edge. `false` is the inherited
/// line, where the predecessor admits it and its custody passes on.
pub(super) const ENROLLED_OWNER_KEY_STARTS_OWN_CUSTODY: bool = true;

/// The `OwnerKeyEnroll` judge, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// participant check. On `Ok` the dispatcher applies the op (`upsert_device`,
/// with no admitter edge from the predecessor under
/// [`ENROLLED_OWNER_KEY_STARTS_OWN_CUSTODY`]: the predecessor's signature is
/// the key's authorization, not its custody) and advances the predecessor's
/// sequence; the carrier's install key keeps its own sequence.
pub(super) fn judge_owner_key_enroll(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    enroll: &OwnerKeyEnroll,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<OwnerKeyEnrollReading, AuthorityFoldIssue> {
    // The owner's own say-so alone: the codec and the shape check refuse an
    // agent's act and an answered ask, and the judge holds the same line.
    if enroll.act.by != ActBy::Owner || enroll.act.answer.is_some() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    // The predecessor: an owner root on the parents' roster, live and
    // consenting under this fold's consent arm (a managed root as its
    // context allows), past its own last sequence. A key only a passkey
    // vouched for vouches for no further key until it is confirmed (lead
    // ruling WEBPASSKEY-BLIND-SIGNATURE = B), unless the owner's choice
    // "Let my passkey remove devices and keys" is on in the parents (Engine
    // ruling WEBPASSKEY-OPTIN-HOME = A).
    let predecessor = entry.signer_key();
    let Some(root) = state.roster.get(predecessor).filter(|root| !root.revoked) else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    if root.roles & ROLE_OWNER == 0
        || !context.device_can_consent(root)
        || (state.passkey_vouch_unconfirmed(predecessor) && !state.passkey_full_owner())
    {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    // A fresh key enrols; a key only a passkey vouched for, vouched for
    // again by a key that may confirm it, is confirmed; anything else is
    // no enrollment.
    let reading = if fresh_owner_key(state, &enroll.device.key) {
        OwnerKeyEnrollReading::Enrolment
    } else if confirms_passkey_vouch(state, &enroll.device.key, predecessor) {
        OwnerKeyEnrollReading::Confirmation
    } else {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    };
    if state
        .seqs
        .get(predecessor)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    // The carrier: its install key is the one cosign, the one carrier rule
    // admits it in the parents, and the owner is live there.
    let Some(carrier_key) = OwnerKeyEnroll::carrier_key(entry) else {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    };
    let carrier = super::machine_claims::folded_machine_in(state, enroll.carrier);
    if !super::owner_act_signer_admits(carrier.as_ref(), &state.roster, carrier_key) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if !super::owner_act::owner_live_at(state, enroll.act.owner) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    // The machine that holds the key: a live machine of the vault.
    if !super::machine_claims::folded_machine_in(state, enroll.machine)
        .as_ref()
        .is_some_and(machine_is_live)
    {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    Ok(reading)
}

/// What a counted `OwnerKeyEnroll` does.
pub(super) enum OwnerKeyEnrollReading {
    /// A fresh key joins the roster.
    Enrolment,
    /// A non-passkey key vouches again for a key only a passkey vouched for,
    /// which then acts in full (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B).
    /// The roster does not change.
    Confirmation,
}

impl FoldState {
    /// Whether `key` is a key only a passkey vouched for, not yet confirmed
    /// (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B): it vouches for no
    /// further key, and [`Self::passkey_limited`] holds for it, while the
    /// owner's choice [`Self::passkey_full_owner`] is off.
    pub(super) fn passkey_vouch_unconfirmed(&self, key: &AuthorityKey) -> bool {
        self.passkey_vouched_keys.contains(key) && !self.passkey_vouch_confirmations.contains(key)
    }

    /// Whether `key` is a passkey or a key only a passkey vouched for, not
    /// yet confirmed: a key the passkey limits reach whenever the owner's
    /// choice [`Self::passkey_full_owner`] is off, read whatever the choice.
    fn passkey_bound(&self, key: &AuthorityKey) -> bool {
        self.passkey_contexts.contains_key(key) || self.passkey_vouch_unconfirmed(key)
    }

    /// Whether the owner's choice "Let my passkey remove devices and keys"
    /// ([`PolicySetting::PasskeyFullOwner`], Engine ruling
    /// WEBPASSKEY-OPTIN-HOME = A) is on in this state: the setting has a live
    /// act, and every live act of it is on ([`passkey_full_owner_value`]).
    /// No act, an act that turned it off, and two acts that did not see each
    /// other unless both are on, all read off. It reads the register as every
    /// replica holds it, with no pin and no install's counting, as the judge
    /// of each entry's parents must.
    pub(super) fn passkey_full_owner(&self) -> bool {
        let Ok(Some(target)) = PolicySetting::PasskeyFullOwner.reserved_target() else {
            return false;
        };
        self.policy_settings
            .every_live_choice_is(target, &passkey_full_owner_value(true))
    }

    /// Whether `key` authorizes no `ReRoot`, no `RotateKey`, no
    /// `EnrollDevice`, no revoke of another owner key or of a key its
    /// parents do not hold (a device or an actor binding), no actor binding,
    /// and no roster-signed machine profile in any role, from any
    /// signature position: a passkey (Engine ruling WEBPASSKEY-PASSKEY-OWN-REVOKE = B),
    /// or a key only a passkey vouched for, until confirmed (lead ruling
    /// WEBPASSKEY-BLIND-SIGNATURE = B), while the owner's choice
    /// [`Self::passkey_full_owner`] is off; with it on, no key is limited
    /// (Engine ruling WEBPASSKEY-OPTIN-HOME = A). The one reader of these
    /// limits: a rule that counts an entry's participants asks it of each.
    pub(super) fn passkey_limited(&self, key: &AuthorityKey) -> bool {
        self.passkey_bound(key) && !self.passkey_full_owner()
    }
}

/// Whether `target` is the reserved target of the owner's choice "Let my
/// passkey remove devices and keys": the frontier
/// [`FoldState::passkey_full_owner`] reads.
pub(super) fn is_passkey_full_owner_target(target: crate::entity_id::EntityId) -> bool {
    matches!(
        PolicySetting::PasskeyFullOwner.reserved_target(),
        Ok(Some(reserved)) if reserved == target
    )
}

/// Whether `predecessor` confirms `key` by vouching for it again: `key` is
/// live and only a passkey vouched for it, and `predecessor` is another key,
/// owner-held (on a hosted vault, outside the host's custody) and no passkey. That it is
/// itself confirmed, live and consenting is the judge's predecessor check.
fn confirms_passkey_vouch(
    state: &FoldState,
    key: &AuthorityKey,
    predecessor: &AuthorityKey,
) -> bool {
    state.passkey_vouch_unconfirmed(key)
        && predecessor != key
        && state.roster.get(key).is_some_and(|device| !device.revoked)
        && may_confirm_passkey_vouch(state, predecessor)
}

/// Whether `predecessor`'s vouch confirms a key: it is no passkey and no
/// key only a passkey vouched for, whatever the owner's choice (with the
/// choice on, such a key vouches, and its vouch confirms nothing), and it is
/// owner-held (on a hosted vault, outside the host's custody). That it is
/// live and consenting is the judge's predecessor check.
fn may_confirm_passkey_vouch(state: &FoldState, predecessor: &AuthorityKey) -> bool {
    !state.passkey_bound(predecessor)
        && !(state.hosted && super::machine_profile::in_host_custody(state, predecessor))
}

/// Marks a counted enrollment's key as passkey-vouched when its predecessor
/// is a passkey (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B), or a key only
/// a passkey vouched for, which vouches only while the owner's choice
/// [`FoldState::passkey_full_owner`] is on: turning it off brings back the
/// limits of the key it vouched for too (Engine ruling WEBPASSKEY-OPTIN-HOME
/// = A). It marks the key as confirmed when its predecessor is a key that
/// may confirm one: a fresh enrolment by such a key is its confirmation too,
/// so a passkey's vouch for the same key on a sibling branch limits nothing
/// once the fold merges the two (both sets merge by union; Astra delta
/// review finding 2).
pub(super) fn remember_passkey_vouch(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    enroll: &OwnerKeyEnroll,
) {
    let predecessor = entry.signer_key();
    if state.passkey_bound(predecessor) {
        state.passkey_vouched_keys.insert(enroll.device.key.clone());
    } else if may_confirm_passkey_vouch(state, predecessor) {
        state
            .passkey_vouch_confirmations
            .insert(enroll.device.key.clone());
    }
}

/// Whether a passkey-limited `key` ([`FoldState::passkey_limited`]) may not
/// authorize `op`: a `ReRoot`; a `RotateKey`, the re-root of one key, which
/// would hand the key's standing to a successor no limit reaches; an
/// `EnrollDevice`, a vouch for a further key outside the `OwnerKeyEnroll`
/// judge that marks it; and a `RevokeDevice` of any key but itself that its
/// parents do not hold as a non-owner or revoked row (Sol xhigh stack review
/// F1). A key the parents do not hold at all is barred too: its tombstone
/// would revoke an owner key enrolled on a sibling branch once the fold
/// merges the two (Astra stack review finding 1). A `RevokeActor` reads the
/// same way: its watermark would kill an owner key's binding on a sibling
/// branch for good (Astra delta review finding 1). A `BindActor` or
/// `RebindActor`: of another key it would move that key's binding to an
/// actor of its choosing, and of itself it would make any row an actor's on
/// every branch for good, which ends the standing of a machine with that
/// row (Astra delta 2 review finding 1). And a roster-signed
/// `MachineProfile` in any role: one that answers a machine as the owner's
/// (`Owned(_)`) or removes one is the owner's say-so for a machine, of the
/// vouch and revoke class (OPUS-SECREAD-A N1), and one in any other role
/// names a key for the machine, whose second key claim poisons an owned
/// machine for good, the removal by another name (blind review #8451 F1).
/// Judged by the op alone, so that no sibling branch reopens it; an
/// act-carried answer is the carrier's, signed by its install key, and
/// never reaches this. Every other op passes.
fn passkey_limits_bar(state: &FoldState, op: &AuthorityOp, key: &AuthorityKey) -> bool {
    match op {
        AuthorityOp::ReRoot { .. }
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::MachineProfile(_) => true,
        AuthorityOp::RevokeDevice {
            revoked_key: target,
        }
        | AuthorityOp::RevokeActor {
            authority_key: target,
            ..
        } => {
            target != key
                && !state
                    .roster
                    .get(target)
                    .is_some_and(|device| device.revoked || device.roles & ROLE_OWNER == 0)
        }
        _ => false,
    }
}

/// Marks the key a counted entry re-roots, rotates or enrols a device to as
/// passkey-vouched when the entry's consent rests on passkey-bound keys
/// ([`consent_rests_on`]): a passkey or a key only a passkey vouched for
/// signs it, or its other participants give no consent, so that a cosign
/// hands its standing on as a signature does (Sol xhigh review of PR 1c,
/// finding 1). The owner's choice [`FoldState::passkey_full_owner`] was on
/// in its parents, or the limits would have barred it, and turning the
/// choice off brings back the limits of each key it handed its standing to
/// (Engine ruling WEBPASSKEY-OPTIN-HOME = A).
pub(super) fn remember_passkey_successor(
    state: &mut FoldState,
    op: &AuthorityOp,
    signer: &AuthorityKey,
    participants: &BTreeSet<AuthorityKey>,
    context: FoldContext<'_>,
) {
    let successor = match op {
        AuthorityOp::EnrollDevice { device }
        | AuthorityOp::RotateKey {
            new_device: device, ..
        }
        | AuthorityOp::ReRoot { new_device: device } => &device.key,
        _ => return,
    };
    let bound = participants
        .iter()
        .filter(|key| state.passkey_bound(key))
        .cloned()
        .collect::<BTreeSet<_>>();
    if consent_rests_on(state, participants, signer, &bound, context) {
        state.passkey_vouched_keys.insert(successor.clone());
    }
}

/// Whether the consent of an entry signed by `signer` with `participants`
/// (its signer and every cosign) rests on `keys`: `signer` is one of them,
/// or the participants outside them give no consent. The generic rule
/// refuses an entry whose consent rests on the keys the passkey limits bar
/// ([`passkey_barred_participants`]); [`remember_passkey_successor`] reads
/// the same rule over the passkey-bound keys, so each successor it marks is
/// one the limits would have barred.
pub(super) fn consent_rests_on(
    state: &FoldState,
    participants: &BTreeSet<AuthorityKey>,
    signer: &AuthorityKey,
    keys: &BTreeSet<AuthorityKey>,
    context: FoldContext<'_>,
) -> bool {
    keys.contains(signer)
        || (!keys.is_empty()
            && !super::entry_transition_predicates::has_authority_consent(
                state,
                &participants
                    .difference(keys)
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                context,
            ))
}

/// The participants of an entry with `op` (its signer and every cosign)
/// whose consent the passkey limits do not count: each passkey-limited key
/// the op bars ([`passkey_limits_bar`]). The generic rule refuses the entry
/// when its signer is one, and otherwise asks the consent of the rest, so a
/// limited key lends no consent from a cosign either (Sol xhigh stack review
/// F2).
pub(super) fn passkey_barred_participants(
    state: &FoldState,
    op: &AuthorityOp,
    participants: &BTreeSet<AuthorityKey>,
) -> BTreeSet<AuthorityKey> {
    participants
        .iter()
        .filter(|key| state.passkey_limited(key) && passkey_limits_bar(state, op, key))
        .cloned()
        .collect()
}

/// Whether `key` is fresh in `state`: no roster row names it, live or
/// revoked, so a revoked key never comes back; no actor binding names it;
/// and no machine revision named it as an install key and no owner anchor
/// signed with it. An owner key never doubles as a machine, actor or anchor
/// key: the carrier rule and the machine fold read a roster key as no
/// machine's. Install keys and anchor keys are Ed25519 alone, so a passkey's
/// P-256 key is neither.
fn fresh_owner_key(state: &FoldState, key: &AuthorityKey) -> bool {
    !state.roster.contains_key(key)
        && !state.actor_bindings.contains_key(key)
        && match key {
            AuthorityKey::Ed25519(bytes) => {
                !state.machine_keys.contains_key(bytes) && !state.root_anchors.contains_key(bytes)
            }
            AuthorityKey::P256(_) => true,
        }
}

/// Whether every passkey-form signature on `entry` (a P-256 signature that
/// is a WebAuthn assertion envelope, its primary or a cosign) names a
/// context its key's enrollment pinned in `contexts` (row
/// WEB-PASSKEY-OWNER-KEY; Sol xhigh F2). An entry with none passes; with
/// `None` (before genesis) any passkey-form signature fails.
pub(super) fn passkey_signatures_in_context(
    contexts: Option<&BTreeMap<AuthorityKey, BTreeSet<WebAuthnContext>>>,
    entry: &AuthorityLogEntry,
) -> bool {
    std::iter::once(&entry.signer)
        .chain(&entry.cosigns)
        .filter(|signature| {
            signature.suite == AuthoritySignatureSuite::P256 && signature.signature.len() != 64
        })
        .all(|signature| {
            let Some(context) = webauthn_assertion_context(&signature.signature) else {
                return false;
            };
            contexts
                .and_then(|contexts| contexts.get(&signature.public_key))
                .is_some_and(|pinned| pinned.contains(&context))
        })
}

/// Pins a counted passkey enrollment's context for its key (row
/// WEB-PASSKEY-OWNER-KEY): its own assertion's RP id hash and origin.
pub(super) fn remember_passkey_context(state: &mut FoldState, enroll: &OwnerKeyEnroll) {
    if let Some(context) = enroll.passkey_context() {
        state
            .passkey_contexts
            .entry(enroll.device.key.clone())
            .or_default()
            .insert(context);
    }
}

/// A live machine of the vault, in any role: no chain removed it, and some
/// chain of it is live (the carrier rule's liveness, without its key).
fn machine_is_live(machine: &FoldedMachine) -> bool {
    machine.chains().all(|(_, chain)| !chain.removed)
        && machine.chains().any(|(_, chain)| chain.is_live())
}
