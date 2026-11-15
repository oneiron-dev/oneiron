//! A person's own slip-key proof of their conversation-training choice (row
//! PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF; ruling CARRIER-PERSON-OPT-BACK-IN
//! = A; pass 26 "an act counts for what its proved actor may do").
//!
//! A person who is not the vault owner proves their own opt back in with the
//! binding key K of one of their own live human slips. K's secret lives only
//! on their device; the client signs the fixed statement
//! ([`conversation_training_statement`]) before the request, and the proof
//! rides in the op. The judge reads the entry's parent state alone, so every
//! replica judges the same rows the same way. A person proof either proves at
//! the parent state or the entry is forged, as [`super::owner_proof`] treats
//! a bad cosign: there is no waiting on a proof.
//!
//! The proof lets the act through the not-mine carrier's wait as an owner
//! key's proof does, and it never answers the owner's asks. The vault owner
//! proves with the owner key, never a slip key. A person's own opt-out lands
//! with no proof, so the fold never judges a proof on it and the door drops
//! one unstored: an opt-out never fails on a proof.

use std::collections::BTreeMap;

use super::*;

/// The actor class a person's own slip carries. `CONSENT_ACTOR_CLASS` (the
/// consent doors' name for it) is not reachable from the fold, so this names
/// the same class through the authority-side constant.
const PERSON_PROOF_ACTOR_CLASS: &str = ACTOR_CLASS_HUMAN;

/// Whether `set`'s person proof proves at the parent state `state`: `false`
/// when the person signed none. A signed proof either proves or the entry is
/// forged ([`AuthorityFoldIssue::InvalidEntry`]), as
/// [`super::owner_proof::owner_proof_key`] treats a bad cosign.
pub(super) fn person_choice_proved(
    state: &FoldState,
    set: &ConversationTrainingSet,
    hash: AuthorityEntryHash,
) -> std::result::Result<bool, AuthorityFoldIssue> {
    if set.person_proof.is_none() {
        return Ok(false);
    }
    // The vault owner proves with the owner key, never a slip key: no human
    // actor binding may name the person.
    let person_has_human_binding = state.actor_bindings.values().any(|binding| {
        binding.actor_ref == set.act.owner && binding.actor_class == PERSON_PROOF_ACTOR_CLASS
    });
    if proof_holds(
        &state.slips,
        &state.roster,
        &state.vault_id,
        person_has_human_binding,
        set,
    ) {
        Ok(true)
    } else {
        Err(AuthorityFoldIssue::InvalidEntry(hash))
    }
}

/// The one judge of a person proof, shared by the fold
/// ([`person_choice_proved`]) and the person's door: whether the proof `set`
/// carries holds on the parent state's slips, roster and vault id.
/// `person_has_human_binding` is whether any human actor binding names the
/// act's person, which each side reads off its own bindings type. The door
/// also asks its own clock ([`AuthorityFold::slip_is_live_at`]); the fold
/// keeps no clock, so this asks none.
pub(super) fn proof_holds(
    slips: &SlipAuthorityState,
    roster: &BTreeMap<AuthorityKey, FoldedDevice>,
    vault_id: &[u8; 32],
    person_has_human_binding: bool,
    set: &ConversationTrainingSet,
) -> bool {
    let Some(proof) = &set.person_proof else {
        return false;
    };
    // 1. The slip's logged mint.
    let Some(mint) = slips.mints.get(&proof.slip) else {
        return false;
    };
    let claims = &mint.action.claims;
    // 2. The person's own human slip: their holder, the human class, no
    // parent, and none of the bounds a delegated or special-purpose slip
    // carries (the exclusions the person credential mirrors).
    if claims.holder_ref != set.act.owner.to_hex()
        || claims.actor_class.as_deref() != Some(PERSON_PROOF_ACTOR_CLASS)
        || claims.parent_id.is_some()
        || claims.trusted_contact.is_some()
        || claims.share_ref.is_some()
        || claims.invitation_ref.is_some()
        || claims.delegation.is_some()
        || claims.seat_claim.is_some()
    {
        return false;
    }
    // 3. This vault's slip.
    if claims.vault_id != *vault_id {
        return false;
    }
    // 4. Live: the minting hosts live, neither revoked nor consumed.
    // `FoldState` keeps no valid-entries set, so unlike
    // [`AuthorityFold::slip_is_live`] there is no entry-hash check here; the
    // door's own liveness check covers it on its side.
    if !slips.is_live(&proof.slip, roster)
        || slips.revoked.contains(&proof.slip)
        || slips.consumed.contains(&proof.slip)
    {
        return false;
    }
    // 5. The vault owner proves with the owner key, never a slip key.
    if person_has_human_binding {
        return false;
    }
    // 6. K's strict signature over the statement for this choice.
    let statement = match conversation_training_statement(
        &claims.vault_id,
        set.act.owner,
        set.leave_out,
        set.act.seen,
        proof.slip,
    ) {
        Ok(statement) => statement,
        Err(_) => return false,
    };
    strong_ed25519_verified_once(&claims.binding_key, &statement, &proof.signature)
}
