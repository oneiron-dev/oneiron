//! The admitting node's one consumption of a relayed intent (FIX 7494).
//!
//! First one snapshot reads the intent, its group and this node's admission
//! of it, the rows its act names, and the holder's operation signature under
//! the slip's actual logged mint signer, over the challenge rebuilt here.
//! Then the owner proof is minted the one way it is minted
//! ([`Vault::authenticate_owner`]) and bound to that verified slip, owner
//! tier or person tier, as a direct `tasks.answer` binds it. Last, one writer
//! revalidates that exact proof, makes the act's effect and saves the signed
//! result, so a result exists exactly when its effect does. Before a word's
//! effect, that writer checks the write a direct `tasks.answer` needs; a
//! refusal there is its result in that same writer. Any other refusal is
//! saved in a writer of its own. A refused act made no effect.

use super::*;
use crate::authority::VerifiedSlip;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, ErrorKind};
use crate::memory::MEMORY_CODE_INTERNAL;

/// Whether an intent is done with at this node, or waits for rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Standing {
    /// Consumed, consumed already, or not this node's to consume.
    Settled,
    /// A row it names, or its slip's mint, has not landed here yet.
    Pending,
}

/// What the snapshot read of an intent this node admitted found.
enum Verdict {
    /// A row its act names, or its slip's mint, has not landed here yet.
    Waits,
    /// The holder's proof does not verify for this intent here.
    Refused,
    /// The holder's slip, verified for this intent.
    Verified(Box<VerifiedSlip>),
}

/// The holder's authority, bound to their verified slip.
enum HolderAuthority {
    /// The vault's live owner on their own full slip
    /// ([`Vault::bind_owner_credential`]).
    Owner(AuthenticatedOwner),
    /// A live person on their own slip ([`Vault::bind_person_credential`]),
    /// who answers for themself alone.
    Person(AuthenticatedOwner),
}

impl HolderAuthority {
    /// The owner proof the word is admitted under, as a direct `tasks.answer`
    /// carries it: the owner's, and none for anyone else.
    fn owner(&self) -> Option<&AuthenticatedOwner> {
        match self {
            Self::Owner(owner) => Some(owner),
            Self::Person(_) => None,
        }
    }

    /// The proof's actor, rechecked in the acting writer `txn`.
    fn revalidate_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<EntityId> {
        match self {
            Self::Owner(owner) => owner.revalidate_in_txn(vault, txn),
            Self::Person(person) => person.revalidate_person_in_txn(vault, txn),
        }
    }
}

/// Consumes the intent `id` at this node, once (FIX 7494).
///
/// # Errors
/// A storage error; the intent stays pending.
pub(super) fn consume_intent(vault: &Vault, id: EntityId) -> Result<Standing> {
    let Some((intent, verdict)) = check_intent(vault, id)? else {
        return Ok(Standing::Settled);
    };
    let slip = match verdict {
        Verdict::Waits => return Ok(Standing::Pending),
        Verdict::Refused => return refuse(vault, id, &intent, MEMORY_CODE_FORBIDDEN),
        Verdict::Verified(slip) => *slip,
    };
    let authority = match authenticate(vault, intent.holder, slip.clone()) {
        Ok(authority) => authority,
        Err(error) if is_refusal(&error) => {
            return refuse(vault, id, &intent, MEMORY_CODE_FORBIDDEN);
        }
        Err(error) => return Err(error),
    };
    match vault.with_write_txn_grouped(|txn| act_in_txn(vault, txn, id, &intent, &slip, &authority))
    {
        Ok(acted) => {
            // As `tasks_answer` does after its commit; a signal lost here is
            // replayed from the peer wait index.
            if acted
                && let Err(error) = crate::llm::send_peer_result_signal(
                    vault,
                    intent.group,
                    vault.store.clock.now_recorded_at(),
                )
            {
                tracing::warn!(%error, "a relayed ask word's peer-result signal was not sent");
            }
            Ok(Standing::Settled)
        }
        Err(error) if error.kind() == ErrorKind::AskDependencyPending => Ok(Standing::Pending),
        Err(error) if is_refusal(&error) => {
            let code = MemoryError::from(error).code;
            refuse(vault, id, &intent, &code)
        }
        Err(error) => Err(error),
    }
}

/// Whether `error` is the ask's or the proof's refusal of the act, which
/// the result keeps, rather than a failure to try again.
fn is_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::Gate(_) | Error::Record(_) | Error::EntityNotFound | Error::IndexOverflow(_)
    ) && error.kind() != ErrorKind::AskDependencyPending
}

/// The snapshot read of the intent `id`: `None` when it is gone, consumed
/// already, or for an ask this node did not admit.
fn check_intent(vault: &Vault, id: EntityId) -> Result<Option<(AskForwardIntent, Verdict)>> {
    let txn = vault.store.env.read_txn()?;
    let Some(intent) = read_intent(vault, &txn, id)? else {
        return Ok(None);
    };
    if read_result(vault, &txn, id, &intent)?.is_some() {
        return Ok(None);
    }
    let Some(group) = ask_record::read_group(vault, &txn, intent.group)? else {
        return Ok(None);
    };
    if !ask_record::owns_revision(vault, &txn, intent.group, &group)? {
        return Ok(None);
    }
    if rows_pending(vault, &txn, &intent, &group)? {
        return Ok(Some((intent, Verdict::Waits)));
    }
    let Some(vault_id) = vault.authority_view_readonly_in_txn(&txn)?.vault_id else {
        return Ok(Some((intent, Verdict::Refused)));
    };
    // Rebuilt here, from this node's vault and its own group's revision.
    let challenge = challenge(
        &vault_id,
        intent.group,
        group.effective.what.revision,
        id,
        intent.holder,
        &intent.act,
    )?;
    let (Ok(slip), Some(signature)) = (
        crate::authority::CapabilitySlip::from_token(&intent.proof.token),
        intent.proof.signature_bytes(),
    ) else {
        return Ok(Some((intent, Verdict::Refused)));
    };
    let verdict = match vault.verify_ask_forward_holder_in_txn(&txn, &slip, &challenge, &signature)
    {
        // The slip's mint has not reached this node's authority log yet.
        Ok(None) => Verdict::Waits,
        Ok(Some(verified)) if holds_for(&verified, intent.holder) => {
            Verdict::Verified(Box::new(verified))
        }
        Ok(Some(_)) => Verdict::Refused,
        Err(error) if is_refusal(&error) => Verdict::Refused,
        Err(error) => return Err(error),
    };
    Ok(Some((intent, verdict)))
}

/// Whether `slip` is `holder`'s own human slip, never handed to another key.
fn holds_for(slip: &VerifiedSlip, holder: EntityId) -> bool {
    let claims = slip.claims();
    claims.holder_ref == holder.to_hex()
        && claims.actor_class.as_deref() == Some("human")
        && claims.trusted_contact.is_none()
        && !slip.is_transferred()
}

/// Whether a row the intent's act names has not landed here yet: the
/// holder's PERSON and member TASK, and a word's result and provenance. The
/// ask's own checks judge each row once it is here.
fn rows_pending(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent: &AskForwardIntent,
    group: &AskGroup,
) -> Result<bool> {
    let mut rows = vec![intent.holder];
    if let Some(member) = group
        .members
        .iter()
        .find(|member| member.actor == intent.holder.to_hex())
    {
        rows.push(ask_record::entity(&member.task)?);
    }
    if let AskForwardAct::Word(word) = &intent.act {
        rows.push(word.result_ref);
        rows.extend(
            word.provenance_refs
                .iter()
                .copied()
                .map(crate::task_verb::ConsultPayloadRef::entity_ref),
        );
    }
    for row in rows {
        if vault.get_entity_type_in_txn(txn, &row)?.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Mints the holder's owner proof the one way it is minted
/// ([`Vault::authenticate_owner`]), now that their slip and their signature
/// over this intent verified, and binds it to that slip with the tier a
/// direct `tasks.answer` binds: the vault's live owner on their own full slip
/// carries the owner's proof; anyone else their own person proof.
fn authenticate(vault: &Vault, holder: EntityId, slip: VerifiedSlip) -> Result<HolderAuthority> {
    let principal = holder.to_hex();
    if slip.is_full_vault_owner_grade()
        && slip.claims().parent_id.is_none()
        && let Some(owner) = vault.authenticate_recorded_owner(
            holder,
            &principal,
            crate::store::GateDecisionId::now(),
        )?
        && vault.is_live_vault_owner(&owner)?
    {
        return vault
            .bind_owner_credential(owner, slip)
            .map(HolderAuthority::Owner);
    }
    let person = vault.authenticate_owner(
        holder,
        &principal,
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault
        .bind_person_credential(person, slip)
        .map(HolderAuthority::Person)
}

/// The one writer: the intent's act, its effect and its signed result, or
/// nothing. `Ok(false)` when it made no effect: another writer saved its
/// result first, or `slip` does not carry the word's write, and that
/// refusal is the result (FIX 7494).
fn act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    intent: &AskForwardIntent,
    slip: &VerifiedSlip,
    authority: &HolderAuthority,
) -> Result<bool> {
    if vault.get_raw_in(txn, &result_id(id)?)?.is_some() {
        return Ok(false);
    }
    let group =
        ask_record::read_group(vault, txn, intent.group)?.ok_or_else(ask_record::invalid)?;
    if !ask_record::owns_revision(vault, txn, intent.group, &group)? {
        return Err(ask_record::invalid());
    }
    // The exact proof again, in the acting writer.
    let holder = authority.revalidate_in_txn(vault, txn)?;
    if holder != intent.holder {
        return Err(Error::Gate(
            crate::error::GateError::ConsentOwnerNotAuthenticated(
                "the relayed word's proof names another person",
            ),
        ));
    }
    // The cutoff is this node's clock, never the replica's.
    let now = vault.store.clock.now_recorded_at();
    // A word writes the holder's answer, so it needs the write a direct
    // `tasks.answer` needs. Its refusal is settled here, before any effect.
    if let AskForwardAct::Word(_) = &intent.act
        && let Some(code) = word_write_refusal_in_txn(vault, txn, holder, slip)?
    {
        let outcome = AskForwardOutcome::Refused { code };
        put_result_in_txn(vault, txn, id, intent, &group, outcome, now)?;
        return Ok(false);
    }
    let outcome = match &intent.act {
        AskForwardAct::Word(word) => {
            let owner = authority.owner();
            let answer = ask_record::admit_word(
                vault,
                txn,
                intent.group,
                &group,
                crate::WriteActor::new(holder, crate::EdgeActorClass::Human),
                word,
                owner,
                now,
            )?;
            if word.inform_for.is_none() && word.companion_for.is_none() {
                crate::task_verb::lifecycle_facade::complete_ask_member_in_txn(
                    vault, txn, &answer, word, now,
                )
                .map_err(|_| ask_record::invalid())?;
            }
            crate::task_verb::ask_settlement::settle_with_owner_in(
                vault,
                txn,
                intent.group,
                now,
                owner,
            )?;
            AskForwardOutcome::Answered {
                answer: Box::new(answer),
            }
        }
        AskForwardAct::Void => AskForwardOutcome::Voided {
            generation: crate::task_verb::ask_option_link::void_seat_in_txn(
                vault,
                txn,
                intent.group,
                &group,
                holder,
                now,
            )?,
        },
    };
    put_result_in_txn(vault, txn, id, intent, &group, outcome, now)?;
    Ok(true)
}

/// The refusal code for `holder`'s word on `slip`, or `None` when the word
/// may write (FIX 7494). It is the check a direct `tasks.answer` makes:
/// the core write scope its door requires ([`carries_core_write`]), then
/// the actor checks its writer runs, the shared-vault content write
/// authorization among them ([`Memory::verify_actor_write_in_txn`]).
/// Each refusal keeps the code that door answers.
fn word_write_refusal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    holder: EntityId,
    slip: &VerifiedSlip,
) -> Result<Option<String>> {
    if !carries_core_write(slip) {
        return Ok(Some(MEMORY_CODE_FORBIDDEN.to_owned()));
    }
    match vault
        .memory(holder, crate::EdgeActorClass::Human)
        .verify_actor_write_in_txn(txn)
    {
        Ok(()) => Ok(None),
        // A store that did not read is no refusal: the intent stays pending.
        Err(error) if error.code == MEMORY_CODE_INTERNAL => {
            tracing::warn!(%error, "a relayed ask word's write check did not read");
            Err(Error::InvariantViolation(
                "a relayed ask word's write check did not read",
            ))
        }
        Err(refusal) => Ok(Some(refusal.code)),
    }
}

/// Whether `slip` carries the core write scope a direct `tasks.answer`
/// requires (FIX 7494), read as the HTTP door grants it: the `write` or
/// `core:write` verb on a slip no invitation bounds, with no record or
/// channel caveat and every axis but its verbs at the top.
fn carries_core_write(slip: &VerifiedSlip) -> bool {
    let claims = slip.claims();
    let mut whole = crate::federation::Scope::top();
    whole.verbs = slip.scope().verbs.clone();
    claims.invitation_ref.is_none()
        && (slip.allows_verb("write") || slip.allows_verb("core:write"))
        && claims.records.is_empty()
        && claims.channels.is_empty()
        && whole.is_narrowing_of(slip.scope())
}

/// Saves the ask's or the proof's refusal of the intent `id`, under the
/// existing memory error `code`, in a writer of its own: the refused act
/// made no effect.
fn refuse(vault: &Vault, id: EntityId, intent: &AskForwardIntent, code: &str) -> Result<Standing> {
    vault.with_write_txn_grouped(|txn| {
        if vault.get_raw_in(txn, &result_id(id)?)?.is_some() {
            return Ok(());
        }
        let group =
            ask_record::read_group(vault, txn, intent.group)?.ok_or_else(ask_record::invalid)?;
        let outcome = AskForwardOutcome::Refused {
            code: code.to_owned(),
        };
        let now = vault.store.clock.now_recorded_at();
        put_result_in_txn(vault, txn, id, intent, &group, outcome, now)
    })?;
    Ok(Standing::Settled)
}

/// Puts the intent `id`'s result, signed with its group's issuer key, which
/// this node holds as the ask's admitting node.
fn put_result_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    intent: &AskForwardIntent,
    group: &AskGroup,
    outcome: AskForwardOutcome,
    now: u64,
) -> Result<()> {
    let mut result = AskForwardResult {
        intent: id,
        group: intent.group,
        payload_digest: intent.payload_digest,
        outcome,
        at: now,
        signature: Vec::new(),
    };
    result.signature =
        ask_record::sign_forward_result(vault, txn, intent.group, group, &result.signed_body()?)?;
    ask_record::put(vault, txn, result_id(id)?, RESULT, &result, now)
}
