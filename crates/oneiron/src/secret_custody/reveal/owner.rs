//! The owner's doors: the asks and receipts, the answer to one ask, and the
//! owner's own read of a value.

use super::{
    OwnerSecretReveal, READER_AGENT, READER_OWNER, REVEALS, RevealAct, RevealRow, RevealTarget,
    SECRET_REVEAL_OPERATION, SecretRevealAnswer, SecretRevealAnswered, SecretRevealAsk,
    SecretRevealState, append_reveal_decision_in_txn, checked_text, not_active,
    resolve_handle_in_txn, unknown, value_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::genui::{ConsentAskCard, ConsentScopeEscalator};
use crate::secret_custody::{SecretCustodyStatus, resolve_secret_ref_in_txn};
use crate::vault::Vault;

impl Vault {
    /// The vault's reveals for the owner, newest first: each with its
    /// receipt so far and, while it waits on the owner, its ask card and the
    /// digest an answer sends back. `pending_only` keeps the open asks. No
    /// value is read.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// owner's.
    pub fn secret_reveals(
        &self,
        owner: &AuthenticatedOwner,
        pending_only: bool,
        limit: usize,
    ) -> Result<Vec<SecretRevealAsk>> {
        owner.revalidate(self)?;
        let principal = owner.principal_ref_for_read(self)?;
        let now = self.store.clock.now_recorded_at();
        let txn = self.store.env.read_txn()?;
        let mut asks = Vec::new();
        for row in REVEALS.iter_rev_from(&self.store, &txn, &[])? {
            if asks.len() >= limit {
                break;
            }
            let (reveal, row) = row?;
            let open = row.state == SecretRevealState::Asked && now < row.expires_at;
            if pending_only && !open {
                continue;
            }
            asks.push(ask_view(&reveal, &row, open, principal)?);
        }
        Ok(asks)
    }

    /// The owner's answer to one asked reveal, against the exact digest the
    /// card showed: `once` mints the approve-once marker for this reveal,
    /// `standing` writes a standing grant on this connection × this class ×
    /// this project, and `deny` records the refusal. Each through the consent
    /// door that writes its receipt, in one transaction with the reveal.
    /// A reveal is answered once, and only while its window is open.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// owner's. [`GateError::ConsentApproveOnceSpent`] for a reveal already
    /// answered. [`GateError::InvalidConsentBound`] for an expired ask or a
    /// digest that is not this ask's. [`Error::EntityNotFound`] for no such
    /// agent reveal.
    pub fn answer_secret_reveal(
        &self,
        owner: &AuthenticatedOwner,
        reveal: &EntityId,
        expected_digest: &[u8; 32],
        answer: SecretRevealAnswer,
    ) -> Result<SecretRevealAnswered> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut row = REVEALS
                .get(&self.store, txn, reveal)?
                .filter(|row| row.reader == READER_AGENT)
                .ok_or(Error::EntityNotFound)?;
            if row.state != SecretRevealState::Asked {
                return Err(Error::Gate(GateError::ConsentApproveOnceSpent(
                    "this reveal is not waiting on an answer",
                )));
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            if now >= row.expires_at {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "this reveal's ask has expired",
                )));
            }
            let digest = row.stored_once_digest()?;
            if digest.as_bytes() != expected_digest {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "the answer names another ask than this reveal's",
                )));
            }
            let receipt = match answer {
                SecretRevealAnswer::Once => {
                    row.state = SecretRevealState::ApprovedOnce;
                    self.approve_once_in_txn(txn, owner, digest)?
                }
                SecretRevealAnswer::Standing => {
                    row.state = SecretRevealState::ApprovedStanding;
                    self.create_standing_grant_in_txn(txn, owner, row.bound()?)?
                }
                SecretRevealAnswer::Deny => {
                    row.state = SecretRevealState::Denied;
                    self.deny_consent_in_txn(txn, owner, digest)?
                }
            };
            row.answered_by = Some(format!("{READER_OWNER}:{}", actor.to_hex()));
            row.decision = Some(receipt.decision_id());
            REVEALS.put(&self.store, txn, reveal, &row)?;
            Ok(SecretRevealAnswered {
                reveal: *reveal,
                answer,
                decision: receipt.decision_id(),
                grant_ref: receipt.grant_ref(),
            })
        })
    }

    /// The owner reads a secret's value on their own surface, with a reason
    /// the receipt keeps. The proof is rechecked at the owner tier in the
    /// transaction that reads the value, as
    /// [`Vault::register_secret_as_owner`] rechecks it. Any record that is
    /// not revoked reads: the custody floor caps what reaches a model, not
    /// what its owner sees. No lease is stamped; the reveal row, and its Gate
    /// record, are the receipt.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// owner's. [`GateError::InvalidConsentBound`] for a reason that is
    /// empty, longer than 512 bytes or more than one line. The scan's refusal
    /// for a reason that holds a credential.
    /// [`SecretError::SecretRefNotFound`](crate::error::SecretError::SecretRefNotFound)
    /// for no such secret.
    /// [`SecretError::SecretCustodyNotActive`](crate::error::SecretError::SecretCustodyNotActive)
    /// for a revoked one.
    pub fn reveal_secret_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        target: &RevealTarget,
        reason: &str,
    ) -> Result<OwnerSecretReveal> {
        let reason = checked_text(
            reason,
            "an owner's reveal names its reason",
            "an owner's reason is one line of at most 512 bytes",
        )?;
        let reveal = self.store.clock.entity_id()?;
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &actor)? {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "only the vault owner reads a secret's value",
                )));
            }
            let (handle, secret) = match target {
                RevealTarget::Handle(handle) => resolve_handle_in_txn(&self.store, txn, handle)?,
                RevealTarget::Name(name) => {
                    let secret = resolve_secret_ref_in_txn(&self.store, txn, name)?
                        .ok_or_else(|| unknown(name))?;
                    let handle = crate::ports::ShortIdStoreRead::port_short_id_reference(
                        &self.store,
                        txn,
                        &secret,
                    )?
                    .map(|(short, _)| short)
                    .unwrap_or_else(|| name.clone());
                    (handle, secret)
                }
            };
            let (value, status, class) = value_in_txn(&self.store, txn, &secret, &handle)?;
            if status == SecretCustodyStatus::Revoked {
                return Err(not_active(&handle));
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut row = RevealRow {
                reader: READER_OWNER.to_owned(),
                actor,
                connection: None,
                provider: None,
                secret,
                handle,
                class: class.as_str().to_owned(),
                why: reason,
                project: None,
                run: None,
                created_at: now,
                expires_at: now,
                state: SecretRevealState::Delivered,
                once_digest: None,
                asked_decision: None,
                answered_by: Some(format!("{READER_OWNER}:{}", actor.to_hex())),
                decision: None,
                lease: None,
                delivered_at: Some(now),
            };
            row.decision = Some(append_reveal_decision_in_txn(
                self,
                txn,
                &reveal,
                &row,
                RevealAct::OwnerRead,
                reveal.as_bytes().to_vec(),
            )?);
            REVEALS.put(&self.store, txn, &reveal, &row)?;
            Ok(OwnerSecretReveal {
                value,
                receipt: row.receipt(reveal)?,
            })
        })
    }
}

/// One reveal as the owner reads it. The card and the digest are there only
/// while the ask is open.
fn ask_view(
    reveal: &EntityId,
    row: &RevealRow,
    open: bool,
    principal: &str,
) -> Result<SecretRevealAsk> {
    let state = if row.state == SecretRevealState::Asked && !open {
        SecretRevealState::Expired
    } else {
        row.state
    };
    let agents = row.reader == READER_AGENT;
    let card = if open {
        let connection = row.connection.as_deref().unwrap_or_default();
        let card = ConsentAskCard::new(
            format!("secret-reveal:{}", reveal.to_hex()),
            principal,
            format!(
                "{connection} asks to reveal {} ({}) to its model: {}",
                row.handle, row.class, row.why
            ),
            row.disclosure().unwrap_or_default(),
            SECRET_REVEAL_OPERATION,
            vec![
                ConsentScopeEscalator::JustOnce,
                ConsentScopeEscalator::AlwaysThisChannel,
            ],
        )?
        .with_channel(connection);
        Some(match row.asked_decision {
            Some(decision) => card.with_origin_receipt_ref(format!("gate:{}", decision.to_hex())),
            None => card,
        })
    } else {
        None
    };
    Ok(SecretRevealAsk {
        receipt: row.receipt(*reveal)?,
        state,
        expires_at: row.expires_at,
        disclosure: row.disclosure(),
        once_digest: if open {
            Some(row.stored_once_digest()?)
        } else {
            None
        },
        grant_ref: if agents {
            Some(row.bound()?.digest().to_hex())
        } else {
            None
        },
        card,
    })
}
