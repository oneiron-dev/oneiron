//! The agent's doors: `reveal`, `wait` and `describe` on a handle.

use super::{
    HandleReveal, READER_AGENT, REVEAL_ASK_TTL_SECS, REVEAL_LEASE_TTL_SECS, REVEALS, RevealAct,
    RevealAsker, RevealAuthority, RevealRow, SecretHandleCard, SecretProvenance,
    SecretRevealDecision, SecretRevealState, SecretRevealWait, append_reveal_decision_in_txn,
    checked_text, resolve_handle_in_txn, reveal_class, unknown,
};
use super::notice::{notify_reveal_ask_in_txn, settle_reveal_notices_in_txn};
use crate::consent::{
    approve_once_authorization_in_txn, approve_once_decision_in_txn, load_active_standing_grants,
    spend_approve_once_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::run_bound::reveal_run_admission;
use crate::secret_custody::{SecretCustodyFloor, read_secret_custody_admission_in_txn};
use crate::vault::Vault;

impl Vault {
    /// `reveal(handle, why)`: an agent asks for a secret's value for its
    /// model. Returns the pending reveal every time; `wait` collects it.
    ///
    /// One write transaction resolves the handle, admits the reveal (the
    /// class's live floor and the record's widest binding must reach T1, so a
    /// cross-vault or doored credential never reaches a model), and runs the
    /// one consent check. A standing grant on this connection × this class ×
    /// this project covers it; otherwise it is asked, and a pending Gate
    /// record names the digest the owner's answer must carry.
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound)
    /// for a `why` that is empty, longer than 512 bytes or more than one line,
    /// or text that is no handle. The scan's refusal for a `why` that holds a
    /// credential. [`SecretError::SecretRefNotFound`](crate::error::SecretError::SecretRefNotFound)
    /// for a handle that names no secret.
    /// [`SecretError::SecretTierDenied`](crate::error::SecretError::SecretTierDenied)
    /// for a secret no model may hold.
    /// [`SecretError::SecretBindingDenied`](crate::error::SecretError::SecretBindingDenied)
    /// for a secret a run found, asked for by another run (FIX 8028).
    pub(crate) fn reveal_secret(
        &self,
        asker: &RevealAsker,
        handle: &str,
        why: &str,
    ) -> Result<EntityId> {
        let why = checked_text(
            why,
            "a reveal says why it needs the value",
            "a reveal's why is one line of at most 512 bytes",
        )?;
        let reveal = self.store.clock.entity_id()?;
        self.with_write_txn_grouped(|txn| {
            let (handle, secret, class, person) = if handle.trim().starts_with("pr") {
                let (handle, person, target) =
                    super::person::resolve_person_in(self, txn, asker, handle)?;
                (handle, person, "names".to_owned(), Some(target))
            } else {
                let (handle, secret) = resolve_handle_in_txn(&self.store, txn, handle)?;
                let rec = read_secret_custody_admission_in_txn(&self.store, txn, &secret)?
                    .ok_or_else(|| unknown(&handle))?;
                let floor = SecretCustodyFloor::resolve(&self.store, txn)?;
                crate::secret_lease::reveal_tier_admission(&rec, &floor)?;
                // A secret a run found reveals to that run (FIX 8028).
                reveal_run_admission(&rec.name, &handle, asker.attempt.as_ref())?;
                (handle, secret, rec.class.as_str().to_owned(), None)
            };
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut row = RevealRow {
                reader: READER_AGENT.to_owned(),
                actor: Some(asker.agent),
                connection: Some(asker.connection()),
                provider: asker.provider.clone(),
                secret,
                person,
                handle,
                class,
                why,
                project: asker.project,
                run: asker.run.clone(),
                created_at: now,
                expires_at: now.saturating_add(REVEAL_ASK_TTL_SECS),
                state: SecretRevealState::Covered,
                once_digest: None,
                asked_decision: None,
                answered_by: None,
                decision: None,
                lease: None,
                delivered_at: None,
                file: None,
                notices: Vec::new(),
                closed: None,
                task: asker.task.clone(),
                attempt: asker.attempt,
                scope: None,
            };
            row.once_digest = Some(*row.ask_digest(&reveal).as_bytes());
            let grants = load_active_standing_grants(&self.store, txn)?;
            match row.covering(&grants)? {
                Some((scope, grant_ref)) => {
                    row.answered_by = Some(standing(&grant_ref));
                    row.scope = Some(scope);
                }
                None => file_ask_in_txn(self, txn, &reveal, &mut row, now)?,
            }
            REVEALS.put(&self.store, txn, &reveal, &row)?;
            Ok(reveal)
        })
    }

    /// `wait(pending)`: where the asking agent's reveal stands, and its value
    /// the first time it is granted. Another agent's reveal reads as not
    /// found.
    ///
    /// A covered reveal is checked again now: still covered, its value goes
    /// out with a quiet use receipt; a grant revoked meanwhile files the ask
    /// now. An approved-once reveal spends its marker. Delivery stamps the T1
    /// lease, receipt first, in this same transaction, so a failure writes
    /// nothing and spends nothing. A delivered reveal answers `granted` with
    /// its receipt and no value.
    pub(crate) fn wait_secret_reveal(
        &self,
        asker: &RevealAsker,
        reveal: &EntityId,
    ) -> Result<SecretRevealWait> {
        self.with_write_txn_grouped(|txn| {
            // A file's read is collected by reading the file again.
            let mut row = REVEALS
                .get(&self.store, txn, reveal)?
                .filter(|row| {
                    row.is_agents(&asker.agent)
                        && row.file.is_none()
                        && row.project == asker.project
                        && row.run == asker.run
                        && row.connection.as_deref() == Some(asker.connection().as_str())
                })
                .ok_or(Error::EntityNotFound)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let answer = |decision, row: &RevealRow| -> Result<SecretRevealWait> {
                Ok(SecretRevealWait {
                    decision,
                    value: None,
                    receipt: Some(row.receipt(*reveal)?),
                })
            };
            // An approve-once covers the provider the owner saw. When the
            // host now binds another, the reveal asks again for it, before
            // the marker is spent; the old marker stays unspent (FIX 7991).
            if row.state == SecretRevealState::ApprovedOnce
                && now < row.expires_at
                && row.provider != asker.provider
            {
                row.provider.clone_from(&asker.provider);
                file_ask_in_txn(self, txn, reveal, &mut row, now)?;
                REVEALS.put(&self.store, txn, reveal, &row)?;
                return answer(SecretRevealDecision::Pending, &row);
            }
            // A PERSON claim is re-admitted in this writer before any grant
            // is spent or receipt is written. A changed claim needs a new ask.
            let person_value = if row.person.is_some()
                && matches!(
                    row.state,
                    SecretRevealState::Covered
                        | SecretRevealState::ApprovedOnce
                        | SecretRevealState::ApprovedStanding
                ) {
                Some(super::person::value_in(self, txn, asker, &row)?)
            } else {
                None
            };
            let state = row.state;
            match state {
                SecretRevealState::Delivered => return answer(SecretRevealDecision::Granted, &row),
                SecretRevealState::Denied => return answer(SecretRevealDecision::Denied, &row),
                SecretRevealState::Expired => return answer(SecretRevealDecision::Expired, &row),
                SecretRevealState::Unavailable => {
                    return answer(SecretRevealDecision::Unavailable, &row);
                }
                _ if now >= row.expires_at => {
                    row.state = SecretRevealState::Expired;
                    // An expired ask leaves no open notice (FIX 2355).
                    settle_reveal_notices_in_txn(self, txn, &mut row)?;
                    REVEALS.put(&self.store, txn, reveal, &row)?;
                    return answer(SecretRevealDecision::Expired, &row);
                }
                SecretRevealState::Asked => return answer(SecretRevealDecision::Pending, &row),
                SecretRevealState::Covered | SecretRevealState::ApprovedStanding => {
                    let grants = load_active_standing_grants(&self.store, txn)?;
                    let Some((scope, grant_ref)) = row.covering(&grants)? else {
                        file_ask_in_txn(self, txn, reveal, &mut row, now)?;
                        REVEALS.put(&self.store, txn, reveal, &row)?;
                        return answer(SecretRevealDecision::Pending, &row);
                    };
                    let used = self.record_standing_grant_use_in_txn(
                        txn,
                        &grant_ref,
                        row.stored_once_digest()?,
                    )?;
                    if state == SecretRevealState::Covered {
                        row.answered_by = Some(standing(&grant_ref));
                    }
                    row.scope = Some(scope);
                    row.decision = Some(used.decision_id());
                }
                SecretRevealState::ApprovedOnce => {
                    let digest = row.stored_once_digest()?;
                    let authorization =
                        approve_once_authorization_in_txn(&self.store, txn, &digest)?.ok_or(
                            Error::InvariantViolation(
                                "an approved reveal has no approve-once marker",
                            ),
                        )?;
                    spend_approve_once_in_txn(&self.store, txn, &authorization)?;
                    row.decision = approve_once_decision_in_txn(&self.store, txn, &digest)?;
                }
            }
            if let Some(value) = person_value {
                row.state = SecretRevealState::Delivered;
                row.delivered_at = Some(now);
                REVEALS.put(&self.store, txn, reveal, &row)?;
                Ok(SecretRevealWait {
                    decision: SecretRevealDecision::Granted,
                    value: Some(value),
                    receipt: Some(row.receipt(*reveal)?),
                })
            } else {
                deliver_in_txn(self, txn, reveal, row)
            }
        })
    }

    /// `describe(h)` on a secret handle: its label, class, status and
    /// provenance, and what a reveal would do for `asker` now. No value, and
    /// nothing written.
    pub(crate) fn describe_secret_handle(
        &self,
        handle: &str,
        asker: Option<&RevealAsker>,
    ) -> Result<SecretHandleCard> {
        let txn = self.store.env.read_txn()?;
        let (handle, secret) = resolve_handle_in_txn(&self.store, &txn, handle)?;
        let rec = read_secret_custody_admission_in_txn(&self.store, &txn, &secret)?
            .ok_or_else(|| unknown(&handle))?;
        let provenance = crate::batch::secret_scan::mask_origin_in_txn(&self.store, &txn, &secret)?
            .map(|origin| SecretProvenance {
                record: origin.record,
                place: origin.place,
                kind: origin
                    .reason
                    .strip_prefix("gate.secret_scan.")
                    .unwrap_or(&origin.reason)
                    .to_owned(),
                masked_at: origin.masked_at,
            });
        let floor = SecretCustodyFloor::resolve(&self.store, &txn)?;
        let attempt = asker.and_then(|asker| asker.attempt.as_ref());
        let admitted = crate::secret_lease::reveal_tier_admission(&rec, &floor)
            .and_then(|()| reveal_run_admission(&rec.name, &handle, attempt));
        let reveal = match admitted {
            Err(Error::Secret(refused)) => HandleReveal::Refused {
                reason: refused.to_string(),
            },
            Err(error) => return Err(error),
            Ok(()) => match asker {
                None => HandleReveal::Asks,
                Some(asker) => {
                    let grants = load_active_standing_grants(&self.store, &txn)?;
                    asker
                        .reach()
                        .covering_grant(&asker.connection(), &reveal_class(rec.class), &grants)?
                        .map_or(HandleReveal::Asks, |(_, grant_ref)| {
                            HandleReveal::Hydrates { grant_ref }
                        })
                }
            },
        };
        Ok(SecretHandleCard {
            handle,
            label: rec.name,
            class: rec.class,
            status: rec.status,
            provenance,
            reveal,
        })
    }
}

/// Files the owner's ask for `row`, now: its window, the digest an answer
/// must carry, the pending Gate record that names both, and one inbox Ask
/// per live owner (FIX 2355). A re-ask settles the old ask's notices first.
pub(super) fn file_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reveal: &EntityId,
    row: &mut RevealRow,
    now: u64,
) -> Result<()> {
    settle_reveal_notices_in_txn(vault, txn, row)?;
    row.state = SecretRevealState::Asked;
    row.answered_by = None;
    row.expires_at = now.saturating_add(REVEAL_ASK_TTL_SECS);
    let digest = row.ask_digest(reveal);
    row.once_digest = Some(*digest.as_bytes());
    row.asked_decision = Some(append_reveal_decision_in_txn(
        vault,
        txn,
        reveal,
        row,
        RevealAct::Asked,
        digest.as_bytes().to_vec(),
    )?);
    notify_reveal_ask_in_txn(vault, txn, reveal, row)?;
    Ok(())
}

/// Delivers a granted reveal in `txn`: the T1 lease (receipt first), then the
/// row, then the value to the caller.
fn deliver_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reveal: &EntityId,
    mut row: RevealRow,
) -> Result<SecretRevealWait> {
    let connection = row
        .connection
        .clone()
        .ok_or(Error::CorruptedIndex("secret reveal connection"))?;
    let authority = RevealAuthority {
        secret: row.secret,
        handle: row.handle.clone(),
        class: row.class()?,
        effector: format!("model:{connection}"),
    };
    let materialized = crate::secret_lease::stamp_reveal_lease_in_txn(
        vault,
        txn,
        &authority,
        REVEAL_LEASE_TTL_SECS,
    )?;
    row.state = SecretRevealState::Delivered;
    row.lease = Some(materialized.lease.lease_id);
    row.delivered_at = Some(materialized.lease.granted_at);
    REVEALS.put(&vault.store, txn, reveal, &row)?;
    Ok(SecretRevealWait {
        decision: SecretRevealDecision::Granted,
        value: Some(materialized.value),
        receipt: Some(row.receipt(*reveal)?),
    })
}

pub(super) fn standing(grant_ref: &str) -> String {
    format!("standing:{grant_ref}")
}
