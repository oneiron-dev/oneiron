//! Vault-local durable reserve/settle/refund ledger for research-loop spend.
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Durable reserve/settle/refund ledger for the RSI research-loop spend budget. Key: ().
const RSI_LINE: SideTable<(), Line, LegacyJson> = SideTable::new(&side_table::BUDGET_RSI_LINE);
#[doc(hidden)]
use oneiron_verb_wire::llm::budget::rsi::{RsiLine, RsiResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Reservation {
    amount: u64,
    line: RsiLine,
    purpose: Option<RsiSpendPurpose>,
    share: Option<String>,
    settlement: Option<RsiSettlement>,
    overdraft: Option<RsiOverdraftReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Line {
    config: RsiBudgetConfig,
    suspended: bool,
    reservations: BTreeMap<String, Reservation>,
}

impl Line {
    fn usage(
        &self,
        line: RsiLine,
        accepts: impl Fn(&Reservation) -> bool,
    ) -> RsiResult<(u64, u64)> {
        let (mut spent, mut reserved) = (0u64, 0u64);
        for row in self.reservations.values().filter(|row| accepts(row)) {
            let amount = match (row.line, &row.settlement) {
                (RsiLine::Tokens, Some(RsiSettlement::Spent(amount)))
                | (RsiLine::Exposure, Some(RsiSettlement::Exposure(amount))) => Some(*amount),
                (RsiLine::Tokens, Some(RsiSettlement::Unknown))
                | (_, None)
                | (_, Some(RsiSettlement::Refunded)) => None,
                _ => return Err(crate::Error::CorruptedIndex("RSI budget settlement line").into()),
            };
            if row.line != line {
                continue;
            }
            if let Some(amount) = amount {
                spent = spent.checked_add(amount).ok_or(RsiBudgetError::Exhausted)?;
            } else if row.settlement.is_none() || row.settlement == Some(RsiSettlement::Unknown) {
                reserved = reserved
                    .checked_add(row.amount)
                    .ok_or(RsiBudgetError::Exhausted)?;
            }
        }
        Ok((spent, reserved))
    }
    /// Only token reservations draw from shares and their unallocated pool.
    /// Exploration is an independent exposure line, not a token-share debit.
    fn free_pool_usage(&self) -> RsiResult<u64> {
        let mut by_share = BTreeMap::<&str, u64>::new();
        let mut free_used = 0u64;
        for row in self
            .reservations
            .values()
            .filter(|row| row.line == RsiLine::Tokens)
        {
            let units = match row.settlement {
                Some(RsiSettlement::Spent(units)) => units,
                Some(RsiSettlement::Refunded) => 0,
                None | Some(RsiSettlement::Unknown) => row.amount,
                Some(RsiSettlement::Exposure(_)) => {
                    return Err(crate::Error::CorruptedIndex("RSI token settlement line").into());
                }
            };
            if let Some(share) = row.share.as_deref() {
                let total = by_share.entry(share).or_default();
                *total = total.checked_add(units).ok_or(RsiBudgetError::Exhausted)?;
            } else {
                free_used = free_used
                    .checked_add(units)
                    .ok_or(RsiBudgetError::Exhausted)?;
            }
        }
        for (key, used) in by_share {
            let allocation = self.config.shares.get(key).map_or(0, |share| share.units);
            free_used = free_used
                .checked_add(used.saturating_sub(allocation))
                .ok_or(RsiBudgetError::Exhausted)?;
        }
        Ok(free_used)
    }

    fn free_pool_limit(&self) -> RsiResult<u64> {
        let allocated = self.config.shares.values().try_fold(0u64, |total, share| {
            total
                .checked_add(share.units)
                .ok_or(RsiBudgetError::Exhausted)
        })?;
        self.config
            .limit
            .checked_sub(allocated)
            .ok_or(RsiBudgetError::Exhausted)
    }

    fn has_room(
        &self,
        line: RsiLine,
        limit: u64,
        amount: u64,
        accepts: impl Fn(&Reservation) -> bool,
    ) -> RsiResult<()> {
        let (spent, reserved) = self.usage(line, accepts)?;
        if spent
            .checked_add(reserved)
            .and_then(|n| n.checked_add(amount))
            .is_none_or(|total| total > limit)
        {
            return Err(RsiBudgetError::Exhausted);
        }
        Ok(())
    }
}

/// The install's signing keys for a token reservation under a share, which
/// may overdraw it: an overdraft is signed by this install's device key, and
/// its keys load before the write transaction, as every signing door's do. A
/// failure refuses only a reservation that overdraws.
pub(crate) struct RsiSigning(Option<crate::Result<()>>);

impl RsiSigning {
    /// No overdraft can arise: an exposure reservation, or tokens under no
    /// share.
    pub(crate) fn none() -> Self {
        Self(None)
    }
}

/// A token reservation's own terms: what it is for, the share it draws on,
/// and the signing keys loaded for a possible overdraft.
struct TokenTerms {
    purpose: RsiSpendPurpose,
    share: Option<String>,
    signing: RsiSigning,
}

fn load(vault: &Vault, txn: &heed::RoTxn<'_>) -> RsiResult<Line> {
    RSI_LINE
        .get(&vault.store, txn, &())?
        .ok_or(RsiBudgetError::Unconfigured)
}
fn save(vault: &Vault, txn: &mut heed::RwTxn<'_>, line: &Line) -> RsiResult<()> {
    RSI_LINE.put(&vault.store, txn, &(), line)?;
    Ok(())
}

/// Refuses a top-up that raises by nothing, before any read.
fn refuse_zero_raise(top_up: &RsiTopUp) -> RsiResult<()> {
    let units = match top_up {
        RsiTopUp::Tokens { units, .. }
        | RsiTopUp::Exploration { units, .. }
        | RsiTopUp::Share { units, .. } => *units,
    };
    if units == 0 {
        return Err(RsiBudgetError::InvalidConfig);
    }
    Ok(())
}

/// Raises the one limiting line `top_up` names on `line`, in memory: an
/// overflow, an unknown share, or shares past the token limit refuse.
fn raise_line(line: &mut Line, top_up: &RsiTopUp) -> RsiResult<()> {
    match top_up {
        RsiTopUp::Tokens { units, .. } => {
            line.config.limit = line
                .config
                .limit
                .checked_add(*units)
                .ok_or(RsiBudgetError::InvalidConfig)?;
        }
        RsiTopUp::Exploration { units, .. } => {
            line.config.exploration_exposure_limit = line
                .config
                .exploration_exposure_limit
                .checked_add(*units)
                .ok_or(RsiBudgetError::InvalidConfig)?;
        }
        RsiTopUp::Share { share, units, .. } => {
            let row = line
                .config
                .shares
                .get_mut(share)
                .ok_or(RsiBudgetError::InvalidConfig)?;
            row.units = row
                .units
                .checked_add(*units)
                .ok_or(RsiBudgetError::InvalidConfig)?;
            let allocated = line
                .config
                .shares
                .values()
                .try_fold(0u64, |total, share| total.checked_add(share.units));
            if allocated.is_none_or(|allocated| allocated > line.config.limit) {
                return Err(RsiBudgetError::InvalidConfig);
            }
        }
    }
    Ok(())
}

impl Vault {
    /// Creates the line once. Reconfiguration cannot erase receipts or spend.
    pub fn configure_rsi_budget(&self, config: RsiBudgetConfig) -> RsiResult<()> {
        if config
            .shares
            .iter()
            .any(|(key, share)| key.is_empty() || share.units > config.limit)
            || config
                .shares
                .values()
                .try_fold(0u64, |total, share| total.checked_add(share.units))
                .is_none_or(|allocated| allocated > config.limit)
        {
            return Err(RsiBudgetError::InvalidConfig);
        }
        let mut txn = self.store.env.write_txn()?;
        if RSI_LINE.contains(&self.store, &txn, &())? {
            return Err(RsiBudgetError::InvalidConfig);
        }
        save(
            self,
            &mut txn,
            &Line {
                config,
                suspended: false,
                reservations: BTreeMap::new(),
            },
        )?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// The configured lines and shares, exactly as the owner set them.
    pub fn rsi_budget_config(&self) -> RsiResult<RsiBudgetConfig> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        Ok(load(self, &txn)?.config)
    }

    /// Raises one exact limiting line inside the write that stores it.
    /// Receipts, spend and the suspension hold are untouched: resuming held
    /// work is a separate owner act.
    pub fn top_up_rsi_budget(&self, top_up: RsiTopUp) -> RsiResult<RsiBudgetConfig> {
        refuse_zero_raise(&top_up)?;
        let mut txn = self.store.env.write_txn()?;
        let mut line = load(self, &txn)?;
        raise_line(&mut line, &top_up)?;
        let config = line.config.clone();
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(config)
    }

    /// [`Self::top_up_rsi_budget`] as the owner door's act: raising a
    /// limiting line is the act that checks in (act class `spend_over_cap`,
    /// named at the door; P25-SHAPE Q4 = A). The owner's proof is rechecked
    /// in the writer; the owner's own raise goes on that proof, and with
    /// `applied` the owner applies an asker's approved check-in for exactly
    /// this raise, spent in this writer after every refusal, so a refused
    /// raise leaves it unspent (2k10b). Returns the decision.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds; the top-up's refusals; a check-in that
    /// does not apply.
    pub(crate) fn top_up_rsi_budget_with_check_in(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        top_up: &RsiTopUp,
        applied: Option<&crate::check_in::AppliedCheckIn<'_>>,
    ) -> RsiResult<crate::check_in::CheckInDecision> {
        refuse_zero_raise(top_up)?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let mut line = load(self, &txn)?;
        raise_line(&mut line, top_up)?;
        let decision = crate::check_in::owner_act_decision_in_txn(
            self,
            &mut txn,
            crate::check_in::ActClass::SpendOverCap,
            applied,
        )?;
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(decision)
    }

    /// Reserve token-denominated loop spend; this cannot debit exploration exposure.
    pub fn reserve_rsi_budget(
        &self,
        id: EntityId,
        units: u64,
        purpose: RsiSpendPurpose,
        share: Option<String>,
    ) -> RsiResult<()> {
        let signing = self.rsi_token_signing(share.as_deref());
        self.reserve_rsi_line(
            id,
            units,
            Some(TokenTerms {
                purpose,
                share,
                signing,
            }),
        )
    }

    /// Reserve exposure for a bandit slice, independently of token spend.
    pub fn reserve_rsi_exploration(&self, id: EntityId, exposure: u64) -> RsiResult<()> {
        self.reserve_rsi_line(id, exposure, None)
    }

    /// Loads the signing keys a token reservation under `share` may need,
    /// before its write transaction opens.
    pub(crate) fn rsi_token_signing(&self, share: Option<&str>) -> RsiSigning {
        RsiSigning(
            share
                .is_some()
                .then(|| self.prepare_install_signing().map(|_| ())),
        )
    }

    /// [`Self::reserve_rsi_budget`] inside the caller's write, with the
    /// signing keys [`Self::rsi_token_signing`] loaded before it. An
    /// exhausted line's suspension is written into `txn` with the
    /// `Exhausted` refusal, for the caller to commit.
    pub(crate) fn reserve_rsi_budget_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        units: u64,
        purpose: RsiSpendPurpose,
        share: Option<String>,
        signing: RsiSigning,
    ) -> RsiResult<()> {
        self.reserve_rsi_line_in_txn(
            txn,
            id,
            units,
            Some(TokenTerms {
                purpose,
                share,
                signing,
            }),
        )
    }

    /// [`Self::reserve_rsi_exploration`] inside the caller's write; an
    /// exhausted line's suspension is written as
    /// [`Self::reserve_rsi_budget_in_txn`]'s is.
    pub(crate) fn reserve_rsi_exploration_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        exposure: u64,
    ) -> RsiResult<()> {
        self.reserve_rsi_line_in_txn(txn, id, exposure, None)
    }

    fn reserve_rsi_line(
        &self,
        id: EntityId,
        amount: u64,
        tokens: Option<TokenTerms>,
    ) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn()?;
        let reserved = self.reserve_rsi_line_in_txn(&mut txn, id, amount, tokens);
        // An exhausted line keeps its suspension with the refusal.
        if matches!(reserved, Ok(()) | Err(RsiBudgetError::Exhausted)) {
            txn.commit().map_err(crate::Error::from)?;
        }
        reserved
    }

    /// One reservation on the token line (`tokens` names its terms) or the
    /// exposure line, in `txn`. `Exhausted` leaves the line suspended in
    /// `txn`; any other refusal writes nothing.
    fn reserve_rsi_line_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        amount: u64,
        tokens: Option<TokenTerms>,
    ) -> RsiResult<()> {
        let (kind, purpose, share, signing) = match tokens {
            Some(TokenTerms {
                purpose,
                share,
                signing,
            }) => (RsiLine::Tokens, Some(purpose), share, signing.0),
            None => (RsiLine::Exposure, None, None, None),
        };
        let mut line = load(self, txn)?;
        if line.suspended {
            return Err(RsiBudgetError::Suspended);
        }
        if line.reservations.contains_key(&id.to_hex()) {
            return Err(RsiBudgetError::DuplicateReservation);
        }
        let pool_before = if kind == RsiLine::Tokens {
            Some(line.free_pool_usage()?)
        } else {
            None
        };
        let key = id.to_hex();
        line.reservations.insert(
            key.clone(),
            Reservation {
                amount,
                line: kind,
                purpose,
                share: share.clone(),
                settlement: None,
                overdraft: None,
            },
        );
        let admission = (|| {
            let limit = match kind {
                RsiLine::Tokens => line.config.limit,
                RsiLine::Exposure => line.config.exploration_exposure_limit,
            };
            line.has_room(kind, limit, 0, |_| true)?;
            if kind == RsiLine::Tokens {
                if let Some(share) = &share
                    && let Some(policy) = line.config.shares.get(share)
                    && policy.pinned
                {
                    line.has_room(kind, policy.units, 0, |row| {
                        row.share.as_ref() == Some(share)
                    })?;
                }
                let pool_after = line.free_pool_usage()?;
                if pool_after > line.free_pool_limit()? {
                    return Err(RsiBudgetError::Exhausted);
                }
                if let Some(share) = &share
                    && !line
                        .config
                        .shares
                        .get(share)
                        .is_some_and(|policy| policy.pinned)
                {
                    let overdrawn = pool_after
                        - pool_before.ok_or(crate::Error::InvariantViolation(
                            "RSI token pool missing before admission",
                        ))?;
                    if overdrawn > 0 {
                        return Ok(Some((share.clone(), overdrawn)));
                    }
                }
            }
            Ok(None)
        })();
        match admission {
            Ok(overdraft) => {
                let overdraft = match overdraft {
                    Some((share, units)) => {
                        match signing {
                            Some(Ok(())) => {}
                            Some(Err(error)) => return Err(error.into()),
                            None => {
                                return Err(crate::Error::InvariantViolation(
                                    "an RSI overdraft without a share",
                                )
                                .into());
                            }
                        }
                        Some(self.sign_rsi_overdraft_in_txn(txn, id, share, units)?)
                    }
                    None => None,
                };
                let row =
                    line.reservations
                        .get_mut(&key)
                        .ok_or(crate::Error::InvariantViolation(
                            "RSI reservation missing after admission",
                        ))?;
                row.overdraft = overdraft;
            }
            Err(RsiBudgetError::Exhausted) => {
                line.reservations.remove(&key);
                line.suspended = true;
                save(self, txn, &line)?;
                return Err(RsiBudgetError::Exhausted);
            }
            Err(other) => return Err(other),
        }
        save(self, txn, &line)?;
        Ok(())
    }

    /// Settle token spend once, releasing unused reserved tokens.
    pub fn settle_rsi_budget(&self, id: EntityId, spent: u64) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Spent(spent))
    }

    /// Settle exploration exposure once, releasing unused reserved exposure.
    pub fn settle_rsi_exploration(&self, id: EntityId, exposure: u64) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Exposure(exposure))
    }

    /// Refunds an unspent reservation. Settled spend cannot be erased.
    pub fn refund_rsi_budget(&self, id: EntityId) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Refunded)
    }

    fn finish_rsi_reservation(&self, id: EntityId, settlement: RsiSettlement) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn()?;
        self.finish_rsi_reservation_in_txn(&mut txn, id, settlement)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// Settle or refund one reservation inside the caller's write: spent
    /// tokens (or unknown) on the token line, exposure on the exposure line,
    /// a refund on either. A refusal writes nothing.
    pub(crate) fn finish_rsi_reservation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        settlement: RsiSettlement,
    ) -> RsiResult<()> {
        let mut line = load(self, txn)?;
        let row = line
            .reservations
            .get_mut(&id.to_hex())
            .ok_or(RsiBudgetError::ReservationRequired)?;
        if !matches!(
            (row.line, &settlement),
            (
                RsiLine::Tokens,
                RsiSettlement::Spent(_) | RsiSettlement::Unknown
            ) | (RsiLine::Exposure, RsiSettlement::Exposure(_))
                | (_, RsiSettlement::Refunded)
        ) {
            return Err(RsiBudgetError::WrongLine);
        }
        if let Some(current) = &row.settlement {
            return if *current == settlement {
                Ok(())
            } else {
                Err(RsiBudgetError::ReservationRequired)
            };
        }
        // Token spend already happened: record it whole even past the
        // reservation. Future admission still applies the configured caps.
        if let RsiSettlement::Exposure(amount) = settlement
            && amount > row.amount
        {
            return Err(RsiBudgetError::Exhausted);
        }
        row.settlement = Some(settlement);
        save(self, txn, &line)?;
        Ok(())
    }

    /// A suspension holds new work; admitted work can still settle honestly.
    pub fn suspend_rsi_budget(&self, suspended: bool) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn()?;
        let mut line = load(self, &txn)?;
        line.suspended = suspended;
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// Releases the hold on new loop work; admitted work may already settle while held.
    pub fn resume_rsi_budget(&self) -> RsiResult<()> {
        self.suspend_rsi_budget(false)
    }

    pub fn rsi_budget(&self) -> RsiResult<RsiBudgetRead> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        let (spent, reserved) = line.usage(RsiLine::Tokens, |_| true)?;
        Ok(RsiBudgetRead {
            limit: line.config.limit,
            spent,
            reserved,
            suspended: line.suspended,
        })
    }

    /// Reads the exposure line without adding token spend to it.
    pub fn rsi_exploration(&self) -> RsiResult<RsiExplorationRead> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        let (spent_exposure, reserved_exposure) = line.usage(RsiLine::Exposure, |_| true)?;
        Ok(RsiExplorationRead {
            exposure_limit: line.config.exploration_exposure_limit,
            spent_exposure,
            reserved_exposure,
            suspended: line.suspended,
        })
    }

    /// Signs the overdraft of `units` on `share` admitted for `reservation`,
    /// bound to this vault's store, with this install's device key, in the
    /// reservation's own write transaction.
    fn sign_rsi_overdraft_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        reservation: EntityId,
        share: String,
        units: u64,
    ) -> RsiResult<RsiOverdraftReceipt> {
        use ed25519_dalek::Signer;
        let identity = crate::identity::ensure_device_identity_in_txn(self, txn)?;
        let mut receipt = RsiOverdraftReceipt {
            share,
            units,
            reservation: crate::research_budget::hex_lower(reservation.as_bytes()),
            vault: crate::research_budget::hex_lower(self.vault_id().as_bytes()),
            public_key: crate::research_budget::hex_lower(
                &identity.signing_key.verifying_key().to_bytes(),
            ),
            signature: String::new(),
        };
        let signature = identity.signing_key.sign(&receipt.transcript()?);
        receipt.signature = crate::research_budget::hex_lower(&signature.to_bytes());
        Ok(receipt)
    }

    /// Whether `receipt` is a verifiable overdraft receipt of this vault: its
    /// signature holds, it names this vault's store, and its key is this
    /// install's device key.
    ///
    /// # Errors
    /// A store failure.
    pub fn verify_rsi_overdraft(&self, receipt: &RsiOverdraftReceipt) -> RsiResult<bool> {
        if !receipt.verify()
            || receipt.vault != crate::research_budget::hex_lower(self.vault_id().as_bytes())
        {
            return Ok(false);
        }
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let device = crate::identity::read_device_verifying_key_in_txn(self, &txn)?;
        Ok(device.is_some_and(|key| receipt.public_key == crate::research_budget::hex_lower(&key)))
    }

    /// Reads the token-share overdraft stamped at reservation, including after settlement.
    pub fn rsi_overdraft(&self, id: EntityId) -> RsiResult<Option<RsiOverdraftReceipt>> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        Ok(line
            .reservations
            .get(&id.to_hex())
            .and_then(|row| row.overdraft.clone()))
    }

    /// Reads the terminal receipt without exposing another vault's key material.
    pub fn rsi_settlement(&self, id: EntityId) -> RsiResult<Option<RsiSettlement>> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        Ok(line
            .reservations
            .get(&id.to_hex())
            .and_then(|row| row.settlement.clone()))
    }
}

pub use crate::research_budget::{
    RsiBudgetConfig, RsiBudgetError, RsiBudgetRead, RsiBudgetShare, RsiExplorationRead,
    RsiOverdraftReceipt, RsiSettlement, RsiSpendPurpose, RsiTopUp,
};
