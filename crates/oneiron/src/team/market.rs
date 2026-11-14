//! The MARKET pattern's ledger (ARCH-0079 #market, OF-540).
//!
//! A market's referee is a rule signed before the work: a test suite, a
//! holdout or a pinned judge. It decides without an opinion of its own, and a
//! score counts only when it carries that signed rule's digest. Inside one
//! run, the central ledger mints the run's lease into shares and a bounty;
//! agents spend their share, the referee scores submissions, and the bounty
//! goes to the winner. Three modes: M1 bounty; M2 halving plus wildcard,
//! where each round keeps the top half and protected exploration keeps a
//! wildcard; M3 islands, where an agent may pay from its share to peek at
//! another island's submissions. Price markets are rejected: nothing here
//! bids or prices.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// Markets, by team reference.
const MARKET: SideTable<String, Market, Named> = SideTable::new(&side_table::TEAM_MARKET);

/// Longest reference kept.
const MAX_REF_BYTES: usize = 256;

/// The share of the pool held back as the bounty when the caller names none.
pub const DEFAULT_BOUNTY_SHARE: f64 = 0.2;

#[doc(hidden)]
pub use oneiron_records::team::market::{
    LedgerEntry, LedgerKind, Market, MarketMode, MarketResult, Participant, RefereeKind,
    SignedReferee, Submission,
};

fn bounded(text: &str, what: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_BYTES || text.contains('\0') {
        return Err(Error::InvalidClaimBody(what));
    }
    Ok(())
}

fn update<T>(vault: &Vault, team_ref: &str, f: impl FnOnce(&mut Market) -> Result<T>) -> Result<T> {
    vault.with_write_txn_grouped(|wtxn| {
        let mut market = MARKET
            .get(&vault.store, wtxn, &team_ref.to_owned())?
            .ok_or(Error::EntityNotFound)?;
        let out = f(&mut market)?;
        MARKET.put(&vault.store, wtxn, &market.team_ref, &market)?;
        Ok(out)
    })
}

/// Opens a market: mints the run's `pool`, holds back the bounty, grants the
/// rest as equal shares (islands assigned in turn) and records the referee.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the referee was not signed before the
/// market opens, the agents are empty, repeated or too many, the bounty
/// share is outside [0, 1), or a market already exists for the run; storage
/// errors.
pub fn open_market(
    vault: &Vault,
    team_ref: &str,
    mode: MarketMode,
    referee: SignedReferee,
    pool: u64,
    bounty_share: f64,
    agents: &[String],
    protected: &[String],
    now: u64,
) -> Result<Market> {
    bounded(team_ref, "a team reference is 1..=256 bytes without NUL")?;
    bounded(
        &referee.rule_ref,
        "a referee rule is 1..=256 bytes without NUL",
    )?;
    bounded(
        &referee.digest,
        "a referee digest is 1..=256 bytes without NUL",
    )?;
    if referee.signed_at > now {
        return Err(Error::InvalidClaimBody(
            "a market's referee is signed before the work",
        ));
    }
    if !(0.0..1.0).contains(&bounty_share) {
        return Err(Error::InvalidClaimBody("a bounty share lies in [0, 1)"));
    }
    // A market has no agent cap (ARCH-0079: width has no count cap).
    if agents.is_empty() {
        return Err(Error::InvalidClaimBody("a market holds at least one agent"));
    }
    if let MarketMode::Islands { islands, .. } = mode
        && islands == 0
    {
        return Err(Error::InvalidClaimBody("an island market has an island"));
    }
    let mut participants = BTreeMap::new();
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let granted = ((pool as f64) * (1.0 - bounty_share)).floor() as u64;
    let share = granted / agents.len() as u64;
    for (i, agent) in agents.iter().enumerate() {
        bounded(agent, "an agent reference is 1..=256 bytes without NUL")?;
        let island = match mode {
            #[allow(clippy::cast_possible_truncation)]
            MarketMode::Islands { islands, .. } => Some((i as u32) % islands),
            _ => None,
        };
        let fresh = Participant {
            share,
            spent: 0,
            earned: 0,
            island,
            active: true,
            protected: protected.contains(agent),
        };
        if participants.insert(agent.clone(), fresh).is_some() {
            return Err(Error::InvalidClaimBody("an agent joins a market once"));
        }
    }
    let mut market = Market {
        team_ref: team_ref.to_owned(),
        mode,
        referee,
        pool,
        bounty: pool - share * agents.len() as u64,
        participants,
        submissions: Vec::new(),
        ledger: Vec::new(),
        round: 0,
        opened_at: now,
        result: None,
    };
    market.post(now, None, LedgerKind::Mint, pool);
    for agent in agents {
        market.post(now, Some(agent), LedgerKind::Grant, share);
    }
    vault.with_write_txn_grouped(|wtxn| {
        if MARKET.contains(&vault.store, wtxn, &market.team_ref)? {
            return Err(Error::InvalidClaimBody("a run opens one market"));
        }
        MARKET.put(&vault.store, wtxn, &market.team_ref, &market)?;
        Ok(())
    })?;
    Ok(market)
}

/// Spends `units` from an agent's run-local share. The share is the limit.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] past the share, for an unknown or retired
/// agent, or on a closed market; storage errors.
pub fn spend_share(
    vault: &Vault,
    team_ref: &str,
    agent: &str,
    units: u64,
    now: u64,
) -> Result<u64> {
    update(vault, team_ref, |market| {
        let p = market.open_participant(agent)?;
        let left = (p.share + p.earned).saturating_sub(p.spent);
        if units > left {
            return Err(Error::InvalidClaimBody(
                "a spend never exceeds the agent's share",
            ));
        }
        p.spent += units;
        let left = left - units;
        market.post(now, Some(agent), LedgerKind::Spend, units);
        Ok(left)
    })
}

/// Records a submission. Every submission postdates the signed referee.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for an unknown or retired agent, a closed
/// market or a malformed reference; storage errors.
pub fn submit(
    vault: &Vault,
    team_ref: &str,
    agent: &str,
    submission_ref: &str,
    now: u64,
) -> Result<()> {
    bounded(
        submission_ref,
        "a submission reference is 1..=256 bytes without NUL",
    )?;
    update(vault, team_ref, |market| {
        market.open_participant(agent)?;
        if now < market.referee.signed_at {
            return Err(Error::InvalidClaimBody(
                "no submission predates the signed referee",
            ));
        }
        market.submissions.push(Submission {
            agent: agent.to_owned(),
            submission_ref: submission_ref.to_owned(),
            at: now,
            score: None,
            passed: None,
        });
        Ok(())
    })
}

/// Pays the peek price from an agent's share to read another island's
/// submissions; the island's active members split the price. Returns the
/// island's submission references.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] outside an island market, for its own island,
/// past the share, or for an unknown island; storage errors.
pub fn peek_island(
    vault: &Vault,
    team_ref: &str,
    agent: &str,
    island: u32,
    now: u64,
) -> Result<Vec<String>> {
    update(vault, team_ref, |market| {
        let MarketMode::Islands {
            islands,
            peek_price,
        } = market.mode
        else {
            return Err(Error::InvalidClaimBody("only an island market sells peeks"));
        };
        if island >= islands {
            return Err(Error::InvalidClaimBody("no such island"));
        }
        let p = market.open_participant(agent)?;
        if p.island == Some(island) {
            return Err(Error::InvalidClaimBody(
                "an agent reads its own island free",
            ));
        }
        if (p.share + p.earned).saturating_sub(p.spent) < peek_price {
            return Err(Error::InvalidClaimBody(
                "a peek is paid from the agent's share",
            ));
        }
        p.spent += peek_price;
        market.post(
            now,
            Some(agent),
            LedgerKind::PeekPaid { island },
            peek_price,
        );
        let members: Vec<String> = market
            .participants
            .iter()
            .filter(|(_, m)| m.active && m.island == Some(island))
            .map(|(name, _)| name.clone())
            .collect();
        if members.is_empty() {
            market.bounty += peek_price;
        } else {
            let each = peek_price / members.len() as u64;
            let rest = peek_price - each * members.len() as u64;
            for member in &members {
                if let Some(m) = market.participants.get_mut(member) {
                    m.earned += each;
                }
                market.post(now, Some(member), LedgerKind::PeekEarned, each);
            }
            market.bounty += rest;
        }
        Ok(market
            .submissions
            .iter()
            .filter(|s| members.contains(&s.agent))
            .map(|s| s.submission_ref.clone())
            .collect())
    })
}

/// Records the signed referee's scores and pass verdicts. Each score must
/// carry the digest of the rule signed before the work; nobody else's
/// opinion scores a market.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a digest that is not the signed rule's, a
/// non-finite score, an unknown submission or a closed market; storage errors.
pub fn referee_scores(
    vault: &Vault,
    team_ref: &str,
    referee_digest: &str,
    scores: &[(String, f64, bool)],
) -> Result<()> {
    update(vault, team_ref, |market| {
        if market.result.is_some() {
            return Err(Error::InvalidClaimBody("the market is closed"));
        }
        if market.referee.digest != referee_digest {
            return Err(Error::InvalidClaimBody(
                "only the referee signed before the work scores a market",
            ));
        }
        for (submission_ref, score, passed) in scores {
            if !score.is_finite() {
                return Err(Error::InvalidClaimBody("a referee score is finite"));
            }
            let found = market
                .submissions
                .iter_mut()
                .find(|s| s.submission_ref == *submission_ref)
                .ok_or(Error::InvalidClaimBody("no such submission"))?;
            found.score = Some(*score);
            found.passed = Some(*passed);
        }
        Ok(())
    })
}

/// M2's round: keep the top half by best refereed score, plus at least one
/// wildcard for exploration (protected agents first, then the unscored, then
/// the next best). Retired agents' unspent shares return to the bounty.
/// Returns the agents kept.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] outside a halving market or on a closed one;
/// storage errors.
pub fn halving_round(vault: &Vault, team_ref: &str, now: u64) -> Result<Vec<String>> {
    update(vault, team_ref, |market| {
        let MarketMode::HalvingWildcard { wildcard_slots } = market.mode else {
            return Err(Error::InvalidClaimBody("only a halving market runs rounds"));
        };
        if market.result.is_some() {
            return Err(Error::InvalidClaimBody("the market is closed"));
        }
        let best = market.best_scores();
        let mut active: Vec<(String, Option<f64>, bool)> = market
            .participants
            .iter()
            .filter(|(_, p)| p.active)
            .map(|(name, p)| (name.clone(), best.get(name.as_str()).copied(), p.protected))
            .collect();
        active.sort_by(|a, b| {
            b.1.unwrap_or(f64::NEG_INFINITY)
                .total_cmp(&a.1.unwrap_or(f64::NEG_INFINITY))
                .then_with(|| a.0.cmp(&b.0))
        });
        let keep_top = active.len().div_ceil(2);
        let mut kept: Vec<String> = active.iter().take(keep_top).map(|a| a.0.clone()).collect();
        let mut rest: Vec<&(String, Option<f64>, bool)> = active.iter().skip(keep_top).collect();
        // Protected exploration first, then the untried, then the next best.
        rest.sort_by_key(|a| (!a.2, a.1.is_some()));
        // The better half continue, with one wildcard kept.
        kept.extend(
            rest.iter()
                .take((wildcard_slots as usize).max(1))
                .map(|a| a.0.clone()),
        );
        let retired: Vec<String> = active
            .iter()
            .map(|a| a.0.clone())
            .filter(|name| !kept.contains(name))
            .collect();
        for name in &retired {
            let returned = market.participants.get_mut(name).map(|p| {
                p.active = false;
                (p.share + p.earned).saturating_sub(p.spent)
            });
            if let Some(units) = returned {
                if let Some(p) = market.participants.get_mut(name) {
                    p.spent += units;
                }
                market.bounty += units;
                market.post(now, Some(name), LedgerKind::Return, units);
            }
        }
        market.round += 1;
        kept.sort();
        Ok(kept)
    })
}

/// Closes the market: a bounty pays the first submission the signed rule
/// passed (earliest submission time; insertion order breaks equal times),
/// other modes pay the best refereed submission (ties go to the earlier
/// submission). A bounty with no passing submission closes with no winner
/// and keeps its bounty unpaid, as does a market with no scored submission.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] on an already closed market; storage errors.
pub fn close_market(vault: &Vault, team_ref: &str, now: u64) -> Result<MarketResult> {
    update(vault, team_ref, |market| {
        if market.result.is_some() {
            return Err(Error::InvalidClaimBody("the market is closed"));
        }
        let winner = match market.mode {
            MarketMode::Bounty => market
                .submissions
                .iter()
                .enumerate()
                .filter(|(_, s)| s.passed == Some(true))
                .min_by(|(ia, a), (ib, b)| a.at.cmp(&b.at).then_with(|| ia.cmp(ib)))
                .map(|(_, s)| s.clone()),
            _ => market
                .submissions
                .iter()
                .filter(|s| s.score.is_some())
                .max_by(|a, b| {
                    a.score
                        .unwrap_or(f64::NEG_INFINITY)
                        .total_cmp(&b.score.unwrap_or(f64::NEG_INFINITY))
                        .then_with(|| b.at.cmp(&a.at))
                })
                .cloned(),
        };
        let bounty = market.bounty;
        if let Some(win) = &winner {
            if let Some(p) = market.participants.get_mut(&win.agent) {
                p.earned += bounty;
            }
            market.post(now, Some(&win.agent), LedgerKind::Award, bounty);
            market.bounty = 0;
        }
        let result = MarketResult {
            winner: winner.as_ref().map(|w| w.agent.clone()),
            winning_submission: winner.map(|w| w.submission_ref),
            bounty,
            closed_at: now,
        };
        market.result = Some(result.clone());
        Ok(result)
    })
}

/// One run's market, if it opened one.
///
/// # Errors
///
/// Storage errors.
pub fn market(vault: &Vault, team_ref: &str) -> Result<Option<Market>> {
    let rtxn = vault.store.env.read_txn()?;
    MARKET.get(&vault.store, &rtxn, &team_ref.to_owned())
}
