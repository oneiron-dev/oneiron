//! A market's lease unit ([MARKET-SEAT-LEASE-UNIT]; Engine ANSWER
//! MARKET-SEAT-LEASE-UNIT = A, 28 Nov).
//!
//! ARCH-0079 #market compares patterns "at equal lease". A seat on a
//! subscription reports no price, and the engine never observes an attached
//! seat's own turns, so the one unit it meters the same on every harness is
//! the GPU second: a unit claim's machine-signed end charges
//! `min(billed, reserved)` seconds when it settles. A market's pool and its
//! shares count in GPU seconds, and each verdict, sealed or screen, spends
//! the seconds its referee run charged from the submitting member's share,
//! in the verdict's own write. A member whose share cannot pay is refused
//! that verdict with nothing written: the market's own ledger rations it.
//! Seat time stays free. A market opened before the unit was recorded states
//! none and spends nothing.

use super::{LedgerKind, Market};
use crate::gpu_line::{ClaimState, UnitClaim};
use crate::team::run::{TeamLeaseUnit, TeamMarketLeaseView, TeamMarketSpend};

/// The unit a market opens in when its terms name none.
pub const DEFAULT_LEASE_UNIT: TeamLeaseUnit = TeamLeaseUnit::GpuSeconds;

/// The seconds `claim`'s end charged; none before it ends.
fn charged_secs(claim: &UnitClaim) -> u64 {
    match &claim.state {
        ClaimState::Ended(terminal) => terminal.charged_secs,
        ClaimState::Claimed | ClaimState::Started => 0,
    }
}

/// Spends what the referee run `claim` charged from the share of the member
/// whose submission is `index`, as one Spend line at `now`. `None` for a
/// verdict whose evidence did not hold (no claim: the market buys it
/// nothing) and for a market that states no unit. Refused with the market
/// untouched when the member's share cannot pay it
/// (`team_market_share_spent`); a retired member's share went back to the
/// bounty.
pub(super) fn charge_verdict(
    market: &mut Market,
    index: usize,
    claim: Option<&UnitClaim>,
    now: u64,
) -> std::result::Result<Option<TeamMarketSpend>, &'static str> {
    let (Some(claim), Some(unit)) = (claim, market.unit) else {
        return Ok(None);
    };
    let charged = charged_secs(claim);
    let agent = market.submissions[index].agent.clone();
    let Some(member) = market.participants.get_mut(&agent) else {
        return Err("team_market_outside_team");
    };
    let left = (member.share + member.earned).saturating_sub(member.spent);
    if charged > left.saturating_add(u64::MAX) {
        return Err("team_market_share_spent");
    }
    member.spent += charged;
    market.post(now, Some(&agent), LedgerKind::Spend, charged);
    Ok(Some(TeamMarketSpend {
        unit,
        charged,
        left: left.saturating_sub(charged),
    }))
}

/// Each member's share, spend and what it has left, in member key order.
pub(super) fn lease_views(market: &Market) -> Vec<TeamMarketLeaseView> {
    market
        .participants
        .iter()
        .map(|(participant, member)| TeamMarketLeaseView {
            participant: participant.clone(),
            share: member.share,
            spent: member.spent,
            earned: member.earned,
            left: (member.share + member.earned).saturating_sub(member.spent),
        })
        .collect()
}
