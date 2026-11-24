//! Which selected allocation a host-paid call holds on (row M2-I,
//! allocations by wallet). A host account selects one live allocation per
//! slot, a slot being a unit and the wallet the host named for it. One rule
//! for the in-memory [`super::HostAccount`] and the durable allocation
//! ledger, judged before anything is reserved:
//!
//! - A run an owner's agent Grant funds (FIX 7766) looks only at the slots
//!   of that Grant's wallet, compared byte for byte.
//! - The unit: a slot in the call's own unit first, else the one unit the
//!   call's rates price. Rates that price two selected units name no choice.
//! - Inside that unit an unfunded run takes the only slot, else the host's
//!   walletless one.
//! - No fallback: the slot chosen here holds or refuses the call. An
//!   exhausted or closed slot never sends it to another unit or wallet.
use super::declaration::LeaseUnit;
use super::host::UnitRate;
use crate::federation::WalletRef;

/// One selected allocation's slot: its unit and the wallet the host named.
#[derive(Debug, Clone, Copy)]
pub(super) struct Slot<'a> {
    pub(super) unit: &'a LeaseUnit,
    pub(super) wallet: Option<&'a WalletRef>,
}

/// Why no selected allocation can hold a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SlotMiss {
    /// The account selects no allocation.
    Empty,
    /// The run's Grant names wallet `expected`, and no selected allocation
    /// the call can draw on is of it. `live` is the wallet of the allocation
    /// the call would hold with no Grant, when there is one.
    Wallet {
        expected: WalletRef,
        live: Option<WalletRef>,
    },
    /// No rate converts the call into the unit of any allocation it may
    /// hold on; `to` is the first such allocation's unit.
    Unpriced { to: LeaseUnit },
    /// Several allocations could hold the call and the host named none of
    /// them: two units its rates price, or two wallets' allocations in its
    /// unit with no walletless one.
    Ambiguous { units: Vec<LeaseUnit> },
}

/// The index in `slots` of the allocation a call in `native` units, priced
/// by `rates`, holds on, for a run funded by `funding`'s wallet or by none.
pub(super) fn select(
    slots: &[Slot<'_>],
    native: &LeaseUnit,
    rates: &[UnitRate],
    funding: Option<&WalletRef>,
) -> Result<usize, SlotMiss> {
    if slots.is_empty() {
        return Err(SlotMiss::Empty);
    }
    let candidates: Vec<usize> = (0..slots.len())
        .filter(|&index| funding.is_none_or(|wallet| slots[index].wallet == Some(wallet)))
        .collect();
    // What the call would hold with no Grant, named in a wallet refusal.
    let unfunded_wallet = || {
        select(slots, native, rates, None)
            .ok()
            .and_then(|index| slots[index].wallet.cloned())
    };
    let Some(&first) = candidates.first() else {
        // Only a Grant's wallet leaves no candidate: an unfunded run sees
        // every slot, and there is at least one.
        return Err(match funding {
            Some(expected) => SlotMiss::Wallet {
                expected: expected.clone(),
                live: unfunded_wallet(),
            },
            None => SlotMiss::Empty,
        });
    };
    let in_native: Vec<usize> = candidates
        .iter()
        .copied()
        .filter(|&index| slots[index].unit == native)
        .collect();
    let in_unit = if in_native.is_empty() {
        let priced: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|&index| {
                rates
                    .iter()
                    .any(|rate| rate.unit == *slots[index].unit && rate.per > 0)
            })
            .collect();
        let mut units: Vec<LeaseUnit> = Vec::new();
        for &index in &priced {
            if !units.contains(slots[index].unit) {
                units.push(slots[index].unit.clone());
            }
        }
        match units.len() {
            0 => {
                // The Grant's wallet holds nothing the call can draw on
                // while another wallet's allocation is in its unit or
                // priced for it: the wallet refuses it, also when the
                // unfunded choice would be ambiguous. The unfunded probe
                // only names the wallet the call would hold on.
                let drawable_elsewhere = slots.iter().any(|slot| {
                    slot.unit == native
                        || rates
                            .iter()
                            .any(|rate| rate.unit == *slot.unit && rate.per > 0)
                });
                return Err(match funding {
                    Some(expected) if drawable_elsewhere => SlotMiss::Wallet {
                        expected: expected.clone(),
                        live: unfunded_wallet(),
                    },
                    _ => SlotMiss::Unpriced {
                        to: slots[first].unit.clone(),
                    },
                });
            }
            1 => priced,
            _ => return Err(SlotMiss::Ambiguous { units }),
        }
    } else {
        in_native
    };
    match in_unit.as_slice() {
        [only] => Ok(*only),
        several => several
            .iter()
            .copied()
            .find(|&index| slots[index].wallet.is_none())
            .ok_or_else(|| SlotMiss::Ambiguous {
                units: vec![slots[several[0]].unit.clone()],
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str) -> LeaseUnit {
        LeaseUnit::new(name).expect("unit")
    }

    fn wallet(id: &str) -> WalletRef {
        WalletRef {
            issuer: "host".to_owned(),
            id: id.to_owned(),
        }
    }

    #[test]
    fn the_native_unit_wins_and_a_second_priced_unit_is_no_choice() {
        let (money, gpu, tokens) = (unit("micro_usd"), unit("gpu_seconds"), unit("tokens"));
        let lane = wallet("lane");
        let slots = [
            Slot {
                unit: &money,
                wallet: None,
            },
            Slot {
                unit: &gpu,
                wallet: Some(&lane),
            },
        ];
        let in_money = [UnitRate {
            unit: money.clone(),
            per: 1,
            cost: 1,
        }];
        assert_eq!(select(&slots, &gpu, &in_money, None), Ok(1));
        assert_eq!(select(&slots, &tokens, &in_money, None), Ok(0));
        let both = [
            in_money[0].clone(),
            UnitRate {
                unit: gpu.clone(),
                per: 1,
                cost: 1,
            },
        ];
        assert_eq!(
            select(&slots, &tokens, &both, None),
            Err(SlotMiss::Ambiguous {
                units: vec![money.clone(), gpu.clone()]
            })
        );
        assert_eq!(
            select(&slots, &tokens, &[], None),
            Err(SlotMiss::Unpriced { to: money.clone() })
        );
        // The lane's Grant sees only its line: tokens priced in money are
        // not its wallet's, and the money allocation names no wallet.
        assert_eq!(
            select(&slots, &tokens, &in_money, Some(&lane)),
            Err(SlotMiss::Wallet {
                expected: lane.clone(),
                live: None
            })
        );
        assert_eq!(select(&slots, &gpu, &[], Some(&lane)), Ok(1));
        assert_eq!(select(&[], &gpu, &[], None), Err(SlotMiss::Empty));
    }

    /// Review 10403 P1-3: a funded call whose Grant's wallet holds nothing
    /// it can draw on is the wallet's refusal, also when the unfunded choice
    /// between two other wallets would be ambiguous.
    #[test]
    fn a_funded_call_with_nothing_in_its_wallet_is_refused_by_the_wallet() {
        let (money, gpu) = (unit("micro_usd"), unit("gpu_seconds"));
        let (a, b, c) = (wallet("a"), wallet("b"), wallet("c"));
        let slots = [
            Slot {
                unit: &gpu,
                wallet: Some(&a),
            },
            Slot {
                unit: &money,
                wallet: Some(&b),
            },
            Slot {
                unit: &money,
                wallet: Some(&c),
            },
        ];
        assert_eq!(
            select(&slots, &money, &[], None),
            Err(SlotMiss::Ambiguous {
                units: vec![money.clone()]
            })
        );
        assert_eq!(
            select(&slots, &money, &[], Some(&a)),
            Err(SlotMiss::Wallet {
                expected: a.clone(),
                live: None
            })
        );
        let tokens = unit("tokens");
        assert_eq!(
            select(&slots, &tokens, &[], Some(&a)),
            Err(SlotMiss::Unpriced { to: gpu.clone() }),
            "a call no allocation can draw on stays a unit mismatch"
        );
    }
}
