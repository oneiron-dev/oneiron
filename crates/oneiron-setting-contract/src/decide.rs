//! Which stored row a read takes its value from: one order for every key.

use crate::SettingMode;

/// One stored row a read found on its chain.
#[derive(Debug, Clone, PartialEq)]
pub struct FoundRow<V> {
    /// Its scope's place on the chain: 0 is the narrowest.
    pub at: usize,
    /// Whether it is the item's own row; `false` for the item-less row.
    pub item: bool,
    pub mode: SettingMode,
    /// Whether the owner set it.
    pub by_owner: bool,
    /// Its value; `None` when the stored bytes do not decode.
    pub value: Option<V>,
}

/// A learned key's fit at one place on the chain: the fit of the cell that place keys, once that
/// cell has runs of its own.
#[derive(Debug, Clone, PartialEq)]
pub struct FoundFit<V> {
    /// Its scope's place on the chain: 0 is the narrowest.
    pub at: usize,
    pub value: V,
}

impl<V> FoundRow<V> {
    /// Narrowest scope first; at one scope the item's own row first.
    const fn rank(&self) -> (usize, bool) {
        (self.at, !self.item)
    }
}

/// What decided a read.
#[derive(Debug, PartialEq)]
pub enum Decided<'a, V> {
    /// The owner's pin.
    Pin(&'a FoundRow<V>),
    /// A value row.
    Row(&'a FoundRow<V>),
    /// A learned key's fit.
    Fit(&'a FoundFit<V>),
    /// No row: the catalogue default.
    Default,
    /// The deciding row, at this place on the chain, does not decode.
    Unreadable(usize),
}

/// The row that decides a read over `rows`, the rows found on the chain, and `fits`, a learned
/// key's fits on it:
/// 1. the narrowest owner pin; only the owner writes a pin, so any other is passed over;
/// 2. else the narrowest value row, the item's own row before the item-less row at one scope; a
///    learned key's fit at the same scope or a narrower one decides before it, since a learned
///    key's value row is the seed its fit learns from, and a fit is never held inside a row;
/// 3. a row a holder set, on a key that has a comparator (`no_wider(a, b)`: `a` is no wider than
///    `b`; from stage 6.0 only a learned key's read passes one), is held inside the nearest owner
///    value row at its scope or a wider one, and where the owner set none there, inside the
///    catalogue default `default`: the owner's value, else the default, is the cap, and the
///    holder's row stays stored;
/// 4. else the catalogue default.
///
/// A deciding row that does not decode is [`Decided::Unreadable`], never the default; so is an
/// owner's cap row that does not decode, since the holder's row cannot be shown to sit inside it.
#[must_use]
pub fn decide<'a, V>(
    rows: &'a [FoundRow<V>],
    fits: &'a [FoundFit<V>],
    no_wider: Option<&dyn Fn(&V, &V) -> bool>,
    default: Option<&V>,
) -> Decided<'a, V> {
    let narrowest = |mode: SettingMode, owner_only: bool| {
        rows.iter()
            .filter(|row| row.mode == mode && (row.by_owner || !owner_only))
            .min_by_key(|row| row.rank())
    };
    if let Some(pin) = narrowest(SettingMode::Pin, true) {
        return match pin.value {
            Some(_) => Decided::Pin(pin),
            None => Decided::Unreadable(pin.at),
        };
    }
    let row = narrowest(SettingMode::Value, false);
    if let Some(fit) = fits.iter().min_by_key(|fit| fit.at)
        && row.is_none_or(|row| fit.at <= row.at)
    {
        return Decided::Fit(fit);
    }
    let Some(row) = row else {
        return Decided::Default;
    };
    let Some(value) = &row.value else {
        return Decided::Unreadable(row.at);
    };
    let Some(no_wider) = no_wider.filter(|_| !row.by_owner) else {
        return Decided::Row(row);
    };
    let cap = rows
        .iter()
        .filter(|cap| cap.mode == SettingMode::Value && cap.by_owner && cap.at >= row.at)
        .min_by_key(|cap| cap.rank());
    match cap {
        None => match default {
            Some(default) if !no_wider(value, default) => Decided::Default,
            _ => Decided::Row(row),
        },
        Some(cap) => match &cap.value {
            None => Decided::Unreadable(cap.at),
            Some(cap_value) if no_wider(value, cap_value) => Decided::Row(row),
            Some(_) => Decided::Row(cap),
        },
    }
}

/// What a read of a key whose order has a meet takes from its rows ([`decide_met`]).
#[derive(Debug, PartialEq)]
pub enum Met<'a, V> {
    /// The value in force. `by` is the narrowest row that took part and holds that value (a pin
    /// before the value row at its own scope); `None` when no row does: no row took part
    /// (`rows` is 0) and the default stands, or the meet of several rows is a value none of them
    /// holds alone. `rows` counts the rows that took part.
    Value {
        value: V,
        by: Option<&'a FoundRow<V>>,
        rows: usize,
    },
    /// A row that takes part, at this place on the chain, does not decode.
    Unreadable(usize),
}

/// The value of a key whose order has a meet (DESIGN 1.5, "The read"), over `rows`, the rows
/// found on a chain whose vault sits at place `vault_at`:
/// 1. start: the narrowest owner pin, the item's own before the item-less one at one scope; else
///    the vault's value rows, the item's and the item-less one, met; else `default`;
/// 2. narrow: every value row at the pin's scope or narrower (with no pin, every value row below
///    the vault) meets the start. A value row only ever makes the result stricter, and no value
///    row replaces another, whoever set it. A row a move carried narrows as a value row does.
///
/// A pin no owner set is passed over. A row that takes part and does not decode makes the read
/// [`Met::Unreadable`] at the narrowest such place; a row the pin releases plays no part.
#[must_use]
pub fn decide_met<'a, V: Clone + PartialEq>(
    rows: &'a [FoundRow<V>],
    vault_at: usize,
    meet: &dyn Fn(&V, &V) -> V,
    default: &V,
) -> Met<'a, V> {
    let pin = rows
        .iter()
        .filter(|row| row.mode == SettingMode::Pin && row.by_owner)
        .min_by_key(|row| row.rank());
    let mut taking: Vec<&FoundRow<V>> = rows
        .iter()
        .filter(|row| row.mode != SettingMode::Pin && pin.is_none_or(|pin| row.at <= pin.at))
        .chain(pin)
        .collect();
    // Narrowest first; at one place the item's row first, and a pin before a value row.
    taking.sort_by_key(|row| (row.rank(), row.mode != SettingMode::Pin));
    if let Some(row) = taking.iter().find(|row| row.value.is_none()) {
        return Met::Unreadable(row.at);
    }
    let starts_at_default = pin.is_none() && !taking.iter().any(|row| row.at == vault_at);
    let mut met = starts_at_default.then(|| default.clone());
    for value in taking.iter().filter_map(|row| row.value.as_ref()) {
        met = Some(match met {
            Some(so_far) => meet(&so_far, value),
            None => value.clone(),
        });
    }
    let value = met.unwrap_or_else(|| default.clone());
    let by = taking
        .iter()
        .find(|row| row.value.as_ref() == Some(&value))
        .copied();
    Met::Value {
        value,
        by,
        rows: taking.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Decided, FoundFit, FoundRow, Met, decide, decide_met};
    use crate::{SettingMode, lower_no_wider};

    fn row(at: usize, item: bool, mode: SettingMode, by_owner: bool, value: u64) -> FoundRow<u64> {
        FoundRow {
            at,
            item,
            mode,
            by_owner,
            value: Some(value),
        }
    }

    fn value_of(decided: &Decided<'_, u64>) -> Option<u64> {
        match decided {
            Decided::Pin(row) | Decided::Row(row) => row.value,
            Decided::Fit(fit) => Some(fit.value),
            Decided::Default | Decided::Unreadable(_) => None,
        }
    }

    #[test]
    fn no_row_reads_the_default() {
        assert_eq!(decide::<u64>(&[], &[], None, None), Decided::Default);
    }

    #[test]
    fn the_narrowest_owner_pin_decides_over_any_value_row() {
        let rows = [
            row(0, true, SettingMode::Value, true, 1),
            row(2, false, SettingMode::Pin, true, 2),
            row(1, false, SettingMode::Pin, true, 3),
            row(1, false, SettingMode::Pin, false, 4),
        ];
        let decided = decide(&rows, &[], None, None);
        assert!(matches!(decided, Decided::Pin(_)));
        assert_eq!(value_of(&decided), Some(3));
    }

    #[test]
    fn the_narrowest_value_row_decides_and_the_items_row_first() {
        let rows = [
            row(1, true, SettingMode::Value, true, 1),
            row(0, false, SettingMode::Value, true, 2),
            row(0, true, SettingMode::Value, true, 3),
        ];
        assert_eq!(value_of(&decide(&rows, &[], None, None)), Some(3));
    }

    #[test]
    fn a_holders_row_is_held_inside_the_owners_row_at_its_scope_or_wider() {
        let lower = lower_no_wider::<u64>;
        let no_wider: Option<&dyn Fn(&u64, &u64) -> bool> = Some(&lower);
        // inside the owner's cap: the holder's row decides
        let rows = [
            row(0, false, SettingMode::Value, false, 5),
            row(1, false, SettingMode::Value, true, 8),
        ];
        assert_eq!(value_of(&decide(&rows, &[], no_wider, None)), Some(5));
        // above it: the owner's row decides, and the holder's stays stored
        let rows = [
            row(0, false, SettingMode::Value, false, 9),
            row(1, false, SettingMode::Value, true, 8),
        ];
        assert_eq!(value_of(&decide(&rows, &[], no_wider, None)), Some(8));
        // the nearest owner row at the holder's scope or wider is the cap, its item row first
        let rows = [
            row(0, true, SettingMode::Value, false, 9),
            row(0, false, SettingMode::Value, true, 6),
            row(1, true, SettingMode::Value, true, 2),
        ];
        assert_eq!(value_of(&decide(&rows, &[], no_wider, None)), Some(6));
        // a key with no comparator: the holder's row stands
        let rows = [
            row(0, false, SettingMode::Value, false, 9),
            row(1, false, SettingMode::Value, true, 8),
        ];
        assert_eq!(value_of(&decide(&rows, &[], None, None)), Some(9));
    }

    #[test]
    fn with_no_owner_row_a_holders_row_is_held_inside_the_default() {
        let lower = lower_no_wider::<u64>;
        let no_wider: Option<&dyn Fn(&u64, &u64) -> bool> = Some(&lower);
        let default = 10;
        // inside the default: the holder's row decides
        let rows = [row(0, false, SettingMode::Value, false, 4)];
        assert_eq!(
            value_of(&decide(&rows, &[], no_wider, Some(&default))),
            Some(4)
        );
        // the default itself is inside it
        let rows = [row(0, false, SettingMode::Value, false, 10)];
        assert_eq!(
            value_of(&decide(&rows, &[], no_wider, Some(&default))),
            Some(10)
        );
        // above it: the default decides, and the holder's row stays stored
        let rows = [row(0, false, SettingMode::Value, false, 12)];
        assert_eq!(
            decide(&rows, &[], no_wider, Some(&default)),
            Decided::Default
        );
        // an owner row is the cap, the default plays no part
        let rows = [
            row(0, false, SettingMode::Value, false, 12),
            row(1, false, SettingMode::Value, true, 20),
        ];
        assert_eq!(
            value_of(&decide(&rows, &[], no_wider, Some(&default))),
            Some(12)
        );
        // the owner's own row above the default stands
        let rows = [row(0, false, SettingMode::Value, true, 12)];
        assert_eq!(
            value_of(&decide(&rows, &[], no_wider, Some(&default))),
            Some(12)
        );
        // a key with no comparator: the holder's row stands
        let rows = [row(0, false, SettingMode::Value, false, 12)];
        assert_eq!(
            value_of(&decide(&rows, &[], None, Some(&default))),
            Some(12)
        );
    }

    #[test]
    fn a_deciding_row_that_does_not_decode_is_unreadable_never_the_default() {
        let mut pin = row(1, false, SettingMode::Pin, true, 0);
        pin.value = None;
        assert_eq!(decide(&[pin], &[], None, None), Decided::Unreadable(1));
        let mut value = row(0, false, SettingMode::Value, true, 0);
        value.value = None;
        let rows = [value, row(1, false, SettingMode::Value, true, 3)];
        assert_eq!(decide(&rows, &[], None, None), Decided::Unreadable(0));
        let mut cap = row(1, false, SettingMode::Value, true, 0);
        cap.value = None;
        let rows = [row(0, false, SettingMode::Value, false, 3), cap];
        let lower = lower_no_wider::<u64>;
        assert_eq!(
            decide(&rows, &[], Some(&lower), None),
            Decided::Unreadable(1)
        );
    }

    fn fit(at: usize, value: u64) -> FoundFit<u64> {
        FoundFit { at, value }
    }

    #[test]
    fn a_fit_decides_over_the_value_row_at_its_scope_and_over_wider_ones() {
        let rows = [
            row(0, false, SettingMode::Value, true, 1),
            row(1, false, SettingMode::Value, true, 2),
        ];
        let fits = [fit(0, 7)];
        let decided = decide(&rows, &fits, None, None);
        assert!(matches!(decided, Decided::Fit(_)));
        assert_eq!(value_of(&decided), Some(7));
        let rows = [row(2, false, SettingMode::Value, true, 2)];
        assert_eq!(value_of(&decide(&rows, &[fit(1, 7)], None, None)), Some(7));
        assert_eq!(value_of(&decide(&[], &[fit(3, 7)], None, None)), Some(7));
    }

    #[test]
    fn a_narrower_value_row_decides_over_a_wider_fit_and_the_narrowest_fit_first() {
        let rows = [row(0, false, SettingMode::Value, true, 1)];
        let fits = [fit(1, 7)];
        let decided = decide(&rows, &fits, None, None);
        assert!(matches!(decided, Decided::Row(_)));
        assert_eq!(value_of(&decided), Some(1));
        assert_eq!(
            value_of(&decide(&[], &[fit(2, 9), fit(1, 7)], None, None)),
            Some(7)
        );
    }

    #[test]
    fn an_owner_pin_decides_over_a_fit_and_a_fit_is_never_held_inside_a_row() {
        let rows = [row(3, false, SettingMode::Pin, true, 4)];
        let fits = [fit(0, 7)];
        let decided = decide(&rows, &fits, None, None);
        assert!(matches!(decided, Decided::Pin(_)));
        assert_eq!(value_of(&decided), Some(4));
        // a holder's pin is passed over, as without a fit
        let rows = [row(0, false, SettingMode::Pin, false, 4)];
        assert_eq!(value_of(&decide(&rows, &[fit(1, 7)], None, None)), Some(7));
        // the owner's row and the default cap a holder's row, never a fit
        let lower = lower_no_wider::<u64>;
        let rows = [row(1, false, SettingMode::Value, true, 3)];
        let default = 2;
        assert_eq!(
            value_of(&decide(&rows, &[fit(0, 9)], Some(&lower), Some(&default))),
            Some(9)
        );
    }

    fn met_value(met: &Met<'_, u64>) -> Option<u64> {
        match met {
            Met::Value { value, .. } => Some(*value),
            Met::Unreadable(_) => None,
        }
    }

    fn met_by(met: &Met<'_, u64>) -> Option<(usize, SettingMode)> {
        match met {
            Met::Value { by, .. } => by.map(|row| (row.at, row.mode)),
            Met::Unreadable(_) => None,
        }
    }

    #[test]
    fn a_met_read_meets_every_row_below_the_vault_with_the_vaults_value() {
        let min = |a: &u64, b: &u64| *a.min(b);
        // No row: the default, from no row.
        let met = decide_met::<u64>(&[], 2, &min, &7);
        assert_eq!(
            met,
            Met::Value {
                value: 7,
                by: None,
                rows: 0
            }
        );
        // A world row of 5 under a vault of 3 does not bind: the world reads 3.
        let rows = [
            row(1, false, SettingMode::Value, false, 5),
            row(2, false, SettingMode::Value, true, 3),
        ];
        let met = decide_met(&rows, 2, &min, &7);
        assert_eq!(
            (met_value(&met), met_by(&met)),
            (Some(3), Some((2, SettingMode::Value)))
        );
        // Raise the vault to 30: the world row binds, whoever set it.
        let rows = [
            row(1, false, SettingMode::Value, false, 10),
            row(2, false, SettingMode::Value, true, 30),
        ];
        assert_eq!(met_value(&decide_met(&rows, 2, &min, &7)), Some(10));
        // With no vault row the default is the start, and a looser row below does not bind.
        let rows = [row(0, false, SettingMode::Value, false, 9)];
        let met = decide_met(&rows, 2, &min, &7);
        assert_eq!(
            met,
            Met::Value {
                value: 7,
                by: None,
                rows: 1
            }
        );
        // The vault's value rows are the start, also when looser than the default.
        let rows = [row(2, false, SettingMode::Value, true, 12)];
        assert_eq!(met_value(&decide_met(&rows, 2, &min, &7)), Some(12));
        // At the vault the item's row and the item-less row meet.
        let rows = [
            row(2, true, SettingMode::Value, true, 6),
            row(2, false, SettingMode::Value, true, 4),
        ];
        assert_eq!(met_value(&decide_met(&rows, 2, &min, &7)), Some(4));
    }

    #[test]
    fn an_owner_pin_releases_the_rows_wider_than_itself_and_narrower_rows_still_narrow_it() {
        let min = |a: &u64, b: &u64| *a.min(b);
        let rows = [
            row(0, false, SettingMode::Value, false, 15),
            row(1, false, SettingMode::Pin, true, 20),
            row(1, false, SettingMode::Value, false, 25),
            row(2, false, SettingMode::Value, true, 5),
        ];
        let met = decide_met(&rows, 2, &min, &7);
        assert_eq!(
            (met_value(&met), met_by(&met)),
            (Some(15), Some((0, SettingMode::Value)))
        );
        let rows = [
            row(1, false, SettingMode::Pin, true, 20),
            row(2, false, SettingMode::Value, true, 5),
        ];
        let met = decide_met(&rows, 2, &min, &7);
        assert_eq!(
            (met_value(&met), met_by(&met)),
            (Some(20), Some((1, SettingMode::Pin)))
        );
        // A pin no owner set is passed over.
        let rows = [
            row(1, false, SettingMode::Pin, false, 20),
            row(2, false, SettingMode::Value, true, 5),
        ];
        assert_eq!(met_value(&decide_met(&rows, 2, &min, &7)), Some(5));
        // An unreadable row the pin releases plays no part; one it reaches makes the read unreadable.
        let mut released = row(2, false, SettingMode::Value, true, 0);
        released.value = None;
        let rows = [row(1, false, SettingMode::Pin, true, 20), released];
        assert_eq!(met_value(&decide_met(&rows, 2, &min, &7)), Some(20));
        let mut reached = row(0, false, SettingMode::Value, false, 0);
        reached.value = None;
        let rows = [reached, row(1, false, SettingMode::Pin, true, 20)];
        assert_eq!(decide_met(&rows, 2, &min, &7), Met::Unreadable(0));
    }

    #[test]
    fn a_meet_that_no_single_row_holds_names_no_row() {
        let and = |a: &u64, b: &u64| a & b;
        let rows = [
            row(0, false, SettingMode::Value, false, 0b110),
            row(2, false, SettingMode::Value, true, 0b011),
        ];
        let met = decide_met(&rows, 2, &and, &0b111);
        assert_eq!(
            met,
            Met::Value {
                value: 0b010,
                by: None,
                rows: 2
            }
        );
    }

    #[test]
    fn a_carried_row_narrows_as_a_value_row_and_one_row_keys_pass_it_over() {
        let min = |a: &u64, b: &u64| *a.min(b);
        let rows = [
            row(0, false, SettingMode::Carried, true, 4),
            row(1, false, SettingMode::Value, false, 6),
            row(2, false, SettingMode::Value, true, 9),
        ];
        let met = decide_met(&rows, 2, &min, &10);
        assert_eq!(
            (met_value(&met), met_by(&met)),
            (Some(4), Some((0, SettingMode::Carried)))
        );
        // A pin narrower than the carried row releases it, as it releases a value row.
        let rows = [
            row(1, false, SettingMode::Carried, true, 4),
            row(0, false, SettingMode::Pin, true, 8),
        ];
        assert_eq!(met_value(&decide_met(&rows, 2, &min, &10)), Some(8));
        // A key that reads one row never reads a carried row.
        let rows = [
            row(0, false, SettingMode::Carried, true, 4),
            row(1, false, SettingMode::Value, true, 6),
        ];
        assert_eq!(value_of(&decide(&rows, &[], None, None)), Some(6));
    }
}
