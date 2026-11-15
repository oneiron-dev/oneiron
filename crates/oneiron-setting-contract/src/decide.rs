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
/// 3. a row a holder set, on a key that names its tighter direction (`tighter(a, b)`: `a` is at
///    least as tight as `b`), is held inside the nearest owner value row at its scope or a wider
///    one, and where the owner set none there, inside the catalogue default `default`: the
///    owner's value, else the default, is the cap, and the holder's row stays stored;
/// 4. else the catalogue default.
///
/// A deciding row that does not decode is [`Decided::Unreadable`], never the default; so is an
/// owner's cap row that does not decode, since the holder's row cannot be shown to sit inside it.
#[must_use]
pub fn decide<'a, V>(
    rows: &'a [FoundRow<V>],
    fits: &'a [FoundFit<V>],
    tighter: Option<&dyn Fn(&V, &V) -> bool>,
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
    let Some(tighter) = tighter.filter(|_| !row.by_owner) else {
        return Decided::Row(row);
    };
    let cap = rows
        .iter()
        .filter(|cap| cap.mode == SettingMode::Value && cap.by_owner && cap.at >= row.at)
        .min_by_key(|cap| cap.rank());
    match cap {
        None => match default {
            Some(default) if !tighter(value, default) => Decided::Default,
            _ => Decided::Row(row),
        },
        Some(cap) => match &cap.value {
            None => Decided::Unreadable(cap.at),
            Some(cap_value) if tighter(value, cap_value) => Decided::Row(row),
            Some(_) => Decided::Row(cap),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{Decided, FoundFit, FoundRow, decide};
    use crate::{SettingMode, lower_is_tighter};

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
        let lower = lower_is_tighter::<u64>;
        let tighter: Option<&dyn Fn(&u64, &u64) -> bool> = Some(&lower);
        // inside the owner's cap: the holder's row decides
        let rows = [
            row(0, false, SettingMode::Value, false, 5),
            row(1, false, SettingMode::Value, true, 8),
        ];
        assert_eq!(value_of(&decide(&rows, &[], tighter, None)), Some(5));
        // above it: the owner's row decides, and the holder's stays stored
        let rows = [
            row(0, false, SettingMode::Value, false, 9),
            row(1, false, SettingMode::Value, true, 8),
        ];
        assert_eq!(value_of(&decide(&rows, &[], tighter, None)), Some(8));
        // the nearest owner row at the holder's scope or wider is the cap, its item row first
        let rows = [
            row(0, true, SettingMode::Value, false, 9),
            row(0, false, SettingMode::Value, true, 6),
            row(1, true, SettingMode::Value, true, 2),
        ];
        assert_eq!(value_of(&decide(&rows, &[], tighter, None)), Some(6));
        // a key with no tighter direction: the holder's row stands
        let rows = [
            row(0, false, SettingMode::Value, false, 9),
            row(1, false, SettingMode::Value, true, 8),
        ];
        assert_eq!(value_of(&decide(&rows, &[], None, None)), Some(9));
    }

    #[test]
    fn with_no_owner_row_a_holders_row_is_held_inside_the_default() {
        let lower = lower_is_tighter::<u64>;
        let tighter: Option<&dyn Fn(&u64, &u64) -> bool> = Some(&lower);
        let default = 10;
        // inside the default: the holder's row decides
        let rows = [row(0, false, SettingMode::Value, false, 4)];
        assert_eq!(
            value_of(&decide(&rows, &[], tighter, Some(&default))),
            Some(4)
        );
        // the default itself is inside it
        let rows = [row(0, false, SettingMode::Value, false, 10)];
        assert_eq!(
            value_of(&decide(&rows, &[], tighter, Some(&default))),
            Some(10)
        );
        // above it: the default decides, and the holder's row stays stored
        let rows = [row(0, false, SettingMode::Value, false, 12)];
        assert_eq!(
            decide(&rows, &[], tighter, Some(&default)),
            Decided::Default
        );
        // an owner row is the cap, the default plays no part
        let rows = [
            row(0, false, SettingMode::Value, false, 12),
            row(1, false, SettingMode::Value, true, 20),
        ];
        assert_eq!(
            value_of(&decide(&rows, &[], tighter, Some(&default))),
            Some(12)
        );
        // the owner's own row above the default stands
        let rows = [row(0, false, SettingMode::Value, true, 12)];
        assert_eq!(
            value_of(&decide(&rows, &[], tighter, Some(&default))),
            Some(12)
        );
        // a key with no tighter direction: the holder's row stands
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
        let lower = lower_is_tighter::<u64>;
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
        let lower = lower_is_tighter::<u64>;
        let rows = [row(1, false, SettingMode::Value, true, 3)];
        let default = 2;
        assert_eq!(
            value_of(&decide(&rows, &[fit(0, 9)], Some(&lower), Some(&default))),
            Some(9)
        );
    }
}
