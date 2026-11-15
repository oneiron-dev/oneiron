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
    /// No row: the catalogue default.
    Default,
    /// The deciding row, at this place on the chain, does not decode.
    Unreadable(usize),
}

/// The row that decides a read over `rows`, the rows found on the chain:
/// 1. the narrowest owner pin; only the owner writes a pin, so any other is passed over;
/// 2. else the narrowest value row, the item's own row before the item-less row at one scope;
/// 3. a row a holder set, on a key that names its tighter direction (`tighter(a, b)`: `a` is at
///    least as tight as `b`), is held inside the nearest owner value row at its scope or a wider
///    one: the owner's value is the cap, and the holder's row stays stored;
/// 4. else the catalogue default.
///
/// A deciding row that does not decode is [`Decided::Unreadable`], never the default; so is an
/// owner's cap row that does not decode, since the holder's row cannot be shown to sit inside it.
#[must_use]
pub fn decide<'a, V>(
    rows: &'a [FoundRow<V>],
    tighter: Option<&dyn Fn(&V, &V) -> bool>,
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
    let Some(row) = narrowest(SettingMode::Value, false) else {
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
        None => Decided::Row(row),
        Some(cap) => match &cap.value {
            None => Decided::Unreadable(cap.at),
            Some(cap_value) if tighter(value, cap_value) => Decided::Row(row),
            Some(_) => Decided::Row(cap),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{Decided, FoundRow, decide};
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
            Decided::Default | Decided::Unreadable(_) => None,
        }
    }

    #[test]
    fn no_row_reads_the_default() {
        assert_eq!(decide::<u64>(&[], None), Decided::Default);
    }

    #[test]
    fn the_narrowest_owner_pin_decides_over_any_value_row() {
        let rows = [
            row(0, true, SettingMode::Value, true, 1),
            row(2, false, SettingMode::Pin, true, 2),
            row(1, false, SettingMode::Pin, true, 3),
            row(1, false, SettingMode::Pin, false, 4),
        ];
        let decided = decide(&rows, None);
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
        assert_eq!(value_of(&decide(&rows, None)), Some(3));
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
        assert_eq!(value_of(&decide(&rows, tighter)), Some(5));
        // above it: the owner's row decides, and the holder's stays stored
        let rows = [
            row(0, false, SettingMode::Value, false, 9),
            row(1, false, SettingMode::Value, true, 8),
        ];
        assert_eq!(value_of(&decide(&rows, tighter)), Some(8));
        // the nearest owner row at the holder's scope or wider is the cap, its item row first
        let rows = [
            row(0, true, SettingMode::Value, false, 9),
            row(0, false, SettingMode::Value, true, 6),
            row(1, true, SettingMode::Value, true, 2),
        ];
        assert_eq!(value_of(&decide(&rows, tighter)), Some(6));
        // a key with no tighter direction: the holder's row stands
        let rows = [
            row(0, false, SettingMode::Value, false, 9),
            row(1, false, SettingMode::Value, true, 8),
        ];
        assert_eq!(value_of(&decide(&rows, None)), Some(9));
    }

    #[test]
    fn a_deciding_row_that_does_not_decode_is_unreadable_never_the_default() {
        let mut pin = row(1, false, SettingMode::Pin, true, 0);
        pin.value = None;
        assert_eq!(decide(&[pin], None), Decided::Unreadable(1));
        let mut value = row(0, false, SettingMode::Value, true, 0);
        value.value = None;
        let rows = [value, row(1, false, SettingMode::Value, true, 3)];
        assert_eq!(decide(&rows, None), Decided::Unreadable(0));
        let mut cap = row(1, false, SettingMode::Value, true, 0);
        cap.value = None;
        let rows = [row(0, false, SettingMode::Value, false, 3), cap];
        let lower = lower_is_tighter::<u64>;
        assert_eq!(decide(&rows, Some(&lower)), Decided::Unreadable(1));
    }
}
