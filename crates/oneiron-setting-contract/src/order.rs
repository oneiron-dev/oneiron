//! How a key says which side of a change is safe (DESIGN 15-setting-primitive section 1.5, "The
//! order"): one [`Order`] per key, from a closed list, and the two functions each order derives.
//!
//! The meet is the stricter of two values; the read combines rows with it. `no_wider(a, b)` says
//! `a` is no wider than `b`; the door judges a move with it. Every meet here is lawful: the same
//! result in either order, `meet(a, a) = a`, and the same result however three values are
//! grouped, because the read, the default layer and the stage 7 merge fold rows in no fixed
//! order. Nobody writes a meet by hand: a key names its order, and these functions are its meet.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// How a key orders its values. The list is closed; each entry is an order the engine's code
/// already lets a change land by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    /// No value is stricter than another: a move is safe only when it changes nothing, so only
    /// the key's holders move it. The default.
    None,
    /// The key guards nothing: no access, authority, money or identity moves with it. Every move
    /// is neutral, and an agent holder's move never asks (AUTH-1 = A).
    Neutral,
    /// The smaller value is the stricter: a cap, a lifetime, a threshold.
    Lower,
    /// The larger value is the stricter: a wait, a rest, a count of agreeing rulings.
    Higher,
    /// The value that ranks first in a declared list, strictest first ([`ChainOrder`]).
    Chain,
    /// A permit list: a subset is the stricter, and the meet is the intersection.
    Subset,
    /// A protect list: a superset is the stricter, and the meet is the union.
    Superset,
    /// A struct: every part is no wider under its own order ([`EachOrder`], [`each_order!`]).
    Each,
    /// The key's own comparator, with no meet: such a key has one slot, at the vault.
    Custom,
}

impl Order {
    /// Whether rows of a key with this order combine by their meet: only then does a row added
    /// below the vault only narrow, and only then is there a free safe move.
    #[must_use]
    pub const fn has_meet(self) -> bool {
        matches!(
            self,
            Self::Lower | Self::Higher | Self::Chain | Self::Subset | Self::Superset | Self::Each
        )
    }

    /// The order's wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Neutral => "neutral",
            Self::Lower => "lower",
            Self::Higher => "higher",
            Self::Chain => "chain",
            Self::Subset => "subset",
            Self::Superset => "superset",
            Self::Each => "each",
            Self::Custom => "custom",
        }
    }
}

/// Which way a change moved its row, as its change row records it (DESIGN 1.5 "The rule"): the
/// row it leaves against the row it replaces, by the key's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeDirection {
    /// The row it leaves is no wider than the row it replaces: a safe move.
    Tighter,
    /// The row it replaces is no wider than the row it leaves, and they differ.
    Looser,
    /// Neither is no wider than the other: "cannot tell", which counts as loose. Every move of a
    /// key whose read takes one row and that has no comparator.
    Unordered,
    /// The key guards nothing ([`Order::Neutral`]).
    Neutral,
}

impl ChangeDirection {
    /// The direction of a move that leaves `left` where `replaced` was, by `no_wider`.
    #[must_use]
    pub fn of<V>(left: &V, replaced: &V, no_wider: impl Fn(&V, &V) -> bool) -> Self {
        if no_wider(left, replaced) {
            Self::Tighter
        } else if no_wider(replaced, left) {
            Self::Looser
        } else {
            Self::Unordered
        }
    }
}

/// How many holders must say yes to a loose move (DESIGN 1.5, "Who may make which move").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Quorum {
    /// Any one holder (DEC-0005 `#widen-holders`). The default.
    One,
    /// Every live holder, for a loose move; a safe move still needs one.
    All,
}

/// Which end of a number order an absent optional value is ("No cap" is the loosest cap; "never
/// prune" is the strictest receipt horizon). The key says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsentEnd {
    Loosest,
    Strictest,
}

/// The meet of [`Order::Lower`]: the smaller.
#[must_use]
pub fn lower_meet<T: PartialOrd + Clone>(a: &T, b: &T) -> T {
    if a <= b { a.clone() } else { b.clone() }
}

/// [`Order::Lower`]'s comparator: `a <= b`.
#[must_use]
pub fn lower_no_wider<T: PartialOrd>(a: &T, b: &T) -> bool {
    a <= b
}

/// The meet of [`Order::Higher`]: the larger.
#[must_use]
pub fn higher_meet<T: PartialOrd + Clone>(a: &T, b: &T) -> T {
    if a >= b { a.clone() } else { b.clone() }
}

/// [`Order::Higher`]'s comparator: `a >= b`.
#[must_use]
pub fn higher_no_wider<T: PartialOrd>(a: &T, b: &T) -> bool {
    a >= b
}

/// The meet of a number order over an optional value. `HIGHER` picks [`Order::Higher`] over
/// [`Order::Lower`]; `ABSENT_STRICTEST` says the absent value is the order's strictest end
/// ([`AbsentEnd::Strictest`]) rather than its loosest.
#[must_use]
pub fn absent_meet<T: PartialOrd + Clone, const HIGHER: bool, const ABSENT_STRICTEST: bool>(
    a: &Option<T>,
    b: &Option<T>,
) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) if HIGHER => Some(higher_meet(a, b)),
        (Some(a), Some(b)) => Some(lower_meet(a, b)),
        (None, _) | (_, None) if ABSENT_STRICTEST => None,
        (None, other) | (other, None) => other.clone(),
    }
}

/// [`absent_meet`]'s comparator.
#[must_use]
pub fn absent_no_wider<T: PartialOrd, const HIGHER: bool, const ABSENT_STRICTEST: bool>(
    a: &Option<T>,
    b: &Option<T>,
) -> bool {
    match (a, b) {
        (Some(a), Some(b)) if HIGHER => higher_no_wider(a, b),
        (Some(a), Some(b)) => lower_no_wider(a, b),
        (None, None) => true,
        (None, Some(_)) => ABSENT_STRICTEST,
        (Some(_), None) => !ABSENT_STRICTEST,
    }
}

/// A value of [`Order::Chain`]: one of a closed list, strictest first. Every value the type can
/// hold is in the list; one that is not ranks after all of them, so no move to it is safe.
pub trait ChainOrder: PartialEq + Clone + 'static {
    /// Every value, strictest first.
    const STRICTEST_FIRST: &'static [Self];
}

fn chain_rank<T: ChainOrder>(value: &T) -> usize {
    T::STRICTEST_FIRST
        .iter()
        .position(|listed| listed == value)
        .unwrap_or(T::STRICTEST_FIRST.len())
}

/// The meet of [`Order::Chain`]: the one that ranks first.
#[must_use]
pub fn chain_meet<T: ChainOrder>(a: &T, b: &T) -> T {
    if chain_rank(a) <= chain_rank(b) {
        a.clone()
    } else {
        b.clone()
    }
}

/// [`Order::Chain`]'s comparator: `a` ranks at or before `b`, or they are equal.
#[must_use]
pub fn chain_no_wider<T: ChainOrder>(a: &T, b: &T) -> bool {
    a == b || chain_rank(a) < chain_rank(b)
}

/// A value of [`Order::Subset`] or [`Order::Superset`]: a set of members. The meet's result is in
/// the canonical order (sorted, no repeats), so its check passes it unchanged.
pub trait SetOrder: Sized {
    type Member: Ord + Clone;
    /// The members.
    fn members(&self) -> BTreeSet<Self::Member>;
    /// The value that holds exactly `members`.
    fn from_members(members: BTreeSet<Self::Member>) -> Self;
}

impl<M: Ord + Clone> SetOrder for Vec<M> {
    type Member = M;
    fn members(&self) -> BTreeSet<M> {
        self.iter().cloned().collect()
    }
    fn from_members(members: BTreeSet<M>) -> Self {
        members.into_iter().collect()
    }
}

impl<M: Ord + Clone> SetOrder for BTreeSet<M> {
    type Member = M;
    fn members(&self) -> BTreeSet<M> {
        self.clone()
    }
    fn from_members(members: BTreeSet<M>) -> Self {
        members
    }
}

/// The meet of [`Order::Subset`]: the intersection.
#[must_use]
pub fn subset_meet<T: SetOrder>(a: &T, b: &T) -> T {
    T::from_members(a.members().intersection(&b.members()).cloned().collect())
}

/// [`Order::Subset`]'s comparator: `a` is a subset of `b`.
#[must_use]
pub fn subset_no_wider<T: SetOrder>(a: &T, b: &T) -> bool {
    a.members().is_subset(&b.members())
}

/// The meet of [`Order::Superset`]: the union.
#[must_use]
pub fn superset_meet<T: SetOrder>(a: &T, b: &T) -> T {
    T::from_members(a.members().union(&b.members()).cloned().collect())
}

/// [`Order::Superset`]'s comparator: `a` is a superset of `b`.
#[must_use]
pub fn superset_no_wider<T: SetOrder>(a: &T, b: &T) -> bool {
    a.members().is_superset(&b.members())
}

/// The meet of an `exact` part of an [`Order::Each`] struct: the part itself when the two are
/// equal, else the part's strictest value (the flat order).
#[must_use]
pub fn exact_meet<T: PartialEq + Clone>(a: &T, b: &T, strictest: fn() -> T) -> T {
    if a == b { a.clone() } else { strictest() }
}

/// An `exact` part's comparator: equal, or `a` is the part's strictest value.
#[must_use]
pub fn exact_no_wider<T: PartialEq>(a: &T, b: &T, strictest: fn() -> T) -> bool {
    a == b || *a == strictest()
}

/// A value of [`Order::Each`]: a struct whose every part names its own order. Only
/// [`each_order!`] implements it, part by part.
pub trait EachOrder: Sized {
    /// The meet, part by part.
    #[must_use]
    fn meet_each(&self, other: &Self) -> Self;
    /// Every part is no wider than the other's under its own order.
    fn no_wider_each(&self, other: &Self) -> bool;
}

/// The meet of [`Order::Each`].
#[must_use]
pub fn each_meet<T: EachOrder>(a: &T, b: &T) -> T {
    a.meet_each(b)
}

/// [`Order::Each`]'s comparator.
#[must_use]
pub fn each_no_wider<T: EachOrder>(a: &T, b: &T) -> bool {
    a.no_wider_each(b)
}

/// Derives [`EachOrder`] for a struct: every field names its order, and the struct literal the
/// macro writes fails to compile when a field is left out.
///
/// ```ignore
/// oneiron_setting_contract::each_order!(SnapshotReadSettings {
///     max_open: lower,
///     floor_secs: higher,
///     mode: exact(SnapshotMode::strictest),
///     cap: lower_or_absent(AbsentEnd::Loosest),
/// });
/// ```
///
/// A part is `lower`, `higher`, `chain`, `subset`, `superset`, `each`, `exact(<fn() -> part>)`,
/// or, on an `Option` of a number, `lower_or_absent(<AbsentEnd>)` / `higher_or_absent(...)`.
#[macro_export]
macro_rules! each_order {
    ($ty:ty { $($field:ident : $part:ident $(($arg:expr))?),+ $(,)? }) => {
        impl $crate::EachOrder for $ty {
            fn meet_each(&self, other: &Self) -> Self {
                Self {
                    $($field: $crate::each_part!(meet, $part $(($arg))?, &self.$field, &other.$field),)+
                }
            }
            fn no_wider_each(&self, other: &Self) -> bool {
                true $(&& $crate::each_part!(no_wider, $part $(($arg))?, &self.$field, &other.$field))+
            }
        }
    };
}

/// One part of [`each_order!`]: its meet or its comparator.
#[doc(hidden)]
#[macro_export]
macro_rules! each_part {
    (meet, lower, $a:expr, $b:expr) => {
        $crate::lower_meet($a, $b)
    };
    (no_wider, lower, $a:expr, $b:expr) => {
        $crate::lower_no_wider($a, $b)
    };
    (meet, higher, $a:expr, $b:expr) => {
        $crate::higher_meet($a, $b)
    };
    (no_wider, higher, $a:expr, $b:expr) => {
        $crate::higher_no_wider($a, $b)
    };
    (meet, chain, $a:expr, $b:expr) => {
        $crate::chain_meet($a, $b)
    };
    (no_wider, chain, $a:expr, $b:expr) => {
        $crate::chain_no_wider($a, $b)
    };
    (meet, subset, $a:expr, $b:expr) => {
        $crate::subset_meet($a, $b)
    };
    (no_wider, subset, $a:expr, $b:expr) => {
        $crate::subset_no_wider($a, $b)
    };
    (meet, superset, $a:expr, $b:expr) => {
        $crate::superset_meet($a, $b)
    };
    (no_wider, superset, $a:expr, $b:expr) => {
        $crate::superset_no_wider($a, $b)
    };
    (meet, each, $a:expr, $b:expr) => {
        $crate::each_meet($a, $b)
    };
    (no_wider, each, $a:expr, $b:expr) => {
        $crate::each_no_wider($a, $b)
    };
    (meet, exact($strictest:expr), $a:expr, $b:expr) => {
        $crate::exact_meet($a, $b, $strictest)
    };
    (no_wider, exact($strictest:expr), $a:expr, $b:expr) => {
        $crate::exact_no_wider($a, $b, $strictest)
    };
    (meet, lower_or_absent($end:expr), $a:expr, $b:expr) => {
        $crate::absent_part_meet($a, $b, false, $end)
    };
    (no_wider, lower_or_absent($end:expr), $a:expr, $b:expr) => {
        $crate::absent_part_no_wider($a, $b, false, $end)
    };
    (meet, higher_or_absent($end:expr), $a:expr, $b:expr) => {
        $crate::absent_part_meet($a, $b, true, $end)
    };
    (no_wider, higher_or_absent($end:expr), $a:expr, $b:expr) => {
        $crate::absent_part_no_wider($a, $b, true, $end)
    };
}

/// [`absent_meet`] for one part of [`each_order!`], with the order and the end as values.
#[doc(hidden)]
#[must_use]
pub fn absent_part_meet<T: PartialOrd + Clone>(
    a: &Option<T>,
    b: &Option<T>,
    higher: bool,
    end: AbsentEnd,
) -> Option<T> {
    match (higher, end) {
        (false, AbsentEnd::Loosest) => absent_meet::<T, false, false>(a, b),
        (false, AbsentEnd::Strictest) => absent_meet::<T, false, true>(a, b),
        (true, AbsentEnd::Loosest) => absent_meet::<T, true, false>(a, b),
        (true, AbsentEnd::Strictest) => absent_meet::<T, true, true>(a, b),
    }
}

/// [`absent_no_wider`] for one part of [`each_order!`].
#[doc(hidden)]
#[must_use]
pub fn absent_part_no_wider<T: PartialOrd>(
    a: &Option<T>,
    b: &Option<T>,
    higher: bool,
    end: AbsentEnd,
) -> bool {
    match (higher, end) {
        (false, AbsentEnd::Loosest) => absent_no_wider::<T, false, false>(a, b),
        (false, AbsentEnd::Strictest) => absent_no_wider::<T, false, true>(a, b),
        (true, AbsentEnd::Loosest) => absent_no_wider::<T, true, false>(a, b),
        (true, AbsentEnd::Strictest) => absent_no_wider::<T, true, true>(a, b),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fmt::Debug;

    use super::{
        AbsentEnd, ChainOrder, ChangeDirection, absent_meet, absent_no_wider, chain_meet,
        chain_no_wider, each_meet, each_no_wider, higher_meet, higher_no_wider, lower_meet,
        lower_no_wider, subset_meet, subset_no_wider, superset_meet, superset_no_wider,
    };

    /// The meet laws over every pair and triple of `values`, and `no_wider` agreeing with the
    /// meet: `a` is no wider than `b` exactly when `meet(a, b) = a`.
    fn lawful<T: PartialEq + Debug>(
        values: &[T],
        meet: impl Fn(&T, &T) -> T,
        no_wider: impl Fn(&T, &T) -> bool,
    ) {
        for a in values {
            assert_eq!(meet(a, a), *a, "a meet with itself: {a:?}");
            for b in values {
                assert_eq!(meet(a, b), meet(b, a), "either order: {a:?} {b:?}");
                assert_eq!(no_wider(a, b), meet(a, b) == *a, "no_wider: {a:?} {b:?}");
                for c in values {
                    assert_eq!(
                        meet(&meet(a, b), c),
                        meet(a, &meet(b, c)),
                        "any grouping: {a:?} {b:?} {c:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn number_orders_are_lawful_and_name_opposite_sides() {
        lawful(&[0_u64, 3, 5, 9], lower_meet, lower_no_wider);
        lawful(&[0_u64, 3, 5, 9], higher_meet, higher_no_wider);
        lawful(&[-1.5_f64, 0.0, 2.25], lower_meet, lower_no_wider);
        lawful(&[false, true], higher_meet, higher_no_wider);
        assert_eq!(lower_meet(&3_u64, &5), 3);
        assert_eq!(higher_meet(&3_u64, &5), 5);
    }

    #[test]
    fn an_absent_value_is_the_end_its_key_names() {
        let values = [None, Some(1_u64), Some(4)];
        lawful(
            &values,
            absent_meet::<u64, false, false>,
            absent_no_wider::<u64, false, false>,
        );
        lawful(
            &values,
            absent_meet::<u64, false, true>,
            absent_no_wider::<u64, false, true>,
        );
        lawful(
            &values,
            absent_meet::<u64, true, false>,
            absent_no_wider::<u64, true, false>,
        );
        lawful(
            &values,
            absent_meet::<u64, true, true>,
            absent_no_wider::<u64, true, true>,
        );
        // No cap is the loosest cap: any cap is no wider than none.
        assert_eq!(absent_meet::<u64, false, false>(&None, &Some(4)), Some(4));
        assert!(absent_no_wider::<u64, false, false>(&Some(4), &None));
        // Never prune is the strictest horizon of a receipt kept longest.
        assert_eq!(absent_meet::<u64, true, true>(&None, &Some(4)), None);
        assert!(!absent_no_wider::<u64, true, true>(&Some(4), &None));
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Mode {
        Ask,
        Notify,
        Act,
    }

    impl ChainOrder for Mode {
        const STRICTEST_FIRST: &'static [Self] = &[Self::Ask, Self::Notify, Self::Act];
    }

    #[test]
    fn a_chain_meets_to_the_earlier_value() {
        lawful(
            &[Mode::Ask, Mode::Notify, Mode::Act],
            chain_meet,
            chain_no_wider,
        );
        assert_eq!(chain_meet(&Mode::Act, &Mode::Notify), Mode::Notify);
    }

    #[test]
    fn a_permit_list_meets_to_the_intersection_and_a_protect_list_to_the_union() {
        let sets: Vec<Vec<String>> = [vec![], vec!["a"], vec!["a", "b"], vec!["b", "c"]]
            .into_iter()
            .map(|set| set.into_iter().map(str::to_owned).collect())
            .collect();
        lawful(&sets, subset_meet, subset_no_wider);
        lawful(&sets, superset_meet, superset_no_wider);
        let ab = vec!["b".to_owned(), "a".to_owned()];
        let bc = vec!["c".to_owned(), "b".to_owned()];
        assert_eq!(subset_meet(&ab, &bc), vec!["b".to_owned()]);
        assert_eq!(
            superset_meet(&ab, &bc),
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
            "canonical order"
        );
        // A set given in another order is the same set.
        assert!(subset_no_wider(&ab, &vec!["a".to_owned(), "b".to_owned()]));
        let one: BTreeSet<u8> = [1].into();
        assert_eq!(subset_meet(&one, &[1, 2].into()), one);
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Bounds {
        max_open: u64,
        floor_secs: u64,
        mode: Mode,
        cap: Option<u64>,
    }

    fn strictest_mode() -> Mode {
        Mode::Ask
    }

    crate::each_order!(Bounds {
        max_open: lower,
        floor_secs: higher,
        mode: exact(strictest_mode),
        cap: lower_or_absent(AbsentEnd::Loosest),
    });

    #[test]
    fn a_struct_meets_part_by_part() {
        let bounds = |max_open, floor_secs, mode, cap| Bounds {
            max_open,
            floor_secs,
            mode,
            cap,
        };
        let values = [
            bounds(5, 10, Mode::Act, None),
            bounds(3, 20, Mode::Act, Some(7)),
            bounds(8, 5, Mode::Notify, Some(2)),
            bounds(3, 20, Mode::Ask, None),
        ];
        lawful(&values, each_meet, each_no_wider);
        assert_eq!(
            each_meet(&values[0], &values[2]),
            bounds(5, 10, Mode::Ask, Some(2)),
            "an exact part that differs meets to its strictest"
        );
        assert!(each_no_wider(&values[1], &values[0]));
        assert!(
            !each_no_wider(&values[2], &values[0]),
            "tighter in one part, looser in another"
        );
    }

    #[test]
    fn a_change_is_tighter_looser_or_unordered() {
        assert_eq!(
            ChangeDirection::of(&3_u64, &5, lower_no_wider),
            ChangeDirection::Tighter
        );
        assert_eq!(
            ChangeDirection::of(&5_u64, &3, lower_no_wider),
            ChangeDirection::Looser
        );
        let a = vec!["a".to_owned()];
        let b = vec!["b".to_owned()];
        assert_eq!(
            ChangeDirection::of(&a, &b, subset_no_wider),
            ChangeDirection::Unordered
        );
    }
}
