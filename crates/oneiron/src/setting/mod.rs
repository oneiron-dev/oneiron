//! The Setting primitive (DESIGN 15-setting-primitive, stage 0.1): one kind of stored choice in
//! place of a table, a codec, a door and a verb per knob.
//!
//! A Setting is a stored choice: for one key, at one scope, a value that someone with the power
//! set, in force until it is changed or cleared. Everything the engine knows about a key is one
//! catalogue row, [`SettingSpec`], declared with [`setting_keys!`] in its module's
//! `setting_keys.rs`; the crate's build script lists every row in the catalogue. A key costs that
//! row and, if no primitive fits, its value type ([`SettingValue`]).
//!
//! - Rows: [`tables`]. `SETTING` holds the keys whose choice the live vault keeps through a
//!   restore, `SETTING_CONTENT` the few whose choice travels with the records; one key and row
//!   shape in both.
//! - Read: [`Setting::read_in_txn`] for a typed reader; the verbs read through the same walk. One
//!   walk for every key ([`oneiron_setting_contract::decide`]); every read says which row
//!   decided it.
//! - Set: [`Vault::set_setting`], one door that judges every write as a move (DESIGN 1.5, stage
//!   6.0): the key's order says which way the move goes, the caller's capacity says what it may
//!   do, and the authority rule admits it or not, live in the write. The owner makes any move; a
//!   holder of the key (its own Grant line `settings.set:<key>`, or a live `engine.controls`
//!   grant for its class) tightens at once and asks the user to loosen; a row's subject narrows
//!   its own row; anything else waits on a check-in. Every change row records its direction.
//! - Change stream: every change is one `SETTING_CHANGE` row, written in the commit that makes it,
//!   and the feeds' `settings` source.
//! - Defaults: the default layer (DESIGN 1.5, stage 6.0): what the vault accepted from each
//!   pack, as rows at `SettingScope::Pack`, written only by the pack door. The `engine` pack is
//!   this build's catalogue and runs at open; a tighter default lands, a looser one waits for the
//!   owner's yes (`vault.settings.accept_defaults`). A read with no deciding row starts there.
//! - Verbs: `vault.settings.get`, `vault.settings.list`, `vault.settings.set`,
//!   `vault.settings.accept_defaults`.
//!
//! Stage 0.1 lands the primitive unused: no engine key is in the catalogue yet, and no value in
//! force moves.

mod catalogue;
mod change;
mod learned;
mod pack;
mod read;
mod set;
pub(crate) mod tables;

use std::marker::PhantomData;

pub use oneiron_setting_contract::{
    AbsentEnd, ChainOrder, ChangeDirection, EachOrder, EncodedValue, FitCell, Order, Quorum,
    ReadBy, Resolved, Restore, ScopeKind, SetOrder, Setter, SettingMode, SettingScope,
    SettingSource, SettingSync, SettingValue,
};

#[cfg(feature = "sync")]
pub(crate) use self::catalogue::leave_keeps_row;
pub use self::catalogue::{catalogue, spec_named};
pub use self::change::SettingChange;
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) use self::change::change_in_txn;
pub(crate) use self::change::{
    erase_setting_change_actor_in_txn, erase_setting_content_actor_in_txn,
    erase_setting_entity_in_txn, erase_setting_row_actor_in_txn, settings_after_in_txn,
    settings_head_in_txn,
};
pub use self::learned::{LEARNED_SCOPES, LearnedRange, SettingFitView};
pub use self::pack::{ENGINE_PACK, PackApplied, ProposedDefaultView};
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) use self::pack::{delete_layer_row, layer_row_revision};
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) use self::read::put_stored_bytes;
pub use self::read::{Requested, SettingCatalogueEntry, SettingRowView, SettingView};
pub(crate) use self::read::{SettingListFilter, SettingReader, reader_reads_key_in_txn};
pub(crate) use self::set::run_after_commit;
pub use self::set::{EngineSetting, SetSetting, SetSettingOutcome, SettingCaller};
use crate::Vault;
use crate::check_in::ActClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::EngineControlClass;

/// The Grant line that makes an agent a holder of one key (DESIGN 1.2 step 3): it sets the key's
/// value rows inside the owner's, and its widening asks the user (AUTH-1 = A). A Grant lists it
/// as a verb, matched exactly.
#[must_use]
pub fn set_line(key: &str) -> String {
    format!("settings.set:{key}")
}

/// The Grant line that lets an agent read one key whole.
#[must_use]
pub fn get_line(key: &str) -> String {
    format!("settings.get:{key}")
}

/// Who may set a key without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetBy {
    /// The owner alone. These are owner acts, and stay owner acts unless the owner grants them:
    /// a Grant line names one key ([`set_line`]).
    Owner,
    /// The owner, and a live holder of this `engine.controls` class.
    Class(EngineControlClass),
    /// The owner, and the agent or person the row's scope names, on its own row.
    Subject,
}

/// The items a family key admits: per channel, per act class, per offer.
#[derive(Debug, Clone, Copy)]
pub struct ItemDomain {
    /// What an item names, for the catalogue.
    pub name: &'static str,
    /// Whether `item` is one of them.
    pub admits: fn(&str) -> bool,
}

/// The one hook a key may run in the write that changes it: re-arm a schedule, clear parks that
/// wait on the key, or refuse the change on state the value's own check cannot see. It runs only
/// on an applied change, after its rows are put; its `Err` fails the whole write, so neither row
/// lands and the caller sees that error. A row that arrives by sync or a restore never passes
/// through it, so a refusal here needs its reader to hold the same line.
pub type OnChange = fn(&Vault, &mut heed::RwTxn<'_>, &SettingChange) -> Result<()>;

/// The one hook a key may run once the write that changed it has committed: wake a host that
/// reads the key (a reader woken inside the write would see the last commit's value).
pub type OnCommitted = fn(&Vault);

/// One catalogue row: everything the engine knows about a key. Data, not code.
#[derive(Clone, Copy)]
pub struct SettingSpec {
    /// Dotted lowercase ASCII, unique in the catalogue.
    pub name: &'static str,
    /// The row's doc comment: what the key chooses.
    pub doc: &'static str,
    /// The value's type: decode, check, JSON Schema, default, strictest, order.
    pub kind: &'static dyn ValueKind,
    /// The kinds of scope a row may sit at. The vault is always one.
    pub scopes: &'static [ScopeKind],
    /// For a family key, the items it admits.
    pub item: Option<ItemDomain>,
    /// Who may set it without asking.
    pub set_by: SetBy,
    /// How many holders must say yes to a loose move. `All` waits for its count, which lands with
    /// the Grant of a person's setting class (stage 6d-1): the door refuses a loose move of such a
    /// key until then.
    pub quorum: Quorum,
    /// The check-in act class of a change (ARCH-0082 act table).
    pub act: ActClass,
    pub read_by: ReadBy,
    pub restore: Restore,
    pub sync: SettingSync,
    pub on_change: Option<OnChange>,
    /// Run after the commit of each write that applied a change to the key (not on an equal
    /// value, not on a change that waits on a check-in).
    pub after_commit: Option<OnCommitted>,
}

impl SettingSpec {
    /// What a row leaves out: a vault-scoped owner act of reversible work, read by holders, kept
    /// live through a restore, the same on every machine, with no hook. Every row names its own
    /// `name`, `doc` and `kind`.
    pub const BASE: Self = Self {
        name: "",
        doc: "",
        kind: &NoKind,
        scopes: &[ScopeKind::Vault],
        item: None,
        set_by: SetBy::Owner,
        quorum: Quorum::One,
        act: ActClass::ReversibleWork,
        read_by: ReadBy::Holders,
        restore: Restore::Live,
        sync: SettingSync::Vault,
        on_change: None,
        after_commit: None,
    };

    /// Whether a row may sit at `kind`.
    #[must_use]
    pub fn admits_scope(&self, kind: ScopeKind) -> bool {
        kind == ScopeKind::Vault || self.scopes.contains(&kind)
    }

    /// Whether a fit learns this key under its rows ([`Kind::learned`]).
    #[must_use]
    pub fn is_learned(&self) -> bool {
        self.kind.learned_range().is_some()
    }

    /// Whether a read meets the key's rows (DESIGN 1.5 "The read"): its order has a meet and no
    /// fit learns it. Only such a key has a free safe move; every other key reads one row.
    #[must_use]
    pub fn reads_met(&self) -> bool {
        self.kind.order().has_meet() && !self.is_learned()
    }

    /// Whether `item` is one this key admits: none for a key that is no family, one of its
    /// domain's for one that is.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an item outside the key's domain, or an item on a key that has none.
    pub fn check_item(&self, item: Option<&str>) -> Result<()> {
        match (item, self.item) {
            (None, _) => Ok(()),
            (Some(item), Some(domain)) => {
                oneiron_setting_contract::check_item(item)?;
                if (domain.admits)(item) {
                    Ok(())
                } else {
                    Err(Error::InvalidConfig(format!(
                        "`{item}` is not one of the {} `{}` admits",
                        domain.name, self.name
                    )))
                }
            }
            (Some(_), None) => Err(Error::InvalidConfig(format!(
                "`{}` is one setting, not a family: it takes no item",
                self.name
            ))),
        }
    }
}

impl std::fmt::Debug for SettingSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettingSpec")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A key's value type, as the catalogue sees it without its Rust type: what the verbs, the walk
/// and the change stream need.
pub trait ValueKind: Sync {
    /// The value's JSON Schema.
    fn schema(&self) -> serde_json::Value;
    /// The catalogue default, encoded.
    ///
    /// # Errors
    ///
    /// A default that does not encode.
    fn default_value(&self) -> Result<EncodedValue>;
    /// The strictest value, encoded: what an unreadable row reads as. `None` when the key names
    /// none, and an unreadable row then fails the read.
    ///
    /// # Errors
    ///
    /// A value that does not encode.
    fn strictest_value(&self) -> Result<Option<EncodedValue>>;
    /// Whether `stored` decodes as this type.
    fn decodes(&self, stored: &EncodedValue) -> bool;
    /// `stored` as JSON; `None` when it does not decode.
    fn to_json(&self, stored: &EncodedValue) -> Option<serde_json::Value>;
    /// `json` decoded, checked ([`SettingValue::check`]) and encoded.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a value of another shape, or the check's refusal.
    fn from_json(&self, json: serde_json::Value) -> Result<EncodedValue>;
    /// The key's order: which side of a change is safe.
    fn order(&self) -> Order;
    /// The stricter of `a` and `b`, encoded; `None` for an order with no meet, or when either
    /// does not decode.
    fn meet(&self, a: &EncodedValue, b: &EncodedValue) -> Option<EncodedValue>;
    /// Whether `a` is no wider than `b`: by the order's comparator, and by equality where the
    /// key has none; `None` when either does not decode.
    fn no_wider(&self, a: &EncodedValue, b: &EncodedValue) -> Option<bool>;
    /// `stored` with every mention of the erased entity `id` taken out, when the key names how
    /// ([`Kind::erase_mentions`]) and `stored` mentions it; `None` otherwise.
    fn erase_mentions_in(&self, stored: &EncodedValue, id: EntityId) -> Option<EncodedValue> {
        let _ = (stored, id);
        None
    }

    /// A learned key's range ([`Kind::learned`]); `None` for a key no fit learns.
    fn learned_range(&self) -> Option<LearnedRange> {
        None
    }
}

/// The typed [`ValueKind`] of a key whose value is a `T`: its default, and optionally its
/// strictest value, its order and how an erase takes an entity out of a value.
pub struct Kind<T> {
    default: fn() -> T,
    strictest: Option<fn() -> T>,
    order: Order,
    /// The order's meet; only an order constructor below writes it.
    meet: Option<fn(&T, &T) -> T>,
    /// The order's comparator; `None`: equality.
    no_wider: Option<fn(&T, &T) -> bool>,
    erase_mentions: Option<fn(&T, EntityId) -> Option<T>>,
    learned: Option<LearnedRange>,
}

impl<T: SettingValue> Kind<T> {
    /// A kind whose default is `default()`.
    #[must_use]
    pub const fn new(default: fn() -> T) -> Self {
        Self {
            default,
            strictest: None,
            order: Order::None,
            meet: None,
            no_wider: None,
            erase_mentions: None,
            learned: None,
        }
    }

    /// This kind, whose unreadable row reads as `strictest()`.
    #[must_use]
    pub const fn strictest(self, strictest: fn() -> T) -> Self {
        Self {
            strictest: Some(strictest),
            ..self
        }
    }

    /// This kind, of a key whose moves guard nothing ([`Order::Neutral`]): no access,
    /// authority, money or identity moves with its value, so an agent holder's move never asks.
    #[must_use]
    pub const fn neutral(self) -> Self {
        Self {
            order: Order::Neutral,
            ..self
        }
    }

    /// This kind, judged by its own comparator ([`Order::Custom`]): `no_wider(a, b)` says `a` is
    /// no wider than `b`, as the manifest's comparator arm for the table says today. It has no
    /// meet, so the key has one slot, at the vault, and takes no request.
    #[must_use]
    pub const fn custom(self, no_wider: fn(&T, &T) -> bool) -> Self {
        Self {
            order: Order::Custom,
            meet: None,
            no_wider: Some(no_wider),
            ..self
        }
    }

    /// This kind with `order`, and the meet and comparator that order derives.
    const fn ordered(
        self,
        order: Order,
        meet: fn(&T, &T) -> T,
        no_wider: fn(&T, &T) -> bool,
    ) -> Self {
        Self {
            order,
            meet: Some(meet),
            no_wider: Some(no_wider),
            ..self
        }
    }

    /// This kind, whose value may name entities: `erase(value, id)` is the value with `id` taken
    /// out, or `None` when the value does not name it. An erase of `id` rewrites each stored row
    /// of the key in place with it, and writes no change row (the change rows that name `id` go).
    #[must_use]
    pub const fn erase_mentions(self, erase: fn(&T, EntityId) -> Option<T>) -> Self {
        Self {
            erase_mentions: Some(erase),
            ..self
        }
    }

    /// The kind as given: [`setting_keys!`] passes each row's kind through it, so a row's kind
    /// is of the row's own value type.
    #[must_use]
    pub const fn of(kind: Self) -> Self {
        kind
    }

    /// `stored` as a `T`, or `None`.
    pub(crate) fn decode(stored: &EncodedValue) -> Option<T> {
        stored.decode::<T>()
    }

    pub(crate) fn default_typed(&self) -> T {
        (self.default)()
    }

    pub(crate) fn strictest_typed(&self) -> Option<T> {
        self.strictest.map(|strictest| strictest())
    }

    /// The order's meet; `None` for an order that has none.
    pub(crate) fn meet_typed(&self) -> Option<fn(&T, &T) -> T> {
        self.meet
    }

    /// The order's comparator, for the cap a learned key's holder row is held inside; `None`
    /// where the key has none.
    pub(crate) fn no_wider_typed(&self) -> Option<fn(&T, &T) -> bool> {
        self.no_wider
    }
}

impl<T: SettingValue + PartialOrd> Kind<T> {
    /// This kind, whose smaller value is the stricter ([`Order::Lower`]): a cap, a lifetime, a
    /// threshold. On an `Option`, [`Self::lower_or_absent`] names which end the absent value is.
    #[must_use]
    pub const fn lower(self) -> Self {
        self.ordered(
            Order::Lower,
            oneiron_setting_contract::lower_meet::<T>,
            oneiron_setting_contract::lower_no_wider::<T>,
        )
    }

    /// This kind, whose larger value is the stricter ([`Order::Higher`]): a wait, a rest, a count
    /// of agreeing rulings.
    #[must_use]
    pub const fn higher(self) -> Self {
        self.ordered(
            Order::Higher,
            oneiron_setting_contract::higher_meet::<T>,
            oneiron_setting_contract::higher_no_wider::<T>,
        )
    }
}

impl<T: SettingValue + PartialOrd> Kind<Option<T>> {
    /// This kind, of an optional number whose smaller value is the stricter, with the absent
    /// value at `end` ("no cap" is the loosest cap).
    #[must_use]
    pub const fn lower_or_absent(self, end: AbsentEnd) -> Self {
        match end {
            AbsentEnd::Loosest => self.ordered(
                Order::Lower,
                oneiron_setting_contract::absent_meet::<T, false, false>,
                oneiron_setting_contract::absent_no_wider::<T, false, false>,
            ),
            AbsentEnd::Strictest => self.ordered(
                Order::Lower,
                oneiron_setting_contract::absent_meet::<T, false, true>,
                oneiron_setting_contract::absent_no_wider::<T, false, true>,
            ),
        }
    }

    /// This kind, of an optional number whose larger value is the stricter, with the absent
    /// value at `end` ("never prune" is the strictest horizon of a receipt).
    #[must_use]
    pub const fn higher_or_absent(self, end: AbsentEnd) -> Self {
        match end {
            AbsentEnd::Loosest => self.ordered(
                Order::Higher,
                oneiron_setting_contract::absent_meet::<T, true, false>,
                oneiron_setting_contract::absent_no_wider::<T, true, false>,
            ),
            AbsentEnd::Strictest => self.ordered(
                Order::Higher,
                oneiron_setting_contract::absent_meet::<T, true, true>,
                oneiron_setting_contract::absent_no_wider::<T, true, true>,
            ),
        }
    }
}

impl<T: SettingValue + ChainOrder> Kind<T> {
    /// This kind, whose stricter value ranks first in its type's list ([`Order::Chain`]).
    #[must_use]
    pub const fn chain(self) -> Self {
        self.ordered(
            Order::Chain,
            oneiron_setting_contract::chain_meet::<T>,
            oneiron_setting_contract::chain_no_wider::<T>,
        )
    }
}

impl<T: SettingValue + SetOrder> Kind<T> {
    /// This kind, of a permit list ([`Order::Subset`]): a subset is the stricter.
    #[must_use]
    pub const fn subset(self) -> Self {
        self.ordered(
            Order::Subset,
            oneiron_setting_contract::subset_meet::<T>,
            oneiron_setting_contract::subset_no_wider::<T>,
        )
    }

    /// This kind, of a protect list ([`Order::Superset`]): a superset is the stricter.
    #[must_use]
    pub const fn superset(self) -> Self {
        self.ordered(
            Order::Superset,
            oneiron_setting_contract::superset_meet::<T>,
            oneiron_setting_contract::superset_no_wider::<T>,
        )
    }
}

impl<T: SettingValue + EachOrder> Kind<T> {
    /// This kind, of a struct whose every part names its order
    /// ([`oneiron_setting_contract::each_order!`]): it is no wider when every part is.
    #[must_use]
    pub const fn each(self) -> Self {
        self.ordered(
            Order::Each,
            oneiron_setting_contract::each_meet::<T>,
            oneiron_setting_contract::each_no_wider::<T>,
        )
    }
}

impl Kind<f64> {
    /// This kind, of a learned key (ARCH-0003 `#learning-settings`): a number in `[min, max]` that
    /// a fit learns under the stored rows. A value row is the seed the fit starts from and names
    /// its weight in runs; once a cell's fit has runs of its own it decides at its place before
    /// the seed there; the owner's pin fixes the value against it. A row outside the range is
    /// refused, and a fit outside it is clamped into it. A learned key has no item and sits only at
    /// the goal, project, task type and vault scopes, the places a fit's cell is keyed by.
    #[must_use]
    pub const fn learned(self, min: f64, max: f64) -> Self {
        Self {
            learned: Some(LearnedRange { min, max }),
            ..self
        }
    }
}

impl<T: SettingValue> ValueKind for Kind<T> {
    fn schema(&self) -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(T)).unwrap_or(serde_json::Value::Null)
    }

    fn default_value(&self) -> Result<EncodedValue> {
        EncodedValue::encode(&(self.default)())
    }

    fn strictest_value(&self) -> Result<Option<EncodedValue>> {
        self.strictest
            .map(|strictest| EncodedValue::encode(&strictest()))
            .transpose()
    }

    fn decodes(&self, stored: &EncodedValue) -> bool {
        Self::decode(stored).is_some()
    }

    fn to_json(&self, stored: &EncodedValue) -> Option<serde_json::Value> {
        Self::decode(stored).and_then(|value| serde_json::to_value(value).ok())
    }

    fn from_json(&self, json: serde_json::Value) -> Result<EncodedValue> {
        let value: T = serde_json::from_value(json).map_err(|error| {
            Error::InvalidConfig(format!("the value is not of this key's type: {error}"))
        })?;
        let encoded = EncodedValue::checked(value)?;
        // Only `Kind<f64>` is learned, so its value decodes as a number.
        if let Some(range) = self.learned
            && !encoded
                .decode::<f64>()
                .is_some_and(|value| range.contains(value))
        {
            return Err(Error::InvalidConfig(format!(
                "a value of this learned key lies in [{}, {}]",
                range.min, range.max
            )));
        }
        Ok(encoded)
    }

    fn order(&self) -> Order {
        self.order
    }

    fn meet(&self, a: &EncodedValue, b: &EncodedValue) -> Option<EncodedValue> {
        let meet = self.meet?;
        EncodedValue::encode(&meet(&Self::decode(a)?, &Self::decode(b)?)).ok()
    }

    fn no_wider(&self, a: &EncodedValue, b: &EncodedValue) -> Option<bool> {
        let (a, b) = (Self::decode(a)?, Self::decode(b)?);
        Some(match self.no_wider {
            Some(no_wider) => no_wider(&a, &b),
            None => a == b,
        })
    }

    fn learned_range(&self) -> Option<LearnedRange> {
        self.learned
    }

    fn erase_mentions_in(&self, stored: &EncodedValue, id: EntityId) -> Option<EncodedValue> {
        let erase = self.erase_mentions?;
        // The erase must land whatever the value's check says of the rest: encode, never refuse.
        EncodedValue::encode(&erase(&Self::decode(stored)?, id)?).ok()
    }
}

/// The kind of [`SettingSpec::BASE`], which every row replaces.
struct NoKind;

impl ValueKind for NoKind {
    fn schema(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    fn default_value(&self) -> Result<EncodedValue> {
        Err(no_kind())
    }

    fn strictest_value(&self) -> Result<Option<EncodedValue>> {
        Err(no_kind())
    }

    fn decodes(&self, _stored: &EncodedValue) -> bool {
        false
    }

    fn to_json(&self, _stored: &EncodedValue) -> Option<serde_json::Value> {
        None
    }

    fn from_json(&self, _json: serde_json::Value) -> Result<EncodedValue> {
        Err(no_kind())
    }

    fn order(&self) -> Order {
        Order::None
    }

    fn meet(&self, _a: &EncodedValue, _b: &EncodedValue) -> Option<EncodedValue> {
        None
    }

    fn no_wider(&self, _a: &EncodedValue, _b: &EncodedValue) -> Option<bool> {
        None
    }
}

fn no_kind() -> Error {
    Error::InvariantViolation("a setting row names no value kind")
}

/// A typed handle on one catalogue key: what [`setting_keys!`] declares, and what a reader reads
/// through.
pub struct Setting<T: 'static> {
    pub(crate) spec: &'static SettingSpec,
    pub(crate) kind: &'static Kind<T>,
    pub(crate) value: PhantomData<fn() -> T>,
}

/// Any catalogue key, whatever its value type: the catalogue's entry.
pub trait SettingKey: Sync {
    fn spec(&self) -> &'static SettingSpec;
}

impl<T: SettingValue> SettingKey for Setting<T> {
    fn spec(&self) -> &'static SettingSpec {
        self.spec
    }
}

/// Declares catalogue keys, each a `static` [`Setting`] in the module that invokes it. Rows live
/// in a module's `setting_keys.rs`, where the crate's build script reads them into the
/// catalogue.
///
/// ```ignore
/// crate::setting::setting_keys! {
///     /// The owner's undo-send window: seconds a send waits before it goes.
///     pub(crate) UNDO_SEND: UndoSendSecs = "outbound.undo_send" {
///         kind: Kind::new(UndoSendSecs::off),
///         item: Some(OUTBOUND_CHANNEL),
///     };
/// }
/// ```
///
/// `kind` is the row's [`Kind`]; every other field is a [`SettingSpec`] field, and a field left
/// out takes [`SettingSpec::BASE`]'s.
macro_rules! setting_keys {
    ($(
        $(#[doc = $doc:literal])*
        $vis:vis $name:ident : $ty:ty = $key:literal {
            kind: $kind:expr
            $(, $field:ident : $value:expr)* $(,)?
        };
    )*) => {$(
        $(#[doc = $doc])*
        $vis static $name: $crate::setting::Setting<$ty> = $crate::setting::Setting {
            spec: &$crate::setting::SettingSpec {
                name: $key,
                doc: concat!($($doc, "\n",)*),
                kind: &$crate::setting::Kind::<$ty>::of($kind),
                $($field: $value,)*
                ..$crate::setting::SettingSpec::BASE
            },
            kind: &$crate::setting::Kind::<$ty>::of($kind),
            value: ::core::marker::PhantomData,
        };
    )*};
}
pub(crate) use setting_keys;
