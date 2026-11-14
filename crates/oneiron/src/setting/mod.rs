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
//! - Set: [`Vault::set_setting`], one door whose power is checked live in its write: the owner
//!   sets every key; a live holder of the key's `engine.controls` class sets a key of that class;
//!   a subject tightens its own row; anyone else's change waits on a check-in.
//! - Change stream: every change is one `SETTING_CHANGE` row, written in the commit that makes it,
//!   and the feeds' `settings` source.
//! - Verbs: `vault.settings.get`, `vault.settings.list`, `vault.settings.set`.
//!
//! Stage 0.1 lands the primitive unused: no engine key is in the catalogue yet, and no value in
//! force moves.

mod catalogue;
mod change;
mod read;
mod set;
pub(crate) mod tables;

use std::marker::PhantomData;

pub use oneiron_setting_contract::{
    EncodedValue, ReadBy, Resolved, Restore, ScopeKind, Setter, SettingMode, SettingScope,
    SettingSource, SettingSync, SettingValue, higher_is_tighter, lower_is_tighter,
};

pub use self::catalogue::{catalogue, spec_named};
pub use self::change::SettingChange;
pub(crate) use self::change::{
    erase_setting_change_actor_in_txn, erase_setting_content_actor_in_txn,
    erase_setting_entity_in_txn, erase_setting_row_actor_in_txn, settings_after_in_txn,
    settings_head_in_txn,
};
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) use self::read::put_stored_bytes;
pub use self::read::{SettingCatalogueEntry, SettingRowView, SettingView};
pub(crate) use self::read::{SettingListFilter, SettingReader, reader_reads_key_in_txn};
pub use self::set::{SetSetting, SetSettingOutcome, SettingCaller};
use crate::Vault;
use crate::check_in::ActClass;
use crate::error::{Error, Result};
use crate::federation::EngineControlClass;

/// Who may set a key without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetBy {
    /// The owner alone. These are owner acts, and stay owner acts unless the owner grants them.
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
/// wait on the key.
pub type OnChange = fn(&Vault, &mut heed::RwTxn<'_>, &SettingChange) -> Result<()>;

/// One catalogue row: everything the engine knows about a key. Data, not code.
#[derive(Clone, Copy)]
pub struct SettingSpec {
    /// Dotted lowercase ASCII, unique in the catalogue.
    pub name: &'static str,
    /// The row's doc comment: what the key chooses.
    pub doc: &'static str,
    /// The value's type: decode, check, JSON Schema, default, strictest, tighter direction.
    pub kind: &'static dyn ValueKind,
    /// The kinds of scope a row may sit at. The vault is always one.
    pub scopes: &'static [ScopeKind],
    /// For a family key, the items it admits.
    pub item: Option<ItemDomain>,
    /// Who may set it without asking.
    pub set_by: SetBy,
    /// The check-in act class of a change (ARCH-0082 act table).
    pub act: ActClass,
    pub read_by: ReadBy,
    pub restore: Restore,
    pub sync: SettingSync,
    pub on_change: Option<OnChange>,
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
        act: ActClass::ReversibleWork,
        read_by: ReadBy::Holders,
        restore: Restore::Live,
        sync: SettingSync::Vault,
        on_change: None,
    };

    /// Whether a row may sit at `kind`.
    #[must_use]
    pub fn admits_scope(&self, kind: ScopeKind) -> bool {
        kind == ScopeKind::Vault || self.scopes.contains(&kind)
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
    /// Whether the key names which direction is tighter.
    fn has_direction(&self) -> bool;
    /// Whether `a` is at least as tight as `b`; `None` without a direction or when either does
    /// not decode.
    fn is_tighter(&self, a: &EncodedValue, b: &EncodedValue) -> Option<bool>;
}

/// The typed [`ValueKind`] of a key whose value is a `T`: its default, and optionally its
/// strictest value and its tighter direction.
pub struct Kind<T> {
    default: fn() -> T,
    strictest: Option<fn() -> T>,
    tighter: Option<fn(&T, &T) -> bool>,
}

impl<T: SettingValue> Kind<T> {
    /// A kind whose default is `default()`.
    #[must_use]
    pub const fn new(default: fn() -> T) -> Self {
        Self {
            default,
            strictest: None,
            tighter: None,
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

    /// This kind, whose tighter direction is `tighter(a, b)`: `a` is at least as tight as `b`
    /// ([`lower_is_tighter`], [`higher_is_tighter`]).
    #[must_use]
    pub const fn tighter(self, tighter: fn(&T, &T) -> bool) -> Self {
        Self {
            tighter: Some(tighter),
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

    pub(crate) fn tighter_typed(&self) -> Option<fn(&T, &T) -> bool> {
        self.tighter
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
        EncodedValue::checked(value)
    }

    fn has_direction(&self) -> bool {
        self.tighter.is_some()
    }

    fn is_tighter(&self, a: &EncodedValue, b: &EncodedValue) -> Option<bool> {
        let tighter = self.tighter?;
        Some(tighter(&Self::decode(a)?, &Self::decode(b)?))
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

    fn has_direction(&self) -> bool {
        false
    }

    fn is_tighter(&self, _a: &EncodedValue, _b: &EncodedValue) -> Option<bool> {
        None
    }
}

fn no_kind() -> Error {
    Error::InvariantViolation("a setting row names no value kind")
}

/// A typed handle on one catalogue key: what [`setting_keys!`] declares, and what a reader reads
/// through.
pub struct Setting<T> {
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
