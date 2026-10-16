//! The engine's `[limits]` rows and the port a crossed row asks through
//! (ARCH-0044 C5, OF-520).
//!
//! A row is a bound, set far above everyday use, on work an engine door
//! serves. Crossing one never refuses: the door measures where the bound
//! lives, tells the installed [`LimitAsk`] port, and serves the work whole.
//! The server installs its OF-520 questions as the port when it opens the
//! vault; an embedding app may install its own. With no port installed, a
//! crossing asks nobody.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

/// One engine `[limits]` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EngineLimit {
    /// Serialized bytes of one keyed-memory value with its stored wrapper
    /// (`key_value_put`).
    KeyedValueJsonBytes,
}

impl EngineLimit {
    /// Every engine row.
    pub const ALL: [Self; 1] = [Self::KeyedValueJsonBytes];

    /// The config key that sets the row.
    pub const fn key(self) -> &'static str {
        match self {
            Self::KeyedValueJsonBytes => "limits.keyed_value_json_bytes",
        }
    }

    /// What the row is set to when nothing sets it.
    pub const fn default_bound(self) -> u64 {
        match self {
            Self::KeyedValueJsonBytes => 64 << 20,
        }
    }
}

/// What each engine row is set to: its default, unless set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineLimits {
    set: BTreeMap<EngineLimit, u64>,
}

impl EngineLimits {
    /// What `row` is set to.
    pub fn bound(&self, row: EngineLimit) -> u64 {
        self.set.get(&row).copied().unwrap_or(row.default_bound())
    }

    /// Sets `row` to `bound`.
    pub fn set(&mut self, row: EngineLimit, bound: u64) {
        self.set.insert(row, bound);
    }
}

/// Where a crossed engine row asks whether everything is okay. It is told on
/// the serving path, possibly inside a write transaction, so it must not wait
/// on storage or on the work it is told about; keeping the question is its
/// own business.
pub trait LimitAsk: Send + Sync {
    /// `row`, set to `bound`, measured `measured`. The work is served either
    /// way.
    fn crossed(&self, row: EngineLimit, bound: u64, measured: u64);
}

/// One open vault's engine rows: what they are set to, fixed when it opened,
/// and the port they ask through, none until a host installs one.
#[derive(Default)]
pub struct LimitWatch {
    bounds: EngineLimits,
    ask: RwLock<Option<Arc<dyn LimitAsk>>>,
}

impl LimitWatch {
    /// Rows set to `bounds`, asking nobody yet.
    pub fn new(bounds: EngineLimits) -> Self {
        Self {
            bounds,
            ask: RwLock::default(),
        }
    }

    /// Installs the port crossings ask through, in place of any before it.
    pub fn install(&self, ask: Arc<dyn LimitAsk>) {
        *self.ask.write().unwrap_or_else(PoisonError::into_inner) = Some(ask);
    }

    /// What `row` is set to.
    pub fn bound(&self, row: EngineLimit) -> u64 {
        self.bounds.bound(row)
    }

    /// Work measured `measured` against `row`: past what the row is set to,
    /// the installed port is asked. It never refuses; the caller serves the
    /// work either way.
    pub fn measure(&self, row: EngineLimit, measured: u64) {
        let bound = self.bound(row);
        if measured <= bound {
            return;
        }
        let ask = self
            .ask
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(ask) = ask {
            ask.crossed(row, bound, measured);
        }
    }
}
