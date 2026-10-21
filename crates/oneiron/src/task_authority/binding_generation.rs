//! The binding generation a consult party held when its consult was minted.
//!
//! A generation names bindings, never an authority-log frontier: a frontier
//! is where one replica happened to observe a binding, so two replicas
//! holding the same binding would record different ones, and a key rebound
//! away and back would find its old frontier qualifying again. A binding's
//! identity is its key, epoch, actor and class, and every rebind or regrant
//! is a new epoch.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::error::{Error, RecordError, Result};

/// One binding's identity, a digest of its key, epoch, actor and class.
pub type BindingId = [u8; 32];

/// The live bindings a consult party held when the consult was minted, every
/// one of them, in ascending order. The party acts as itself while it still
/// holds one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingGeneration {
    bindings: Vec<BindingId>,
}

impl BindingGeneration {
    const EMPTY: Self = Self {
        bindings: Vec::new(),
    };

    /// The generation naming every one of `bindings`, or `None` when there
    /// are none.
    pub(crate) fn from_bindings(bindings: impl IntoIterator<Item = BindingId>) -> Option<Self> {
        let sorted: BTreeSet<BindingId> = bindings.into_iter().collect();
        (!sorted.is_empty()).then(|| Self {
            bindings: sorted.into_iter().collect(),
        })
    }

    /// [`Self::from_bindings`] for bindings of several classes: every one is
    /// named, so no class the party holds is left out.
    pub(crate) fn from_classed_bindings(bindings: &[(&str, BindingId)]) -> Option<Self> {
        Self::from_bindings(bindings.iter().map(|(_, binding)| *binding))
    }

    /// The bindings named, in ascending order.
    #[must_use]
    pub fn bindings(&self) -> &[BindingId] {
        &self.bindings
    }

    pub(crate) fn names(&self, binding: &BindingId) -> bool {
        self.bindings.binary_search(binding).is_ok()
    }

    /// Two facts for the same party converge on the bindings both name. Two
    /// replicas holding the same bindings name them alike; genuinely
    /// different generations meet on none, and no binding then acts as the
    /// party.
    pub(crate) fn meet(held: Option<Self>, seen: Option<Self>) -> Option<Self> {
        match (held, seen) {
            (None, None) => None,
            (Some(held), Some(seen)) => Some(Self {
                bindings: held
                    .bindings
                    .into_iter()
                    .filter(|binding| seen.names(binding))
                    .collect(),
            }),
            // One fact recorded no binding and the other some: hold to the
            // stricter, which none of them satisfies.
            _ => Some(Self::EMPTY),
        }
    }

    pub(super) fn encode(&self) -> Value {
        Value::Array(
            self.bindings()
                .iter()
                .map(|binding| Value::Binary(binding.to_vec()))
                .collect(),
        )
    }

    /// Strict: one or more 32-byte binaries in strictly ascending order, so
    /// one generation has one encoding. Every one is read, however many.
    pub(super) fn decode(value: &Value) -> Result<Self> {
        let invalid = || {
            Error::Record(RecordError::InvalidTaskBody(
                "task authority fact generation",
            ))
        };
        let items = value.as_array().ok_or_else(invalid)?;
        if items.is_empty() {
            return Err(invalid());
        }
        let mut bindings: Vec<BindingId> = Vec::with_capacity(items.len());
        for item in items {
            // Binary only: `Value::as_slice` would also read a string's bytes.
            let Value::Binary(bytes) = item else {
                return Err(invalid());
            };
            let binding = BindingId::try_from(bytes.as_slice()).map_err(|_| invalid())?;
            if bindings.last().is_some_and(|last| *last >= binding) {
                return Err(invalid());
            }
            bindings.push(binding);
        }
        Ok(Self { bindings })
    }
}
