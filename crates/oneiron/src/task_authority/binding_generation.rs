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

/// Most bindings one generation names. A party holding more live bindings
/// when its consult is minted keeps the lowest identities, which only ever
/// narrows the bindings that act as it.
pub const MAX_GENERATION_BINDINGS: usize = 8;

/// The live bindings a consult party held when the consult was minted. The
/// party acts as itself while it still holds one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingGeneration {
    len: u8,
    bindings: [BindingId; MAX_GENERATION_BINDINGS],
}

impl BindingGeneration {
    const EMPTY: Self = Self {
        len: 0,
        bindings: [[0; 32]; MAX_GENERATION_BINDINGS],
    };

    /// The generation naming `bindings`, or `None` when there are none.
    pub(crate) fn from_bindings(bindings: impl IntoIterator<Item = BindingId>) -> Option<Self> {
        let sorted: BTreeSet<BindingId> = bindings.into_iter().collect();
        let mut generation = Self::EMPTY;
        for binding in sorted.into_iter().take(MAX_GENERATION_BINDINGS) {
            generation.push(binding);
        }
        (generation.len > 0).then_some(generation)
    }

    fn push(&mut self, binding: BindingId) {
        self.bindings[usize::from(self.len)] = binding;
        self.len += 1;
    }

    /// The bindings named, in ascending order.
    #[must_use]
    pub fn bindings(&self) -> &[BindingId] {
        &self.bindings[..usize::from(self.len)]
    }

    pub(crate) fn names(&self, binding: &BindingId) -> bool {
        self.bindings().contains(binding)
    }

    /// Two facts for the same party converge on the bindings both name. Two
    /// replicas holding the same bindings name them alike; genuinely
    /// different generations meet on none, and no binding then acts as the
    /// party.
    pub(crate) fn meet(held: Option<Self>, seen: Option<Self>) -> Option<Self> {
        match (held, seen) {
            (None, None) => None,
            (Some(held), Some(seen)) => {
                let mut met = Self::EMPTY;
                for binding in held.bindings().iter().filter(|binding| seen.names(binding)) {
                    met.push(*binding);
                }
                Some(met)
            }
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

    /// Strict: one to [`MAX_GENERATION_BINDINGS`] 32-byte binaries in
    /// strictly ascending order, so one generation has one encoding.
    pub(super) fn decode(value: &Value) -> Result<Self> {
        let invalid = || {
            Error::Record(RecordError::InvalidTaskBody(
                "task authority fact generation",
            ))
        };
        let items = value.as_array().ok_or_else(invalid)?;
        if items.is_empty() || items.len() > MAX_GENERATION_BINDINGS {
            return Err(invalid());
        }
        let mut generation = Self::EMPTY;
        for item in items {
            // Binary only: `Value::as_slice` would also read a string's bytes.
            let Value::Binary(bytes) = item else {
                return Err(invalid());
            };
            let binding = BindingId::try_from(bytes.as_slice()).map_err(|_| invalid())?;
            if generation
                .bindings()
                .last()
                .is_some_and(|last| *last >= binding)
            {
                return Err(invalid());
            }
            generation.push(binding);
        }
        Ok(generation)
    }
}
