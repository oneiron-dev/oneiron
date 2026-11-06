//! Native final attribute-vector admission for parser sink operations.

use super::{ArenaReserveError, Tree};
use crate::entities::Attr;
use crate::node::NodeId;
use html5ever::Attribute;
use std::fmt::{self, Debug};
use std::mem::{replace, size_of};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct AttributeReservation {
    _guard: Arc<dyn Send + Sync>,
}

impl AttributeReservation {
    pub(crate) fn from_tag_guard(guard: html5ever::tokenizer::TagAttributeGuard) -> Self {
        Self {
            _guard: Arc::new(guard),
        }
    }
}

impl Debug for AttributeReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttributeReservation")
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
pub(crate) struct PreparedAttributes {
    pub(crate) attrs: Vec<Attr>,
    pub(crate) reservation: Option<AttributeReservation>,
}

impl PreparedAttributes {
    pub(crate) fn try_reserve<R, E>(
        &mut self,
        additional: usize,
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<(), ArenaReserveError<E>>
    where
        R: Send + Sync + 'static,
    {
        try_reserve(&mut self.attrs, &mut self.reservation, additional, reserve, settle)
    }
}

fn try_reserve<R, E>(
    attrs: &mut Vec<Attr>,
    reservation: &mut Option<AttributeReservation>,
    additional: usize,
    reserve: impl FnOnce(usize) -> Result<R, E>,
    settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
) -> Result<(), ArenaReserveError<E>>
where
    R: Send + Sync + 'static,
{
    let required = attrs
        .len()
        .checked_add(additional)
        .ok_or(ArenaReserveError::CapacityOverflow)?;
    if required <= attrs.capacity() {
        return Ok(());
    }
    let capacity = required.max(attrs.capacity().saturating_mul(2));
    let bytes = capacity
        .checked_mul(size_of::<Attr>())
        .ok_or(ArenaReserveError::CapacityOverflow)?;
    let mut guard = reserve(bytes).map_err(ArenaReserveError::Refused)?;
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(capacity)
        .map_err(ArenaReserveError::Allocation)?;
    let actual = replacement
        .capacity()
        .checked_mul(size_of::<Attr>())
        .ok_or(ArenaReserveError::CapacityOverflow)?;
    settle(&mut guard, actual).map_err(ArenaReserveError::Refused)?;
    let guard = AttributeReservation {
        _guard: Arc::new(guard),
    };
    replacement.append(attrs);
    let old_attrs = replace(attrs, replacement);
    let old_reservation = replace(reservation, Some(guard));
    drop(old_attrs);
    drop(old_reservation);
    Ok(())
}

impl Tree {
    pub(crate) fn take_prepared_attributes(&self) -> Option<PreparedAttributes> {
        self.prepared_attributes.borrow_mut().take()
    }

    /// Prepare final attribute storage for the immediately following parser
    /// element creation. The sink moves this allocation into that element.
    pub fn try_prepare_parser_attributes<R, E>(
        &self,
        count: usize,
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<(), ArenaReserveError<E>>
    where
        R: Send + Sync + 'static,
    {
        let mut prepared = PreparedAttributes::default();
        try_reserve(
            &mut prepared.attrs,
            &mut prepared.reservation,
            count,
            reserve,
            settle,
        )?;
        let old = self.prepared_attributes.replace(Some(prepared));
        drop(old);
        Ok(())
    }

    /// Reserve the actual element's destination before parser attribute merge.
    /// Incoming duplicates are compared with the original destination names.
    pub fn try_reserve_parser_added_attributes<R, E>(
        &self,
        target: &NodeId,
        incoming: &[Attribute],
        reserve: impl FnOnce(usize) -> Result<R, E>,
        settle: impl FnOnce(&mut R, usize) -> Result<(), E>,
    ) -> Result<(), ArenaReserveError<E>>
    where
        R: Send + Sync + 'static,
    {
        let mut nodes = self.nodes.borrow_mut();
        let Some(element) = nodes
            .get_mut(target.value)
            .and_then(|node| node.as_element_mut())
        else {
            return Ok(());
        };
        let additional = incoming
            .iter()
            .filter(|attr| {
                !element
                    .attrs
                    .iter()
                    .any(|existing| existing.name == attr.name)
            })
            .count();
        try_reserve(
            &mut element.attrs,
            &mut element.attrs_reservation,
            additional,
            reserve,
            settle,
        )
    }
}
