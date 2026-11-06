//! Fallible reservation of the native node arena, without a node-count limit.

use super::Tree;
use crate::node::{NodeData, NodeId, TreeNode};
use std::cell::RefCell;
use std::collections::TryReserveError;
use std::mem::size_of;

/// Why native node storage could not be reserved.
#[derive(Debug)]
pub enum ArenaReserveError<E> {
    /// The caller's admission or capacity settlement refused the reservation.
    Refused(E),
    /// The requested native capacity cannot be represented.
    CapacityOverflow,
    /// The allocator could not reserve native storage.
    Allocation(TryReserveError),
}

impl Tree {
    /// Reserve the root's native storage before constructing any node handle.
    /// The returned guard must outlive the tree, unless transferred on replacement.
    pub fn try_new_with_reservation<E, G>(
        root: NodeData,
        mut reserve: impl FnMut(usize) -> Result<G, E>,
        mut settle: impl FnMut(&mut G, usize) -> Result<(), E>,
    ) -> Result<(Self, G), ArenaReserveError<E>> {
        let mut guard = reserve(size_of::<TreeNode>()).map_err(ArenaReserveError::Refused)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(1)
            .map_err(ArenaReserveError::Allocation)?;
        let bytes = nodes
            .capacity()
            .checked_mul(size_of::<TreeNode>())
            .ok_or(ArenaReserveError::CapacityOverflow)?;
        settle(&mut guard, bytes).map_err(ArenaReserveError::Refused)?;
        nodes.push(TreeNode::new(NodeId::new(0), root));
        Ok((
            Self {
                nodes: RefCell::new(nodes),
            },
            guard,
        ))
    }

    /// Reserve actual node capacity before an operation that can create nodes.
    /// This replaces storage rather than reallocating it. The caller keeps the
    /// old guard until this method has freed the old block and returned a new one.
    /// A failure creates no handle and leaves the original arena unchanged.
    pub fn try_reserve_nodes<E, G>(
        &self,
        additional: usize,
        mut reserve: impl FnMut(usize) -> Result<G, E>,
        mut settle: impl FnMut(&mut G, usize) -> Result<(), E>,
    ) -> Result<Option<G>, ArenaReserveError<E>> {
        let mut nodes = self.nodes.borrow_mut();
        let required = nodes
            .len()
            .checked_add(additional)
            .ok_or(ArenaReserveError::CapacityOverflow)?;
        if required <= nodes.capacity() {
            return Ok(None);
        }
        let capacity = required.max(nodes.capacity().saturating_mul(2));
        let bytes = capacity
            .checked_mul(size_of::<TreeNode>())
            .ok_or(ArenaReserveError::CapacityOverflow)?;
        let mut guard = reserve(bytes).map_err(ArenaReserveError::Refused)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(ArenaReserveError::Allocation)?;
        let actual = replacement
            .capacity()
            .checked_mul(size_of::<TreeNode>())
            .ok_or(ArenaReserveError::CapacityOverflow)?;
        settle(&mut guard, actual).map_err(ArenaReserveError::Refused)?;
        replacement.append(&mut nodes);
        std::mem::swap(&mut *nodes, &mut replacement);
        drop(replacement);
        Ok(Some(guard))
    }
}
