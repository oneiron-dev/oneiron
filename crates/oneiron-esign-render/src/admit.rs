//! The admission hook the shared drawing program charges before it allocates.
//!
//! Every vector growth, string clone, pixel buffer, dictionary entry, and
//! fresh-document object is admitted through this trait at the same place
//! the organ's port admitted it against its operation ledger. The provided
//! methods hold the organ's moved growth and insert policy verbatim; the
//! organ inherits them, and the engine overrides every method with native
//! growth that never fails.

use std::mem::size_of;

use lopdf::{Object, ObjectId};

/// What the drawing program admits against before it allocates: the organ's
/// operation ledger, or nothing for the engine. Never `dyn`: the leaf is
/// generic over `A: Admission`.
pub trait Admission {
    /// How an admission refusal reads: the ledger's refusal for the organ,
    /// [`std::convert::Infallible`] for the engine.
    type Error;

    /// Admit `len` values of `T`, about to be allocated.
    fn admit_len<T>(&self, len: usize) -> Result<(), Self::Error>;

    /// Return freed bytes previously admitted.
    fn release_admitted(&self, bytes: u64);

    /// The refusal for a growth the address space cannot hold.
    fn alloc_failed(bytes: usize) -> Self::Error;

    /// Grow one vector under admission, with double-capacity growth and the
    /// old buffer's release: the organ's `reserve` verbatim.
    fn reserve<T>(&self, output: &mut Vec<T>, additional: usize) -> Result<(), Self::Error> {
        let needed = output
            .len()
            .checked_add(additional)
            .ok_or_else(|| Self::alloc_failed(usize::MAX))?;
        if needed <= output.capacity() {
            return Ok(());
        }
        let old_capacity = output.capacity();
        let target = old_capacity.saturating_mul(2).max(needed);
        let bytes = layout_bytes::<T>(target).ok_or_else(|| Self::alloc_failed(usize::MAX))?;
        self.admit_len::<T>(target)?;
        output
            .try_reserve_exact(target - output.len())
            .map_err(|_| Self::alloc_failed(bytes))?;
        let old_bytes = layout_bytes::<T>(old_capacity).unwrap_or(0);
        self.release_admitted(u64::try_from(old_bytes).unwrap_or(u64::MAX));
        Ok(())
    }

    /// Push one value under admission: `reserve` plus `Vec::push`.
    fn push<T>(&self, output: &mut Vec<T>, value: T) -> Result<(), Self::Error> {
        self.reserve(output, 1)?;
        output.push(value);
        Ok(())
    }

    /// Admit one fresh `Dictionary` entry: key bytes plus a BTree entry share.
    fn admit_dict_entry(&self, key_len: usize) -> Result<(), Self::Error> {
        let bytes = btree_entry_bytes::<Vec<u8>, Object>()
            .checked_add(key_len)
            .ok_or_else(|| Self::alloc_failed(usize::MAX))?;
        self.admit_len::<u8>(bytes)
    }

    /// Admit one fresh `Document` object: the objects-map entry share. The
    /// object's heap is admitted where it is built.
    fn admit_object(&self) -> Result<(), Self::Error> {
        self.admit_len::<u8>(btree_entry_bytes::<ObjectId, Object>())
    }

    /// Admit one image-cache entry: the map share plus the cloned key's bytes.
    fn admit_image_entry(&self, key_len: usize) -> Result<(), Self::Error> {
        let bytes = btree_entry_bytes::<String, ObjectId>()
            .checked_add(key_len)
            .ok_or_else(|| Self::alloc_failed(usize::MAX))?;
        self.admit_len::<u8>(bytes)
    }

    /// Admit one raster image dictionary built whole: `entries` shares plus
    /// the key and inline-name heap bytes the map holds.
    fn admit_image_dict(
        &self,
        entries: usize,
        keys: usize,
        names: usize,
    ) -> Result<(), Self::Error> {
        let bytes = btree_entry_bytes::<Vec<u8>, Object>()
            .checked_mul(entries)
            .and_then(|shares| shares.checked_add(btree_node_bytes::<Vec<u8>, Object>()))
            .and_then(|shares| shares.checked_add(keys))
            .and_then(|shares| shares.checked_add(names))
            .ok_or_else(|| Self::alloc_failed(usize::MAX))?;
        self.admit_len::<u8>(bytes)
    }
}

fn layout_bytes<T>(len: usize) -> Option<usize> {
    len.checked_mul(size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
}

const fn btree_node_bytes<K, V>() -> usize {
    11 * (size_of::<K>() + size_of::<V>()) + 12 * size_of::<usize>() + 64
}

const fn btree_entry_bytes<K, V>() -> usize {
    btree_node_bytes::<K, V>().div_ceil(5)
}
