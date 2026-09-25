//! Pure interning state machine. No source-local handle can select a destination kind.

use super::types::{
    PackByteMapSnapshot, PackInstanceEnvelope, PackInstanceOrigin, PackKindIdentity,
    PackKindRegistration, invalid,
};
use crate::error::{Error, RegistryError, Result};
use crate::registry::{TypeByteZone, zone_of};
use std::collections::BTreeSet;

// The final local pack slot doubles as the shared subtype carrier on overflow.
// This is an allocation policy, not a globally identified entity kind.
pub(super) const SHARED_HANDLE: u8 = 247;

impl PackByteMapSnapshot {
    pub(super) fn empty() -> Self {
        Self {
            version: 1,
            map_id: *crate::entity_id::EntityId::now().as_bytes(),
            revision: 0,
            registrations: Default::default(),
            slot_generations: Default::default(),
        }
    }

    /// Validate an exported snapshot as data. This never activates it locally.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || crate::entity_id::EntityId::from_bytes(self.map_id).is_err() {
            return Err(invalid("invalid pack map version or lineage"));
        }
        let mut handles = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        let mut allocations = BTreeSet::new();
        for (name, row) in &self.registrations {
            row.identity.validate()?;
            if name != &row.identity.name
                || row.generation == 0
                || (row.active && row.handle.is_none())
                || !prefixes.insert(row.identity.short_id_prefix())
            {
                return Err(invalid("pack map key, generation or prefix conflict"));
            }
            if let Some(handle) = row.handle
                && (zone_of(handle) != TypeByteZone::PackHandle
                    || (handle != SHARED_HANDLE && !handles.insert(handle))
                    || !allocations.insert((handle, row.generation))
                    || !self.slot_generations.get(&handle).is_some_and(|last| {
                        if handle == SHARED_HANDLE {
                            *last >= row.generation
                        } else {
                            *last == row.generation
                        }
                    }))
            {
                return Err(invalid("pack map handle or generation conflict"));
            }
        }
        if self.slot_generations.iter().any(|(handle, generation)| {
            zone_of(*handle) != TypeByteZone::PackHandle || *generation == 0
        }) {
            return Err(invalid("invalid historical pack slot generation"));
        }
        Ok(())
    }

    pub(super) fn install(&mut self, identity: &PackKindIdentity) -> Result<PackKindRegistration> {
        identity.validate()?;
        if let Some(prior) = self.registrations.get_mut(&identity.name) {
            if prior.identity != *identity {
                return Err(Error::Registry(RegistryError::PackKindNameCollision(
                    identity.name.clone(),
                )));
            }
            if prior.handle.is_some() {
                prior.active = true;
                return Ok(prior.clone());
            }
        }
        // Include inactive rows: their handle remains pinned until GC proves
        // that not even a soft-deleted shell in the active store refers to it.
        let occupied: BTreeSet<u8> = self
            .registrations
            .values()
            .filter_map(|r| r.handle)
            .collect();
        let handle = (u8::MIN..=u8::MAX)
            .find(|b| zone_of(*b) == TypeByteZone::PackHandle && !occupied.contains(b))
            .unwrap_or(SHARED_HANDLE);
        let generation = self
            .slot_generations
            .get(&handle)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("pack slot generation"))?;
        self.slot_generations.insert(handle, generation);
        let row = PackKindRegistration {
            identity: identity.clone(),
            handle: Some(handle),
            generation,
            active: true,
        };
        self.registrations
            .insert(identity.name.clone(), row.clone());
        Ok(row)
    }

    pub(super) fn installed(&self, name: &str) -> Result<&PackKindRegistration> {
        self.registrations
            .get(name)
            .filter(|row| row.active && row.handle.is_some())
            .ok_or_else(|| Error::Registry(RegistryError::PackKindNotInstalled(name.to_owned())))
    }

    pub(super) fn envelope(
        &self,
        name: &str,
        payload: &[u8],
    ) -> Result<(u8, PackInstanceEnvelope)> {
        let row = self.installed(name)?;
        let handle = row
            .handle
            .ok_or_else(|| invalid("active pack kind has no handle"))?;
        Ok((
            handle,
            PackInstanceEnvelope {
                version: 1,
                kind: row.identity.clone(),
                generation: row.generation,
                origin: PackInstanceOrigin {
                    map_id: self.map_id,
                    handle,
                    generation: row.generation,
                },
                payload: payload.to_vec(),
            },
        ))
    }

    pub(super) fn validate_instance(
        &self,
        handle: u8,
        envelope: &PackInstanceEnvelope,
    ) -> Result<()> {
        envelope.validate()?;
        let row = self.installed(&envelope.kind.name)?;
        if row.identity != envelope.kind
            || row.handle != Some(handle)
            || row.generation != envelope.generation
        {
            return Err(invalid(
                "pack instance identity or local allocation is stale",
            ));
        }
        Ok(())
    }

    pub(super) fn remap(
        &self,
        envelope: &PackInstanceEnvelope,
    ) -> Result<(u8, PackInstanceEnvelope)> {
        envelope.validate()?;
        let row = self.installed(&envelope.kind.name)?;
        if row.identity != envelope.kind {
            return Err(Error::Registry(RegistryError::PackKindNameCollision(
                envelope.kind.name.clone(),
            )));
        }
        let mut mapped = envelope.clone();
        mapped.generation = row.generation;
        Ok((
            row.handle
                .ok_or_else(|| invalid("active pack kind has no handle"))?,
            mapped,
        ))
    }
}
