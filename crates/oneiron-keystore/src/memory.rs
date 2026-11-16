//! Process memory only, for tests: a restart loses every slot and every sealed
//! value, so no host keeps its machine's seed here.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::sealed_bytes::check_sealed_len;
use crate::{
    DeviceKeystore, KeystoreError, KeystoreLocality, KeystoreSlot, Result, SealedBytesName,
    SealedBytesStore,
};

/// Slots live in this value and are wiped when it drops. Sealed values live
/// beside them, under names of their own.
#[derive(Default)]
pub struct MemoryKeystore {
    slots: Mutex<HashMap<KeystoreSlot, Zeroizing<[u8; 32]>>>,
    sealed: Mutex<HashMap<SealedBytesName, Vec<u8>>>,
}

impl MemoryKeystore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::fmt::Debug for MemoryKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryKeystore(..)")
    }
}

impl DeviceKeystore for MemoryKeystore {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let slots = self.slots.lock().map_err(|_| KeystoreError::Denied)?;
        Ok(slots.get(slot).map(|secret| Zeroizing::new(**secret)))
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()> {
        let mut slots = self.slots.lock().map_err(|_| KeystoreError::Denied)?;
        if slots.contains_key(slot) {
            return Err(KeystoreError::AlreadyExists);
        }
        slots.insert(*slot, Zeroizing::new(*secret));
        Ok(())
    }

    fn delete(&self, slot: &KeystoreSlot) -> Result<()> {
        let mut slots = self.slots.lock().map_err(|_| KeystoreError::Denied)?;
        slots.remove(slot);
        Ok(())
    }

    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<bool> {
        let mut slots = self.slots.lock().map_err(|_| KeystoreError::Denied)?;
        let Some(held) = slots.get_mut(slot) else {
            return Ok(false);
        };
        **held = *secret;
        Ok(true)
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ProcessOnly
    }

    fn sealed_bytes(&self) -> Option<&dyn SealedBytesStore> {
        Some(self)
    }
}

impl SealedBytesStore for MemoryKeystore {
    fn get_sealed(&self, name: &SealedBytesName) -> Result<Option<Vec<u8>>> {
        let sealed = self.sealed.lock().map_err(|_| KeystoreError::Denied)?;
        Ok(sealed.get(name).cloned())
    }

    fn put_sealed(&self, name: &SealedBytesName, sealed: &[u8]) -> Result<()> {
        check_sealed_len(sealed)?;
        let mut held = self.sealed.lock().map_err(|_| KeystoreError::Denied)?;
        held.insert(*name, sealed.to_vec());
        Ok(())
    }

    fn delete_sealed(&self, name: &SealedBytesName) -> Result<()> {
        let mut held = self.sealed.lock().map_err(|_| KeystoreError::Denied)?;
        held.remove(name);
        Ok(())
    }
}
