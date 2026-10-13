//! Process memory only: for tests and for hosts that hold no secret at rest.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::{DeviceKeystore, KeystoreError, KeystoreLocality, KeystoreSlot, Result};

/// Slots live in this value and are wiped when it drops.
#[derive(Default)]
pub struct MemoryKeystore {
    slots: Mutex<HashMap<KeystoreSlot, Zeroizing<[u8; 32]>>>,
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

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ProcessOnly
    }
}
