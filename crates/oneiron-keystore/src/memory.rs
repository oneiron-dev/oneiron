//! Process memory only, for tests: a restart loses every slot and every sealed
//! value, so no host keeps its machine's seed here.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::auth_bound::{check_auth_value, without_trailing_zeros};
use crate::sealed_bytes::check_sealed_len;
use crate::{
    AuthBoundError, AuthBoundSecretStore, DeviceKeystore, KeystoreError, KeystoreLocality,
    KeystoreSlot, Result, SealedBytesName, SealedBytesStore,
};

/// Slots live in this value and are wiped when it drops. Sealed values live
/// beside them, under names of their own.
#[derive(Default)]
pub struct MemoryKeystore {
    slots: Mutex<HashMap<KeystoreSlot, Zeroizing<[u8; 32]>>>,
    sealed: Mutex<HashMap<SealedBytesName, Vec<u8>>>,
    /// The stand-in for hardware that counts wrong auth values, when a test
    /// asked for one.
    auth_bound: Option<Mutex<CountedAuthBound>>,
}

/// The auth-bound secret of a keystore made by
/// [`MemoryKeystore::with_counted_auth_bound`], counted as a TPM counts.
struct CountedAuthBound {
    held: Option<HeldAuthBound>,
    wrong_tries: u32,
    max_wrong_tries: u32,
    wait_secs: u64,
}

/// A secret and the auth value it rests under.
struct HeldAuthBound {
    /// The auth value as the hardware keeps it: without trailing zeros.
    auth: Zeroizing<Vec<u8>>,
    secret: Zeroizing<[u8; 32]>,
}

impl MemoryKeystore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A keystore that also holds an auth-bound secret
    /// ([`DeviceKeystore::auth_bound_secret`]) and counts as a TPM does:
    /// after `max_wrong_tries` wrong auth values it takes none, a right one
    /// included, and answers `wait_secs`. A right value does not clear the
    /// count; [`Self::forget_wrong_auth_tries`] does, as the hardware's
    /// recovery time would.
    #[must_use]
    pub fn with_counted_auth_bound(max_wrong_tries: u32, wait_secs: u64) -> Self {
        Self {
            auth_bound: Some(Mutex::new(CountedAuthBound {
                held: None,
                wrong_tries: 0,
                max_wrong_tries,
                wait_secs,
            })),
            ..Self::default()
        }
    }

    /// Clears the count of wrong auth values: the hardware's recovery time
    /// has passed. Nothing to clear on a keystore made without a counter.
    pub fn forget_wrong_auth_tries(&self) {
        if let Some(counted) = &self.auth_bound
            && let Ok(mut counted) = counted.lock()
        {
            counted.wrong_tries = 0;
        }
    }

    fn counted(&self) -> Result<std::sync::MutexGuard<'_, CountedAuthBound>> {
        self.auth_bound
            .as_ref()
            .ok_or(KeystoreError::Unsupported(
                "this keystore holds no auth-bound secret",
            ))?
            .lock()
            .map_err(|_| KeystoreError::Denied)
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

    fn auth_bound_secret(&self) -> Option<&dyn AuthBoundSecretStore> {
        self.auth_bound
            .as_ref()
            .map(|_| self as &dyn AuthBoundSecretStore)
    }
}

impl AuthBoundSecretStore for MemoryKeystore {
    fn holds_auth_bound(&self) -> Result<bool> {
        Ok(self.counted()?.held.is_some())
    }

    fn put_auth_bound(&self, auth: &[u8], secret: &[u8; 32]) -> Result<()> {
        check_auth_value(auth)?;
        self.counted()?.held = Some(HeldAuthBound {
            auth: Zeroizing::new(without_trailing_zeros(auth).to_vec()),
            secret: Zeroizing::new(*secret),
        });
        Ok(())
    }

    fn open_auth_bound(
        &self,
        auth: &[u8],
    ) -> std::result::Result<Option<Zeroizing<[u8; 32]>>, AuthBoundError> {
        check_auth_value(auth)?;
        let mut counted = self.counted()?;
        let Some(held) = &counted.held else {
            return Ok(None);
        };
        if counted.wrong_tries >= counted.max_wrong_tries {
            return Err(AuthBoundError::LockedOut {
                wait_secs: counted.wait_secs,
            });
        }
        if held.auth.as_slice() == without_trailing_zeros(auth) {
            return Ok(Some(Zeroizing::new(*held.secret)));
        }
        counted.wrong_tries += 1;
        Err(AuthBoundError::WrongAuth)
    }

    fn delete_auth_bound(&self) -> Result<()> {
        self.counted()?.held = None;
        Ok(())
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
