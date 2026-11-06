//! The owner's explicit naming of this install's predecessor device key.

use serde::{Deserialize, Serialize};

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::EdgeActorClass;
use crate::consent::AuthenticatedOwner;

/// A predecessor as an erase receipt spells it. The client is a string so
/// SDK callers preserve all 64 bits. A returned value confirms the naming
/// act committed, not that the predecessor's pending sweeps have completed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DevicePredecessor {
    /// The receipt's `att_client`: exactly 16 lowercase hexadecimal digits.
    pub client: String,
    /// The receipt's `att_pk`: exactly 64 lowercase hexadecimal digits.
    pub device_key: String,
}

impl DevicePredecessor {
    /// The exact identifiers carried by the receipt, with no numeric SDK
    /// conversion, fingerprint substitution or current-device fallback.
    pub fn identifiers(&self) -> MemoryResult<(u64, [u8; 32])> {
        if !lower_hex(&self.client, 16) {
            return Err(MemoryError::bad_request(
                "client must be 16 lowercase hexadecimal digits",
            ));
        }
        if !lower_hex(&self.device_key, 64) {
            return Err(MemoryError::bad_request(
                "device_key must be 64 lowercase hexadecimal digits",
            ));
        }
        let client = u64::from_str_radix(&self.client, 16)
            .map_err(|_| MemoryError::bad_request("invalid predecessor client"))?;
        let mut device_key = [0; 32];
        for (index, byte) in device_key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.device_key[index * 2..index * 2 + 2], 16)
                .map_err(|_| MemoryError::bad_request("invalid predecessor device key"))?;
        }
        Ok((client, device_key))
    }
}

fn lower_hex(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Memory<'_> {
    /// `vault.devices.predecessor.name`: the actual owner names a predecessor
    /// under the native door, which supplies this install's successor and
    /// revalidates the owner in the authority writer before committing.
    pub fn device_predecessor_name_as(
        &self,
        owner: &AuthenticatedOwner,
        input: DevicePredecessor,
    ) -> MemoryResult<DevicePredecessor> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "device predecessor naming acts as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        let (client, device_key) = input.identifiers()?;
        self.vault.name_device_predecessor_as_owner(
            owner,
            self.owner_surface(),
            client,
            device_key,
        )?;
        Ok(input)
    }
}
