//! Historical bindings of the actual content-gate inputs, not permission.

#[cfg(feature = "sync")]
use std::io::Write;

use serde::{Deserialize, Serialize};

#[cfg(feature = "sync")]
use super::malformed;
use crate::EntityId;
#[cfg(feature = "sync")]
use crate::WriteActor;
#[cfg(feature = "sync")]
use crate::batch::NativeSkillFinalInput;
#[cfg(feature = "sync")]
use crate::batch::shared_vault_write::SharedVaultWrite;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::federation::SharedVaultWriteInputs;

/// Only fingerprints cross the witness boundary. Source bodies and semantic
/// actor ids stay in the original private, transaction-owned input frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ContentSource {
    Unobserved,
    Personal,
    Shared {
        vault_id: u64,
        previous_scope: Option<[u8; 32]>,
        before: Option<SharedSuccess>,
        after: Option<SharedSuccess>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SharedSuccess {
    grant: [u8; 16],
    inputs_fingerprint: [u8; 32],
    expiry_checked_at: Option<u64>,
}

impl ContentSource {
    #[cfg(feature = "sync")]
    pub(super) fn capture(input: &NativeSkillFinalInput<'_>) -> Result<Self> {
        let Some(source) = input.content_inputs() else {
            return Ok(Self::Unobserved);
        };
        let Some(vault_id) = source.shared_vault_id() else {
            return Ok(Self::Personal);
        };
        Ok(Self::Shared {
            vault_id,
            // This is the original current scope, including at publication
            // one; it is never reconstructed from a previous native fact.
            previous_scope: source.previous_scope().map(fingerprint).transpose()?,
            before: source.before().map(SharedSuccess::capture).transpose()?,
            after: source.after().map(SharedSuccess::capture).transpose()?,
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        if let Self::Shared { before, after, .. } = self {
            for source in [before, after].into_iter().flatten() {
                EntityId::from_bytes(source.grant)?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "sync")]
impl SharedSuccess {
    fn capture(source: SharedVaultWriteInputs<'_>) -> Result<Self> {
        let SharedVaultWrite::Content(scope) = source.requested() else {
            return Err(malformed());
        };
        let (grant, raw) = source.grant();
        // Encode the original eight inputs, including the full writer and
        // distinct importer principal. No receiver-time lookup or stamp mint.
        // Fold bytes include install-local state and diagnostics: this binds
        // that exact source, not a universally reproducible authority proof.
        let inputs_fingerprint = fingerprint(&(
            source.vault_id(),
            actor_input(source.writer()),
            actor_input(source.principal()),
            source.fold(),
            grant.as_bytes(),
            raw,
            scope,
            source.expiry_checked_at(),
        ))?;
        Ok(Self {
            grant: *grant.as_bytes(),
            inputs_fingerprint,
            expiry_checked_at: source.expiry_checked_at(),
        })
    }
}

#[cfg(feature = "sync")]
fn actor_input(
    actor: WriteActor,
) -> (
    [u8; 16],
    u8,
    Option<crate::authority::AuthorityEntryHash>,
    Option<[u8; 16]>,
) {
    (
        *actor.entity_ref().as_bytes(),
        actor.actor_class() as u8,
        actor.authority_frontier(),
        actor.run_attempt(),
    )
}

/// Feed the typed encoding straight into the hash, without retaining a raw
/// serialized authority fold, scope, grant or principal body in a buffer.
#[cfg(feature = "sync")]
fn fingerprint<T: Serialize + ?Sized>(value: &T) -> Result<[u8; 32]> {
    let mut writer = FingerprintWriter(blake3::Hasher::new());
    value
        .serialize(&mut rmp_serde::Serializer::new(&mut writer).with_struct_map())
        .map_err(|_| malformed())?;
    Ok(*writer.0.finalize().as_bytes())
}

#[cfg(feature = "sync")]
struct FingerprintWriter(blake3::Hasher);

#[cfg(feature = "sync")]
impl Write for FingerprintWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
