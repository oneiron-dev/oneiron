//! The hosted import's verbs (ARCH-0027 #hosted-import; the Engine's rulings
//! of 13 Nov 07:14, substrate behind grants): `vault.imports.get` reads one
//! job's progress, and `vault.imports.cancel` stops one job.
//!
//! - `get` is a read. It answers the vault's owner under the owner's proof,
//!   or a holder of a live Steward grant that names `read` and reaches the
//!   whole vault, checked at each read (untangle 6.6c).
//! - `cancel` is the owner's act. It answers the owner under the owner's
//!   proof, or a holder of a live Steward grant that names `delete` itself
//!   and reaches the whole vault, a grant only the owner gives, checked in
//!   the cancel's own write. It mints and attests nothing.
//!
//! An embedded handle's owner is the handle that holds the vault's writer
//! lease ([`Memory::embedded_owner`]); every other handle calls as its own
//! actor, a holder. A server takes the owner's proof from the request
//! instead and calls the `_as_owner` and `_as_reader` doors.

use serde::{Deserialize, Serialize};

use super::hosted::{HostedImportCanceller, HostedImportId, HostedImportStatus, HostedImportView};
use crate::consent::AuthenticatedOwner;
use crate::federation::{SubstrateRead, admit_substrate_read_by};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{Vault, WriteActor};

/// The read verb's name, as a refusal names it.
const GET_VERB: &str = "vault.imports.get";

/// The cancel verb's name, as a refusal names it.
const CANCEL_VERB: &str = "vault.imports.cancel";

/// Names one hosted import: `vault.imports.get`'s and
/// `vault.imports.cancel`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostedImportLookup {
    /// The import's id, as 32 lowercase hex digits (`oneiron import
    /// <source> <file> --hosted` prints it).
    pub import: String,
}

impl HostedImportLookup {
    fn id(&self) -> MemoryResult<HostedImportId> {
        HostedImportId::parse(&self.import)
            .ok_or_else(|| MemoryError::bad_request("an import id is 32 lowercase hex digits"))
    }
}

/// `vault.imports.cancel`'s answer: the job's state after the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct HostedImportCancel {
    /// The import's id, as 32 lowercase hex digits.
    pub import: String,
    /// `cancelling` until the job's worker has stopped it, then `cancelled`.
    /// A job that had already ended keeps its state.
    pub state: HostedImportStatus,
}

/// `vault.imports.get` under the owner's proof.
///
/// # Errors
///
/// A proof that no longer holds, an id that does not parse, and storage
/// errors.
pub fn hosted_import_get_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HostedImportLookup,
) -> MemoryResult<Option<HostedImportView>> {
    let id = input.id()?;
    Ok(vault.hosted_import_view_as_owner(owner, id)?)
}

/// `vault.imports.get` for a holder of a live Steward grant that names
/// `read` and reaches the whole vault, checked at this read.
///
/// # Errors
///
/// A reader who holds no such grant, an id that does not parse, and storage
/// errors.
pub fn hosted_import_get_as_reader(
    vault: &Vault,
    reader: WriteActor,
    input: &HostedImportLookup,
) -> MemoryResult<Option<HostedImportView>> {
    let id = input.id()?;
    admit_substrate_read_by(vault, reader, GET_VERB, SubstrateRead::Import)?;
    Ok(vault.hosted_import_view(id)?)
}

/// `vault.imports.get` on a bound handle: the embedded owner reads under its
/// own proof, any other caller as a reader.
///
/// # Errors
///
/// As [`hosted_import_get_as_owner`] and [`hosted_import_get_as_reader`].
pub fn hosted_import_get(
    memory: &Memory<'_>,
    input: HostedImportLookup,
) -> MemoryResult<Option<HostedImportView>> {
    match memory.embedded_owner(GET_VERB) {
        Ok(owner) => hosted_import_get_as_owner(memory.vault(), &owner, &input),
        Err(_) => hosted_import_get_as_reader(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
            &input,
        ),
    }
}

/// `vault.imports.cancel` as `canceller`: an unended job is Cancelling until
/// its worker stops it. `None` when there is no such import.
///
/// # Errors
///
/// A canceller who is neither the owner under a proof that holds nor a
/// holder of the grant (FORBIDDEN), an id that does not parse, and storage
/// errors.
pub fn hosted_import_cancel_as(
    vault: &Vault,
    canceller: HostedImportCanceller<'_>,
    input: &HostedImportLookup,
) -> MemoryResult<Option<HostedImportCancel>> {
    let id = input.id()?;
    if !vault.hosted_import_cancel_allowed(canceller)? {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{CANCEL_VERB} is the vault owner's act, or a holder's of a Steward grant naming \
                 `delete` that reaches the whole vault"
            ),
            &[
                "Ask the owner for the grant.",
                "A grant narrowed to some projects, worlds, bands or a sensitivity ceiling does \
                 not cancel an import.",
            ],
        ));
    }
    Ok(vault
        .hosted_import_cancel(canceller, id)?
        .map(|row| HostedImportCancel {
            import: id.to_hex(),
            state: row.state.status(),
        }))
}

/// `vault.imports.cancel` on a bound handle: the embedded owner cancels
/// under its own proof, any other caller as a holder.
///
/// # Errors
///
/// As [`hosted_import_cancel_as`].
pub fn hosted_import_cancel(
    memory: &Memory<'_>,
    input: HostedImportLookup,
) -> MemoryResult<Option<HostedImportCancel>> {
    match memory.embedded_owner(CANCEL_VERB) {
        Ok(owner) => {
            hosted_import_cancel_as(memory.vault(), HostedImportCanceller::Owner(&owner), &input)
        }
        Err(_) => hosted_import_cancel_as(
            memory.vault(),
            HostedImportCanceller::Holder(memory.actor()),
            &input,
        ),
    }
}
