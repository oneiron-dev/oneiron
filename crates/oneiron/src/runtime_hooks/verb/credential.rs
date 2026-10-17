//! A credential caller's call a verb hook's ask stopped, resumed through the
//! door it came in by (ARCH-0080 §3 Ask). Only the host verifies a
//! credential again, so the ask saves a reference to the exact instrument and
//! the door, never the credential; the instrument the request was admitted on
//! waits beside the row as its witness, pinned in the ask's own write.
//!
//! Once the ask settles proceed, the drain hands the saved call to the check
//! the host installed. The check verifies the witness against current
//! authority, rebuilds the caller from it and runs the call through its door,
//! whose own admission runs again. The answer is never the credential: any
//! failure ends the call refused, with one receipt, and a renewed credential
//! starts a new invocation.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::authority::InvocationSlipBinding;
use crate::memory::{MemoryError, MemoryResult};
use crate::receipt::{CallOutcome, CallReceiptInput, CallTransport};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, Result, Vault};

use super::state::DrainScope;
use super::{InvocationId, VerbResume};

/// The witness each credential call's ask pinned, by invocation.
const WITNESSES: SideTable<[u8; 16], VerbAskWitness, Named> =
    SideTable::new(&side_table::HOOKS_VERB_ASK_WITNESS);

thread_local! {
    /// The witness of the credential call whose pre chain runs on this
    /// thread: its ask pins it.
    static WITNESS: RefCell<Option<InvocationSlipBinding>> = const { RefCell::new(None) };
}

/// Where a credential came from. Only a logged slip has a reference its host
/// verifies again; any other caller resumes on its own retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerbAskCredentialSource {
    /// A logged capability slip, admitted with its holder's proof.
    Slip,
}

/// The exact instrument a credential caller presented, as its host binds it
/// on the caller's handle (`Memory::with_credential_instrument`). It names
/// the credential; it is no authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbAskInstrument {
    pub source: VerbAskCredentialSource,
    /// The vault the slip was minted for.
    pub vault: [u8; 32],
    /// The logged slip's id.
    pub slip: [u8; 32],
    /// BLAKE3 of the token presented: a caveated copy is not its mint.
    pub fingerprint: [u8; 32],
    /// BLAKE3 of the authority the host projected from it, its principal and
    /// scopes: the ceiling the call was admitted under.
    pub ceiling: [u8; 32],
}

/// The door a credential call came in by, and what it carried beside the
/// call's input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerbAskDoor {
    /// A facade row, in the room turn the call named, if any.
    Facade { room: Option<EntityId> },
    /// A tool-first MCP row, through the connector registration whose STREAM
    /// connection is `connection`, admitted under that registration's
    /// `ceiling` (BLAKE3).
    Mcp {
        connection: String,
        ceiling: [u8; 32],
    },
}

/// What a credential call's ask saves to run it again: the exact instrument
/// and the door, where the caller sat included. No authority on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbAskCredentialRef {
    pub instrument: VerbAskInstrument,
    pub door: VerbAskDoor,
    /// Whether the caller sat on this device (DEC-0005).
    pub on_device: bool,
}

/// A credential call's reference, with the instrument its request was
/// admitted on (`Memory::verb_ask_credential`).
#[derive(Debug, Clone)]
pub struct VerbAskCredential {
    reference: VerbAskCredentialRef,
    witness: InvocationSlipBinding,
}

impl VerbAskCredential {
    pub(crate) const fn new(
        reference: VerbAskCredentialRef,
        witness: InvocationSlipBinding,
    ) -> Self {
        Self { reference, witness }
    }

    #[must_use]
    pub const fn reference(&self) -> &VerbAskCredentialRef {
        &self.reference
    }

    pub(super) fn into_witness(self) -> InvocationSlipBinding {
        self.witness
    }
}

/// Why the drain ended a credential call before it ran. Every refusal ends
/// the call (OF-580 defaults): nothing waits for a credential to come back,
/// none unavailable is tried again, and no renewed one stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbAskRefusal {
    /// The slip's mint, or the kept witness, is gone.
    CredentialMissing,
    /// The slip or an ancestor was revoked.
    CredentialRevoked,
    /// The slip's lifetime ended.
    CredentialExpired,
    /// The instrument no longer verifies as the one the call was admitted on.
    CredentialChanged,
    /// The host could not establish the credential: no check installed, the
    /// server stopping, or an MCP registration it no longer holds.
    CredentialUnavailable,
    /// The credential's scope, or its connector's, no longer admits the call.
    ScopeRefused,
    /// The door the call came in by cannot be rebuilt.
    ContextUnavailable,
}

impl VerbAskRefusal {
    const ALL: [Self; 7] = [
        Self::CredentialMissing,
        Self::CredentialRevoked,
        Self::CredentialExpired,
        Self::CredentialChanged,
        Self::CredentialUnavailable,
        Self::ScopeRefused,
        Self::ContextUnavailable,
    ];

    /// The stable code a retry's `CompletedWithError` carries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CredentialMissing => "CREDENTIAL_MISSING",
            Self::CredentialRevoked => "CREDENTIAL_REVOKED",
            Self::CredentialExpired => "CREDENTIAL_EXPIRED",
            Self::CredentialChanged => "CREDENTIAL_CHANGED",
            Self::CredentialUnavailable => "CREDENTIAL_UNAVAILABLE",
            Self::ScopeRefused => "SCOPE_REFUSED",
            Self::ContextUnavailable => "CONTEXT_UNAVAILABLE",
        }
    }

    /// The refusal `code` names, if it names one.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|refusal| refusal.code() == code)
    }

    /// Whether the caller's own credential refused: anything but a door or
    /// a credential this host could not establish.
    #[must_use]
    pub const fn names_credential(self) -> bool {
        !matches!(self, Self::CredentialUnavailable | Self::ContextUnavailable)
    }

    const fn message(self) -> &'static str {
        match self {
            Self::CredentialMissing => "the credential this call was admitted on is gone",
            Self::CredentialRevoked => "the credential this call was admitted on was revoked",
            Self::CredentialExpired => "the credential this call was admitted on expired",
            Self::CredentialChanged => {
                "the credential no longer verifies as the one this call was admitted on"
            }
            Self::CredentialUnavailable => "this host could not verify the call's credential again",
            Self::ScopeRefused => "the credential's scope no longer admits this call",
            Self::ContextUnavailable => "the door this call came in by cannot run it again",
        }
    }

    /// The error a refused call ends with. Its code is never the engine's
    /// internal one, so the drain saves it and the call ends.
    pub(super) fn error(self) -> MemoryError {
        MemoryError::new(
            self.code(),
            format!("settlement did not run this call: {}", self.message()),
            &["Call again with a new invocation, on a credential that holds now."],
        )
    }
}

/// One saved call the drain hands the host's check.
#[derive(Debug)]
pub struct VerbAskSavedCall {
    pub invocation: InvocationId,
    pub verb: String,
    pub actor: EntityId,
    pub class: EdgeActorClass,
    /// The saved args: the door checks them again as the caller's own.
    pub args: Value,
    pub reference: VerbAskCredentialRef,
    /// The instrument the caller's request was admitted on. Verify it again
    /// before anything runs; it grants nothing as it is.
    pub witness: InvocationSlipBinding,
}

/// What the host's check did with a saved call.
#[derive(Debug)]
pub enum VerbAskResumed {
    /// The door ran the call: what it returned, or its error.
    Ran(MemoryResult<Value>),
    /// The call was refused before it ran.
    Refused(VerbAskRefusal),
}

/// The host's check for credential calls (ARCH-0080 §3 Ask): only it verifies
/// a credential again and knows the door a call came in by.
pub trait VerbAskCredentialCheck: Send + Sync {
    /// Whether the host would resume a call on `reference`, judged in the
    /// ask's own write `txn` before the engine pins `witness` there. It must
    /// only read. `false` saves no reference: the call resumes on its
    /// caller's retry.
    fn retain_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        reference: &VerbAskCredentialRef,
        witness: &InvocationSlipBinding,
    ) -> bool;

    /// Runs `call` again through the door it came in by, as its credential
    /// stands now: the witness verified again, the caller rebuilt from it
    /// and the door's own admission run. `drain` goes with the call to each
    /// thread its door runs the call's pre chain on. It runs on the hook
    /// runner's blocking thread, outside any write.
    fn resume(&self, call: VerbAskSavedCall, drain: VerbAskDrainPermit) -> VerbAskResumed;
}

/// The drain's leave to run one held call again, on whichever thread its door
/// runs the call's pre chain. Only the drain mints one, while it holds the
/// call; nothing a caller sends builds one and it is never stored. Without the
/// drain's hold it grants nothing.
#[derive(Debug, Clone)]
pub struct VerbAskDrainPermit {
    invocation: InvocationId,
}

impl VerbAskDrainPermit {
    const fn new(invocation: InvocationId) -> Self {
        Self { invocation }
    }

    #[must_use]
    pub const fn invocation(&self) -> InvocationId {
        self.invocation
    }

    /// Marks this thread as the drain's run of the call until the scope
    /// drops: the call's boundary here enters as the drain's own.
    #[must_use]
    pub fn enter(&self) -> VerbAskDrainScope {
        VerbAskDrainScope {
            _scope: DrainScope::enter(self.invocation),
        }
    }
}

/// A thread marked as the drain's run of one call, until dropped.
#[must_use]
pub struct VerbAskDrainScope {
    _scope: DrainScope,
}

/// The witness the pre chain on this thread pins if its call asks, while held.
pub(super) struct WitnessScope(Option<InvocationSlipBinding>, PhantomData<*const ()>);

impl WitnessScope {
    pub(super) fn enter(witness: Option<InvocationSlipBinding>) -> Self {
        Self(WITNESS.with(|held| held.replace(witness)), PhantomData)
    }
}

impl Drop for WitnessScope {
    fn drop(&mut self) {
        let before = self.0.take();
        WITNESS.with(|held| *held.borrow_mut() = before);
    }
}

/// The witness of the credential call whose pre chain runs on this thread.
pub(super) fn witness_on_thread() -> Option<InvocationSlipBinding> {
    WITNESS.with(|held| held.borrow().clone())
}

/// One credential call's pinned witness: the ask it waits on, the reference
/// it backs and the instrument itself. No secret: a slip, its holder's
/// challenge and that signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerbAskWitness {
    #[serde(with = "crate::serialize::entity_ref")]
    ask: EntityId,
    reference: VerbAskCredentialRef,
    binding: InvocationSlipBinding,
}

/// The target ask `ask` saves under `key`, in its own write: a credential
/// call's witness is pinned beside the row when the host's check keeps it,
/// and the call saves its reference; else it saves none and resumes on its
/// caller's retry. Any other target clears a witness an earlier ask of the
/// invocation left.
pub(super) fn retain_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: [u8; 16],
    ask: EntityId,
    resume: Option<&VerbResume>,
    witness: Option<&InvocationSlipBinding>,
) -> Result<Option<VerbResume>> {
    let Some(VerbResume::Credential { reference }) = resume else {
        forget_in_txn(vault, txn, key)?;
        return Ok(resume.cloned());
    };
    let check = vault.verb_hook_state.credential_check();
    let (Some(check), Some(binding)) = (check, witness) else {
        forget_in_txn(vault, txn, key)?;
        return Ok(None);
    };
    if !check.retain_in_txn(vault, txn, reference, binding) {
        forget_in_txn(vault, txn, key)?;
        return Ok(None);
    }
    let witness = VerbAskWitness {
        ask,
        reference: reference.clone(),
        binding: binding.clone(),
    };
    WITNESSES.put(&vault.store, txn, &key, &witness)?;
    Ok(resume.cloned())
}

/// Forgets the witness under `key`, once its call no longer resumes.
pub(super) fn forget_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, key: [u8; 16]) -> Result<()> {
    WITNESSES.delete(&vault.store, txn, &key).map(drop)
}

/// Hands the drain's held call stopped on ask `ask` to the host's check, the
/// call's thread marked as the drain's. No check installed, or no witness
/// pinned for this ask and reference, refuses it before anything runs.
#[expect(
    clippy::too_many_arguments,
    reason = "the saved call's parts, as the drain read them"
)]
pub(super) fn resume(
    vault: &Vault,
    key: [u8; 16],
    ask: EntityId,
    verb: String,
    actor: EntityId,
    class: EdgeActorClass,
    args: Value,
    reference: VerbAskCredentialRef,
) -> Result<VerbAskResumed> {
    let Some(check) = vault.verb_hook_state.credential_check() else {
        return Ok(VerbAskResumed::Refused(
            VerbAskRefusal::CredentialUnavailable,
        ));
    };
    let witness = {
        let rtxn = vault.store.env.read_txn()?;
        WITNESSES.get_lenient(&vault.store, &rtxn, &key)?
    };
    let Some(witness) =
        witness.filter(|witness| witness.ask == ask && witness.reference == reference)
    else {
        return Ok(VerbAskResumed::Refused(VerbAskRefusal::CredentialMissing));
    };
    let invocation = InvocationId(key);
    let call = VerbAskSavedCall {
        invocation,
        verb,
        actor,
        class,
        args,
        reference,
        witness: witness.binding,
    };
    let _draining = DrainScope::enter(invocation);
    Ok(check.resume(call, VerbAskDrainPermit::new(invocation)))
}

/// What one ended credential call's refusal receipt names: the call, its
/// caller and its credential's id, never a secret or a body.
pub(super) struct RefusalReceipt {
    transport: CallTransport,
    verb: String,
    actor_ref: String,
    actor_class: String,
    credential_ref: String,
    request_digest: String,
}

impl RefusalReceipt {
    pub(super) fn new(
        reference: &VerbAskCredentialRef,
        verb: &str,
        actor: EntityId,
        class: EdgeActorClass,
        args: &Value,
    ) -> Self {
        Self {
            transport: match reference.door {
                VerbAskDoor::Facade { .. } => CallTransport::HttpFacade,
                VerbAskDoor::Mcp { .. } => CallTransport::Mcp,
            },
            verb: verb.to_owned(),
            actor_ref: actor.to_hex(),
            actor_class: class.gate_actor_class().to_owned(),
            credential_ref: crate::receipt::hex_lower(&reference.instrument.slip),
            request_digest: crate::receipt::call_json_digest(args),
        }
    }

    /// The receipt of the call ended with `code` and `message`.
    pub(super) fn refused(self, code: &str, message: &str) -> CallReceiptInput {
        CallReceiptInput {
            transport: self.transport,
            verb: self.verb,
            actor_ref: self.actor_ref,
            actor_class: self.actor_class,
            credential_ref: Some(self.credential_ref),
            outcome: CallOutcome::Refused {
                code: code.to_owned(),
            },
            request_digest: self.request_digest,
            result_digest: Some(crate::receipt::call_refusal_digest(code, message)),
            served: Vec::new(),
        }
    }
}

/// The host's check, as the vault holds it.
pub(super) type CredentialCheck = Arc<dyn VerbAskCredentialCheck>;
