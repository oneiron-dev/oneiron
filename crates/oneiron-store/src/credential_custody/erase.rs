//! An erased credential stays erased (KS-6 part 2, FIX-LIST 7403, 5687): one
//! terminal fence per credential id an authorized erase reached, the
//! discovery that stages every key the id names to retire, and the finisher
//! that carries them out.
//!
//! An owner's erase of a custody record, and a run-bound seat's end (FIX
//! 8028), write the fence first, in the erase's own transaction: value-free
//! and permanent. Then the prefix catalog lists every custody subject the id
//! names (its value's, and every transition's and request input's instance,
//! abandoned ones included) and an erase intent is staged for each through
//! the newest generation custody holds of it. A catalog or generation read
//! that faults leaves the fence's discovery owed, warned: the finisher, a
//! reopen and upkeep retry it, and the erase's receipt never reads complete
//! meanwhile (CALLS `KS-6 erase discovery fault`). A fence that does not
//! write is warned and the erase lands all the same: its receipt still
//! binds the credential's whole erase, pending, and the finisher installs
//! the fence again from the erase intents the erase committed. No erase is
//! refused for either.
//!
//! The fence closes the id, every generation and instance of it: no key is
//! minted under it again, no body is put under it again, and no image, fork,
//! restore, activation, archive or transition brings it back, nor is a
//! carrier of it kept or relayed (CALLS `KS-6 erase fence form`).
//! Re-entering a credential takes a new id. A fence that does not read
//! where a path would install or re-admit a handle from an image or a fork
//! withholds that handle alone, PendingCustody, warned; anywhere else
//! today's path goes on, warned.
//!
//! Only an erase retires a credential's value keys: nothing stages one for
//! a rotate or a revoke, an image's own erase rows never land (`fences`),
//! and the finisher runs an erase's intent alone. So a retired credential
//! value key in custody a restore takes, and a credential key's erase
//! intent, are erase-only evidence: a fence is derived from them, never
//! from a peer's tombstone. A carrier's key also retires once what it
//! carried is answered (FIX 7402): a Retention intent of a transition's or
//! request input's instance, which the finisher runs too and which no fence
//! is ever derived from.
//!
//! A fence's value-free fact reaches key custody at its erase, once the
//! erase's writer commits (FIX 11211, `fence_journal`); the finisher hands
//! every fact over again and journals none twice.

use std::cell::RefCell;
use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::key_custody::erase_evidence::CredentialFenceFact;
use crate::key_custody::erase_evidence::FenceFact;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySubject;
use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use crate::side_table::key::SideKey;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;
use oneiron_contracts::entity_id::EntityId;

/// The kinds a credential's id names in custody, by its id as their items'
/// first 16 bytes: its value, its transitions' and its request inputs'
/// instances. A connector call's resume key is no credential's.
pub const CREDENTIAL_PARENT_KINDS: [CustodyKind; 3] = [
    CustodyKind::CredentialValue,
    CustodyKind::CustodyTransition,
    CustodyKind::CustodyRequestInput,
];

/// How an erase keeps a credential erased (CALLS `KS-6 erase fence form`,
/// Engine 10-21 22:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyEraseFenceForm {
    /// One value-free LIVE fence per erased id, permanent, its discovery
    /// owed until every key the id names is staged to retire. A fence that
    /// does not read where a path would install or re-admit a handle from
    /// an image or a fork withholds that one handle, PendingCustody with a
    /// warned retry, and everything else proceeds; anywhere else today's
    /// path goes on, warned. Nothing is refused, nothing comes back.
    TerminalParentIdWithPendingDiscovery,
}

pub const CUSTODY_ERASE_FENCE_FORM: CustodyEraseFenceForm =
    CustodyEraseFenceForm::TerminalParentIdWithPendingDiscovery;

/// What a discovery fault leaves (CALLS `KS-6 erase discovery fault`,
/// Engine 10-21 22:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyEraseDiscoveryFault {
    /// The fence stands, its discovery owed: the finisher, a reopen and
    /// upkeep retry it, and the erase's receipt reads pending until a full
    /// discovery completes. Never a refused erase, an empty success, a
    /// timeout or an expiry.
    FenceAndRetryBeforeComplete,
}

pub const CUSTODY_ERASE_DISCOVERY_FAULT: CustodyEraseDiscoveryFault =
    CustodyEraseDiscoveryFault::FenceAndRetryBeforeComplete;

/// Where one fence's discovery stands: one byte, `0` owed, `1` complete
/// with no key found, `2` complete with keys found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discovery {
    Owed,
    Complete { keys: bool },
}

impl RawValue for Discovery {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![match self {
            Self::Owed => 0,
            Self::Complete { keys: false } => 1,
            Self::Complete { keys: true } => 2,
        }])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [0] => Ok(Self::Owed),
            [1] => Ok(Self::Complete { keys: false }),
            [2] => Ok(Self::Complete { keys: true }),
            _ => Err(Error::CorruptedIndex("credential erase fence").into()),
        }
    }
}

/// The credential a custody subject of one of [`CREDENTIAL_PARENT_KINDS`]
/// belongs to: its item's first 16 bytes.
pub fn parent_of(subject: &CustodySubject) -> Option<EntityId> {
    if !CREDENTIAL_PARENT_KINDS.contains(&subject.kind()) {
        return None;
    }
    let id = <[u8; 16]>::try_from(subject.item().get(..16)?).ok()?;
    EntityId::from_bytes(id).ok()
}

/// What a fence says of one credential id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceLookup {
    /// An authorized erase reached it: it never comes back.
    Fenced,
    /// Its own fence, or the evidence it is derived from, did not read.
    Faulted,
    /// No erase reached it.
    Clear,
}

/// The erase an id's write would bring back (CALLS `KS-6 erase fence
/// form`): the backstop every common write seam refuses with.
pub fn erased_id() -> Error {
    Error::Secret(SecretError::InvalidSecretCustodyBody(
        "an erased credential's id is never written again; re-enter it under a new id",
    ))
}

/// What this thread's writers staged: how many credential erases, for the
/// post-commit detection of the writer it runs in, each id whose fence did
/// not write, which its erase's receipt binds all the same, and each id
/// fenced whose fact goes to key custody once its writer commits (FIX
/// 11211).
struct Staged {
    pub count: u64,
    pub unfenced: BTreeSet<EntityId>,
    pub fences_to_journal: BTreeSet<EntityId>,
}

thread_local! {
    static STAGED: RefCell<Staged> = const {
        RefCell::new(Staged {
            count: 0,
            unfenced: BTreeSet::new(),
            fences_to_journal: BTreeSet::new(),
        })
    };
}

/// How many credential erases this thread has staged: a writer that sees
/// it move staged one, and finishes it after its commit.
pub fn credential_erases_staged() -> u64 {
    STAGED.with(|staged| staged.borrow().count)
}
