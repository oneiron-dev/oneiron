//! Who reads a lift-marked LFS object's real bytes over a chunk exchange
//! (FIX 2897; ARCH-0069: "the owner gets the real file", a granted agent the
//! real bytes with a reason log, every other reader the hold).
//!
//! The host builds one [`LfsReadAuthority`] at a transfer's first manifest or
//! WANT request, from its own authentication of the caller: the owner by his
//! verified read key, a machine the owner trusts as his own that the
//! owner's sync lane proved, or an agent whose read a standing grant covers
//! or the owner approved once, its receipt written. It holds it with the
//! transfer, and judges it again at each later page, WANT and release,
//! without spending an approval or asking again. The wire carries a granted
//! read's reference, which the host checks; never a verdict.

use crate::authority::PeerMachine;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::{Memory, MemoryResult};
use crate::origin::lfs::LfsOid;
use crate::secret_custody::SecretSight;
use crate::{EntityId, Vault};

/// What a reader asks of a lift-marked object's read, in its request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChunkRead {
    /// A granted read's first request: why the agent needs the real bytes.
    Ask {
        /// The agent's why, one line.
        why: String,
    },
    /// A later request of the read the host granted: the reference its
    /// reply named.
    Held {
        /// The read's reference.
        read: EntityId,
    },
}

/// The lift sweep's mark on an object as it travels with its real bytes: the
/// detector's reason and when it was made, never a value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChunkMark {
    /// The detector's reason for the first hit.
    pub reason: String,
    /// When the mark was made.
    pub marked_at: u64,
}

/// The authority one transfer reads a lift-marked object's real bytes under,
/// as its host built it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LfsReadAuthority {
    /// The vault's owner, by his verified read key.
    Owner,
    /// A machine the owner trusts as his own, proved on his sync lane.
    OwnerMachine(PeerMachine),
    /// An agent's granted read: its reference.
    Granted(EntityId),
}

impl LfsReadAuthority {
    /// The granted read's reference a reply names, for the read's later
    /// requests to name.
    #[must_use]
    pub fn reference(self) -> Option<EntityId> {
        match self {
            Self::Granted(read) => Some(read),
            Self::Owner | Self::OwnerMachine(_) => None,
        }
    }
}

/// The host's judgment of a lift-marked object's read (FIX 2897): the
/// authority a request reads the object's real bytes under, as the host's
/// own authentication of it and its [`ChunkRead`] give it, or `None`.
pub type LfsMarkedReader<'a> =
    &'a mut dyn FnMut(LfsOid, Option<&ChunkRead>) -> Result<Option<LfsReadAuthority>>;

impl Vault {
    /// The authority a machine the owner trusts as his own reads a
    /// lift-marked object's real bytes under on his sync lane (FIX 2897):
    /// `peer`, which the connection proved, while it stands here as live,
    /// `Owned(Yours)` and trusted under this install's pin on the very key it
    /// proved. `None` for every other machine, a proved roster machine the
    /// owner never called his included, and when the fold cannot be read.
    #[must_use]
    pub fn lfs_owner_machine_read(&self, peer: PeerMachine) -> Option<LfsReadAuthority> {
        let PeerMachine::Proven { machine, key } = peer else {
            return None;
        };
        let txn = self.store.env.read_txn().ok()?;
        let view = self.authority_view_readonly_in_txn(&txn).ok()?;
        let mine = view
            .trusted_machine(machine)
            .is_some_and(|trusted| trusted.profile.machine_key == key);
        mine.then_some(LfsReadAuthority::OwnerMachine(peer))
    }
}

impl Memory<'_> {
    /// The authority this caller reads the lift-marked LFS object `oid`'s
    /// real bytes under, as `read` asks (FIX 2897): the owner, by his
    /// verified read key; an agent that says why, once a standing grant
    /// covers its read of the object whole or the owner approved it once,
    /// and its receipt is written; an agent that names the read it was
    /// granted, while that read stands. `None` for every other caller, and
    /// for an agent whose read waits on the owner: its ask is filed, and the
    /// object stays withheld. A host asks this for a marked object alone.
    ///
    /// # Errors
    /// The read check's: a `why` that is empty, longer than 512 bytes, more
    /// than one line or holds a credential; a binding that does not verify.
    pub fn lfs_read_authority(
        &self,
        oid: LfsOid,
        read: Option<&ChunkRead>,
    ) -> MemoryResult<Option<LfsReadAuthority>> {
        if self.secret_sight()? == SecretSight::Owner {
            return Ok(Some(LfsReadAuthority::Owner));
        }
        let Some(read) = read.filter(|_| self.actor_class() == EdgeActorClass::Agent) else {
            return Ok(None);
        };
        let asker = self.reveal_asker()?;
        let vault = self.vault();
        let granted = match read {
            ChunkRead::Ask { why } => vault.lfs_object_sight(&asker, oid, why)?,
            ChunkRead::Held { read: held } => vault
                .lfs_object_read_stands(&asker, oid, held)?
                .then_some(*held),
        };
        Ok(granted.map(LfsReadAuthority::Granted))
    }

    /// Whether `authority`, built for this caller, still stands for `oid`
    /// now (FIX 2897): the owner's read key still reads as the owner's, the
    /// machine still stands as his own, or the agent's read still stands.
    /// Nothing is spent, asked or written.
    ///
    /// # Errors
    /// As [`Self::lfs_read_authority`].
    pub fn lfs_read_stands(&self, oid: LfsOid, authority: &LfsReadAuthority) -> MemoryResult<bool> {
        Ok(match authority {
            LfsReadAuthority::Owner => self.secret_sight()? == SecretSight::Owner,
            LfsReadAuthority::OwnerMachine(peer) => {
                self.vault().lfs_owner_machine_read(*peer) == Some(*authority)
            }
            LfsReadAuthority::Granted(read) => {
                self.actor_class() == EdgeActorClass::Agent
                    && self
                        .vault()
                        .lfs_object_read_stands(&self.reveal_asker()?, oid, read)?
            }
        })
    }
}
