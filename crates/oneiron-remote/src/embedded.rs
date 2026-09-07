//! The embedded backend: path resolution, the process-local vault registry,
//! and the single-writer lease (ONE-1441 I8/I9).
//!
//! The registry is SDK-owned and lives HERE rather than in `oneiron::vault`,
//! because sharing one native vault between two SDK handles is a property of
//! the SDK's constructor contract, not of the storage engine. The engine's
//! `Vault::open` stays what it is: the door that opens a vault. This module
//! decides how many times that door is walked through.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryError, parse_actor_key};
use oneiron::{EdgeActorClass, EntityId, Error, VAULT_WRITER_LEASE_HELD, Vault, VaultConfig};

use crate::OpenOptions;
use crate::caps::check_dimensions;
use crate::error::{bad_request, sdk_error, transport_error, vault_locked};

/// One native vault and the options it was opened with. The engine Vault
/// itself owns the lease, so server and embedded Arc holders obey one lifetime.
pub(crate) struct SharedVault {
    vault: Vault,
    options: OpenOptions,
}

impl SharedVault {
    pub(crate) fn vault(&self) -> &Vault {
        &self.vault
    }

    fn lease(&self) -> &oneiron::VaultWriterLease {
        self.vault
            .writer_lease()
            .expect("open_owned retains its lease")
    }

    pub(crate) fn held_by_current_process(&self) -> bool {
        self.lease().held_by_current_process()
    }

    pub(crate) fn lease_pid(&self) -> u32 {
        self.lease().pid()
    }
}

/// Canonical path → the shared vault opened for it, weakly.
///
/// WEAK on purpose. A strong map would keep every vault an process ever opened
/// alive until exit, which also keeps its writer lease held: a caller who
/// dropped their last handle would still be locking the directory against
/// themselves. The weak entry lets the last handle's drop close the vault and
/// release the lease, and a later reopen of the same path simply misses.
struct Registry {
    // Published BEFORE touching LazyLock or Mutex: either can be inherited
    // locked by a forked child whose other threads no longer exist.
    pid: AtomicU32,
    entries: LazyLock<Mutex<HashMap<PathBuf, Weak<SharedVault>>>>,
}

impl Registry {
    fn check_pid(&self) -> Result<(), MemoryError> {
        let pid = std::process::id();
        match self
            .pid
            .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(owner) if owner == pid => Ok(()),
            Err(_) => Err(vault_locked()),
        }
    }

    fn guard(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<PathBuf, Weak<SharedVault>>>, MemoryError> {
        self.check_pid()?;
        self.entries.lock().map_err(|_| {
            transport_error("the vault registry was poisoned by a panic in another thread")
        })
    }
}

static REGISTRY: Registry = Registry {
    pid: AtomicU32::new(0),
    entries: LazyLock::new(|| Mutex::new(HashMap::new())),
};

/// Counts the `Vault::open` calls this process has actually made.
///
/// Exists for the contract test that proves a same-PID reopen SHARES rather
/// than reopens (T3). A test that could only compare pointers would pass on an
/// implementation that opened the store twice and threw one away.
static STORE_OPEN_COUNT: AtomicU64 = AtomicU64::new(0);

/// How many times this process has opened a vault store.
#[must_use]
pub fn store_open_count() -> u64 {
    STORE_OPEN_COUNT.load(Ordering::Relaxed)
}

/// Resolves the directory an embedded open will use.
///
/// An omitted path resolves to `~/.oneiron/default` against the CURRENT
/// process home, read at call time so a test (or CI) that sets an isolated
/// `HOME` gets an isolated vault. `~` inside an explicitly supplied path is
/// never expanded: a caller who wrote a literal tilde directory means it, and
/// silently redirecting them to their home directory would be the SDK
/// inventing a path the caller did not ask for.
pub(crate) fn resolve_vault_path(path: Option<&Path>) -> Result<PathBuf, MemoryError> {
    if let Some(path) = path {
        return Ok(path.to_path_buf());
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| {
            bad_request(
                "no home directory is set, so the default vault path cannot be resolved",
                &[
                    "Set HOME (or USERPROFILE on Windows).",
                    "Or pass an explicit path to open().",
                ],
            )
        })?;
    Ok(PathBuf::from(home).join(".oneiron").join("default"))
}

/// Opens or joins the shared vault for `path`.
///
/// The ordering is the single-writer contract in code: create the directory,
/// canonicalize it so two spellings of one vault cannot both be "first", take
/// the exclusive lease, and only THEN open the store. A second process reaches
/// the lease and stops there, having neither created nor touched LMDB state.
pub(crate) fn open_shared(
    path: Option<&Path>,
    options: &OpenOptions,
) -> Result<Arc<SharedVault>, MemoryError> {
    REGISTRY.check_pid()?;
    if let Some(dimensions) = options.dimensions {
        check_dimensions(dimensions)?;
    }
    let requested = resolve_vault_path(path)?;
    std::fs::create_dir_all(&requested).map_err(|error| {
        sdk_error(
            MEMORY_CODE_INTERNAL,
            format!(
                "could not create vault directory {}: {error}",
                requested.display()
            ),
            &["Check the path's parent directory exists and is writable."],
        )
    })?;
    let canonical = requested.canonicalize().map_err(|error| {
        sdk_error(
            MEMORY_CODE_INTERNAL,
            format!(
                "could not resolve vault directory {}: {error}",
                requested.display()
            ),
            &["Check the path is readable and is not a broken symlink."],
        )
    })?;

    let mut registry = REGISTRY.guard()?;
    if let Some(existing) = registry.get(&canonical).and_then(Weak::upgrade) {
        // I8: the registry and the lease's descriptor BOTH survive `fork`, so a
        // child calling the constructor would otherwise be handed the parent's
        // entry and walk straight into the owner bootstrap's write transaction
        // — a core write that runs before any per-verb gate could refuse it.
        // The ownership check therefore belongs here, on the join, and not only
        // on dispatch.
        //
        // It runs BEFORE the options comparison on purpose: a process that does
        // not own this vault is refused for WHOSE the vault is, not for how it
        // asked. Telling a forked child to "reopen with the same options" would
        // name a fix that cannot work.
        if !existing.held_by_current_process() {
            return Err(vault_locked());
        }
        existing
            .lease()
            .validate_directory(&canonical)
            .map_err(MemoryError::from)?;
        // I9: a same-PID reopen JOINS, and only when it asked for the same
        // vault. Divergent options are refused rather than honored-or-ignored,
        // because both alternatives are wrong: honoring them would need a
        // second `Store::open` the lease forbids, and ignoring them would hand
        // back a vault configured as something the caller did not request.
        if existing.options != *options {
            return Err(divergent_options_error(
                &canonical,
                &existing.options,
                options,
            ));
        }
        return Ok(existing);
    }

    let shared = Arc::new(open_uncontended(&canonical, options)?);
    registry.insert(canonical, Arc::downgrade(&shared));
    Ok(shared)
}

/// Takes the lease and opens the store, in that order.
fn open_uncontended(canonical: &Path, options: &OpenOptions) -> Result<SharedVault, MemoryError> {
    let mut config = VaultConfig::default();
    if let Some(dimensions) = options.dimensions {
        config.dimensions = dimensions;
    }
    let vault = Vault::open_owned(canonical, config).map_err(map_lease_error)?;
    STORE_OPEN_COUNT.fetch_add(1, Ordering::Relaxed);
    Ok(SharedVault {
        vault,
        options: options.clone(),
    })
}

/// Maps a lease refusal, and ONLY lease contention, to the single-writer code.
///
/// I8 is explicit that the central `From<Error>` impl is not amended: every
/// other `ConcurrentWrite` in the engine keeps its `INVALID_STATE` meaning,
/// which is the refresh-and-retry family. The mapping is narrowed to the exact
/// contention message so a future unrelated `ConcurrentWrite` on this path
/// cannot start claiming another process holds the vault.
fn map_lease_error(error: Error) -> MemoryError {
    match &error {
        Error::ConcurrentWrite(message) if *message == VAULT_WRITER_LEASE_HELD => vault_locked(),
        _ => MemoryError::from(error),
    }
}

/// Explains a rejected reopen in terms of what actually differed.
fn divergent_options_error(
    canonical: &Path,
    registered: &OpenOptions,
    requested: &OpenOptions,
) -> MemoryError {
    bad_request(
        format!(
            "{} is already open in this process with different options \
             (open dimensions {:?}, requested {:?})",
            canonical.display(),
            registered.dimensions,
            requested.dimensions,
        ),
        &[
            "Reopen with the same options the first open used.",
            "A vault's dimensions are fixed at creation; a second open cannot change them.",
        ],
    )
}

/// The embedded half of [`crate::OneironClient`].
///
/// Cloning is cheap and shares the native vault: `as_actor` produces a new
/// handle bound to another actor over the SAME vault, which is what "returns a
/// new handle; it does not mutate the original" means in memory terms.
#[derive(Clone)]
pub(crate) struct EmbeddedClient {
    shared: Arc<SharedVault>,
    actor: EntityId,
    actor_class: EdgeActorClass,
}

impl EmbeddedClient {
    /// Opens (or joins) a vault and binds the generic embedded owner actor.
    ///
    /// The owner bootstrap is core-owned: `ensure_embedded_owner_actor` is the
    /// one seam allowed to create the constructor's actor, and it does the
    /// check and the create in a single engine transaction. The SDK does not
    /// reach for `batch().put` or any other storage mutation to arrange its
    /// own identity.
    pub(crate) fn open(path: Option<&Path>, options: &OpenOptions) -> Result<Self, MemoryError> {
        let shared = open_shared(path, options)?;
        let actor = shared.vault().ensure_embedded_owner_actor()?;
        Ok(Self {
            shared,
            actor,
            actor_class: EdgeActorClass::Human,
        })
    }

    /// Rebinds to another actor over the same native vault.
    ///
    /// The grammar (`human:<ref>` / `agent:<ref>` / `system:<ref>`) and the
    /// existence check both belong to core `parse_actor_key`, which verifies
    /// the named entity exists and that its stored type admits the asserted
    /// class. The SDK neither parses the key nor decides who may be an actor.
    pub(crate) fn as_actor(&self, actor_key: &str) -> Result<Self, MemoryError> {
        self.ensure_dispatch_pid()?;
        let (actor, actor_class) = parse_actor_key(self.shared.vault(), actor_key)?;
        Ok(Self {
            shared: Arc::clone(&self.shared),
            actor,
            actor_class,
        })
    }

    /// The per-verb single-writer gate (I8).
    ///
    /// A post-`fork` child inherits the lease's file descriptor and therefore
    /// the kernel's lock, so the OS would happily let it write. It never
    /// ACQUIRED the lease, though, and two processes writing one LMDB
    /// environment through one inherited handle is the corruption the lease
    /// exists to prevent. Comparing the acquiring PID against the current one
    /// is the only check that can tell those two cases apart, and it runs
    /// before facade entry so the child fails typed rather than partially.
    pub(crate) fn ensure_dispatch_pid(&self) -> Result<(), MemoryError> {
        if self.shared.held_by_current_process() {
            return Ok(());
        }
        Err(vault_locked())
    }

    /// Binds the engine memory surface to this handle's actor.
    ///
    /// EVERY verb goes through here, so there is exactly one place the SDK can
    /// reach the engine and it is the facade — never `Vault`'s storage doors
    /// (I1/T2).
    pub(crate) fn memory(&self) -> oneiron::memory::Memory<'_> {
        self.shared.vault().memory(self.actor, self.actor_class)
    }

    /// The shared entry, for the reopen-identity contract test.
    pub(crate) fn shared(&self) -> &Arc<SharedVault> {
        &self.shared
    }

    /// The 32-hex id of the actor this handle writes as.
    ///
    /// Read by the wire fixture, which opens a pre-server vault through this
    /// constructor so the core bootstrap creates the owner PERSON, then mints
    /// a slip whose `principal_ref` names that same actor. Without it the
    /// fixture would have to reach for a storage primitive to learn an id the
    /// SDK already knows.
    pub(crate) fn actor_hex(&self) -> String {
        self.actor.to_hex()
    }

    /// The PID recorded by this vault's lease.
    pub(crate) fn lease_pid(&self) -> u32 {
        self.shared.lease_pid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::memory::MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER;

    #[test]
    fn inherited_registry_is_refused_before_locked_mutex() {
        let registry = Arc::new(Registry {
            pid: AtomicU32::new(std::process::id().wrapping_add(1).max(1)),
            entries: LazyLock::new(|| Mutex::new(HashMap::new())),
        });
        let inherited_guard = registry.entries.lock().expect("parent guard");
        let child_registry = Arc::clone(&registry);
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = std::thread::spawn(move || {
            let error = match child_registry.guard() {
                Ok(_) => panic!("a child must not acquire the inherited registry"),
                Err(error) => error,
            };
            tx.send(error.code).expect("probe result");
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(2));
        drop(inherited_guard);
        probe.join().expect("probe thread");
        assert_eq!(
            result.expect("refusal before mutex wait"),
            MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER,
        );
    }
}
