//! Vault-root preflight pair classifier plus descriptor-bound root and LMDB header validators.

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use heed::{Env, EnvOpenOptions};

use crate::config::VaultConfig;
use crate::error::{Error, Result, VaultRootEntry, VaultRootProblem};
#[cfg(all(test, target_os = "linux"))]
use crate::store::test_hooks;

#[cfg(unix)]
use super::super::root_directory::{FileIdentity, file_identity};
#[cfg(target_os = "linux")]
use super::super::root_directory::{
    adopt_descriptor, named_directory_identity, open_root_directory,
};
#[cfg(target_os = "linux")]
use super::manifest_storage_gates::vault_root_open_guard;
use super::manifest_storage_gates::{OwnedEnv, RegisteredPath};
#[cfg(target_os = "linux")]
use super::open_version_keys::MAX_DBS;
use crate::error::StoreError;

#[derive(Clone, Debug)]
pub(super) struct VaultRootPreflight {
    pub(super) is_new_vault: bool,
    pub(super) identity: Option<VaultRootIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VaultRootIdentity {
    pub(super) data: FileIdentity,
    pub(super) lock: FileIdentity,
}

impl VaultRootIdentity {
    pub(super) fn overlaps(&self, other: &Self) -> bool {
        self.data == other.data
            || self.data == other.lock
            || self.lock == other.data
            || self.lock == other.lock
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    pub(super) volume_serial_number: u32,
    pub(super) file_index: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    pub(super) unsupported: (),
}

#[derive(Clone, Debug)]
pub(super) struct VaultRootFile {
    pub(super) identity: FileIdentity,
    pub(super) link_count: u64,
}

pub(super) fn preflight_vault_root(root: &Path) -> Result<VaultRootPreflight> {
    let data = inspect_vault_root_entry(root, VaultRootEntry::Data)?;
    let lock = inspect_vault_root_entry(root, VaultRootEntry::Lock)?;
    classify_vault_root_pair(root, data, lock)
}

/// Applies the pair-level root rules to two already-inspected entries.
///
/// Shared by the create-capable door's path-based preflight and the
/// existing-only door's descriptor-bound binding, so both speak exactly one
/// root-identity vocabulary and neither can classify a pair the other would
/// classify differently. Only WHERE the two entries were read differs.
pub(super) fn classify_vault_root_pair(
    root: &Path,
    data: Option<VaultRootFile>,
    lock: Option<VaultRootFile>,
) -> Result<VaultRootPreflight> {
    match (data, lock) {
        (None, None) => Ok(VaultRootPreflight {
            is_new_vault: true,
            identity: None,
        }),
        (Some(_), None) => Err(vault_root_preflight_error(
            root,
            VaultRootProblem::IncompleteLmdbPair {
                present: VaultRootEntry::Data,
                missing: VaultRootEntry::Lock,
            },
        )),
        (None, Some(_)) => Err(vault_root_preflight_error(
            root,
            VaultRootProblem::IncompleteLmdbPair {
                present: VaultRootEntry::Lock,
                missing: VaultRootEntry::Data,
            },
        )),
        (Some(data), Some(lock)) => {
            if data.identity == lock.identity {
                return Err(vault_root_preflight_error(
                    root,
                    VaultRootProblem::AliasedLmdbFiles {
                        first: VaultRootEntry::Data,
                        second: VaultRootEntry::Lock,
                    },
                ));
            }
            if data.link_count > 1 {
                return Err(vault_root_preflight_error(
                    root,
                    VaultRootProblem::MultipleHardLinks {
                        entry: VaultRootEntry::Data,
                        link_count: data.link_count,
                    },
                ));
            }
            if lock.link_count > 1 {
                return Err(vault_root_preflight_error(
                    root,
                    VaultRootProblem::MultipleHardLinks {
                        entry: VaultRootEntry::Lock,
                        link_count: lock.link_count,
                    },
                ));
            }

            Ok(VaultRootPreflight {
                is_new_vault: false,
                identity: Some(VaultRootIdentity {
                    data: data.identity,
                    lock: lock.identity,
                }),
            })
        }
    }
}

/// The vault root of an existing-only open, held as a filesystem capability.
///
/// The directory descriptor IS the root here: both LMDB entries are validated
/// `openat`/`fstat` relative to it with `O_NOFOLLOW`, their LMDB headers are
/// read back through those same descriptors, and the environment is opened
/// through `/proc/self/fd/<dirfd>` — the pinned local heed seam
/// (`crates/heed/PROVENANCE.md`) hands those exact bytes to `mdb_env_open`
/// without canonicalizing them — so renaming or replacing the pathname cannot
/// redirect the environment onto a directory this door never bound. The
/// descriptor outlives the open and the post-open refresh and is then moved
/// into the [`OwnedEnv`], so its number cannot be recycled while the
/// environment lives.
#[cfg(target_os = "linux")]
pub(super) struct BoundVaultRoot {
    pub(super) dir: File,
    /// Identity of the bound directory itself, so the post-open refresh can
    /// prove the path the CALLER named still resolves to it.
    pub(super) directory: FileIdentity,
    /// Identity of both LMDB entries as captured before the environment open.
    pub(super) identity: VaultRootIdentity,
}

#[cfg(target_os = "linux")]
impl BoundVaultRoot {
    /// Binds an already-canonical `root`. Refuses unless both LMDB entries are
    /// already present as regular, non-symlink, single-link, non-aliased
    /// files: a root with neither entry is the create-capable door's new-vault
    /// state, which this door has no branch for.
    ///
    /// Refuses again unless those two files are already a complete LMDB
    /// environment — see [`validate_bound_lmdb_pair`], which reads their
    /// headers through the very descriptors the classification used. That
    /// second refusal is what keeps a pre-created empty or headerless pair from
    /// reaching a read-write `mdb_env_open` that would initialize it.
    pub(super) fn bind(root: &Path) -> Result<Self> {
        let dir = open_root_directory(root)?;
        let directory = file_identity(&dir.metadata()?);
        let data = bound_vault_root_entry(root, &dir, VaultRootEntry::Data)?;
        let lock = bound_vault_root_entry(root, &dir, VaultRootEntry::Lock)?;
        let classified =
            classify_vault_root_pair(root, bound_entry_info(&data), bound_entry_info(&lock))?;
        let (Some(identity), Some(data), Some(lock)) = (classified.identity, data, lock) else {
            return Err(existing_root_refusal(root, false));
        };
        validate_bound_lmdb_pair(root, &data.file, &lock.file)?;
        Ok(Self {
            dir,
            directory,
            identity,
        })
    }

    /// The descriptor-bound path LMDB opens the environment through.
    pub(super) fn environment_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd()))
    }

    /// Hands the bound directory descriptor to the environment that was opened
    /// through it, so `/proc/self/fd/<dirfd>` keeps naming this exact directory
    /// for as long as that environment lives.
    pub(super) fn into_dir(self) -> File {
        self.dir
    }

    /// Defense in depth after the environment open: the bound descriptor must
    /// still hold exactly the two files whose identity was captured before it,
    /// and the path the caller named must still resolve to the bound
    /// directory. A root renamed away, deleted, or replaced inside the open
    /// window fails one of those and refuses.
    pub(super) fn verify_unchanged(&self, root: &Path) -> Result<VaultRootIdentity> {
        let data = bound_vault_root_entry(root, &self.dir, VaultRootEntry::Data)?;
        let lock = bound_vault_root_entry(root, &self.dir, VaultRootEntry::Lock)?;
        let refreshed =
            classify_vault_root_pair(root, bound_entry_info(&data), bound_entry_info(&lock))?
                .identity;
        if refreshed.as_ref() != Some(&self.identity)
            || named_directory_identity(root)?.as_ref() != Some(&self.directory)
        {
            return Err(existing_root_refusal(root, true));
        }
        Ok(self.identity.clone())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn existing_root_refusal(root: &Path, after_environment_open: bool) -> Error {
    vault_root_preflight_error(
        root,
        VaultRootProblem::NotAnExistingVaultRoot {
            after_environment_open,
        },
    )
}

/// One LMDB entry as the bound root holds it: the still-open descriptor the
/// entry was classified from, plus the identity facts read off it.
///
/// The descriptor is kept so [`validate_bound_lmdb_pair`] can read the file's
/// LMDB header through the SAME `openat(O_RDONLY | O_NOFOLLOW | O_CLOEXEC)`
/// file the classification used. Nothing is ever closed and reopened by
/// pathname for validation.
#[cfg(target_os = "linux")]
pub(super) struct BoundVaultRootEntry {
    pub(super) file: File,
    pub(super) info: VaultRootFile,
}

/// The identity facts alone, for the pair rules both doors share.
#[cfg(target_os = "linux")]
pub(super) fn bound_entry_info(entry: &Option<BoundVaultRootEntry>) -> Option<VaultRootFile> {
    entry.as_ref().map(|entry| entry.info.clone())
}

/// Reads one LMDB entry RELATIVE to the bound directory descriptor. Nothing in
/// the caller's pathname is re-walked, and `O_NOFOLLOW` means a symlink final
/// component is refused (`ELOOP`) rather than followed.
#[cfg(target_os = "linux")]
pub(super) fn bound_vault_root_entry(
    root: &Path,
    dir: &File,
    entry: VaultRootEntry,
) -> Result<Option<BoundVaultRootEntry>> {
    let name = CString::new(entry.file_name())
        .map_err(|_| Error::InvariantViolation("vault root entry file name"))?;
    // SAFETY: `dir` is a live directory descriptor and `name` is a live
    // NUL-terminated C string for the whole call; `adopt_descriptor` checks the
    // returned code before taking ownership of any descriptor.
    // `O_NONBLOCK` keeps a non-regular entry swapped in underneath us from
    // blocking the open; the file type is re-checked from `fstat` below.
    // `O_LARGEFILE` matches what `std::fs::File::open` passes, so a `data.mdb`
    // past the 32-bit offset limit still opens on a 32-bit target.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | libc::O_LARGEFILE,
        )
    };
    let file = match adopt_descriptor(fd) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(vault_root_preflight_error(
                root,
                VaultRootProblem::SymlinkEntry { entry },
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(vault_root_preflight_error(
            root,
            VaultRootProblem::NonRegularEntry { entry },
        ));
    }
    Ok(Some(BoundVaultRootEntry {
        info: VaultRootFile {
            identity: file_identity(&metadata),
            link_count: hard_link_count(&metadata),
        },
        file,
    }))
}

/// `MDB_MAGIC` (mdb.c:661). Stamps the head of BOTH LMDB files.
#[cfg(target_os = "linux")]
pub(super) const LMDB_MAGIC: u32 = 0xBEEF_C0DE;

/// `MDB_DATA_VERSION` (mdb.c:664), with `MDB_DEVEL == 0` (mdb.c:299).
/// `mdb_env_read_header` refuses anything else (mdb.c:4330).
#[cfg(target_os = "linux")]
pub(super) const LMDB_DATA_VERSION: u32 = 1;

/// `MDB_LOCK_VERSION` (mdb.c:666), with `MDB_DEVEL == 0`.
#[cfg(target_os = "linux")]
pub(super) const LMDB_LOCK_VERSION: u32 = 2;

/// `MDB_LOCK_VERSION_BITS` (mdb.c:670): `MDB_LOCK_FORMAT` (mdb.c:936) puts the
/// lock version in the low 12 bits of `mti_format` and the build-specific
/// `MDB_lock_desc` above them. Only the version is portable, so only the
/// version is compared — `mdb_env_setup_locks` compares the whole word
/// (mdb.c:5618) but it is the one this build wrote.
#[cfg(target_os = "linux")]
pub(super) const LMDB_LOCK_VERSION_MASK: u32 = (1 << 12) - 1;

/// `P_META` (mdb.c:1021): page 0 of a real `data.mdb` is a meta page, which
/// `mdb_env_read_header` checks before reading the meta (mdb.c:4319).
#[cfg(target_os = "linux")]
pub(super) const LMDB_PAGE_META_FLAG: u16 = 0x08;

/// `PAGEHDRSZ` = `offsetof(MDB_page, mp_ptrs)` (mdb.c:1060). `MDB_page` is a
/// `pgno_t`/pointer union (`MDB_ID` = `mdb_size_t` = `size_t`; midl.h:46,
/// lmdb.h:196), then `uint16_t mp_pad`, `uint16_t mp_flags`, then a 4-byte
/// union — 16 bytes on a 64-bit build, 12 on a 32-bit one.
#[cfg(target_os = "linux")]
pub(super) const LMDB_PAGE_HEADER_LEN: usize = std::mem::size_of::<usize>() + 8;

/// `offsetof(MDB_page, mp_flags)`: after the pointer-sized union and `mp_pad`.
#[cfg(target_os = "linux")]
pub(super) const LMDB_PAGE_FLAGS_OFFSET: usize = std::mem::size_of::<usize>() + 2;

/// `MDB_meta.mm_magic`: `METADATA(p)` is the first byte after the page header
/// (mdb.c:1063) and `mm_magic` is the meta's first field (mdb.c:1255-1258).
#[cfg(target_os = "linux")]
pub(super) const LMDB_META_MAGIC_OFFSET: usize = LMDB_PAGE_HEADER_LEN;

/// `MDB_meta.mm_version`, immediately after the `uint32_t mm_magic`.
#[cfg(target_os = "linux")]
pub(super) const LMDB_META_VERSION_OFFSET: usize = LMDB_META_MAGIC_OFFSET + 4;

/// `MDB_meta.mm_psize` = `mm_dbs[FREE_DBI].md_pad` (mdb.c:1273), the first
/// field of `mm_dbs`. `mm_dbs` follows `mm_magic` (4) + `mm_version` (4) +
/// `void *mm_address` + `mdb_size_t mm_mapsize`, both pointer-sized; at either
/// pointer width that packs with no padding.
#[cfg(target_os = "linux")]
pub(super) const LMDB_META_PAGE_SIZE_OFFSET: usize =
    LMDB_META_VERSION_OFFSET + 4 + 2 * std::mem::size_of::<usize>();

/// Enough of page 0 to cover every field compared above.
#[cfg(target_os = "linux")]
pub(super) const LMDB_META_PREFIX_LEN: usize = LMDB_META_PAGE_SIZE_OFFSET + 4;

/// `MAX_PAGESIZE` (mdb.c:641), with `PAGEBASE == 0` because `MDB_DEVEL == 0`.
/// A host with larger OS pages is clamped to this at creation (mdb.c:5078).
#[cfg(target_os = "linux")]
pub(super) const LMDB_MAX_PAGE_SIZE: u32 = 0x8000;

/// Coherence floor only: the smallest power of two that can hold one page
/// header plus one `MDB_meta` (136 bytes on a 64-bit build). Real files carry
/// the creating host's OS page size, which is far larger, so this can never
/// refuse a genuine environment.
#[cfg(target_os = "linux")]
pub(super) const LMDB_MIN_PAGE_SIZE: u32 = 256;

/// `NUM_METAS` (mdb.c:1249). A real `data.mdb` always holds both meta pages:
/// `mdb_env_init_meta` writes `psize * 2` bytes before anything else exists.
#[cfg(target_os = "linux")]
pub(super) const LMDB_META_PAGES: u64 = 2;

/// Conservative floor for the lock region. `sizeof(MDB_txninfo)` is a
/// cacheline-padded `MDB_txbody`, a cacheline-padded mutex-name slot and one
/// `MDB_reader` (mdb.c:874-931) — 192 bytes with `CACHELINE == 64`
/// (mdb.c:821) — and `mdb_env_setup_locks` sizes the file at
/// `(maxreaders - 1) * sizeof(MDB_reader) + sizeof(MDB_txninfo)` (mdb.c:5477).
/// The floor sits below every platform's real value, so length alone can only
/// refuse a file no LMDB ever initialized.
#[cfg(target_os = "linux")]
pub(super) const LMDB_LOCK_MIN_LEN: u64 = 64;

/// Refuses unless the two BOUND descriptors already hold a complete,
/// pre-existing LMDB environment.
///
/// This is the never-create boundary, and it runs before any environment open.
/// The existing-only door opens read-write — heed defaults to
/// `EnvFlags::empty()` — so without this gate LMDB would `ftruncate` and
/// initialize a zero-length `lock.mdb` (mdb.c:5477-5484, 5604-5607) and write
/// both meta pages into a zero-length `data.mdb` (`mdb_env_read_header`
/// returns `ENOENT`, so `mdb_env_open2` takes its `newenv` branch,
/// mdb.c:5072-5112). A directory holding two pre-created empty files would
/// become a partial vault before any manifest gate could refuse it.
///
/// A stock `MDB_RDONLY` validation open is NOT a substitute: LMDB opens the
/// lock file `O_RDWR | O_CREAT` and initializes a zero-length one even for a
/// read-only environment (mdb.c:5442-5449, 5477-5484). That is why validation
/// is positioned reads on descriptors this door already holds — refusal here
/// creates, grows, truncates and writes nothing, so there is nothing to clean
/// up.
#[cfg(target_os = "linux")]
pub(super) fn validate_bound_lmdb_pair(root: &Path, data: &File, lock: &File) -> Result<()> {
    validate_bound_lmdb_data(root, data)?;
    validate_bound_lmdb_lock(root, lock)
}

/// `data.mdb` must already carry a coherent first meta page: a meta-flagged
/// page 0, this LMDB's magic and data version, a page size this LMDB could
/// have written, and a file long enough to hold both meta pages.
#[cfg(target_os = "linux")]
pub(super) fn validate_bound_lmdb_data(root: &Path, data: &File) -> Result<()> {
    let len = data.metadata()?.len();
    if len < LMDB_META_PREFIX_LEN as u64 {
        return Err(existing_root_refusal(root, false));
    }
    let mut meta = [0_u8; LMDB_META_PREFIX_LEN];
    data.read_exact_at(&mut meta, 0)?;
    if lmdb_header_u16(&meta, LMDB_PAGE_FLAGS_OFFSET) & LMDB_PAGE_META_FLAG == 0
        || lmdb_header_u32(&meta, LMDB_META_MAGIC_OFFSET) != LMDB_MAGIC
        || lmdb_header_u32(&meta, LMDB_META_VERSION_OFFSET) != LMDB_DATA_VERSION
    {
        return Err(existing_root_refusal(root, false));
    }
    let page_size = lmdb_header_u32(&meta, LMDB_META_PAGE_SIZE_OFFSET);
    if !page_size.is_power_of_two()
        || !(LMDB_MIN_PAGE_SIZE..=LMDB_MAX_PAGE_SIZE).contains(&page_size)
        || len < u64::from(page_size) * LMDB_META_PAGES
    {
        return Err(existing_root_refusal(root, false));
    }
    Ok(())
}

/// `lock.mdb` must already be an initialized reader table: long enough to be
/// one, carrying this LMDB's magic and lock-format version. A precreated
/// zero-length or headerless lock file refuses HERE, before LMDB can grow it.
#[cfg(target_os = "linux")]
pub(super) fn validate_bound_lmdb_lock(root: &Path, lock: &File) -> Result<()> {
    if lock.metadata()?.len() < LMDB_LOCK_MIN_LEN {
        return Err(existing_root_refusal(root, false));
    }
    // `MDB_txbody` opens with `uint32_t mtb_magic` then `uint32_t mtb_format`
    // (mdb.c:874-882), and `MDB_txninfo` opens with that body (mdb.c:905).
    let mut header = [0_u8; 8];
    lock.read_exact_at(&mut header, 0)?;
    if lmdb_header_u32(&header, 0) != LMDB_MAGIC
        || lmdb_header_u32(&header, 4) & LMDB_LOCK_VERSION_MASK != LMDB_LOCK_VERSION
    {
        return Err(existing_root_refusal(root, false));
    }
    Ok(())
}

/// A native-endian `uint32_t` at `offset` of an LMDB header prefix.
///
/// LMDB writes these headers straight out of memory, so its files are
/// host-endian by construction and this must NOT byte-swap. The bytes are
/// copied out of a plain buffer — no C struct is mirrored or transmuted.
#[cfg(target_os = "linux")]
pub(super) fn lmdb_header_u32(header: &[u8], offset: usize) -> u32 {
    let mut field = [0_u8; 4];
    field.copy_from_slice(&header[offset..offset + 4]);
    u32::from_ne_bytes(field)
}

/// A native-endian `uint16_t` at `offset` of an LMDB header prefix.
#[cfg(target_os = "linux")]
pub(super) fn lmdb_header_u16(header: &[u8], offset: usize) -> u16 {
    let mut field = [0_u8; 2];
    field.copy_from_slice(&header[offset..offset + 2]);
    u16::from_ne_bytes(field)
}

/// Binds the existing root and opens its LMDB environment through the bound
/// descriptor. Returns with the root-open guard released, having created
/// nothing and written nothing.
///
/// "Written nothing" is structural, not hopeful: the binding refuses any pair
/// that is not already a complete LMDB environment, so the read-write
/// `mdb_env_open` below can only ever attach to an environment that already
/// existed.
///
/// The guard spans the binding, the path reservation, the unsafe environment
/// open, and the post-open identity assertion, so those are indivisible
/// against another opener exactly as they are on the create-capable path.
#[cfg(target_os = "linux")]
pub(super) fn open_existing_environment(
    path: &Path,
    config: &VaultConfig,
) -> Result<(OwnedEnv, RegisteredPath)> {
    let _vault_root_open_guard = vault_root_open_guard()?;

    // Deliberately no `create_dir_all`: an absent root fails here, with zero
    // filesystem effect.
    let canonical_path = path.canonicalize()?;
    let root = BoundVaultRoot::bind(&canonical_path)?;
    let mut registered_path =
        RegisteredPath::reserve(canonical_path.clone(), Some(root.identity.clone()))?;

    // SAFETY: heed/LMDB require a single Env per environment, the path must not
    // be on NFS or another unsupported network filesystem, and map_size must
    // not be changed concurrently while the environment is open elsewhere.
    //
    // The pinned local heed seam (`crates/heed/PROVENANCE.md`) adds three
    // obligations, each discharged here:
    //
    // * The open path is the `/proc/self/fd/<dirfd>` view of the root THIS call
    //   bound and validated, and the seam hands those exact bytes to
    //   `mdb_env_open` with no canonicalization or re-resolution in between. So
    //   LMDB's own opens of `data.mdb`/`lock.mdb` resolve through the bound
    //   directory inode, and a rename, swap, or ABA of the caller's pathname
    //   cannot redirect them onto a directory this door never bound.
    // * `root` — hence that descriptor — outlives the call and is then moved
    //   into the returned `OwnedEnv`, so the descriptor number cannot be
    //   recycled for as long as the environment lives.
    // * The cache identity is the already-canonical root path, i.e. exactly the
    //   key heed derives for itself on the create-capable door; it is used for
    //   nothing but heed's registry. `RegisteredPath` under the process-local
    //   root-open guard remains this engine's single-environment-per-root
    //   authority, and `verify_unchanged` below is defense in depth, not the
    //   mechanism that makes the open safe.
    //
    // The two hooks are test-only interleave points: they rename or stage
    // directories and never re-enter heed.
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(config.map_size)
            .max_readers(config.max_readers)
            .max_dbs(MAX_DBS)
            .open_with_cache_identity(
                &root.environment_path(),
                canonical_path.clone(),
                || {
                    #[cfg(test)]
                    test_hooks::run_before_lmdb_open(&canonical_path);
                },
                || {
                    #[cfg(test)]
                    test_hooks::run_after_lmdb_open(&canonical_path);
                },
            )?
    };
    // Wrap IMMEDIATELY so every `?` below releases the environment instead of
    // leaking it into heed's process-global registry (ONE-1142).
    let mut env = OwnedEnv {
        env,
        _bound_root_dir: None,
    };
    let refreshed = root.verify_unchanged(&canonical_path)?;
    registered_path.refresh_identity(Some(refreshed))?;
    // Only now, with every post-open check passed, does the environment take
    // ownership of the descriptor it was opened through.
    env.retain_bound_root(root.into_dir());
    Ok((env, registered_path))
}

/// No trustworthy descriptor-bound environment path exists here, so the
/// existing-only door fails closed rather than opening through a pathname a
/// rename could redirect. There is deliberately no pathname fallback.
#[cfg(not(target_os = "linux"))]
pub(super) fn open_existing_environment(
    path: &Path,
    _config: &VaultConfig,
) -> Result<(OwnedEnv, RegisteredPath)> {
    Err(vault_root_preflight_error(
        path,
        VaultRootProblem::UnsupportedPlatform {
            entry: VaultRootEntry::Data,
        },
    ))
}

pub(super) fn inspect_vault_root_entry(
    root: &Path,
    entry: VaultRootEntry,
) -> Result<Option<VaultRootFile>> {
    let path = root.join(entry.file_name());
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(vault_root_preflight_error(
            root,
            VaultRootProblem::SymlinkEntry { entry },
        ));
    }
    if !file_type.is_file() {
        return Err(vault_root_preflight_error(
            root,
            VaultRootProblem::NonRegularEntry { entry },
        ));
    }

    #[cfg(unix)]
    {
        Ok(Some(VaultRootFile {
            identity: file_identity(&metadata),
            link_count: hard_link_count(&metadata),
        }))
    }
    #[cfg(windows)]
    {
        file_info(&path).map(Some)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(vault_root_preflight_error(
            root,
            VaultRootProblem::UnsupportedPlatform { entry },
        ))
    }
}

#[cfg(unix)]
pub(super) fn hard_link_count(metadata: &std::fs::Metadata) -> u64 {
    metadata.nlink()
}

#[cfg(windows)]
pub(super) fn file_info(path: &Path) -> Result<VaultRootFile> {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = std::fs::File::open(path)?;
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file.as_raw_handle()` is a live file handle for the duration of
    // the call, and `info` points to writable, properly aligned storage for the
    // Win32 API to initialize.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `GetFileInformationByHandle` returned non-zero, which means it
    // initialized the BY_HANDLE_FILE_INFORMATION buffer.
    let info = unsafe { info.assume_init() };

    Ok(VaultRootFile {
        identity: FileIdentity {
            volume_serial_number: info.dwVolumeSerialNumber,
            file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        },
        link_count: u64::from(info.nNumberOfLinks),
    })
}

pub(super) fn vault_root_preflight_error(root: &Path, problem: VaultRootProblem) -> Error {
    Error::Store(StoreError::VaultRootPreflight {
        path: root.to_path_buf(),
        problem,
    })
}

/// Whether a post-`Env::open` preflight refusal says this root's LMDB files are
/// reachable under more than one name.
///
/// Used by the creation path to decide whether torn-creation cleanup may unlink
/// the files it just created. It may not when the inode is aliased: the unlink
/// would leave the alias behind as a single-link root and hide the aliasing
/// from the next opener. Deliberately narrow — only these two verdicts describe
/// a shared inode, and every other failure keeps cleanup armed.
pub(super) fn preflight_rejected_aliased_root(error: &Error) -> bool {
    matches!(
        error,
        Error::Store(StoreError::VaultRootPreflight {
            problem: VaultRootProblem::MultipleHardLinks { .. }
                | VaultRootProblem::AliasedLmdbFiles { .. },
            ..
        })
    )
}

pub(super) fn duplicate_open_root(
    open_paths: &HashMap<PathBuf, Option<VaultRootIdentity>>,
    path: &Path,
    identity: &VaultRootIdentity,
) -> Option<PathBuf> {
    open_paths.iter().find_map(|(open_path, open_identity)| {
        (open_path != path
            && open_identity
                .as_ref()
                .is_some_and(|open| open.overlaps(identity)))
        .then(|| open_path.clone())
    })
}
