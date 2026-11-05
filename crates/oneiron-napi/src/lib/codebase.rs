//! Codebase snapshot conversion and codebase-scoped query filters.

use napi::bindgen_prelude::*;
use oneiron::{
    CODEBASE_FORK_HASH_LEN, CODEBASE_SCOPE_KEY_LEN, CodebaseFileEntry, CodebaseSnapshot, RepoRef,
};

use oneiron::host_memory::{MachineMemory, MemoryLease};

use super::boundary::{
    BoundaryResult, parse_content_hash, parse_file_size, parse_fixed_hash, to_napi_err,
};
use super::types::{NapiCodebaseFileEntry, NapiCodebaseSnapshot};

/// FIX74 native-ingress slice: the caller-owned admission guard for one
/// `put_codebase_snapshot`. It wraps the process `MemoryLease` and admits
/// only direct native DTO, core `Vec`, path and callback bytes. It starts
/// empty and admits nothing until the first actual reserve.
pub(super) struct CodebaseMemory {
    pins: Vec<(usize, usize)>,
    pinned_bytes: u64,
    // Fields drop in declaration order: pin storage must die before its lease.
    lease: MemoryLease,
}

impl CodebaseMemory {
    pub(super) fn new() -> Self {
        Self {
            pins: Vec::new(),
            pinned_bytes: 0,
            lease: MachineMemory::process().empty_lease(),
        }
    }

    /// Admit the actual pin-slot layout for one `put_codebase_snapshot`:
    /// capacity `2 * file_count + 3` (each file's hash plus its optional
    /// body, then the id, fork and scope buffers), through the normal
    /// reserve/materialize path with checked arithmetic. This is actual
    /// admitted native allocation, not a guessed byte budget. Call after the
    /// files handle/len/ASK measurement, before the first DTO allocation.
    pub(super) fn prepare_pins(&mut self, file_count: usize) -> BoundaryResult<()> {
        let slots = file_count
            .checked_mul(2)
            .and_then(|doubled| doubled.checked_add(3))
            .ok_or_else(|| format!("native codebase ingress pin slots too many: {file_count}"))?;
        let pins = self.vector::<(usize, usize)>(slots)?;
        self.pins = pins;
        Ok(())
    }

    /// Record one measured FULL backing span. Zero spans are skipped; the
    /// base+len addition is checked. Collection allocates nothing: the slots
    /// were admitted up front and at most `2 * n + 3` spans arrive.
    pub(super) fn push_pin(&mut self, base: usize, len: usize) -> BoundaryResult<()> {
        if len == 0 {
            return Ok(());
        }
        base.checked_add(len)
            .ok_or_else(|| "native codebase ingress pin span overflows address space".to_owned())?;
        self.pins.push((base, len));
        Ok(())
    }

    /// Cache this call's full backing union before any later growth. These
    /// external bytes affect only the idle-floor check, never shared counters.
    pub(super) fn finish_pins(&mut self) {
        self.pins.sort_unstable();
        let mut total: u64 = 0;
        let mut current: Option<(usize, usize)> = None;
        for &(base, len) in &self.pins {
            let end = base.saturating_add(len);
            match current {
                None => current = Some((base, end)),
                Some((cur_base, cur_end)) if base <= cur_end => {
                    if end > cur_end {
                        current = Some((cur_base, end));
                    }
                }
                Some((cur_base, cur_end)) => {
                    total = total.saturating_add((cur_end - cur_base) as u64);
                    current = Some((base, end));
                }
            }
        }
        if let Some((cur_base, cur_end)) = current {
            total = total.saturating_add((cur_end - cur_base) as u64);
        }
        self.pinned_bytes = total;
    }

    /// Floor-only preflight over the ACTUAL provider
    /// `check_irreducible_peak`: `pinned` is the deduped FULL-backing union
    /// outside this lease and `additional` the unreserved growth needed at
    /// the peak. This reserves nothing, charges no JS baseline to the
    /// ledger, and changes no line; every future allocation still needs its
    /// normal FIFO admission.
    pub(super) fn check_peak(&self, additional: u64) -> BoundaryResult<()> {
        self.lease
            .check_irreducible_peak(self.pinned_bytes, additional)
            .map_err(|refusal| format!("native codebase ingress refused: {refusal:?}"))
    }

    pub(super) fn reserve(&mut self, bytes: u64) -> BoundaryResult<()> {
        if bytes == 0 {
            return Ok(());
        }
        self.check_peak(bytes)?;
        self.lease
            .grow_pending_untimed(bytes, &|| false)
            .map_err(|refusal| format!("native codebase ingress refused: {refusal:?}"))
    }

    pub(super) fn vector<T>(&mut self, len: usize) -> BoundaryResult<Vec<T>> {
        let want = (len as u64)
            .checked_mul(std::mem::size_of::<T>() as u64)
            .ok_or_else(|| format!("native codebase ingress vector too long: {len}"))?;
        self.reserve(want)?;
        let vec = Vec::<T>::with_capacity(len);
        let actual = (vec.capacity() as u64)
            .checked_mul(std::mem::size_of::<T>() as u64)
            .ok_or_else(|| format!("native codebase ingress vector too long: {len}"))?;
        self.allocated(want, actual);
        Ok(vec)
    }

    /// Allocate a `Vec` from ALREADY-RESERVED pending bytes, naming its
    /// actual capacity allocated; no second reserve or grow. The caller grew
    /// the whole future peak up front; this consumes this `Vec`'s share.
    pub(super) fn reserved_vector<T>(&mut self, len: usize) -> BoundaryResult<Vec<T>> {
        let want = (len as u64)
            .checked_mul(std::mem::size_of::<T>() as u64)
            .ok_or_else(|| format!("native codebase ingress vector too long: {len}"))?;
        let vec = Vec::<T>::with_capacity(len);
        let actual = (vec.capacity() as u64)
            .checked_mul(std::mem::size_of::<T>() as u64)
            .ok_or_else(|| format!("native codebase ingress vector too long: {len}"))?;
        self.allocated(want, actual);
        Ok(vec)
    }

    pub(super) fn allocated(&mut self, reserved: u64, actual: u64) {
        self.lease.materialized(reserved, actual);
    }
}

struct ContentEntry {
    path: String,
    body: Vec<u8>,
    position: usize,
    /// The JS body length at capture, before the body is copied. Scratch and
    /// peak sums read this, never the still-empty `body`.
    source_len: usize,
}

/// Owned bodies captured before core conversion, sorted by path and original
/// position. The last present body at a path wins, as in the original map.
pub(super) struct CodebaseContents {
    entries: Vec<ContentEntry>,
}

impl CodebaseContents {
    pub(super) fn from_files(
        files: &[NapiCodebaseFileEntry],
        memory: &mut CodebaseMemory,
    ) -> BoundaryResult<Self> {
        // Phase 1, metadata only: clone each path under its actual
        // reserve/materialize, retain the original position and source
        // length, and leave the body empty. No body is copied yet.
        let count = files.iter().filter(|entry| entry.content.is_some()).count();
        let mut entries = memory.vector::<ContentEntry>(count)?;
        for (position, entry) in files.iter().enumerate() {
            if let Some(body) = &entry.content {
                let want = entry.path.len() as u64;
                memory.reserve(want)?;
                let path = entry.path.clone();
                memory.allocated(want, path.capacity() as u64);
                entries.push(ContentEntry {
                    path,
                    body: Vec::new(),
                    position,
                    source_len: body.len(),
                });
            }
        }
        entries.sort_unstable_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then_with(|| a.position.cmp(&b.position))
        });
        // The ONE future peak, checked: every retained body copy (losing
        // duplicates included) plus the exact last-PRESENT selected scratch
        // plus the core Vec while the NAPI Vec still lives. Bytes already in
        // the lease (DTO, paths, slots) are NOT in this total; the floor
        // check adds the lease's own bytes itself.
        let mut bodies: u64 = 0;
        let mut scratch: u64 = 0;
        let mut index = 0;
        while index < entries.len() {
            let mut end = index + 1;
            while end < entries.len() && entries[end].path == entries[index].path {
                end += 1;
            }
            let selected = entries[end - 1].source_len as u64;
            if selected > scratch {
                scratch = selected;
            }
            for slot in &entries[index..end] {
                bodies = bodies
                    .checked_add(slot.source_len as u64)
                    .ok_or_else(|| "native codebase ingress content too long".to_owned())?;
            }
            index = end;
        }
        let core_vec = (files.len() as u64)
            .checked_mul(std::mem::size_of::<CodebaseFileEntry>() as u64)
            .ok_or_else(|| "native codebase ingress manifest too long".to_owned())?;
        let future = bodies
            .checked_add(scratch)
            .and_then(|peak| peak.checked_add(core_vec))
            .ok_or_else(|| "native codebase ingress content too long".to_owned())?;
        // Check the full irreducible peak, then reserve its unallocated
        // share once. Body and core-vector allocations consume that share;
        // the serial callback scratch remains pending through the core call.
        memory.reserve(future)?;
        // Phase 2, bodies in ORIGINAL file order: find each file's metadata
        // slot by (path, position) and copy the body into it. Getter, order,
        // duplicate and last-present semantics are unchanged; no aliasing.
        for (position, entry) in files.iter().enumerate() {
            let Some(body) = &entry.content else {
                continue;
            };
            let want = body.len() as u64;
            let slot = entries
                .binary_search_by(|existing| {
                    existing
                        .path
                        .cmp(&entry.path)
                        .then_with(|| existing.position.cmp(&position))
                })
                .map_err(|_| "native codebase ingress content slot missing".to_owned())?;
            let owned = body.to_vec();
            memory.allocated(want, owned.capacity() as u64);
            entries[slot].body = owned;
        }
        Ok(Self { entries })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn get(&self, path: &str) -> Option<Vec<u8>> {
        let start = self
            .entries
            .partition_point(|entry| entry.path.as_str() < path);
        let mut found: Option<&ContentEntry> = None;
        for entry in &self.entries[start..] {
            if entry.path.as_str() != path {
                break;
            }
            found = Some(entry);
        }
        found.map(|entry| entry.body.clone())
    }
}

pub(super) fn core_codebase_snapshot(
    input: NapiCodebaseSnapshot,
    memory: &mut CodebaseMemory,
) -> BoundaryResult<CodebaseSnapshot> {
    let NapiCodebaseSnapshot {
        project_id,
        repo_ref: repo_ref_string,
        commit_hash,
        fork_hash,
        scope_key,
        files,
    } = input;
    let repo_ref = RepoRef::parse(&repo_ref_string).map_err(|e| e.to_string())?;
    // Consumes the core-Vec share of the ONE pre-grown peak with its actual
    // capacity; no second reserve.
    let mut core_files = memory.reserved_vector::<CodebaseFileEntry>(files.len())?;
    for entry in files {
        core_files.push(CodebaseFileEntry::new(
            entry.path,
            parse_content_hash(&entry.content_hash)?,
            parse_file_size(entry.size_bytes)?,
        ));
    }
    // The admitted native-manifest scalar is RETAINED through the whole
    // synchronous call: `shrink` gives back pending FIRST, so releasing it
    // now would steal the still-PENDING scratch overlap it shares the peak
    // with. The live OS reading already shows the real deallocation, so the
    // retained scalar does not double-charge live pressure; in the fallback
    // it conservatively retains the true earlier peak, not exact current
    // live bytes.
    let fork_hash = fork_hash
        .as_ref()
        .map(|buf| parse_fixed_hash::<CODEBASE_FORK_HASH_LEN>(buf, "fork_hash"))
        .transpose()?;
    let scope_key = scope_key
        .as_ref()
        .map(|buf| parse_fixed_hash::<CODEBASE_SCOPE_KEY_LEN>(buf, "scope_key"))
        .transpose()?;
    let snapshot = CodebaseSnapshot::new(project_id, repo_ref, commit_hash, core_files)
        .map_err(|e| e.to_string())?;
    if let Some(fork_hash) = fork_hash
        && snapshot.fork_hash != fork_hash
    {
        return Err("fork_hash must match the file manifest".to_owned());
    }
    if let Some(scope_key) = scope_key
        && snapshot.scope_key != scope_key
    {
        return Err("scope_key must match project_id and repo_ref".to_owned());
    }
    Ok(snapshot)
}

pub(super) fn napi_codebase_snapshot(
    snapshot: CodebaseSnapshot,
) -> BoundaryResult<NapiCodebaseSnapshot> {
    let files = snapshot
        .files
        .into_iter()
        .map(|entry| {
            let size_bytes = i64::try_from(entry.size_bytes).map_err(|_| {
                format!(
                    "size_bytes must fit in signed 64-bit integer, got {}",
                    entry.size_bytes
                )
            })?;
            Ok(NapiCodebaseFileEntry {
                path: entry.path,
                content_hash: Buffer::from(entry.content_hash.as_slice()),
                size_bytes,
                // Reads return the manifest only; bodies live in ASSET entities.
                content: None,
            })
        })
        .collect::<BoundaryResult<Vec<_>>>()?;
    Ok(NapiCodebaseSnapshot {
        project_id: snapshot.project_id,
        repo_ref: snapshot.repo_ref.canonical(),
        commit_hash: snapshot.commit_hash,
        fork_hash: Some(Buffer::from(snapshot.fork_hash.as_slice())),
        scope_key: Some(Buffer::from(snapshot.scope_key.as_slice())),
        files,
    })
}

/// The codebase filters a scoped search or pack names, parsed once, so a
/// run can apply them again on base without a second parse.
pub(super) struct CodebaseScope {
    repo_ref: Option<RepoRef>,
    project_id: Option<String>,
}

impl CodebaseScope {
    pub(super) fn parse(
        repo_ref: Option<String>,
        project_id: Option<String>,
    ) -> napi::Result<Self> {
        let repo_ref = repo_ref
            .map(|repo_ref| RepoRef::parse(&repo_ref))
            .transpose()
            .map_err(to_napi_err)?;
        Ok(Self {
            repo_ref,
            project_id,
        })
    }

    /// `builder`, filtered to this scope.
    pub(super) fn query<'a>(
        &self,
        mut builder: oneiron::PipelineBuilder<'a>,
    ) -> oneiron::PipelineBuilder<'a> {
        if let Some(repo_ref) = &self.repo_ref {
            builder = builder.filter_repo_ref(repo_ref.clone());
        }
        if let Some(project_id) = &self.project_id {
            builder = builder.filter_project_id(project_id.as_str());
        }
        builder
    }

    /// `builder`, filtered to this scope.
    pub(super) fn pack<'a>(
        &self,
        mut builder: oneiron::ContextPackBuilder<'a>,
    ) -> oneiron::ContextPackBuilder<'a> {
        if let Some(repo_ref) = &self.repo_ref {
            builder = builder.filter_repo_ref(repo_ref.clone());
        }
        if let Some(project_id) = &self.project_id {
            builder = builder.filter_project_id(project_id.as_str());
        }
        builder
    }
}

/// Engine FIX13215 refusal for SharedArrayBuffer-backed `put` inputs on
/// Node runtimes whose `napi_get_arraybuffer_info` cannot measure shared
/// backings. Normal Buffers and every other verb keep Node >= 20.
const SAB_UNMEASURABLE: &str = "codebase snapshot input is backed by a SharedArrayBuffer, whose full extent this Node runtime cannot measure; pass a normal Buffer or use Node 22.21+ / 24.9+";

/// Measure every FULL backing AFTER all getter capture, BEFORE the first
/// body copy: the id, each file hash and content, fork and scope. Each
/// field is taken and restored in place (required hashes via a
/// zero-allocation `Buffer::from(Vec::new())` stand-in); no new DTO vec.
/// Returned N-API handles remain rooted in this callback's handle scope,
/// even after the DTO's temporary Buffer references drop during conversion.
pub(super) fn measure_codebase_backings(
    env: &Env,
    id: &mut Buffer,
    snapshot: &mut NapiCodebaseSnapshot,
    memory: &mut CodebaseMemory,
) -> napi::Result<()> {
    let taken = std::mem::replace(id, Buffer::from(Vec::new()));
    let (rebuilt, span) = measure_full_backing(env, taken)?;
    *id = rebuilt;
    push_span(memory, span)?;
    if let Some(taken) = snapshot.fork_hash.take() {
        let (rebuilt, span) = measure_full_backing(env, taken)?;
        snapshot.fork_hash = Some(rebuilt);
        push_span(memory, span)?;
    }
    if let Some(taken) = snapshot.scope_key.take() {
        let (rebuilt, span) = measure_full_backing(env, taken)?;
        snapshot.scope_key = Some(rebuilt);
        push_span(memory, span)?;
    }
    for entry in &mut snapshot.files {
        let taken = std::mem::replace(&mut entry.content_hash, Buffer::from(Vec::new()));
        let (rebuilt, span) = measure_full_backing(env, taken)?;
        entry.content_hash = rebuilt;
        push_span(memory, span)?;
        if let Some(taken) = entry.content.take() {
            let (rebuilt, span) = measure_full_backing(env, taken)?;
            entry.content = Some(rebuilt);
            push_span(memory, span)?;
        }
    }
    memory.finish_pins();
    Ok(())
}

/// Record one measured span (zero spans skipped) in the prepared slots.
fn push_span(memory: &mut CodebaseMemory, span: Option<(usize, usize)>) -> napi::Result<()> {
    if let Some((base, len)) = span {
        memory
            .push_pin(base, len)
            .map_err(napi::Error::from_reason)?;
    }
    Ok(())
}

/// Measure the FULL backing span of one already-JS-backed `Buffer` and
/// hand back an equivalent live `Buffer` over the same bytes: no JS
/// properties, no copies, no materialization.
///
/// The roundtrip consumes `buffer` through `ToNapiValue` (for a JS-backed
/// `Buffer` this deletes the temporary reference and returns the
/// ORIGINAL raw handle: zero copy, single-shot) and recreates the
/// `Buffer` from that same handle with `FromNapiValue` (a fresh
/// reference over the same bytes; no byte copy). The FULL extent then
/// comes from two raw calls on that handle: `napi_get_typedarray_info`
/// yields the ACTUAL backing handle (transparent for plain and shared
/// backings; never the public `TypedArray.arraybuffer`, which is a
/// constructed VIEW slice), and `napi_get_arraybuffer_info` on that
/// handle yields base plus FULL length.
///
/// `napi_invalid_arg` from the second call means an old-runtime shared
/// backing the engine cannot measure (Node 20, 22 below 22.21, 24 below
/// 24.9): the Engine-ruled typed refusal naming the lifting versions.
/// Any other native error propagates as its own failure. Never gated on
/// `napi_is_arraybuffer`, which is plain-only (false for shared).
fn measure_full_backing(
    env: &Env,
    buffer: Buffer,
) -> napi::Result<(Buffer, Option<(usize, usize)>)> {
    let raw = env.raw();
    // SAFETY: `buffer` is owned and alive here. For a JS-backed Buffer,
    // `to_napi_value` resolves the temporary reference to the original
    // JS handle, deletes that reference, and nulls the moved value's
    // slot, so the dropped shell deletes nothing twice. The handle stays
    // valid in the current callback's N-API handle scope, and the rebuilt
    // Buffer below also takes a fresh reference. No helper closes that scope.
    let handle =
        unsafe { <Buffer as napi::bindgen_prelude::ToNapiValue>::to_napi_value(raw, buffer) }?;
    let mut ty: napi::sys::napi_typedarray_type = 0;
    let mut view_len: usize = 0;
    let mut view_data: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut backing: napi::sys::napi_value = std::ptr::null_mut();
    let mut byte_offset: usize = 0;
    // SAFETY: `handle` is the live original JS Buffer value (Buffers are
    // Uint8Arrays at the V8 level); every out-param is a valid stack
    // slot. The call only reads the value's backing association.
    let status = unsafe {
        napi::sys::napi_get_typedarray_info(
            raw,
            handle,
            &mut ty,
            &mut view_len,
            &mut view_data,
            &mut backing,
            &mut byte_offset,
        )
    };
    if status != napi::sys::Status::napi_ok {
        return Err(napi::Error::new(
            napi::Status::from(status),
            "native codebase ingress backing lookup failed",
        ));
    }
    let mut base: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut full: usize = 0;
    // SAFETY: `backing` is the live backing handle just returned above
    // (plain or shared ArrayBuffer); both out-params are valid slots.
    let status =
        unsafe { napi::sys::napi_get_arraybuffer_info(raw, backing, &mut base, &mut full) };
    if status == napi::sys::Status::napi_invalid_arg {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            SAB_UNMEASURABLE.to_owned(),
        ));
    }
    if status != napi::sys::Status::napi_ok {
        return Err(napi::Error::new(
            napi::Status::from(status),
            "native codebase ingress backing measure failed",
        ));
    }
    // SAFETY: `handle` remains rooted in the current callback's N-API
    // handle scope. `from_napi_value` takes a fresh temporary reference and
    // reads the view bytes, copying none.
    let rebuilt =
        unsafe { <Buffer as napi::bindgen_prelude::FromNapiValue>::from_napi_value(raw, handle) }?;
    let addr = base as usize;
    addr.checked_add(full).ok_or_else(|| {
        napi::Error::from_reason("native codebase ingress pin span overflows address space")
    })?;
    let span = if full == 0 { None } else { Some((addr, full)) };
    Ok((rebuilt, span))
}
