//! The embedded engine (OF-237): the full server `oneiron serve` runs, in the
//! app's own process, over the vault at one path. The plain
//! `oneiron_vault_open` stays beside it, a vault with no server.
//!
//! Every engine call blocks its caller on the engine's own runtime: call it
//! from an app thread, never from an `OneironAppHost` callback, where it
//! fails `EngineError`.

use std::{path::Path, ptr, sync::Arc, time::SystemTime};

use oneiron_server::embedded::{
    BlockingEngine, EmbeddedRequest, embedded_serve_config, host_limits, unix_millis,
};
use oneiron_vault_contract::host_adapters::AppHost;
use zeroize::Zeroizing;

use super::alloc::{buffer_from_vec, free_vec};
use super::guard::{ffi_guard, with_engine, with_optional_slice, write_out};
use super::parse::{string_from_optional, string_from_required, validate_dimensions};
use super::types::{
    OneironAppHost, OneironByteSlice, OneironEngine, OneironReply, OneironSecretSink,
    OneironStatus, OneironVault,
};

/// The app's table, shared by every host the engine builds; `release` runs
/// when the last copy goes.
struct HostTable(OneironAppHost);

// SAFETY: `oneiron_engine_start`'s contract makes its caller vouch that
// `user_data` and every callback may be used from any thread until
// `release` runs.
unsafe impl Send for HostTable {}

// SAFETY: as for `Send`; the table is never written after start.
unsafe impl Sync for HostTable {}

impl Drop for HostTable {
    fn drop(&mut self) {
        if let Some(release) = self.0.release {
            // SAFETY: the caller's callback, run once, after the engine's last
            // use of the table.
            unsafe { release(self.0.user_data) };
        }
    }
}

/// The app's table as the engine's host.
#[derive(Clone)]
pub(super) struct CAppHost(Arc<HostTable>);

impl AppHost for CAppHost {
    fn keychain(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let table = &self.0.0;
        let mut sink = OneironSecretSink { secret: None };
        if let Some(keychain) = table.keychain {
            // SAFETY: the caller's callback; `name` and `sink` outlive the call.
            unsafe { keychain(table.user_data, name.as_ptr(), name.len(), &mut sink) };
        }
        sink.secret
            .ok_or_else(|| anyhow::anyhow!("no such secret in the app keychain: {name}"))
    }

    fn schedule_wake(&mut self, at: Option<SystemTime>) -> anyhow::Result<()> {
        let table = &self.0.0;
        if let Some(schedule_wake) = table.schedule_wake {
            let (has_at, at_unix_ms) = at.map_or((0, 0), |at| (1, unix_millis(at)));
            // SAFETY: the caller's callback.
            unsafe { schedule_wake(table.user_data, has_at, at_unix_ms) };
        }
        Ok(())
    }

    fn ready(&mut self) -> anyhow::Result<()> {
        let table = &self.0.0;
        if let Some(ready) = table.ready {
            // SAFETY: the caller's callback.
            unsafe { ready(table.user_data) };
        }
        Ok(())
    }
}

fn engine_failure(_error: anyhow::Error) -> OneironStatus {
    OneironStatus::EngineError
}

fn status(result: Result<(), OneironStatus>) -> OneironStatus {
    result.map_or_else(|status| status, |()| OneironStatus::Ok)
}

/// Answer a `keychain` callback: copy `len` bytes at `ptr` into `sink` at
/// once.
///
/// Call it before the callback returns; a second call replaces the first.
/// `ptr` may be null only when `len` is 0, an empty secret.
///
/// # Safety
///
/// `sink` is the one the running `keychain` callback was handed. A non-null
/// `ptr` covers `len` readable bytes for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_secret_sink_write(
    sink: *mut OneironSecretSink,
    ptr: *const u8,
    len: usize,
) -> OneironStatus {
    ffi_guard(|| {
        if sink.is_null() {
            return OneironStatus::NullArg;
        }
        let secret = with_optional_slice(ptr, len, |bytes| {
            Ok(Zeroizing::new(bytes.unwrap_or_default().to_vec()))
        });
        match secret {
            Ok(secret) => {
                // SAFETY: non-null, and the running callback's sink, which the
                // engine holds for the whole call.
                unsafe { (*sink).secret = Some(secret) };
                OneironStatus::Ok
            }
            Err(status) => status,
        }
    })
}

/// Open the vault at `path` and serve it in this process: the full server
/// `oneiron serve` runs, with `host` as the app's side.
///
/// The config is the one `oneiron serve --config <config_path>` resolves for
/// this path (`config_path` null with length 0 for none), with `dimensions`
/// when it is not 0. A relay host's config is refused before anything
/// opens. A `memory_bytes` or `cpu_millis_per_second` of 0 is unbounded.
/// Returns once `host.ready` has run. On success `out_engine` receives a
/// handle to release with `oneiron_engine_free` exactly once. `host.release`
/// runs exactly once, whatever this returns, when the engine holds no copy
/// of `host`.
///
/// # Safety
///
/// `path_ptr` covers `path_len` readable bytes, and a non-null
/// `config_path_ptr` covers `config_path_len`. `host`'s `user_data` and
/// callbacks are safe to use from any thread until its `release`. A
/// non-null `out_engine` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_start(
    path_ptr: *const u8,
    path_len: usize,
    dimensions: usize,
    config_path_ptr: *const u8,
    config_path_len: usize,
    host: OneironAppHost,
    memory_bytes: u64,
    cpu_millis_per_second: u32,
    out_engine: *mut *mut OneironEngine,
) -> OneironStatus {
    // Owned at once, so `release` runs once whatever happens below.
    let host = CAppHost(Arc::new(HostTable(host)));
    ffi_guard(move || {
        if let Err(status) = write_out(out_engine, ptr::null_mut()) {
            return status;
        }
        status((move || {
            let path = string_from_required(path_ptr, path_len)?;
            let config_path = string_from_optional(config_path_ptr, config_path_len)?;
            validate_dimensions(dimensions)?;
            // Crash output never carries world text: the engine's hook goes in
            // before any vault opens (owner ruling 2026-10-14, fix 6).
            oneiron::panic_report::install_panic_hook();
            let config = embedded_serve_config(
                Path::new(&path),
                (dimensions != 0).then_some(dimensions),
                config_path.as_deref().map(Path::new),
            )
            .map_err(engine_failure)?;
            let limits = host_limits(
                (memory_bytes != 0).then_some(memory_bytes),
                (cpu_millis_per_second != 0).then_some(cpu_millis_per_second),
            );
            let engine = BlockingEngine::start(host, config, limits).map_err(engine_failure)?;
            write_out(
                out_engine,
                Box::into_raw(Box::new(OneironEngine { engine })),
            )
        })())
    })
}

/// Send the engine one buffered HTTP/1.1 request and collect the whole
/// reply.
///
/// `method` and `path` (origin form, such as `/v1/health`) are UTF-8.
/// `headers` holds zero or more `name: value` lines, each ended by CRLF, sent
/// as given: bring your own auth. A request without `Host` is sent with
/// `Host: localhost`. `headers` and `body` may be empty with a null
/// pointer. A 4xx or 5xx status is a reply. A stopped engine, a reply body
/// over 64 MiB, and `/ws` or any other upgrade fail `EngineError`. On
/// success `out_reply` receives a reply to release with
/// `oneiron_engine_reply_free`.
///
/// # Safety
///
/// `engine` is null or a live handle from `oneiron_engine_start`, not freed
/// during the call. Each non-null slice covers its length in readable bytes
/// and a non-null `out_reply` is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_request(
    engine: *mut OneironEngine,
    method: OneironByteSlice,
    path: OneironByteSlice,
    headers: OneironByteSlice,
    body: OneironByteSlice,
    out_reply: *mut OneironReply,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_reply, OneironReply::empty()) {
            return status;
        }
        status(with_engine(engine, |handle| {
            let request = EmbeddedRequest {
                method: string_from_required(method.ptr, method.len)?,
                path: string_from_required(path.ptr, path.len)?,
                headers: with_optional_slice(headers.ptr, headers.len, |block| {
                    parse_header_block(block.unwrap_or_default())
                })?,
                body: with_optional_slice(body.ptr, body.len, |bytes| {
                    Ok(bytes.unwrap_or_default().to_vec())
                })?,
            };
            let reply = handle.engine.request(request).map_err(engine_failure)?;
            write_out(
                out_reply,
                OneironReply {
                    status: reply.status,
                    headers: buffer_from_vec(header_block(&reply.headers)),
                    body: buffer_from_vec(reply.body),
                },
            )
        }))
    })
}

/// `name: value` lines, each ended by CRLF or LF, as name and value pairs.
fn parse_header_block(block: &[u8]) -> Result<Vec<(String, Vec<u8>)>, OneironStatus> {
    block
        .split(|&byte| byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .map(|line| {
            let colon = line
                .iter()
                .position(|&byte| byte == b':')
                .ok_or(OneironStatus::InvalidArg)?;
            let (name, value) = line.split_at(colon);
            let name = std::str::from_utf8(name).map_err(|_| OneironStatus::Utf8)?;
            Ok((name.to_owned(), value[1..].trim_ascii().to_vec()))
        })
        .collect()
}

/// Each header as one `name: value` line ended by CRLF.
fn header_block(headers: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in headers {
        block.extend_from_slice(name.as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(value);
        block.extend_from_slice(b"\r\n");
    }
    block
}

/// Free a reply returned by `oneiron_engine_request`.
///
/// # Safety
///
/// `reply` is the empty value or one this crate returned, unchanged and not
/// yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_reply_free(reply: OneironReply) -> OneironStatus {
    ffi_guard(|| {
        let headers = free_vec(reply.headers.ptr, reply.headers.len, reply.headers.cap);
        let body = free_vec(reply.body.ptr, reply.body.len, reply.body.cap);
        if headers == OneironStatus::Ok {
            body
        } else {
            headers
        }
    })
}

/// The app's timer fired, or a push arrived: run what is due. A stopped
/// engine serves again first, over the same open vault.
///
/// # Safety
///
/// `engine` is null or a live handle from `oneiron_engine_start`, not freed
/// during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_wake(engine: *mut OneironEngine) -> OneironStatus {
    ffi_guard(|| {
        status(with_engine(engine, |handle| {
            handle.engine.wake().map_err(engine_failure)
        }))
    })
}

/// The app is backgrounding: stop taking requests, drain, stop every worker
/// and return once they have. The vault stays open for the next
/// `oneiron_engine_wake`.
///
/// # Safety
///
/// `engine` is null or a live handle from `oneiron_engine_start`, not freed
/// during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_stop(engine: *mut OneironEngine) -> OneironStatus {
    ffi_guard(|| {
        status(with_engine(engine, |handle| {
            handle.engine.stop().map_err(engine_failure)
        }))
    })
}

/// A storage handle over the engine's SAME open vault, so every
/// `oneiron_vault_*` function works on it; the path is never opened again.
/// Release it with `oneiron_vault_free`. It keeps the vault open, not the
/// engine serving.
///
/// # Safety
///
/// `engine` is null or a live handle from `oneiron_engine_start`, not freed
/// during the call. A non-null `out_vault` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_vault(
    engine: *mut OneironEngine,
    out_vault: *mut *mut OneironVault,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_vault, ptr::null_mut()) {
            return status;
        }
        status(with_engine(engine, |handle| {
            let vault = handle.engine.vault().map_err(engine_failure)?;
            let dimensions = handle.engine.dimensions();
            write_out(
                out_vault,
                Box::into_raw(Box::new(OneironVault { vault, dimensions })),
            )
        }))
    })
}

/// Stop the engine in order, release its runtime, and free the handle.
/// Storage handles from `oneiron_engine_vault` keep the vault until each is
/// freed. From inside a `host` callback the stop finishes on a thread of its
/// own and this returns `EngineError`.
///
/// # Safety
///
/// `engine` is null or a live handle from `oneiron_engine_start` that no
/// other call is using and that is never used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_free(engine: *mut OneironEngine) -> OneironStatus {
    ffi_guard(|| {
        if engine.is_null() {
            return OneironStatus::NullArg;
        }
        // SAFETY: the pointer is a live handle returned by
        // `oneiron_engine_start` and not previously freed.
        let engine = unsafe { Box::from_raw(engine) };
        status(engine.engine.close().map_err(engine_failure))
    })
}
