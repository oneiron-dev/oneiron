//! The embedded engine (OF-237): the full server `oneiron serve` runs, in the
//! app's own process, over the vault at one path. The plain
//! `oneiron_vault_open` stays beside it, a vault with no server.
//!
//! Every engine call blocks its caller on the engine's own runtime: call it
//! from an app thread, never from an `OneironAppHost` callback, where it
//! fails `EngineError`.
//!
//! Built only with the `engine` feature (`cargo build -p oneiron-ffi
//! --features engine`); the default library is the storage ABI alone.

use std::{ffi::c_void, path::Path, ptr, sync::Arc, time::SystemTime};

use oneiron_server::embedded::{
    BlockingConnection, BlockingEngine, EmbeddedRequest, embedded_serve_config, host_limits,
    unix_millis,
};
use oneiron_vault_contract::host_adapters::AppHost;
use zeroize::Zeroizing;

use super::alloc::{buffer_from_vec, free_vec};
use super::guard::{ffi_guard, with_optional_slice, write_out};
use super::parse::{string_from_optional, string_from_required, validate_dimensions};
use super::types::{OneironBuffer, OneironByteSlice, OneironStatus, OneironVault};

/// The app's side of an embedded engine, handed to `oneiron_engine_start`:
/// its keychain, its wake timer and its readiness signal.
///
/// The engine calls these from threads of its own, so `user_data` and every
/// callback must be safe to use from any thread until `release`. A callback
/// must not call back into the engine; such a call fails `EngineError`. A
/// null callback does nothing, and a null `keychain` holds no secret.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironAppHost {
    /// Handed back to every callback unchanged.
    pub user_data: *mut c_void,
    /// One secret from the app keychain by its exact UTF-8 name, borrowed for
    /// the call. Answer with `oneiron_secret_sink_write(sink, ...)` before
    /// returning, which copies the bytes at once; return without writing when
    /// the keychain holds no such secret. `sink` is valid only for the call.
    pub keychain: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            name_ptr: *const u8,
            name_len: usize,
            sink: *mut OneironSecretSink,
        ),
    >,
    /// Arms the app's timer for `at_unix_ms` when `has_at` is 1, or clears
    /// it when `has_at` is 0. When the timer fires the app calls
    /// `oneiron_engine_wake`.
    pub schedule_wake:
        Option<unsafe extern "C" fn(user_data: *mut c_void, has_at: u8, at_unix_ms: u64)>,
    /// The engine opened its vault and takes requests.
    pub ready: Option<unsafe extern "C" fn(user_data: *mut c_void)>,
    /// Called exactly once, when the engine holds no copy of this table,
    /// whatever `oneiron_engine_start` returned: free `user_data` here.
    pub release: Option<unsafe extern "C" fn(user_data: *mut c_void)>,
}

/// Where a `keychain` callback answers, through `oneiron_secret_sink_write`.
pub struct OneironSecretSink {
    secret: Option<Zeroizing<Vec<u8>>>,
}

/// Rust-owned reply of `oneiron_engine_request`. Free it with
/// `oneiron_engine_reply_free`.
#[repr(C)]
#[derive(Debug)]
pub struct OneironReply {
    /// The HTTP status; a 4xx or 5xx is a reply, not an error.
    pub status: u16,
    /// Every reply header as one `name: value` line ended by CRLF, repeats
    /// kept.
    pub headers: OneironBuffer,
    pub body: OneironBuffer,
}

impl OneironReply {
    const fn empty() -> Self {
        Self {
            status: 0,
            headers: OneironBuffer::empty(),
            body: OneironBuffer::empty(),
        }
    }
}

/// Opaque embedded-engine handle returned by `oneiron_engine_start`.
///
/// Release the handle with `oneiron_engine_free` exactly once.
pub struct OneironEngine {
    /// Shared with each connection, which keeps it until it is freed.
    engine: Arc<BlockingEngine<CAppHost>>,
}

/// Opaque handle of one connection the app holds to its engine, returned by
/// `oneiron_engine_connection_open`.
///
/// Release the handle with `oneiron_engine_connection_free` exactly once.
pub struct OneironEngineConnection {
    connection: BlockingConnection,
    /// The engine it belongs to, kept until this handle is freed.
    _engine: Arc<BlockingEngine<CAppHost>>,
}

fn with_engine<R>(
    engine: *mut OneironEngine,
    f: impl FnOnce(&OneironEngine) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if engine.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `engine` is a non-null handle previously returned by
    // `oneiron_engine_start` and not yet freed by `oneiron_engine_free`.
    let engine = unsafe { &*engine };
    f(engine)
}

fn with_connection<R>(
    connection: *mut OneironEngineConnection,
    f: impl FnOnce(&OneironEngineConnection) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if connection.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `connection` is a non-null handle previously returned by
    // `oneiron_engine_connection_open` and not yet freed by
    // `oneiron_engine_connection_free`.
    let connection = unsafe { &*connection };
    f(connection)
}

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
struct CAppHost(Arc<HostTable>);

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
                Box::into_raw(Box::new(OneironEngine {
                    engine: Arc::new(engine),
                })),
            )
        })())
    })
}

/// Send the engine one buffered HTTP/1.1 request and collect the whole
/// reply. For `/ws` or a streamed reply, open a connection instead
/// (`oneiron_engine_connection_open`).
///
/// `method` and `path` (origin form, such as `/.well-known/oneiron`) are UTF-8.
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

/// Open a connection the app holds to the engine's server: one in-process
/// stream it serves as a socket's connection, HTTP/1.1 with upgrades.
///
/// Write the request with `oneiron_engine_connection_send` (a `GET /ws`
/// with its upgrade headers holds `/ws`; after the `101`, send the upgraded
/// protocol's frames, and bring your own auth) and read what the server
/// writes with `oneiron_engine_connection_receive`. A stopped engine fails
/// `EngineError`; a stop drains the connection as it drains a socket's, so
/// after `oneiron_engine_wake` open another. On success `out_connection`
/// receives a handle to release with `oneiron_engine_connection_free` exactly
/// once. The handle keeps the engine's memory, not its serving: once
/// `oneiron_engine_free` has stopped the engine, a receive answers empty and
/// a send fails `EngineError`.
///
/// # Safety
///
/// `engine` is null or a live handle from `oneiron_engine_start`, not freed
/// during the call. A non-null `out_connection` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_connection_open(
    engine: *mut OneironEngine,
    out_connection: *mut *mut OneironEngineConnection,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_connection, ptr::null_mut()) {
            return status;
        }
        status(with_engine(engine, |handle| {
            let connection = handle.engine.connect().map_err(engine_failure)?;
            write_out(
                out_connection,
                Box::into_raw(Box::new(OneironEngineConnection {
                    connection,
                    _engine: Arc::clone(&handle.engine),
                })),
            )
        }))
    })
}

/// Write all of `bytes` to the server, blocking until the connection has
/// taken them. `bytes` may be empty with a null pointer. A closed
/// connection, or one the server has ended, fails `EngineError`.
///
/// # Safety
///
/// `connection` is null or a live handle from
/// `oneiron_engine_connection_open`, not freed during the call. A non-null
/// `bytes.ptr` covers `bytes.len` readable bytes for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_connection_send(
    connection: *mut OneironEngineConnection,
    bytes: OneironByteSlice,
) -> OneironStatus {
    ffi_guard(|| {
        status(with_connection(connection, |handle| {
            with_optional_slice(bytes.ptr, bytes.len, |bytes| {
                handle
                    .connection
                    .send(bytes.unwrap_or_default())
                    .map_err(engine_failure)
            })
        }))
    })
}

/// The next bytes the server wrote, at most 64 KiB, into `out_buffer`,
/// blocking until some arrive. An empty buffer means the server has ended
/// the connection or it was closed. Release a non-empty buffer with
/// `oneiron_buffer_free`.
///
/// # Safety
///
/// `connection` is null or a live handle from
/// `oneiron_engine_connection_open`, not freed during the call. A non-null
/// `out_buffer` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_connection_receive(
    connection: *mut OneironEngineConnection,
    out_buffer: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_buffer, OneironBuffer::empty()) {
            return status;
        }
        status(with_connection(connection, |handle| {
            let bytes = handle.connection.receive().map_err(engine_failure)?;
            write_out(out_buffer, buffer_from_vec(bytes))
        }))
    })
}

/// End the app's side of the connection: a receive blocked on another
/// thread returns empty, later sends fail, and the server reads the end of
/// the stream. The handle stays valid until `oneiron_engine_connection_free`;
/// closing again does nothing.
///
/// # Safety
///
/// `connection` is null or a live handle from
/// `oneiron_engine_connection_open`, not freed during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_connection_close(
    connection: *mut OneironEngineConnection,
) -> OneironStatus {
    ffi_guard(|| {
        status(with_connection(connection, |handle| {
            handle.connection.close().map_err(engine_failure)
        }))
    })
}

/// Close the connection as `oneiron_engine_connection_close` does and free
/// the handle, releasing its share of the engine.
///
/// # Safety
///
/// `connection` is null or a live handle from
/// `oneiron_engine_connection_open` that no other call is using and that is
/// never used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_connection_free(
    connection: *mut OneironEngineConnection,
) -> OneironStatus {
    ffi_guard(|| {
        if connection.is_null() {
            return OneironStatus::NullArg;
        }
        // SAFETY: the pointer is a live handle returned by
        // `oneiron_engine_connection_open` and not previously freed.
        let connection = unsafe { Box::from_raw(connection) };
        status(connection.connection.close().map_err(engine_failure))
    })
}
