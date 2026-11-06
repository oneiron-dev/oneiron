//! One shared-env membership over the C ABI: a connected
//! remote root, one original HTTPS acceptance, and one native bootstrap
//! outcome.
//!
//! A `OneironRemote` connects to the shared home. An acceptance keeps the
//! original `Arc<HttpsSharedInvitationAcceptance>` opaque; its request,
//! complete reply, home URLs and member client read through it.
//! `oneiron_engine_bootstrap_shared_env` imports that original acceptance
//! into the selected target through the engine's own `BlockingEngine` and
//! returns an outcome keeping the original import result and committed flag
//! independently. `oneiron_engine_retain_shared_env` upserts the same entry
//! in the engine's own config file for its next start.
//!
//! Every entry point follows the existing status channel, and a call that
//! fails with a native `MemoryError` additionally keeps that error's
//! complete serialized JSON on the calling thread for
//! `oneiron_shared_last_error_json`; an outcome's inner `MemoryError` also
//! reads nonconsumingly through `oneiron_shared_outcome_error_json`.
//!
//! Built only with the `engine` feature, beside `engine.rs`.

use std::{cell::RefCell, path::Path, ptr, sync::Arc};

use oneiron::Vault;
use oneiron::memory::MemoryError;
use oneiron::verbs::SharedInvitationAcceptWithCredentialRequest;
use oneiron_remote::{HttpsSharedInvitationAcceptance, OneironClient};
use oneiron_server::config::SharedEnvConfig;
use oneiron_server::embedded::embedded_serve_config;

use super::alloc::buffer_from_vec;
use super::engine::{OneironEngine, with_blocking_engine};
use super::engine_error::{engine_failure, engine_failure_ref};
use super::guard::{ffi_guard, write_out};
use super::parse::{string_from_optional, string_from_required};
use super::types::{OneironBuffer, OneironStatus};

/// A connected SDK handle over one shared home, returned by
/// `oneiron_remote_connect` or `oneiron_shared_acceptance_member_client`.
///
/// Release the handle with `oneiron_remote_free` exactly once.
pub struct OneironRemote {
    client: OneironClient,
}

/// One original HTTPS acceptance, returned by `oneiron_remote_accept_https`
/// or `oneiron_remote_retry_https`: the native value, never a decoded
/// receipt.
///
/// Release the handle with `oneiron_shared_acceptance_free` exactly once.
pub struct OneironSharedAcceptance {
    inner: Arc<HttpsSharedInvitationAcceptance>,
}

/// One bootstrap's native import result and committed flag, kept
/// independently, returned by `oneiron_engine_bootstrap_shared_env`.
///
/// Release the handle with `oneiron_shared_outcome_free` exactly once.
pub struct OneironSharedOutcome {
    imported: anyhow::Result<Arc<Vault>>,
    committed: bool,
}

fn with_remote<R>(
    client: *mut OneironRemote,
    f: impl FnOnce(&OneironRemote) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if client.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `client` is a non-null handle previously returned by
    // `oneiron_remote_connect` or `oneiron_shared_acceptance_member_client`
    // and not yet freed by `oneiron_remote_free`.
    let client = unsafe { &*client };
    f(client)
}

fn with_acceptance<R>(
    acceptance: *mut OneironSharedAcceptance,
    f: impl FnOnce(&OneironSharedAcceptance) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if acceptance.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `acceptance` is a non-null handle previously returned by
    // `oneiron_remote_accept_https` or `oneiron_remote_retry_https` and not
    // yet freed by `oneiron_shared_acceptance_free`.
    let acceptance = unsafe { &*acceptance };
    f(acceptance)
}

fn with_outcome<R>(
    outcome: *mut OneironSharedOutcome,
    f: impl FnOnce(&OneironSharedOutcome) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if outcome.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `outcome` is a non-null handle previously returned by
    // `oneiron_engine_bootstrap_shared_env` and not yet freed by
    // `oneiron_shared_outcome_free`.
    let outcome = unsafe { &*outcome };
    f(outcome)
}

thread_local! {
    /// The complete native `MemoryError` of the last shared-env call on
    /// this thread that failed with one, read with
    /// `oneiron_shared_last_error_json`. Every other shared-env call clears
    /// it, so a reader never sees a previous call's error; the two readers
    /// never change it.
    static LAST_SHARED_ERROR: RefCell<Option<MemoryError>> = const { RefCell::new(None) };
}

/// Clears this thread's shared-env `MemoryError`, so no previous error reads
/// as this call's.
fn clear_shared_error() {
    LAST_SHARED_ERROR.with(|last| *last.borrow_mut() = None);
}

/// Keeps the original typed error independently of any later serialization.
fn store_shared_error(error: &MemoryError) {
    LAST_SHARED_ERROR.with(|last| *last.borrow_mut() = Some(error.clone()));
}

/// A native `MemoryError` failure: its complete JSON stays on this thread
/// for `oneiron_shared_last_error_json`, its words stay beside it for
/// `oneiron_engine_last_error` under `Internal`, and the call fails
/// `EngineError`.
fn memory_failure(error: MemoryError) -> OneironStatus {
    store_shared_error(&error);
    engine_failure(anyhow::Error::new(error))
}

/// An engine failure that may itself be a native `MemoryError` (an outer
/// bootstrap or retain error): the exact downcast keeps its complete JSON
/// on this thread, any other error clears it, and either way the call fails
/// `EngineError` through the existing channel.
fn engine_failure_with_shared(error: anyhow::Error) -> OneironStatus {
    let shared = error.downcast_ref::<MemoryError>().cloned();
    LAST_SHARED_ERROR.with(|last| *last.borrow_mut() = shared);
    engine_failure(error)
}

fn status(result: Result<(), OneironStatus>) -> OneironStatus {
    result.map_or_else(|status| status, |()| OneironStatus::Ok)
}

/// Connects to the shared home at `url` with the invitee's invitation
/// credential `key`: the SDK's connected HTTPS root, making no request.
///
/// Both inputs are required UTF-8. On success `out_client` receives a
/// handle to release with `oneiron_remote_free` exactly once. A native
/// refusal fails `EngineError` and keeps its complete `MemoryError` JSON
/// for `oneiron_shared_last_error_json`.
///
/// # Safety
///
/// `url_ptr` covers `url_len` readable bytes and `key_ptr` covers
/// `key_len`. A non-null `out_client` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_remote_connect(
    url_ptr: *const u8,
    url_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    out_client: *mut *mut OneironRemote,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_client, ptr::null_mut()) {
            return status;
        }
        status((|| {
            let url = string_from_required(url_ptr, url_len)?;
            let key = string_from_required(key_ptr, key_len)?;
            let client = OneironClient::connect(&url, &key).map_err(memory_failure)?;
            write_out(
                out_client,
                Box::into_raw(Box::new(OneironRemote { client })),
            )
        })())
    })
}

/// Frees a handle from `oneiron_remote_connect` or
/// `oneiron_shared_acceptance_member_client`.
///
/// # Safety
///
/// `client` is null or a live handle from those functions that no other
/// call is using and that is never used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_remote_free(client: *mut OneironRemote) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if client.is_null() {
            return OneironStatus::NullArg;
        }
        // SAFETY: the pointer is a live handle returned by
        // `oneiron_remote_connect` or
        // `oneiron_shared_acceptance_member_client` and not previously freed.
        drop(unsafe { Box::from_raw(client) });
        OneironStatus::Ok
    })
}

/// Accepts the invitee's invitation through this connected handle with its
/// own holder key, keeping the successful call's original HTTPS value.
///
/// `request_json` is the `vault.members.accept_with_credential` input as
/// UTF-8 JSON: `vault_id` as a decimal string, `invitation`, and the
/// required credential `expires_at`. Another shape is `InvalidArg`, never
/// `EngineError`. Only a connected HTTPS home accepts; any other handle or
/// admission refusal fails `EngineError` and keeps its complete
/// `MemoryError` JSON for `oneiron_shared_last_error_json`. On success
/// `out_acceptance` receives a handle to release with
/// `oneiron_shared_acceptance_free` exactly once. Keep it for bootstrap: a
/// decoded receipt is no substitute.
///
/// # Safety
///
/// `client` is null or a live handle from `oneiron_remote_connect` or
/// `oneiron_shared_acceptance_member_client`, not freed during the call.
/// `request_json_ptr` covers `request_json_len` readable bytes. A non-null
/// `out_acceptance` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_remote_accept_https(
    client: *mut OneironRemote,
    request_json_ptr: *const u8,
    request_json_len: usize,
    out_acceptance: *mut *mut OneironSharedAcceptance,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_acceptance, ptr::null_mut()) {
            return status;
        }
        status(with_remote(client, |remote| {
            let json = string_from_required(request_json_ptr, request_json_len)?;
            let request: SharedInvitationAcceptWithCredentialRequest =
                serde_json::from_str(&json).map_err(|_| OneironStatus::InvalidArg)?;
            let accepted = remote
                .client
                .accept_shared_invitation_https(request)
                .map_err(memory_failure)?;
            write_out(
                out_acceptance,
                Box::into_raw(Box::new(OneironSharedAcceptance {
                    inner: Arc::new(accepted),
                })),
            )
        }))
    })
}

/// Retries a pending HTTPS acceptance under its original invocation: the
/// same request with the refusal's pending payload, not a decoded generic
/// retry reply.
///
/// `pending_json` is the pending refusal's `MemoryError` JSON and
/// `request_json` is the same acceptance input `oneiron_remote_accept_https`
/// takes. Either of another shape is `InvalidArg`. Only the native HTTPS
/// call produces the handle; a refusal fails `EngineError` and keeps its
/// complete `MemoryError` JSON for `oneiron_shared_last_error_json`. On
/// success `out_acceptance` receives a handle to release with
/// `oneiron_shared_acceptance_free` exactly once.
///
/// # Safety
///
/// `client` is null or a live handle from `oneiron_remote_connect` or
/// `oneiron_shared_acceptance_member_client`, not freed during the call.
/// Each JSON pointer covers its length in readable bytes. A non-null
/// `out_acceptance` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_remote_retry_https(
    client: *mut OneironRemote,
    pending_json_ptr: *const u8,
    pending_json_len: usize,
    request_json_ptr: *const u8,
    request_json_len: usize,
    out_acceptance: *mut *mut OneironSharedAcceptance,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_acceptance, ptr::null_mut()) {
            return status;
        }
        status(with_remote(client, |remote| {
            let pending_json = string_from_required(pending_json_ptr, pending_json_len)?;
            let pending: MemoryError =
                serde_json::from_str(&pending_json).map_err(|_| OneironStatus::InvalidArg)?;
            let json = string_from_required(request_json_ptr, request_json_len)?;
            let request: SharedInvitationAcceptWithCredentialRequest =
                serde_json::from_str(&json).map_err(|_| OneironStatus::InvalidArg)?;
            let accepted = remote
                .client
                .retry_shared_invitation_https(&pending, request)
                .map_err(memory_failure)?;
            write_out(
                out_acceptance,
                Box::into_raw(Box::new(OneironSharedAcceptance {
                    inner: Arc::new(accepted),
                })),
            )
        }))
    })
}

/// The normalized HTTPS home the acceptance selected, as UTF-8 bytes.
/// Release a non-empty buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// `acceptance` is null or a live handle from `oneiron_remote_accept_https`
/// or `oneiron_remote_retry_https`, not freed during the call. A non-null
/// `out_url` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_acceptance_home_url(
    acceptance: *mut OneironSharedAcceptance,
    out_url: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_url, OneironBuffer::empty()) {
            return status;
        }
        status(with_acceptance(acceptance, |held| {
            write_out(
                out_url,
                buffer_from_vec(held.inner.home_url().as_bytes().to_vec()),
            )
        }))
    })
}

/// The exact facade URL the original acceptance used, as UTF-8 bytes.
/// Release a non-empty buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// `acceptance` is null or a live handle from `oneiron_remote_accept_https`
/// or `oneiron_remote_retry_https`, not freed during the call. A non-null
/// `out_url` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_acceptance_url(
    acceptance: *mut OneironSharedAcceptance,
    out_url: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_url, OneironBuffer::empty()) {
            return status;
        }
        status(with_acceptance(acceptance, |held| {
            write_out(
                out_url,
                buffer_from_vec(held.inner.acceptance_url().as_bytes().to_vec()),
            )
        }))
    })
}

/// The original acceptance request as UTF-8 JSON; reading it creates no new
/// acceptance. Release a non-empty buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// `acceptance` is null or a live handle from `oneiron_remote_accept_https`
/// or `oneiron_remote_retry_https`, not freed during the call. A non-null
/// `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_acceptance_request_json(
    acceptance: *mut OneironSharedAcceptance,
    out_json: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_json, OneironBuffer::empty()) {
            return status;
        }
        status(with_acceptance(acceptance, |held| {
            let json = serde_json::to_vec(held.inner.request())
                .map_err(|failed| engine_failure(anyhow::Error::new(failed)))?;
            write_out(out_json, buffer_from_vec(json))
        }))
    })
}

/// The complete original receipt and member credential as UTF-8 JSON,
/// available even after member-client creation or native bootstrap fails.
/// Release a non-empty buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// `acceptance` is null or a live handle from `oneiron_remote_accept_https`
/// or `oneiron_remote_retry_https`, not freed during the call. A non-null
/// `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_acceptance_reply_json(
    acceptance: *mut OneironSharedAcceptance,
    out_json: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_json, OneironBuffer::empty()) {
            return status;
        }
        status(with_acceptance(acceptance, |held| {
            let json = serde_json::to_vec(held.inner.reply())
                .map_err(|failed| engine_failure(anyhow::Error::new(failed)))?;
            write_out(out_json, buffer_from_vec(json))
        }))
    })
}

/// A remote member handle on the acceptance's HTTPS home and original HTTP
/// wire, under its returned member credential. Each request still passes
/// the home's ordinary admission checks.
///
/// A malformed returned credential fails `EngineError` and keeps its
/// complete `MemoryError` JSON for `oneiron_shared_last_error_json`; the
/// acceptance and its complete reply stay available. On success
/// `out_client` receives a handle to release with `oneiron_remote_free`
/// exactly once.
///
/// # Safety
///
/// `acceptance` is null or a live handle from `oneiron_remote_accept_https`
/// or `oneiron_remote_retry_https`, not freed during the call. A non-null
/// `out_client` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_acceptance_member_client(
    acceptance: *mut OneironSharedAcceptance,
    out_client: *mut *mut OneironRemote,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_client, ptr::null_mut()) {
            return status;
        }
        status(with_acceptance(acceptance, |held| {
            let client = held.inner.member_client().map_err(memory_failure)?;
            write_out(
                out_client,
                Box::into_raw(Box::new(OneironRemote { client })),
            )
        }))
    })
}

/// Frees a handle from `oneiron_remote_accept_https` or
/// `oneiron_remote_retry_https`.
///
/// # Safety
///
/// `acceptance` is null or a live handle from those functions that no other
/// call is using and that is never used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_acceptance_free(
    acceptance: *mut OneironSharedAcceptance,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if acceptance.is_null() {
            return OneironStatus::NullArg;
        }
        // SAFETY: the pointer is a live handle returned by
        // `oneiron_remote_accept_https` or `oneiron_remote_retry_https` and
        // not previously freed.
        drop(unsafe { Box::from_raw(acceptance) });
        OneironStatus::Ok
    })
}

/// Imports the original acceptance into the selected target and opens that
/// same target in this engine's current shared-env registry.
///
/// `entry_json` is one native `SharedEnvConfig` entry as UTF-8 JSON: `path`,
/// `vault_id` as a number or a decimal string, `member`, `home_url`, and
/// `credential_file`. Another shape is `InvalidArg`. The target config
/// resolves as `oneiron_engine_start` does for the entry's path, with
/// `dimensions` when it is not 0 and `config_file` (null with length 0 for
/// none), never from the personal vault. The credential file must already
/// hold the accepting invitee's key.
///
/// An outer setup or task failure fails `EngineError`, keeps a native
/// `MemoryError`'s complete JSON for `oneiron_shared_last_error_json` when
/// that is what failed, and returns no outcome. Once import answers, its
/// native result and committed flag stay separate on the returned outcome:
/// read them with `oneiron_shared_outcome_committed`,
/// `oneiron_shared_outcome_vault_path` and
/// `oneiron_shared_outcome_error_json`. This call never persists the entry
/// in host configuration. It blocks its caller on the engine's own runtime:
/// call it from an app thread, never from an `OneironAppHost` callback,
/// where it fails `EngineError`.
///
/// # Safety
///
/// `engine` is null or a live handle from `oneiron_engine_start`, not freed
/// during the call. `acceptance` is null or a live handle from
/// `oneiron_remote_accept_https` or `oneiron_remote_retry_https`, not freed
/// during the call. `entry_json_ptr` covers `entry_json_len` readable bytes
/// and a non-null `config_file_ptr` covers `config_file_len`. A non-null
/// `out_outcome` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_bootstrap_shared_env(
    engine: *mut OneironEngine,
    acceptance: *mut OneironSharedAcceptance,
    entry_json_ptr: *const u8,
    entry_json_len: usize,
    dimensions: usize,
    config_file_ptr: *const u8,
    config_file_len: usize,
    out_outcome: *mut *mut OneironSharedOutcome,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_outcome, ptr::null_mut()) {
            return status;
        }
        if acceptance.is_null() {
            return OneironStatus::NullArg;
        }
        // SAFETY: `acceptance` is a non-null handle previously returned by
        // `oneiron_remote_accept_https` or `oneiron_remote_retry_https` and
        // not yet freed by `oneiron_shared_acceptance_free`.
        let acceptance = unsafe { &*acceptance };
        status(with_blocking_engine(engine, |blocking| {
            let json = string_from_required(entry_json_ptr, entry_json_len)?;
            let entry: SharedEnvConfig =
                serde_json::from_str(&json).map_err(|_| OneironStatus::InvalidArg)?;
            let config_file = string_from_optional(config_file_ptr, config_file_len)?;
            let target = embedded_serve_config(
                &entry.path,
                (dimensions != 0).then_some(dimensions),
                config_file.as_deref().map(Path::new),
            )
            .map_err(engine_failure_with_shared)?;
            let (imported, committed) = blocking
                .bootstrap_shared_env(&acceptance.inner, &entry, &target)
                .map_err(engine_failure_with_shared)?;
            write_out(
                out_outcome,
                Box::into_raw(Box::new(OneironSharedOutcome {
                    imported,
                    committed,
                })),
            )
        }))
    })
}

/// The outcome's native publication flag: 1 when the import committed, else
/// 0, including when a later step failed.
///
/// # Safety
///
/// `outcome` is null or a live handle from
/// `oneiron_engine_bootstrap_shared_env`, not freed during the call. A
/// non-null `out_committed` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_outcome_committed(
    outcome: *mut OneironSharedOutcome,
    out_committed: *mut u8,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_committed, 0) {
            return status;
        }
        status(with_outcome(outcome, |held| {
            write_out(out_committed, u8::from(held.committed))
        }))
    })
}

/// The actual registry-held vault's path on success, as UTF-8 bytes. A
/// failed import, credential update or insertion fails `EngineError`: a
/// native `MemoryError` keeps its complete JSON for
/// `oneiron_shared_last_error_json` beside the engine words, any other
/// failure clears it. It never returns an empty or fabricated successful
/// path. Release a non-empty buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// `outcome` is null or a live handle from
/// `oneiron_engine_bootstrap_shared_env`, not freed during the call. A
/// non-null `out_path` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_outcome_vault_path(
    outcome: *mut OneironSharedOutcome,
    out_path: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if let Err(status) = write_out(out_path, OneironBuffer::empty()) {
            return status;
        }
        status(with_outcome(outcome, |held| match &held.imported {
            Ok(vault) => {
                let path = vault.path().to_string_lossy().into_owned();
                write_out(out_path, buffer_from_vec(path.into_bytes()))
            }
            Err(error) => Err(match error.downcast_ref::<MemoryError>() {
                Some(exact) => {
                    store_shared_error(exact);
                    engine_failure_ref(error)
                }
                None => engine_failure_ref(error),
            }),
        }))
    })
}

/// The outcome's inner native `MemoryError` as its complete serialized JSON,
/// read without consuming the outcome: empty when the import succeeded or
/// failed with another error. The identity is the exact downcast, never
/// read from the words.
///
/// A value that does not serialize fails `EngineError` through the existing
/// engine channel instead; the outcome itself is unchanged either way. This
/// reader never changes this thread's shared-env error. Release a non-empty
/// buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// `outcome` is null or a live handle from
/// `oneiron_engine_bootstrap_shared_env`, not freed during the call. A
/// non-null `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_outcome_error_json(
    outcome: *mut OneironSharedOutcome,
    out_json: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_json, OneironBuffer::empty()) {
            return status;
        }
        status(with_outcome(outcome, |held| match &held.imported {
            Ok(_) => Ok(()),
            Err(error) => match error.downcast_ref::<MemoryError>() {
                Some(exact) => {
                    let json = serde_json::to_vec(exact)
                        .map_err(|failed| engine_failure(anyhow::Error::new(failed)))?;
                    write_out(out_json, buffer_from_vec(json))
                }
                None => Ok(()),
            },
        }))
    })
}

/// Frees a handle from `oneiron_engine_bootstrap_shared_env`.
///
/// # Safety
///
/// `outcome` is null or a live handle from that function that no other call
/// is using and that is never used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_outcome_free(
    outcome: *mut OneironSharedOutcome,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        if outcome.is_null() {
            return OneironStatus::NullArg;
        }
        // SAFETY: the pointer is a live handle returned by
        // `oneiron_engine_bootstrap_shared_env` and not previously freed.
        drop(unsafe { Box::from_raw(outcome) });
        OneironStatus::Ok
    })
}

/// Retains one shared-env membership in this engine's own config file for
/// its next start: upserts `entry_json` by `(vault_id, member)` under that
/// file's sibling lock. The running registry is unchanged. Refused without
/// a config file; a managed engine's supervisor stays the writer.
///
/// `entry_json` is one native `SharedEnvConfig` entry as UTF-8 JSON, the
/// same shape `oneiron_engine_bootstrap_shared_env` takes. Another shape is
/// `InvalidArg`. A native failure fails `EngineError` and keeps a native
/// `MemoryError`'s complete JSON for `oneiron_shared_last_error_json` when
/// that is what failed. It blocks its caller: call it from an app thread,
/// never from an `OneironAppHost` callback.
///
/// # Safety
///
/// `engine` is null or a live handle from `oneiron_engine_start`, not freed
/// during the call. `entry_json_ptr` covers `entry_json_len` readable
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_engine_retain_shared_env(
    engine: *mut OneironEngine,
    entry_json_ptr: *const u8,
    entry_json_len: usize,
) -> OneironStatus {
    ffi_guard(|| {
        clear_shared_error();
        status(with_blocking_engine(engine, |blocking| {
            let json = string_from_required(entry_json_ptr, entry_json_len)?;
            let entry: SharedEnvConfig =
                serde_json::from_str(&json).map_err(|_| OneironStatus::InvalidArg)?;
            blocking
                .retain_shared_env(&entry)
                .map_err(engine_failure_with_shared)
        }))
    })
}

/// Reads this thread's last shared-env `MemoryError` as its complete
/// serialized JSON: empty when no shared-env call on this thread has failed
/// with one. A later shared-env call replaces it; a call that succeeds or
/// fails with another status clears it. This reader never changes it.
/// Release a non-empty buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// A non-null `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_shared_last_error_json(
    out_json: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_json, OneironBuffer::empty()) {
            return status;
        }
        let error = LAST_SHARED_ERROR.with(|last| last.borrow().clone());
        status((|| {
            let json = error
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()
                .map_err(|failed| engine_failure(anyhow::Error::new(failed)))?
                .unwrap_or_default();
            write_out(out_json, buffer_from_vec(json))
        })())
    })
}
