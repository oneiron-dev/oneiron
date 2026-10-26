/*
 * Oneiron C ABI for iOS and macOS on-device vault access.
 *
 * Ownership: variable-size outputs are allocated by Rust and returned through
 * OneironBuffer or typed array structs. Release them with the paired
 * oneiron_*_free function from this header. Do not pass Rust-owned pointers
 * to free(), and do not free the same value twice.
 *
 * Boundary validation: EntityId inputs must be exactly 16 bytes. Text queries
 * are capped at 8 KiB and dimensions at 16384; a search limit is served whole.
 *
 * Intentionally absent: start_sync and stop_sync are not exported while sync
 * remains disabled pre-launch.
 *
 * Bound handles (OF-063): oneiron_vault_bind opens a handle over the same
 * open vault whose writes run as the app's principal, inside the off-record
 * session it names, if any. Every other handle writes as the host.
 *
 * Embedded engine (OF-237): oneiron_engine_start runs the full server in this
 * process with the app's OneironAppHost callbacks; oneiron_engine_request
 * sends it one buffered HTTP/1.1 request, oneiron_engine_vault shares its
 * open vault with the storage functions, and oneiron_engine_free stops it in
 * order. oneiron_engine_connection_open opens a connection the app holds
 * (HTTP/1.1 with upgrades, so `/ws`), with _send, _receive, _close and _free.
 * oneiron_engine_artifact_request and oneiron_engine_artifact_connection_open
 * reach the artifact app (`/a/`) on its own origin. A call that fails
 * EngineError leaves its stable OneironEngineErrorCode and words for
 * oneiron_engine_last_error. Engine calls block: make them from app threads,
 * never from a callback. The library exports these only when built with the
 * `engine` cargo feature.
 */


#ifndef ONEIRON_FFI_H
#define ONEIRON_FFI_H

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Status code returned by every fallible C entry point.
 */
typedef enum OneironStatus {
  /**
   * Operation completed successfully.
   */
  OneironStatus_Ok = 0,
  /**
   * A required pointer argument was null.
   */
  OneironStatus_NullArg = 1,
  /**
   * A scalar, length, enum discriminant, or ID value failed validation.
   */
  OneironStatus_InvalidArg = 2,
  /**
   * The requested optional value was not found.
   */
  OneironStatus_NotFound = 3,
  /**
   * The engine returned an error.
   */
  OneironStatus_EngineError = 4,
  /**
   * A Rust panic was caught before it crossed the C ABI boundary.
   */
  OneironStatus_Panic = 5,
  /**
   * Reserved for caller-owned buffer APIs.
   */
  OneironStatus_BufferTooSmall = 6,
  /**
   * Input bytes were not valid UTF-8.
   */
  OneironStatus_Utf8 = 7,
  /**
   * The request needs a model this library does not serve: a context
   * pack's media needs the `ai.embed` rung its space names (OF-370).
   * Retry without it, or on a server that serves that rung.
   */
  OneironStatus_ModelUnavailable = 8,
} OneironStatus;

/**
 * Why the last engine call on this thread failed `EngineError`, read with
 * `oneiron_engine_last_error`.
 */
typedef enum OneironEngineErrorCode {
  /**
   * No engine call on this thread has failed `EngineError`.
   */
  OneironEngineErrorCode_None = 0,
  /**
   * No named cause; the message says what failed.
   */
  OneironEngineErrorCode_Internal = 1,
  /**
   * The engine is stopped; `oneiron_engine_wake` serves it again.
   */
  OneironEngineErrorCode_Stopped = 2,
  /**
   * The engine is closed and refuses every call.
   */
  OneironEngineErrorCode_Closed = 3,
  /**
   * A relay host's config, refused before anything opens.
   */
  OneironEngineErrorCode_RelayRefused = 4,
  /**
   * Called from inside an async runtime or an `OneironAppHost` callback.
   */
  OneironEngineErrorCode_WrongThread = 5,
  /**
   * The serve config did not resolve.
   */
  OneironEngineErrorCode_Config = 6,
  /**
   * The vault did not open.
   */
  OneironEngineErrorCode_VaultOpen = 7,
  /**
   * Serving did not start, or ended before `ready`.
   */
  OneironEngineErrorCode_StartFailed = 8,
  /**
   * The connection or its reply ended: closed, ended by the server, or
   * cut off by a stop.
   */
  OneironEngineErrorCode_ConnectionEnded = 9,
  /**
   * A buffered reply's body is over 64 MiB; open a connection for it.
   */
  OneironEngineErrorCode_ReplyTooLarge = 10,
  /**
   * A request the engine does not send: a path not in origin form, an
   * upgrade on a buffered request, or a malformed method or header.
   */
  OneironEngineErrorCode_BadRequest = 11,
} OneironEngineErrorCode;

/**
 * Opaque embedded-engine handle returned by `oneiron_engine_start`.
 *
 * Release the handle with `oneiron_engine_free` exactly once.
 */
typedef struct OneironEngine OneironEngine;

/**
 * Opaque handle of one connection the app holds to its engine, returned by
 * `oneiron_engine_connection_open`.
 *
 * Release the handle with `oneiron_engine_connection_free` exactly once.
 */
typedef struct OneironEngineConnection OneironEngineConnection;

/**
 * Where a `keychain` callback answers, through `oneiron_secret_sink_write`.
 */
typedef struct OneironSecretSink OneironSecretSink;

/**
 * Opaque vault handle returned by `oneiron_vault_open`,
 * `oneiron_engine_vault` and `oneiron_vault_bind`.
 *
 * Release the handle with `oneiron_vault_free` exactly once.
 */
typedef struct OneironVault OneironVault;

/**
 * The app's side of an embedded engine, handed to `oneiron_engine_start`:
 * its keychain, its wake timer and its readiness signal.
 *
 * The engine calls these from threads of its own, so `user_data` and every
 * callback must be safe to use from any thread until `release`. A callback
 * must not call back into the engine; such a call fails `EngineError`. A
 * null callback does nothing, and a null `keychain` holds no secret.
 */
typedef struct OneironAppHost {
  /**
   * Handed back to every callback unchanged.
   */
  void *user_data;
  /**
   * One secret from the app keychain by its exact UTF-8 name, borrowed for
   * the call. Answer with `oneiron_secret_sink_write(sink, ...)` before
   * returning, which copies the bytes at once; return without writing when
   * the keychain holds no such secret. `sink` is valid only for the call.
   */
  void (*keychain)(void *user_data,
                   const uint8_t *name_ptr,
                   size_t name_len,
                   struct OneironSecretSink *sink);
  /**
   * Arms the app's timer for `at_unix_ms` when `has_at` is 1, or clears
   * it when `has_at` is 0. When the timer fires the app calls
   * `oneiron_engine_wake`.
   */
  void (*schedule_wake)(void *user_data, uint8_t has_at, uint64_t at_unix_ms);
  /**
   * The engine opened its vault and takes requests.
   */
  void (*ready)(void *user_data);
  /**
   * Called exactly once, when the engine holds no copy of this table,
   * whatever `oneiron_engine_start` returned: free `user_data` here.
   */
  void (*release)(void *user_data);
} OneironAppHost;

/**
 * Borrowed byte/string input for arrays such as `dict_search_paths`.
 *
 * Each element is caller-owned and is only borrowed for the duration of the
 * call. String uses are UTF-8 validated by the receiving function.
 */
typedef struct OneironByteSlice {
  const uint8_t *ptr;
  size_t len;
} OneironByteSlice;

/**
 * Rust-owned byte buffer returned by variable-size byte outputs.
 *
 * The caller must release non-empty buffers with `oneiron_buffer_free`. The
 * caller must not pass `ptr` to `free()` and must not call the free function
 * more than once for the same buffer. In Rust it moves rather than copies,
 * like the three array owners, so one value reaches its free function once.
 */
typedef struct OneironBuffer {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} OneironBuffer;

/**
 * Rust-owned reply of `oneiron_engine_request`. Free it with
 * `oneiron_engine_reply_free`.
 */
typedef struct OneironReply {
  /**
   * The HTTP status; a 4xx or 5xx is a reply, not an error.
   */
  uint16_t status;
  /**
   * Every reply header as one `name: value` line ended by CRLF, repeats
   * kept.
   */
  struct OneironBuffer headers;
  struct OneironBuffer body;
} OneironReply;

/**
 * C representation of an edge returned by `edges_out` and `edges_in`.
 */
typedef struct OneironEdgeInfo {
  uint8_t src[16];
  uint32_t kind;
  uint8_t tgt[16];
  double weight;
  int64_t created_at;
  uint8_t has_vad;
  double valence;
  double arousal;
  double dominance;
} OneironEdgeInfo;

/**
 * Rust-owned edge array. Free with `oneiron_edge_info_array_free`.
 */
typedef struct OneironEdgeInfoArray {
  struct OneironEdgeInfo *ptr;
  size_t len;
  size_t cap;
} OneironEdgeInfoArray;

/**
 * C representation of a scored search result.
 */
typedef struct OneironScoredEntity {
  uint8_t id[16];
  double score;
} OneironScoredEntity;

/**
 * Rust-owned scored search result array. Free with
 * `oneiron_scored_entity_array_free`.
 */
typedef struct OneironScoredEntityArray {
  struct OneironScoredEntity *ptr;
  size_t len;
  size_t cap;
} OneironScoredEntityArray;

/**
 * C representation of a subtree traversal entry.
 */
typedef struct OneironSubtreeEntry {
  uint8_t id[16];
  uint32_t depth;
} OneironSubtreeEntry;

/**
 * Rust-owned subtree entry array. Free with
 * `oneiron_subtree_entry_array_free`.
 */
typedef struct OneironSubtreeEntryArray {
  struct OneironSubtreeEntry *ptr;
  size_t len;
  size_t cap;
} OneironSubtreeEntryArray;

/**
 * Borrowed entity input for `oneiron_vault_batch_put_entities`.
 *
 * Each payload is caller-owned and borrowed only for the duration of the
 * call. Entity IDs are fixed-width 16-byte values; `entity_type` must fit in
 * one byte and pass the engine's public entity-type gate.
 */
typedef struct OneironEntityInput {
  uint8_t id[16];
  uint32_t entity_type;
  int64_t occurred_start;
  int64_t occurred_end;
  int64_t learned_at;
  struct OneironByteSlice data;
} OneironEntityInput;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Answer a `keychain` callback: copy `len` bytes at `ptr` into `sink` at
 * once.
 *
 * Call it before the callback returns; a second call replaces the first.
 * `ptr` may be null only when `len` is 0, an empty secret.
 *
 * # Safety
 *
 * `sink` is the one the running `keychain` callback was handed. A non-null
 * `ptr` covers `len` readable bytes for the call.
 */
enum OneironStatus oneiron_secret_sink_write(struct OneironSecretSink *sink,
                                             const uint8_t *ptr,
                                             size_t len);

/**
 * Open the vault at `path` and serve it in this process: the full server
 * `oneiron serve` runs, with `host` as the app's side.
 *
 * The config is the one `oneiron serve --config <config_path>` resolves for
 * this path (`config_path` null with length 0 for none), with `dimensions`
 * when it is not 0. A relay host's config is refused before anything
 * opens. A `memory_bytes` or `cpu_millis_per_second` of 0 is unbounded.
 * Returns once `host.ready` has run. On success `out_engine` receives a
 * handle to release with `oneiron_engine_free` exactly once. `host.release`
 * runs exactly once, whatever this returns, when the engine holds no copy
 * of `host`.
 *
 * # Safety
 *
 * `path_ptr` covers `path_len` readable bytes, and a non-null
 * `config_path_ptr` covers `config_path_len`. `host`'s `user_data` and
 * callbacks are safe to use from any thread until its `release`. A
 * non-null `out_engine` is writable.
 */
enum OneironStatus oneiron_engine_start(const uint8_t *path_ptr,
                                        size_t path_len,
                                        size_t dimensions,
                                        const uint8_t *config_path_ptr,
                                        size_t config_path_len,
                                        struct OneironAppHost host,
                                        uint64_t memory_bytes,
                                        uint32_t cpu_millis_per_second,
                                        struct OneironEngine **out_engine);

/**
 * Send the engine one buffered HTTP/1.1 request and collect the whole
 * reply. For `/ws` or a streamed reply, open a connection instead
 * (`oneiron_engine_connection_open`).
 *
 * `method` and `path` (origin form, such as `/.well-known/oneiron`) are UTF-8.
 * `headers` holds zero or more `name: value` lines, each ended by CRLF, sent
 * as given: bring your own auth. A request without `Host` is sent with
 * `Host: localhost`. `headers` and `body` may be empty with a null
 * pointer. A 4xx or 5xx status is a reply. A stopped engine, a reply body
 * over 64 MiB, and `/ws` or any other upgrade fail `EngineError`. On
 * success `out_reply` receives a reply to release with
 * `oneiron_engine_reply_free`.
 *
 * # Safety
 *
 * `engine` is null or a live handle from `oneiron_engine_start`, not freed
 * during the call. Each non-null slice covers its length in readable bytes
 * and a non-null `out_reply` is writable, for the whole call.
 */
enum OneironStatus oneiron_engine_request(struct OneironEngine *engine,
                                          struct OneironByteSlice method,
                                          struct OneironByteSlice path,
                                          struct OneironByteSlice headers,
                                          struct OneironByteSlice body,
                                          struct OneironReply *out_reply);

/**
 * `oneiron_engine_request` on the artifact app's own origin (`/a/`), apart
 * from the API's: what an app's web view loads artifacts through.
 *
 * # Safety
 *
 * As for `oneiron_engine_request`.
 */
enum OneironStatus oneiron_engine_artifact_request(struct OneironEngine *engine,
                                                   struct OneironByteSlice method,
                                                   struct OneironByteSlice path,
                                                   struct OneironByteSlice headers,
                                                   struct OneironByteSlice body,
                                                   struct OneironReply *out_reply);

/**
 * Free a reply returned by `oneiron_engine_request`.
 *
 * # Safety
 *
 * `reply` is the empty value or one this crate returned, unchanged and not
 * yet freed.
 */
enum OneironStatus oneiron_engine_reply_free(struct OneironReply reply);

/**
 * The app's timer fired, or a push arrived: run what is due. A stopped
 * engine serves again first, over the same open vault.
 *
 * # Safety
 *
 * `engine` is null or a live handle from `oneiron_engine_start`, not freed
 * during the call.
 */
enum OneironStatus oneiron_engine_wake(struct OneironEngine *engine);

/**
 * The app is backgrounding: stop taking requests, drain, stop every worker
 * and return once they have. The vault stays open for the next
 * `oneiron_engine_wake`.
 *
 * # Safety
 *
 * `engine` is null or a live handle from `oneiron_engine_start`, not freed
 * during the call.
 */
enum OneironStatus oneiron_engine_stop(struct OneironEngine *engine);

/**
 * A storage handle over the engine's SAME open vault, so every
 * `oneiron_vault_*` function works on it; the path is never opened again.
 * Release it with `oneiron_vault_free`. It keeps the vault open, not the
 * engine serving. It writes as the host; `oneiron_vault_bind` opens one
 * that writes as the app's principal, inside its session.
 *
 * # Safety
 *
 * `engine` is null or a live handle from `oneiron_engine_start`, not freed
 * during the call. A non-null `out_vault` is writable.
 */
enum OneironStatus oneiron_engine_vault(struct OneironEngine *engine,
                                        struct OneironVault **out_vault);

/**
 * Stop the engine in order, release its runtime, and free the handle.
 * Storage handles from `oneiron_engine_vault` keep the vault until each is
 * freed. From inside a `host` callback the stop finishes on a thread of its
 * own and this returns `EngineError`.
 *
 * # Safety
 *
 * `engine` is null or a live handle from `oneiron_engine_start` that no
 * other call is using and that is never used again.
 */
enum OneironStatus oneiron_engine_free(struct OneironEngine *engine);

/**
 * Open a connection the app holds to the engine's server: one in-process
 * stream it serves as a socket's connection, HTTP/1.1 with upgrades.
 *
 * Write the request with `oneiron_engine_connection_send` (a `GET /ws`
 * with its upgrade headers holds `/ws`; after the `101`, send the upgraded
 * protocol's frames, and bring your own auth) and read what the server
 * writes with `oneiron_engine_connection_receive`. A stopped engine fails
 * `EngineError`; a stop drains the connection as it drains a socket's, so
 * after `oneiron_engine_wake` open another. On success `out_connection`
 * receives a handle to release with `oneiron_engine_connection_free` exactly
 * once. The handle keeps the engine's memory, not its serving: once
 * `oneiron_engine_free` has stopped the engine, a receive answers empty and
 * a send fails `EngineError`.
 *
 * # Safety
 *
 * `engine` is null or a live handle from `oneiron_engine_start`, not freed
 * during the call. A non-null `out_connection` is writable.
 */
enum OneironStatus oneiron_engine_connection_open(struct OneironEngine *engine,
                                                  struct OneironEngineConnection **out_connection);

/**
 * `oneiron_engine_connection_open` on the artifact app's own origin (`/a/`),
 * apart from the API's. The handle is an `OneironEngineConnection`: send,
 * receive, close and free it as any other.
 *
 * # Safety
 *
 * As for `oneiron_engine_connection_open`.
 */
enum OneironStatus oneiron_engine_artifact_connection_open(struct OneironEngine *engine,
                                                           struct OneironEngineConnection **out_connection);

/**
 * Write all of `bytes` to the server, blocking until the connection has
 * taken them. `bytes` may be empty with a null pointer. A closed
 * connection, or one the server has ended, fails `EngineError`.
 *
 * # Safety
 *
 * `connection` is null or a live handle from
 * `oneiron_engine_connection_open`, not freed during the call. A non-null
 * `bytes.ptr` covers `bytes.len` readable bytes for the whole call.
 */
enum OneironStatus oneiron_engine_connection_send(struct OneironEngineConnection *connection,
                                                  struct OneironByteSlice bytes);

/**
 * The next bytes the server wrote, at most 64 KiB, into `out_buffer`,
 * blocking until some arrive. An empty buffer means the server has ended
 * the connection or it was closed. Release a non-empty buffer with
 * `oneiron_buffer_free`.
 *
 * # Safety
 *
 * `connection` is null or a live handle from
 * `oneiron_engine_connection_open`, not freed during the call. A non-null
 * `out_buffer` is writable.
 */
enum OneironStatus oneiron_engine_connection_receive(struct OneironEngineConnection *connection,
                                                     struct OneironBuffer *out_buffer);

/**
 * End the app's side of the connection: a receive blocked on another
 * thread returns empty, later sends fail, and the server reads the end of
 * the stream. The handle stays valid until `oneiron_engine_connection_free`;
 * closing again does nothing.
 *
 * # Safety
 *
 * `connection` is null or a live handle from
 * `oneiron_engine_connection_open`, not freed during the call.
 */
enum OneironStatus oneiron_engine_connection_close(struct OneironEngineConnection *connection);

/**
 * Close the connection as `oneiron_engine_connection_close` does and free
 * the handle, releasing its share of the engine.
 *
 * # Safety
 *
 * `connection` is null or a live handle from
 * `oneiron_engine_connection_open` that no other call is using and that is
 * never used again.
 */
enum OneironStatus oneiron_engine_connection_free(struct OneironEngineConnection *connection);

/**
 * Read why the last engine call on this thread failed `EngineError`: its
 * stable cause into `out_code` and the error's UTF-8 words into
 * `out_message`, which the caller releases with `oneiron_buffer_free`. With
 * no such failure on this thread, `out_code` is `None` and `out_message`
 * empty. A later failing engine call on this thread replaces it; a call that
 * succeeds or fails with another status leaves it.
 *
 * # Safety
 *
 * Each non-null out pointer is writable for the whole call.
 */
enum OneironStatus oneiron_engine_last_error(enum OneironEngineErrorCode *out_code,
                                             struct OneironBuffer *out_message);

/**
 * Free a Rust-owned byte buffer returned by this crate.
 *
 * Passing a null, zero-length buffer is accepted. Passing a mutated buffer,
 * an already-freed buffer, or memory allocated outside this crate is undefined
 * behavior by the C ABI contract.
 *
 * # Safety
 *
 * `buffer` is the empty value or one this crate returned, unchanged and not
 * yet freed.
 */
enum OneironStatus oneiron_buffer_free(struct OneironBuffer buffer);

/**
 * Free a Rust-owned edge array returned by this crate.
 *
 * # Safety
 *
 * `array` is the empty value or one this crate returned, unchanged and not
 * yet freed.
 */
enum OneironStatus oneiron_edge_info_array_free(struct OneironEdgeInfoArray array);

/**
 * Free a Rust-owned scored entity array returned by this crate.
 *
 * # Safety
 *
 * `array` is the empty value or one this crate returned, unchanged and not
 * yet freed.
 */
enum OneironStatus oneiron_scored_entity_array_free(struct OneironScoredEntityArray array);

/**
 * Free a Rust-owned subtree entry array returned by this crate.
 *
 * # Safety
 *
 * `array` is the empty value or one this crate returned, unchanged and not
 * yet freed.
 */
enum OneironStatus oneiron_subtree_entry_array_free(struct OneironSubtreeEntryArray array);

/**
 * Open or create a vault using `VaultConfig::device()`.
 *
 * `dimensions == 0` keeps the device preset default. `dict_search_paths` may
 * be null only when `dict_search_paths_len == 0`; otherwise it must point to
 * an array of UTF-8 `OneironByteSlice` values. On success `out_vault` receives
 * an opaque handle that must be released exactly once with `oneiron_vault_free`.
 *
 * `device_class` is what kind of machine this install is, as the host
 * declares it (FIX 3833): 0 a computer, the generic default, 1 a phone; any
 * other value is `InvalidArg`. It is set before the vault opens, so the
 * install enrols as it, and it is never read off the operating system.
 *
 * # Safety
 *
 * `path_ptr` covers `path_len` readable bytes. A non-null
 * `dict_search_paths` covers `dict_search_paths_len` slices, each covering
 * its own readable bytes. A non-null `out_vault` is writable.
 */
enum OneironStatus oneiron_vault_open(const uint8_t *path_ptr,
                                      size_t path_len,
                                      size_t dimensions,
                                      const struct OneironByteSlice *dict_search_paths,
                                      size_t dict_search_paths_len,
                                      uint8_t device_class,
                                      struct OneironVault **out_vault);

/**
 * Open a NEW handle over `vault`'s same open vault whose writes run as one
 * caller (OF-063): the principal `actor_key` names, inside the off-record
 * session `session` names. `vault` itself is unchanged, and the path is
 * never opened again.
 *
 * `actor_key` is UTF-8 `human:<ref>`, `agent:<ref>` or `system:<ref>`; the
 * named entity must exist and its stored type admit the class. Pass a null
 * pointer with length 0 to bind the embedded owner instead, as an embedded
 * facade client does. `session` is the UTF-8 off-record session reference;
 * pass a null pointer with length 0 to bind none, so the handle writes
 * outside any session. Binding a bound handle binds the new handle to the
 * caller named here alone.
 *
 * The bound handle's puts, batch puts, edges and vectors commit as that
 * caller, below owner grade, once the write's own transaction proves the
 * actor and a shared vault's content-write grant. Its delete runs the
 * `vault.delete` door: owner-only, and an id naming no record is refused
 * `NotFound` with a refusal receipt, which an anonymous off-record session
 * the actor is verified in does not keep. A refusal is `InvalidArg`,
 * `NotFound` or `EngineError`. Reads are the same on every handle.
 *
 * On success `out_vault` receives a handle to release with
 * `oneiron_vault_free` exactly once; it keeps the vault open.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`,
 * `oneiron_engine_vault` or `oneiron_vault_bind`, not freed during the call.
 * Each non-null input pointer covers its length in readable bytes, and a
 * non-null `out_vault` is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_bind(struct OneironVault *vault,
                                      const uint8_t *actor_key_ptr,
                                      size_t actor_key_len,
                                      const uint8_t *session_ptr,
                                      size_t session_len,
                                      struct OneironVault **out_vault);

/**
 * Free an opaque vault handle returned by `oneiron_vault_open`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open` that no other
 * call is using and that is never used again.
 */
enum OneironStatus oneiron_vault_free(struct OneironVault *vault);

/**
 * Return a UTF-8 JSON doctor report for an opened vault.
 *
 * The report is read-only and mirrors `Vault::doctor()`: it observes the
 * persisted compatibility metadata consumed by open-time storage ABI gates
 * without repairing, rebuilding, or changing on-disk layout. On success,
 * `out_buffer` receives Rust-owned bytes that must be released with
 * `oneiron_buffer_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_health_json(struct OneironVault *vault,
                                             struct OneironBuffer *out_buffer);

/**
 * Store an entity blob. A bound handle stores it as its caller
 * (`oneiron_vault_bind`).
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_put_entity(struct OneironVault *vault,
                                            const uint8_t *id_ptr,
                                            size_t id_len,
                                            uint32_t entity_type,
                                            int64_t occurred_start,
                                            int64_t occurred_end,
                                            int64_t learned_at,
                                            const uint8_t *data_ptr,
                                            size_t data_len);

/**
 * Store multiple entity blobs in one vault transaction.
 *
 * `entities` may be null only when `entities_len == 0`. Each payload pointer
 * inside the array must be non-null for its byte length. A bound handle
 * stores them as its caller (`oneiron_vault_bind`).
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. A non-null `entities` covers `entities_len` inputs, and
 * each input's `data` covers its own readable bytes, for the whole call.
 */
enum OneironStatus oneiron_vault_batch_put_entities(struct OneironVault *vault,
                                                    const struct OneironEntityInput *entities,
                                                    size_t entities_len);

/**
 * Retrieve an entity blob by ID.
 *
 * Returns `OneironStatus::NotFound` if the entity does not exist. On success,
 * `out_buffer` receives Rust-owned bytes that must be released with
 * `oneiron_buffer_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_get_entity(struct OneironVault *vault,
                                            const uint8_t *id_ptr,
                                            size_t id_len,
                                            struct OneironBuffer *out_buffer);

/**
 * Delete an entity by ID.
 *
 * `out_existed` receives `1` if the entity existed and `0` otherwise. A
 * bound handle deletes as its caller through the `vault.delete` door
 * (`oneiron_vault_bind`), so an id naming no record is `NotFound`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_delete_entity(struct OneironVault *vault,
                                               const uint8_t *id_ptr,
                                               size_t id_len,
                                               uint8_t *out_existed);

/**
 * Check whether an entity exists.
 *
 * `out_exists` receives `1` if the entity exists and `0` otherwise.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_entity_exists(struct OneironVault *vault,
                                               const uint8_t *id_ptr,
                                               size_t id_len,
                                               uint8_t *out_exists);

/**
 * `oneiron_vault_open`, then this install's own machine profile from the
 * vault's host root secret, so the owner's acts carry from it. The profile
 * carries the `device_class` the host declared, set before the vault opens
 * (FIX 3833).
 *
 * `host_root_secret_ptr` and `host_root_secret_len` are the exact bytes of
 * the server's configured `auth_secret`: null with length 0 names none, and
 * the open is `oneiron_vault_open`'s; a non-null empty secret is
 * `InvalidArg`. `initialize_root` is 0 or 1, and 1 needs a secret: it roots
 * the vault under the secret when this open creates its store and its
 * authority log is empty, a new local-origin vault. Never pass 1 for a
 * replica awaiting its root. A secret that cannot profile the install is
 * `EngineError` with `out_vault` left null; the engine logs the reason.
 *
 * `out_wrong_host_root` is the wrong-root fact: set to 1 when the secret
 * is not this vault's settled root, so it went unused, since this install
 * already carried its profile; the vault then opens under its settled
 * root, as before. It is reported, never refused. It is 0 otherwise,
 * with no secret too, and left 0 on any failure.
 *
 * # Safety
 *
 * As `oneiron_vault_open`, and a non-null `host_root_secret_ptr` covers
 * `host_root_secret_len` readable bytes, borrowed for this call only;
 * `out_wrong_host_root` is non-null and writable for the whole call.
 */
enum OneironStatus oneiron_vault_open_with_host_root(const uint8_t *path_ptr,
                                                     size_t path_len,
                                                     size_t dimensions,
                                                     const struct OneironByteSlice *dict_search_paths,
                                                     size_t dict_search_paths_len,
                                                     uint8_t device_class,
                                                     const uint8_t *host_root_secret_ptr,
                                                     size_t host_root_secret_len,
                                                     uint8_t initialize_root,
                                                     struct OneironVault **out_vault,
                                                     uint8_t *out_wrong_host_root);

/**
 * Store a directed edge between two entities. A bound handle stores it as
 * its caller (`oneiron_vault_bind`).
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_put_edge(struct OneironVault *vault,
                                          const uint8_t *src_ptr,
                                          size_t src_len,
                                          uint32_t kind,
                                          const uint8_t *tgt_ptr,
                                          size_t tgt_len,
                                          double weight);

/**
 * Return outbound edges for a source entity.
 *
 * `out_edges` receives a Rust-owned array that must be released with
 * `oneiron_edge_info_array_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_edges_out(struct OneironVault *vault,
                                           const uint8_t *src_ptr,
                                           size_t src_len,
                                           struct OneironEdgeInfoArray *out_edges);

/**
 * Return inbound edges for a target entity.
 *
 * `out_edges` receives a Rust-owned array that must be released with
 * `oneiron_edge_info_array_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_edges_in(struct OneironVault *vault,
                                          const uint8_t *tgt_ptr,
                                          size_t tgt_len,
                                          struct OneironEdgeInfoArray *out_edges);

/**
 * Search for entities by vector similarity.
 *
 * `query_len` must equal the vault dimensions. `out_results` receives a
 * Rust-owned array that must be released with
 * `oneiron_scored_entity_array_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_search_vector(struct OneironVault *vault,
                                               const double *query_ptr,
                                               size_t query_len,
                                               uint32_t limit,
                                               struct OneironScoredEntityArray *out_results);

/**
 * Search for entities by BM25 text matching.
 *
 * `query_len` must be at most 8 KiB. `out_results` receives a Rust-owned
 * array that must be released with `oneiron_scored_entity_array_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_search_text(struct OneironVault *vault,
                                             const uint8_t *query_ptr,
                                             size_t query_len,
                                             uint32_t limit,
                                             struct OneironScoredEntityArray *out_results);

/**
 * Store a vector embedding for an entity.
 *
 * `vector_len` must equal the vault dimensions. A bound handle stores it as
 * its caller (`oneiron_vault_bind`).
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_put_vector(struct OneironVault *vault,
                                            const uint8_t *id_ptr,
                                            size_t id_len,
                                            const double *vector_ptr,
                                            size_t vector_len);

/**
 * Run a context-pack query and return UTF-8 bytes.
 *
 * `query_text_ptr`, `query_vector_ptr`, `format_ptr` and `media_json_ptr`
 * are optional: pass a null pointer with length 0 to omit. If
 * `limit_is_set == 0`, the default limit of 10 is used; otherwise the pack
 * holds up to `limit` items, however many. The returned buffer must be
 * released with `oneiron_buffer_free`.
 *
 * `media_json_ptr` is UTF-8 JSON of the served context pack's media query
 * (OF-370): `{"space": "<ai.embed rung id>@<provider>", "mime": "image/png",
 * "bytes_b64": "<standard base64>", "kinds": ["image"]}`, `kinds` optional.
 * JSON of another shape is `InvalidArg`. This library serves no `ai.embed`
 * rung, so once every input validates a pack naming media is refused
 * `ModelUnavailable` and nothing is packed: the media is never dropped.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_context_pack(struct OneironVault *vault,
                                              const uint8_t *query_text_ptr,
                                              size_t query_text_len,
                                              const double *query_vector_ptr,
                                              size_t query_vector_len,
                                              uint32_t limit,
                                              uint8_t limit_is_set,
                                              const uint8_t *format_ptr,
                                              size_t format_len,
                                              const uint8_t *media_json_ptr,
                                              size_t media_json_len,
                                              struct OneironBuffer *out_buffer);

/**
 * Return the stored entity type for an entity.
 *
 * Returns `OneironStatus::NotFound` if the entity does not exist.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_get_entity_type(struct OneironVault *vault,
                                                 const uint8_t *id_ptr,
                                                 size_t id_len,
                                                 uint32_t *out_entity_type);

/**
 * Return all entity IDs of a given type as packed 16-byte IDs.
 *
 * `out_ids.len` is the byte length and is always a multiple of 16 on success.
 * Release the buffer with `oneiron_buffer_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_entities_by_type(struct OneironVault *vault,
                                                  uint32_t entity_type,
                                                  struct OneironBuffer *out_ids);

/**
 * Return outbound edge targets filtered by kind and optional target type.
 *
 * If `has_target_type == 0`, `target_type` is ignored. `out_ids.len` is the
 * byte length and is always a multiple of 16 on success. Release the buffer
 * with `oneiron_buffer_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_targets(struct OneironVault *vault,
                                         const uint8_t *src_ptr,
                                         size_t src_len,
                                         uint32_t kind,
                                         uint32_t target_type,
                                         uint8_t has_target_type,
                                         struct OneironBuffer *out_ids);

/**
 * Return inbound edge sources filtered by kind and optional source type.
 *
 * If `has_source_type == 0`, `source_type` is ignored. `out_ids.len` is the
 * byte length and is always a multiple of 16 on success. Release the buffer
 * with `oneiron_buffer_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_sources(struct OneironVault *vault,
                                         const uint8_t *tgt_ptr,
                                         size_t tgt_len,
                                         uint32_t kind,
                                         uint32_t source_type,
                                         uint8_t has_source_type,
                                         struct OneironBuffer *out_ids);

/**
 * Return subtree descendants via `ChildOf` traversal.
 *
 * `out_entries` receives a Rust-owned array that must be released with
 * `oneiron_subtree_entry_array_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_subtree(struct OneironVault *vault,
                                         const uint8_t *root_ptr,
                                         size_t root_len,
                                         uint32_t max_depth,
                                         struct OneironSubtreeEntryArray *out_entries);

/**
 * Walk ancestors via `ChildOf` edges as packed 16-byte IDs.
 *
 * `out_ids.len` is the byte length and is always a multiple of 16 on success.
 * Release the buffer with `oneiron_buffer_free`.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_ancestors(struct OneironVault *vault,
                                           const uint8_t *node_ptr,
                                           size_t node_len,
                                           struct OneironBuffer *out_ids);

/**
 * Check whether making `target` a parent of `node` would create a cycle.
 *
 * `out_would_cycle` receives `1` for true and `0` for false.
 *
 * # Safety
 *
 * `vault` is null or a live handle from `oneiron_vault_open`, not freed
 * during the call. Each non-null input pointer covers its length in readable
 * values and each non-null out pointer is writable, for the whole call.
 */
enum OneironStatus oneiron_vault_would_create_cycle(struct OneironVault *vault,
                                                    const uint8_t *node_ptr,
                                                    size_t node_len,
                                                    const uint8_t *target_ptr,
                                                    size_t target_len,
                                                    uint8_t *out_would_cycle);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* ONEIRON_FFI_H */
