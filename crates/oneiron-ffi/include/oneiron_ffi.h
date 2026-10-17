/*
 * Oneiron C ABI for iOS and macOS on-device vault access.
 *
 * Ownership: variable-size outputs are allocated by Rust and returned through
 * OneironBuffer or typed array structs. Release them with the paired
 * oneiron_*_free function from this header. Do not pass Rust-owned pointers
 * to free(), and do not free the same value twice.
 *
 * Boundary validation: EntityId inputs must be exactly 16 bytes. Text queries
 * are capped at 8 KiB, search limits at 1000, and dimensions at 16384.
 *
 * Intentionally absent: start_sync and stop_sync are not exported while sync
 * remains disabled pre-launch.
 *
 * Embedded engine (OF-237): oneiron_engine_start runs the full server in this
 * process with the app's OneironAppHost callbacks; oneiron_engine_request
 * sends it one buffered HTTP/1.1 request, oneiron_engine_vault shares its
 * open vault with the storage functions, and oneiron_engine_free stops it in
 * order. oneiron_engine_connection_open opens a connection the app holds
 * (HTTP/1.1 with upgrades, so `/ws`), with _send, _receive, _close and _free.
 * Engine calls block: make them from app threads, never from a
 * callback. The library exports these only when built with the `engine`
 * cargo feature.
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
} OneironStatus;

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
 * Opaque vault handle returned by `oneiron_vault_open`.
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
 * engine serving.
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
 * Store an entity blob.
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
 * inside the array must be non-null for its byte length.
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
 * `out_existed` receives `1` if the entity existed and `0` otherwise.
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
 * Store a directed edge between two entities.
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
 * `vector_len` must equal the vault dimensions.
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
 * `query_text_ptr`, `query_vector_ptr`, and `format_ptr` are optional: pass a
 * null pointer with length 0 to omit. If `limit_is_set == 0`, the default
 * limit of 10 is used; otherwise `limit` must be at most 1000. The returned
 * buffer must be released with `oneiron_buffer_free`.
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
