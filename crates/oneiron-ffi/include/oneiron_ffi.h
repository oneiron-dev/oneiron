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
 * remains disabled pre-launch. batch_put_entities is deferred until its C
 * array-of-structs ownership contract is designed.
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
 * Opaque vault handle returned by `oneiron_vault_open`.
 *
 * Release the handle with `oneiron_vault_free` exactly once.
 */
typedef struct OneironVault OneironVault;

/**
 * Rust-owned byte buffer returned by variable-size byte outputs.
 *
 * The caller must release non-empty buffers with `oneiron_buffer_free`. The
 * caller must not pass `ptr` to `free()` and must not call the free function
 * more than once for the same buffer.
 */
typedef struct OneironBuffer {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} OneironBuffer;

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
 * Borrowed byte/string input for arrays such as `dict_search_paths`.
 *
 * Each element is caller-owned and is only borrowed for the duration of the
 * call. String uses are UTF-8 validated by the receiving function.
 */
typedef struct OneironByteSlice {
  const uint8_t *ptr;
  size_t len;
} OneironByteSlice;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Free a Rust-owned byte buffer returned by this crate.
 *
 * Passing a null, zero-length buffer is accepted. Passing a mutated buffer,
 * an already-freed buffer, or memory allocated outside this crate is undefined
 * behavior by the C ABI contract.
 */
enum OneironStatus oneiron_buffer_free(struct OneironBuffer buffer);

/**
 * Free a Rust-owned edge array returned by this crate.
 */
enum OneironStatus oneiron_edge_info_array_free(struct OneironEdgeInfoArray array);

/**
 * Free a Rust-owned scored entity array returned by this crate.
 */
enum OneironStatus oneiron_scored_entity_array_free(struct OneironScoredEntityArray array);

/**
 * Free a Rust-owned subtree entry array returned by this crate.
 */
enum OneironStatus oneiron_subtree_entry_array_free(struct OneironSubtreeEntryArray array);

/**
 * Open or create a vault using `VaultConfig::device()`.
 *
 * `dimensions == 0` keeps the device preset default. `dict_search_paths` may
 * be null only when `dict_search_paths_len == 0`; otherwise it must point to
 * an array of UTF-8 `OneironByteSlice` values. On success `out_vault` receives
 * an opaque handle that must be released exactly once with `oneiron_vault_free`.
 */
enum OneironStatus oneiron_vault_open(const uint8_t *path_ptr,
                                      size_t path_len,
                                      size_t dimensions,
                                      const struct OneironByteSlice *dict_search_paths,
                                      size_t dict_search_paths_len,
                                      struct OneironVault **out_vault);

/**
 * Free an opaque vault handle returned by `oneiron_vault_open`.
 */
enum OneironStatus oneiron_vault_free(struct OneironVault *vault);

/**
 * Store an entity blob.
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
 * Retrieve an entity blob by ID.
 *
 * Returns `OneironStatus::NotFound` if the entity does not exist. On success,
 * `out_buffer` receives Rust-owned bytes that must be released with
 * `oneiron_buffer_free`.
 */
enum OneironStatus oneiron_vault_get_entity(struct OneironVault *vault,
                                            const uint8_t *id_ptr,
                                            size_t id_len,
                                            struct OneironBuffer *out_buffer);

/**
 * Delete an entity by ID.
 *
 * `out_existed` receives `1` if the entity existed and `0` otherwise.
 */
enum OneironStatus oneiron_vault_delete_entity(struct OneironVault *vault,
                                               const uint8_t *id_ptr,
                                               size_t id_len,
                                               uint8_t *out_existed);

/**
 * Check whether an entity exists.
 *
 * `out_exists` receives `1` if the entity exists and `0` otherwise.
 */
enum OneironStatus oneiron_vault_entity_exists(struct OneironVault *vault,
                                               const uint8_t *id_ptr,
                                               size_t id_len,
                                               uint8_t *out_exists);

/**
 * Store a directed edge between two entities.
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
 */
enum OneironStatus oneiron_vault_ancestors(struct OneironVault *vault,
                                           const uint8_t *node_ptr,
                                           size_t node_len,
                                           struct OneironBuffer *out_ids);

/**
 * Check whether making `target` a parent of `node` would create a cycle.
 *
 * `out_would_cycle` receives `1` for true and `0` for false.
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
