/* Plain JavaScript interpreter guest. No quickjs-libc or WASI capability is linked. */
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <float.h>
#include <math.h>
#include <sys/time.h>
#include "quickjs.h"
#include "guest.h"
#include "bootstrap.h"

#define MESSAGE_LIMIT (1024 * 1024)

static bool bad_value(JSContext *ctx) {
    JS_ThrowTypeError(ctx, "invalid typed host argument");
    return false;
}

#include "bridge.h"

/* The upstream Date and initial PRNG clock both enter the typed host import.
   Math.random is replaced by host bytes before any guest source executes. */
int oneiron_gettimeofday(struct timeval *tv, void *zone) {
    (void)zone;
    uint64_t now = guest_clock_now_unix_ms();
    tv->tv_sec = now / 1000;
    tv->tv_usec = (now % 1000) * 1000;
    return 0;
}

static void error_text(JSContext *ctx, guest_string_t *error) {
    JSValue exception = JS_GetException(ctx);
    const char *text = JS_ToCString(ctx, exception);
    guest_string_dup(error, text ? text : "guest exception");
    if (text) JS_FreeCString(ctx, text);
    JS_FreeValue(ctx, exception);
}

static bool proposal_path_allowed(const guest_string_t *path) {
    const size_t outputs = sizeof("/mnt/outputs/") - 1;
    const size_t workspace = sizeof("/mnt/workspace/") - 1;
    if (!path->ptr || path->len > 4096 ||
        !((path->len > outputs && !memcmp(path->ptr, "/mnt/outputs/", outputs)) ||
          (path->len > workspace && !memcmp(path->ptr, "/mnt/workspace/", workspace)))) return false;
    size_t start = 1;
    for (size_t i = 1; i <= path->len; ++i) {
        if (i < path->len && (path->ptr[i] == '\\' || path->ptr[i] == 0)) return false;
        if (i == path->len || path->ptr[i] == '/') {
            size_t size = i - start;
            if (!size || (size == 1 && path->ptr[start] == '.') ||
                (size == 2 && path->ptr[start] == '.' && path->ptr[start + 1] == '.')) return false;
            start = i + 1;
        }
    }
    return true;
}

static bool proposals_from_js(JSContext *ctx, JSValueConst value, guest_step_result_t *out) {
    JSValue length_value = JS_GetPropertyStr(ctx, value, "length");
    uint32_t length;
    int result = JS_ToUint32(ctx, &length, length_value);
    JS_FreeValue(ctx, length_value);
    if (result < 0 || length > 256) return bad_value(ctx);
    out->proposals.ptr = calloc(length, sizeof(*out->proposals.ptr));
    if (length && !out->proposals.ptr) return bad_value(ctx);
    out->proposals.len = length;
    for (uint32_t i = 0; i < length; ++i) {
        JSValue item = JS_GetPropertyUint32(ctx, value, i);
        JSValue tag = JS_GetPropertyStr(ctx, item, "tag");
        JSValue val = JS_GetPropertyStr(ctx, item, "val");
        const char *name = JS_ToCString(ctx, tag);
        guest_proposal_delta_t *delta = &out->proposals.ptr[i];
        bool ok = false;
        if (name && !strcmp(name, "file-write")) {
            delta->tag = GUEST_PROPOSAL_DELTA_FILE_WRITE;
            ok = from_file_proposal(ctx, val, &delta->val.file_write);
            if (ok && !proposal_path_allowed(&delta->val.file_write.path)) ok = bad_value(ctx);
        } else if (name && !strcmp(name, "claim-candidate")) {
            delta->tag = GUEST_PROPOSAL_DELTA_CLAIM_CANDIDATE;
            ok = from_claim_input(ctx, val, &delta->val.claim_candidate);
        } else bad_value(ctx);
        if (name) JS_FreeCString(ctx, name);
        JS_FreeValue(ctx, tag); JS_FreeValue(ctx, val); JS_FreeValue(ctx, item);
        if (!ok) return false;
    }
    return true;
}

typedef union AllocationHeader { size_t size; max_align_t alignment; } AllocationHeader;
static void *guest_alloc(JSMallocState *state, size_t size) {
    if (size > SIZE_MAX - sizeof(AllocationHeader) || (state->malloc_size > state->malloc_limit || size > state->malloc_limit - state->malloc_size)) return NULL;
    AllocationHeader *header = malloc(sizeof(*header) + size);
    if (!header) return NULL;
    header->size = size; state->malloc_size += size; state->malloc_count++;
    return header + 1;
}
static void guest_free(JSMallocState *state, void *ptr) {
    if (!ptr) return;
    AllocationHeader *header = (AllocationHeader *)ptr - 1;
    state->malloc_size -= header->size; state->malloc_count--; free(header);
}
static size_t guest_size(const void *ptr) {
    return ptr ? ((const AllocationHeader *)ptr - 1)->size : 0;
}
static void *guest_realloc(JSMallocState *state, void *ptr, size_t size) {
    if (!ptr) return size ? guest_alloc(state, size) : NULL;
    if (!size) { guest_free(state, ptr); return NULL; }
    size_t old = guest_size(ptr);
    if (size > SIZE_MAX - sizeof(AllocationHeader) || (size > old && (state->malloc_size > state->malloc_limit || size - old > state->malloc_limit - state->malloc_size))) return NULL;
    AllocationHeader *header = realloc((AllocationHeader *)ptr - 1, sizeof(*header) + size);
    if (!header) return NULL;
    header->size = size; state->malloc_size = state->malloc_size - old + size;
    return header + 1;
}
static const JSMallocFunctions allocator = {guest_alloc, guest_free, guest_realloc, guest_size};
static int interrupt(JSRuntime *runtime, void *opaque) {
    (void)runtime;
    uint32_t *ticks = opaque;
    if (!*ticks) return 1;
    --*ticks; return 0;
}

bool exports_guest_run_step(guest_string_t *source, guest_step_result_t *out, guest_string_t *error) {
    memset(out, 0, sizeof(*out));
    if (source->len > MESSAGE_LIMIT) {
        guest_string_dup(error, "script exceeds message budget");
        guest_string_free(source);
        return false;
    }
    JSRuntime *runtime = JS_NewRuntime2(&allocator, NULL);
    if (!runtime) { guest_string_dup(error, "runtime allocation failed"); guest_string_free(source); return false; }
    uint32_t interrupt_ticks = 1000000;
    JS_SetInterruptHandler(runtime, interrupt, &interrupt_ticks);
    JS_SetMemoryLimit(runtime, 24 * 1024 * 1024);
    JS_SetMaxStackSize(runtime, 256 * 1024);
    JSContext *ctx = JS_NewContext(runtime);
    if (!ctx) { JS_FreeRuntime(runtime); guest_string_dup(error, "context allocation failed"); guest_string_free(source); return false; }
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "__oneironAbi", make_abi(ctx));
    JS_FreeValue(ctx, global);
    JSValue collect = JS_Eval(ctx, bootstrap, sizeof(bootstrap) - 1, "oneiron-bootstrap.js", JS_EVAL_TYPE_GLOBAL);
    JSValue execution = JS_UNDEFINED;
    JSValue output = JS_UNDEFINED;
    bool ok = false;
    if (JS_IsException(collect)) goto failed;
    const char *prefix = "(async () => {\n";
    const char *suffix = "\n})()";
    size_t length = strlen(prefix) + source->len + strlen(suffix);
    char *program = malloc(length + 1);
    if (!program) { bad_value(ctx); goto failed; }
    memcpy(program, prefix, strlen(prefix));
    memcpy(program + strlen(prefix), source->ptr, source->len);
    memcpy(program + strlen(prefix) + source->len, suffix, strlen(suffix) + 1);
    execution = JS_Eval(ctx, program, length, "code-run.js", JS_EVAL_TYPE_GLOBAL);
    free(program);
    if (JS_IsException(execution)) goto failed;
    JSContext *job_context;
    int job;
    while ((job = JS_ExecutePendingJob(runtime, &job_context)) > 0) {}
    if (job < 0) goto failed;
    if (JS_PromiseState(ctx, execution) == JS_PROMISE_REJECTED) {
        JS_Throw(ctx, JS_PromiseResult(ctx, execution)); goto failed;
    }
    if (JS_PromiseState(ctx, execution) == JS_PROMISE_PENDING) {
        JS_ThrowTypeError(ctx, "unresolved guest promise has no host continuation"); goto failed;
    }
    output = JS_Call(ctx, collect, JS_UNDEFINED, 0, NULL);
    if (JS_IsException(output)) goto failed;
    JSValue result = JS_GetPropertyStr(ctx, output, "resultJson");
    ok = from_string(ctx, result, &out->result_json);
    JS_FreeValue(ctx, result);
    if (!ok) goto failed;
    JSValue proposals = JS_GetPropertyStr(ctx, output, "proposals");
    ok = proposals_from_js(ctx, proposals, out);
    JS_FreeValue(ctx, proposals);
    if (!ok) goto failed;
    goto cleanup;
failed:
    ok = false;
    error_text(ctx, error);
    guest_step_result_free(out);
    memset(out, 0, sizeof(*out));
cleanup:
    JS_FreeValue(ctx, output); JS_FreeValue(ctx, execution); JS_FreeValue(ctx, collect);
    JS_FreeContext(ctx); JS_FreeRuntime(runtime);
    guest_string_free(source);
    return ok;
}
