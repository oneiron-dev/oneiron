/* Plain JavaScript hook guest. Two imports: a scoped read and the one outcome
   return. No quickjs-libc, clock, random or WASI capability is linked. */
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include "quickjs.h"
#include "hook.h"
#include "hook_bootstrap.h"

#define MESSAGE_LIMIT (1024 * 1024)

/* The clock is the input's `now` (Unix ms), frozen for the run. It reads 0
   while the context initializes, so no ambient time seeds anything. */
static uint64_t frozen_now_ms;

int oneiron_gettimeofday(struct timeval *tv, void *zone) {
    (void)zone;
    tv->tv_sec = frozen_now_ms / 1000;
    tv->tv_usec = (frozen_now_ms % 1000) * 1000;
    return 0;
}

static void error_text(JSContext *ctx, hook_string_t *error) {
    JSValue exception = JS_GetException(ctx);
    const char *text = JS_ToCString(ctx, exception);
    hook_string_dup(error, text ? text : "guest exception");
    if (text) JS_FreeCString(ctx, text);
    JS_FreeValue(ctx, exception);
}

/* One string argument as a borrowed host string, bounded by a message. */
static bool host_text(JSContext *ctx, int argc, JSValueConst *argv, const char **text, size_t *length) {
    if (argc != 1 || !JS_IsString(argv[0])) {
        JS_ThrowTypeError(ctx, "invalid_host_argument");
        return false;
    }
    *text = JS_ToCStringLen(ctx, length, argv[0]);
    if (!*text) return false;
    if (*length > MESSAGE_LIMIT) {
        JS_FreeCString(ctx, *text);
        JS_ThrowTypeError(ctx, "host_argument_over_budget");
        return false;
    }
    return true;
}

static JSValue throw_host_error(JSContext *ctx, hook_string_t *error) {
    JSValue thrown = JS_NewStringLen(ctx, (const char *)error->ptr, error->len);
    hook_string_free(error);
    return JS_Throw(ctx, thrown);
}

static JSValue call_scoped_read(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    (void)this_val;
    const char *text;
    size_t length;
    if (!host_text(ctx, argc, argv, &text, &length)) return JS_EXCEPTION;
    hook_string_t request = {(uint8_t *)text, length};
    hook_string_t result = {0};
    hook_string_t error = {0};
    bool ok = hook_scoped_read(&request, &result, &error);
    JS_FreeCString(ctx, text);
    if (!ok) return throw_host_error(ctx, &error);
    JSValue value = JS_NewStringLen(ctx, (const char *)result.ptr, result.len);
    hook_string_free(&result);
    return value;
}

static JSValue call_ai_verdict(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    (void)this_val;
    const char *text;
    size_t length;
    if (!host_text(ctx, argc, argv, &text, &length)) return JS_EXCEPTION;
    hook_string_t request = {(uint8_t *)text, length};
    hook_string_t result = {0};
    hook_string_t error = {0};
    bool ok = hook_ai_verdict(&request, &result, &error);
    JS_FreeCString(ctx, text);
    if (!ok) return throw_host_error(ctx, &error);
    JSValue value = JS_NewStringLen(ctx, (const char *)result.ptr, result.len);
    hook_string_free(&result);
    return value;
}

static JSValue call_emit_outcome(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    (void)this_val;
    const char *text;
    size_t length;
    if (!host_text(ctx, argc, argv, &text, &length)) return JS_EXCEPTION;
    hook_string_t outcome = {(uint8_t *)text, length};
    hook_string_t error = {0};
    bool ok = hook_emit_outcome(&outcome, &error);
    JS_FreeCString(ctx, text);
    if (!ok) return throw_host_error(ctx, &error);
    return JS_UNDEFINED;
}

static JSValue make_abi(JSContext *ctx) {
    JSValue abi = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, abi, "scoped-read", JS_NewCFunction(ctx, call_scoped_read, "scoped-read", 1));
    JS_SetPropertyStr(ctx, abi, "ai-verdict", JS_NewCFunction(ctx, call_ai_verdict, "ai-verdict", 1));
    JS_SetPropertyStr(ctx, abi, "emit-outcome", JS_NewCFunction(ctx, call_emit_outcome, "emit-outcome", 1));
    return abi;
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

/* A NUL-terminated copy, as QuickJS's parsers require. */
static char *terminated(const char *prefix, const hook_string_t *text, const char *suffix, size_t *length) {
    size_t head = strlen(prefix), tail = strlen(suffix);
    *length = head + text->len + tail;
    char *out = malloc(*length + 1);
    if (!out) return NULL;
    memcpy(out, prefix, head);
    memcpy(out + head, text->ptr, text->len);
    memcpy(out + head + text->len, suffix, tail + 1);
    return out;
}

bool exports_hook_run_hook(hook_string_t *source, hook_string_t *input_json, hook_string_t *error) {
    if (source->len > MESSAGE_LIMIT || input_json->len > MESSAGE_LIMIT) {
        hook_string_dup(error, "hook body or input exceeds message budget");
        hook_string_free(source); hook_string_free(input_json);
        return false;
    }
    frozen_now_ms = 0;
    JSRuntime *runtime = JS_NewRuntime2(&allocator, NULL);
    if (!runtime) {
        hook_string_dup(error, "runtime allocation failed");
        hook_string_free(source); hook_string_free(input_json);
        return false;
    }
    uint32_t interrupt_ticks = 1000000;
    JS_SetInterruptHandler(runtime, interrupt, &interrupt_ticks);
    JS_SetMemoryLimit(runtime, 24 * 1024 * 1024);
    JS_SetMaxStackSize(runtime, 256 * 1024);
    JSContext *ctx = JS_NewContext(runtime);
    if (!ctx) {
        JS_FreeRuntime(runtime);
        hook_string_dup(error, "context allocation failed");
        hook_string_free(source); hook_string_free(input_json);
        return false;
    }
    JSValue input = JS_UNDEFINED, setup = JS_UNDEFINED, complete = JS_UNDEFINED;
    JSValue execution = JS_UNDEFINED, result = JS_UNDEFINED, done = JS_UNDEFINED;
    bool ok = false;
    size_t length;
    char *text = terminated("", input_json, "", &length);
    if (!text) { JS_ThrowOutOfMemory(ctx); goto failed; }
    input = JS_ParseJSON(ctx, text, length, "hook-input.json");
    free(text);
    if (JS_IsException(input)) goto failed;
    double now_ms = -1;
    if (JS_IsObject(input) && JS_IsArray(ctx, input) == 0) {
        JSValue now = JS_GetPropertyStr(ctx, input, "now");
        if (!JS_IsNumber(now) || JS_ToFloat64(ctx, &now_ms, now) < 0) now_ms = -1;
        JS_FreeValue(ctx, now);
    }
    if (!isfinite(now_ms) || now_ms < 0 || now_ms > 9007199254740991.0 || floor(now_ms) != now_ms) {
        JS_ThrowTypeError(ctx, "invalid_hook_input"); goto failed;
    }
    frozen_now_ms = (uint64_t)now_ms;
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "__oneironHookAbi", make_abi(ctx));
    JS_FreeValue(ctx, global);
    setup = JS_Eval(ctx, hook_bootstrap, sizeof(hook_bootstrap) - 1, "oneiron-hook-bootstrap.js", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(setup)) goto failed;
    complete = JS_Call(ctx, setup, JS_UNDEFINED, 1, (JSValueConst *)&input);
    if (JS_IsException(complete)) goto failed;
    text = terminated("(async () => {\n", source, "\n})()", &length);
    if (!text) { JS_ThrowOutOfMemory(ctx); goto failed; }
    execution = JS_Eval(ctx, text, length, "hook.js", JS_EVAL_TYPE_GLOBAL);
    free(text);
    if (JS_IsException(execution)) goto failed;
    JSContext *job_context;
    int job;
    while ((job = JS_ExecutePendingJob(runtime, &job_context)) > 0) {}
    if (job < 0) goto failed;
    if (JS_PromiseState(ctx, execution) == JS_PROMISE_REJECTED) {
        JS_Throw(ctx, JS_PromiseResult(ctx, execution)); goto failed;
    }
    if (JS_PromiseState(ctx, execution) != JS_PROMISE_FULFILLED) {
        JS_ThrowTypeError(ctx, "unresolved hook promise has no host continuation"); goto failed;
    }
    result = JS_PromiseResult(ctx, execution);
    done = JS_Call(ctx, complete, JS_UNDEFINED, 1, (JSValueConst *)&result);
    if (JS_IsException(done)) goto failed;
    ok = true;
    goto cleanup;
failed:
    ok = false;
    error_text(ctx, error);
cleanup:
    JS_FreeValue(ctx, done); JS_FreeValue(ctx, result); JS_FreeValue(ctx, execution);
    JS_FreeValue(ctx, complete); JS_FreeValue(ctx, setup); JS_FreeValue(ctx, input);
    JS_FreeContext(ctx); JS_FreeRuntime(runtime);
    hook_string_free(source); hook_string_free(input_json);
    return ok;
}
