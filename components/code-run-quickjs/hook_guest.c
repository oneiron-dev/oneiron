/* Plain JavaScript hook guest. Three imports: a scoped read, ai.verdict and
   the one outcome return. No quickjs-libc, clock, random or WASI capability
   is linked. */
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

/* Where a thrown Error says it was thrown in the hook body (FIX 9208), as
   the code-mode guest finds it. Only an Error's own data properties are
   read, never a getter, so no guest code runs here; a thrown primitive has
   no position. A parse error names hook.js in fileName/lineNumber/
   columnNumber; a runtime Error names it in the first stack frame that ends
   "(hook.js:L:C)". The line is in hook.js, which puts one envelope line
   first. */
static bool own_data_property(JSContext *ctx, JSValueConst obj, const char *name, JSValue *value) {
    JSPropertyDescriptor desc;
    JSAtom atom = JS_NewAtom(ctx, name);
    if (atom == JS_ATOM_NULL) { JS_FreeValue(ctx, JS_GetException(ctx)); return false; }
    int found = JS_GetOwnProperty(ctx, &desc, obj, atom);
    JS_FreeAtom(ctx, atom);
    if (found < 0) JS_FreeValue(ctx, JS_GetException(ctx));
    if (found <= 0) return false;
    JS_FreeValue(ctx, desc.getter);
    JS_FreeValue(ctx, desc.setter);
    if (desc.flags & JS_PROP_GETSET) { JS_FreeValue(ctx, desc.value); return false; }
    *value = desc.value;
    return true;
}

static bool own_int_property(JSContext *ctx, JSValueConst obj, const char *name, int32_t *out) {
    JSValue value;
    if (!own_data_property(ctx, obj, name, &value)) return false;
    bool ok = JS_VALUE_GET_TAG(value) == JS_TAG_INT;
    if (ok) *out = JS_VALUE_GET_INT(value);
    JS_FreeValue(ctx, value);
    return ok;
}

static bool parse_position(const char *text, int32_t *line, int32_t *column) {
    int64_t parts[2] = {0, 0};
    for (int part = 0; part < 2; ++part) {
        if (*text < '0' || *text > '9') return false;
        while (*text >= '0' && *text <= '9') {
            parts[part] = parts[part] * 10 + (*text++ - '0');
            if (parts[part] > INT32_MAX) return false;
        }
        if (part == 0 && *text++ != ':') return false;
    }
    if (*text != ')' && *text != '\0' && *text != '\n') return false;
    *line = (int32_t)parts[0];
    *column = (int32_t)parts[1];
    return true;
}

static bool stack_position(const char *stack, int32_t *line, int32_t *column) {
    static const char frame[] = "(hook.js:";
    for (const char *start = stack; *start; ) {
        const char *end = strchr(start, '\n');
        if (!end) end = start + strlen(start);
        const char *open = NULL;
        for (const char *at = start; at < end; ++at) if (*at == '(') open = at;
        if (open && end > open && end[-1] == ')' &&
            !strncmp(open, frame, sizeof(frame) - 1) &&
            parse_position(open + sizeof(frame) - 1, line, column)) return true;
        start = *end ? end + 1 : end;
    }
    return false;
}

static bool exception_position(JSContext *ctx, JSValueConst exception, int32_t *line, int32_t *column) {
    if (!JS_IsError(ctx, exception)) return false;
    JSValue file;
    if (own_data_property(ctx, exception, "fileName", &file)) {
        const char *name = JS_IsString(file) ? JS_ToCString(ctx, file) : NULL;
        bool ours = name && !strcmp(name, "hook.js");
        if (name) JS_FreeCString(ctx, name);
        JS_FreeValue(ctx, file);
        if (ours && own_int_property(ctx, exception, "lineNumber", line) &&
            own_int_property(ctx, exception, "columnNumber", column)) return true;
    }
    JSValue stack;
    if (!own_data_property(ctx, exception, "stack", &stack)) return false;
    const char *text = JS_IsString(stack) ? JS_ToCString(ctx, stack) : NULL;
    bool found = text && stack_position(text, line, column);
    if (text) JS_FreeCString(ctx, text);
    JS_FreeValue(ctx, stack);
    return found;
}

static char *decimal(char *out, int32_t value) {
    char digits[12];
    int count = 0;
    do { digits[count++] = (char)('0' + value % 10); value /= 10; } while (value > 0);
    while (count) *out++ = digits[--count];
    return out;
}

/* The body's error: one header line the host strips, then the exception's
   own text exactly as before. The header is "oneiron-guest-error/1 L:C",
   the throw's line and column in the body the guest ran, or
   "oneiron-guest-error/1 -" where there is none. */
static void error_text(JSContext *ctx, hook_string_t *error) {
    static const char header[] = "oneiron-guest-error/1 ";
    JSValue exception = JS_GetException(ctx);
    const char *text = JS_ToCString(ctx, exception);
    const char *body = text ? text : "guest exception";
    int32_t line = 0, column = 0;
    bool placed = exception_position(ctx, exception, &line, &column) && line > 1 && column > 0;
    size_t length = strlen(body);
    char *framed = malloc(sizeof(header) + 24 + length);
    if (framed) {
        char *at = framed;
        memcpy(at, header, sizeof(header) - 1);
        at += sizeof(header) - 1;
        if (placed) {
            at = decimal(at, line - 1);
            *at++ = ':';
            at = decimal(at, column);
        } else *at++ = '-';
        *at++ = '\n';
        memcpy(at, body, length + 1);
        hook_string_dup(error, framed);
        free(framed);
    } else hook_string_dup(error, body);
    if (text) JS_FreeCString(ctx, text);
    JS_FreeValue(ctx, exception);
}

/* One string argument as a borrowed host string. A `bounded` one (an
   ai.verdict request) is held to a message; a scoped read's request and the
   emitted outcome go to the host whole (FIX 9233, 10074, 10086), held only
   to the interpreter's own memory. */
static bool host_text(JSContext *ctx, int argc, JSValueConst *argv, const char **text, size_t *length, bool bounded) {
    if (argc != 1 || !JS_IsString(argv[0])) {
        JS_ThrowTypeError(ctx, "invalid_host_argument");
        return false;
    }
    *text = JS_ToCStringLen(ctx, length, argv[0]);
    if (!*text) return false;
    if (bounded && *length > MESSAGE_LIMIT) {
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
    if (!host_text(ctx, argc, argv, &text, &length, false)) return JS_EXCEPTION;
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
    if (!host_text(ctx, argc, argv, &text, &length, true)) return JS_EXCEPTION;
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
    if (!host_text(ctx, argc, argv, &text, &length, false)) return JS_EXCEPTION;
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
