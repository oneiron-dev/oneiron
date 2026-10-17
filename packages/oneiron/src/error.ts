/**
 * The one error type this package throws (ONE-1441 §Typed error contract).
 *
 * The native boundary serializes the engine's `{code, message, suggestions}`
 * triple into the thrown error's message, so this module's whole job is to
 * turn that string back into a typed object. It does not invent codes, edit
 * messages, or drop suggestions: a caller matching on `code` is matching on
 * the engine's own vocabulary, including codes newer than this package.
 */

/** The serialized shape the native boundary hands back. */
type NativeErrorPayload = {
  code: string
  message: string
  suggestions: string[]
  attempted?: string
  replacement?: string
  schemaRef?: string
  hook?: unknown
}

/** A `WRONG_ROOT` refusal's correction: call `replacement`, never `attempted`. */
export type WrongRoot = {
  readonly attempted: string
  readonly replacement: string
  readonly schemaRef: string
}

/**
 * A verb hook's stop behind a refusal (ARCH-0080 §3), as the engine's
 * MemoryError names it in `hook`. On a `PENDING_ASK` it is `pending`: the
 * invocation the stopped call ran under and the ask's handle, which
 * `Oneiron.retry` resends under.
 */
export type HookStop =
  | {readonly status: "skipped"; readonly hook: string; readonly reason: string}
  | {readonly status: "pending"; readonly invocation: string; readonly ask: string}
  | {readonly status: "hidden"; readonly hook: string}
  | {readonly status: "completed"; readonly invocation: string; readonly result: unknown}
  | {readonly status: "completed_with_error"; readonly invocation: string; readonly code: string; readonly message: string}

/** Every constructor and verb failure reaches user code as this. */
export class OneironError extends Error {
  /** The engine's stable code string, carried verbatim. */
  readonly code: string

  /** Remediation hints; never empty. */
  readonly suggestions: readonly string[]

  /** Present on a `WRONG_ROOT` refusal: the name written and the verb meant. */
  readonly wrongRoot?: WrongRoot

  /**
   * Present when a verb hook stopped the call. On `PENDING_ASK` it names the
   * call's invocation; pass this error to `Oneiron.retry` to resend the call
   * under it.
   */
  readonly hook?: HookStop

  constructor(code: string, message: string, suggestions: readonly string[], wrongRoot?: WrongRoot, hook?: HookStop) {
    super(message)
    this.name = "OneironError"
    this.code = code
    this.suggestions = Object.freeze([...suggestions])
    if (wrongRoot) this.wrongRoot = Object.freeze({...wrongRoot})
    if (hook) this.hook = Object.freeze({...hook})
  }
}

/**
 * Narrows the payload's `hook` to a stop: an object with a string `status`.
 * The engine owns the variants; this only refuses what is not one.
 */
function hookStop(value: unknown): HookStop | undefined {
  if (typeof value !== "object" || value === null) return undefined
  return typeof (value as Record<string, unknown>).status === "string" ? (value as HookStop) : undefined
}

/**
 * Narrows an unknown value to the native payload shape.
 *
 * Structural rather than trusting: the payload crosses as text, and text that
 * parsed as JSON is not yet known to be the contract.
 */
function isNativePayload(value: unknown): value is NativeErrorPayload {
  if (typeof value !== "object" || value === null) return false
  const candidate = value as Record<string, unknown>
  return (
    typeof candidate.code === "string" &&
    candidate.code.length > 0 &&
    typeof candidate.message === "string" &&
    Array.isArray(candidate.suggestions) &&
    candidate.suggestions.every((entry) => typeof entry === "string")
  )
}

/**
 * Translates anything thrown by the native boundary into an `OneironError`.
 *
 * A payload that does not parse becomes a typed `INTERNAL_SERVER_ERROR` rather
 * than escaping as a bare `Error`. That case is a bug in this package or the
 * boundary below it, and the caller should still be able to `catch (e) { if (e
 * instanceof OneironError) ... }` without a second untyped path to handle.
 */
export function translateNativeError(error: unknown): OneironError {
  if (error instanceof OneironError) return error

  const raw = error instanceof Error ? error.message : String(error)
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    parsed = undefined
  }

  if (isNativePayload(parsed)) {
    const suggestions =
      parsed.suggestions.length > 0
        ? parsed.suggestions
        : ["Retry the call, and check the Oneiron logs for this operation."]
    const {attempted, replacement, schemaRef} = parsed
    const wrongRoot =
      typeof attempted === "string" && typeof replacement === "string" && typeof schemaRef === "string"
        ? {attempted, replacement, schemaRef}
        : undefined
    return new OneironError(parsed.code, parsed.message, suggestions, wrongRoot, hookStop(parsed.hook))
  }

  return new OneironError("INTERNAL_SERVER_ERROR", raw, [
    "This is an Oneiron SDK bug; please report it with the message above.",
  ])
}
