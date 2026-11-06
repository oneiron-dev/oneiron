/**
 * Public shared invitation and shared-env holders.
 *
 * Each holder is a plain interface closed over the ORIGINAL native value: no
 * second store, no identifier lookup, no reconstruction from JSON, and no
 * public native accessor. Factories capture the native object directly in
 * their method closures; the module-private symbols exist only so the engine
 * can forward the SAME acceptance to native bootstrap.
 *
 * Inputs keep native wire spelling (`vault_id`, `invitation`, `expires_at`,
 * `path`, `member`, `home_url`, `credential_file`): no camelCase conversion.
 * JSON readers return native text verbatim, never parsed numbers. Pending
 * retries take the original `MemoryError` JSON text
 * (`OneironError.nativeErrorJson`), so full integers parse only in Rust.
 */

import { translateNativeError } from "./error.js"
import type {
  NativeClient,
  NativeSharedAcceptance,
  NativeSharedBootstrapOutcome,
} from "./native.js"

/** The native accept wire shape, as named on the wire. */
export interface SharedInvitationAcceptRequest {
  readonly vault_id: string
  readonly invitation: string
  readonly expires_at: number
}

/** The native `SharedEnvConfig` wire shape, as named on the wire. */
export interface SharedEnvEntry {
  readonly path: string
  readonly vault_id: string | number
  readonly member: string
  readonly home_url: string
  readonly credential_file: string
}

/**
 * A successful acceptance on the connected HTTPS home, holding the original
 * native value. Readers do not consume it; `memberClient` keeps it usable.
 */
export interface SharedInvitationAcceptance<Member> {
  homeUrl(): string
  acceptanceUrl(): string
  /** The original acceptance request as JSON text, verbatim. */
  requestJson(): string
  /** The complete original receipt and member credential as JSON text, verbatim. */
  replyJson(): string
  /** A remote member handle under the accepted credential. */
  memberClient(): Member
}

/**
 * One bootstrap's original import result beside its independent native
 * publication flag. `errorJson` returning `null` is not a success signal.
 */
export interface SharedEnvBootstrapOutcome {
  /** The native publication flag, even when a later step failed. */
  committed(): boolean
  /** The actual imported path, or the inner native error; never synthetic. */
  vaultPath(): string
  /** The inner native `MemoryError` as JSON text, or `null`. */
  errorJson(): string | null
}

/** Makes the public member handle from its native client; supplied inside `Oneiron`. */
export type MemberClientFactory<Member> = (native: NativeClient) => Member

const ACCEPTANCE_NATIVE: unique symbol = Symbol("oneiron.shared.acceptance.native")
const OUTCOME_NATIVE: unique symbol = Symbol("oneiron.shared.outcome.native")

/** Module-private carrier for the original acceptance; never part of the public type. */
interface AcceptanceCarrier {
  readonly [ACCEPTANCE_NATIVE]: NativeSharedAcceptance
}

/** Module-private carrier for the original outcome; never part of the public type. */
interface OutcomeCarrier {
  readonly [OUTCOME_NATIVE]: NativeSharedBootstrapOutcome
}

/**
 * Wraps the original native acceptance. Methods close over `native` directly;
 * `makeMember` is the `Oneiron` factory supplied inside `Oneiron`, so this
 * module never constructs `Oneiron` itself.
 *
 * @internal
 */
export function wrapSharedAcceptance<Member>(
  native: NativeSharedAcceptance,
  makeMember: MemberClientFactory<Member>,
): SharedInvitationAcceptance<Member> {
  const call = <T>(operation: () => T): T => {
    try {
      return operation()
    } catch (error) {
      throw translateNativeError(error)
    }
  }
  const holder: SharedInvitationAcceptance<Member> & AcceptanceCarrier = {
    homeUrl: () => call(() => native.homeUrl()),
    acceptanceUrl: () => call(() => native.acceptanceUrl()),
    requestJson: () => call(() => native.requestJson()),
    replyJson: () => call(() => native.replyJson()),
    memberClient: () => makeMember(call(() => native.memberClient())),
    [ACCEPTANCE_NATIVE]: native,
  }
  return holder
}

/**
 * The SAME original native acceptance for engine bootstrap. Module-private:
 * used by `EmbeddedEngine` only, never re-exported from the package root.
 *
 * @internal
 */
export function unwrapSharedAcceptance(
  acceptance: SharedInvitationAcceptance<unknown>,
): NativeSharedAcceptance {
  return (acceptance as SharedInvitationAcceptance<unknown> & AcceptanceCarrier)[ACCEPTANCE_NATIVE]
}

/**
 * Wraps the original native bootstrap outcome. Methods close over `native`
 * directly; `committed` reads the independent flag, `vaultPath` throws the
 * inner error, and `errorJson` returns data verbatim.
 *
 * @internal
 */
export function wrapBootstrapOutcome(
  native: NativeSharedBootstrapOutcome,
): SharedEnvBootstrapOutcome {
  const call = <T>(operation: () => T): T => {
    try {
      return operation()
    } catch (error) {
      throw translateNativeError(error)
    }
  }
  const holder: SharedEnvBootstrapOutcome & OutcomeCarrier = {
    committed: () => native.committed(),
    vaultPath: () => call(() => native.vaultPath()),
    errorJson: () => call(() => native.errorJson()),
    [OUTCOME_NATIVE]: native,
  }
  return holder
}
