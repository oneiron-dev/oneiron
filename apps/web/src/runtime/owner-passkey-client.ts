/**
 * The browser half of the owner passkey (row WEB-PASSKEY-OWNER-KEY; Engine
 * ruling WAYBACK-E4, shape (b)): this page runs the WebAuthn ceremonies and
 * hands each result to the engine's `/v1/owner/owner-passkeys` routes. The
 * passkey's private key never leaves its authenticator, and every signature
 * is one assertion the person makes there, with the user verified.
 *
 * The engine checks each assertion where it checks every owner signature: it
 * must be a top-level page's `webauthn.get` over the challenge the route
 * answered, with the user present and verified, in the context (RP id and
 * origin) of the passkey's own enrollment. So a passkey enrolled on one
 * origin vouches only from that origin; these ceremonies name no RP id and
 * take the page's own.
 *
 * Nothing here holds or derives a key, and nothing decides who may act: the
 * routes refuse what the vault does not allow (a key a passkey vouched for
 * acts in part until a key that is no passkey confirms it).
 *
 * On a managed host the passkey's enrollment binds no one: the host's root
 * signs it, and the vault counts no `human` binding that only the host
 * signs. So right after enrolling, the passkey signs the owner's own first
 * binding with a second assertion (`/v1/owner/owner-passkeys/bind/prepare`,
 * then `/bind/land`; row PASSKEY-SELF-BIND), and the owner's owner acts pass.
 * That is the one binding a passkey signs. An owner device key binds them
 * with `/v1/owner/owner-signing-keys/bind` instead.
 *
 * A box recovery waits before it lands (`/v1/owner/recovery-holds` lists each
 * attempt, "recovery started, lands at <time>, cancel?"), and any owner of the
 * vault may stop one. An owner whose passkey is an owner key stops it with a
 * Cancel the passkey signs alone (`/v1/owner/owner-passkeys/recovery-hold-cancel/prepare`,
 * then `/land`; row RECOVERY-HOLD-PASSKEY-CANCEL-ROUTE). A passkey answers a
 * hold with a Cancel and nothing else: it revokes no other owner key, so it
 * never says "it is me".
 */

/** The COSE algorithm of ES256 (ECDSA P-256 with SHA-256): the only kind the engine enrolls. */
export const OWNER_PASSKEY_ALGORITHM_ES256 = -7

/** Bytes of the random registration challenge; the engine reads no attestation. */
const REGISTRATION_CHALLENGE_BYTES = 32

const OWNER_PASSKEYS_ROUTE = '/v1/owner/owner-passkeys'

/**
 * One call to an engine owner route: answers the parsed JSON reply, or
 * rejects (an {@link OwnerRouteRefusal} for an answer that is not 2xx). The
 * transport carries the owner's session; these ceremonies add no header.
 */
export type OwnerRouteTransport = (
  method: 'GET' | 'POST',
  path: string,
  body?: Readonly<Record<string, string>>,
) => Promise<unknown>

/** The browser's credential container as these ceremonies use it (`navigator.credentials`). */
export type PasskeyCredentials = Readonly<{
  create(options: CredentialCreationOptions): Promise<Credential | null>
  get(options: CredentialRequestOptions): Promise<Credential | null>
}>

export type OwnerPasskeyDependencies = Readonly<{
  transport: OwnerRouteTransport
  credentials: PasskeyCredentials
}>

/** Why a ceremony stopped on this page before the engine was asked to act. */
export type OwnerPasskeyCeremonyFailure =
  | 'no-credential'
  | 'not-es256'
  | 'no-public-key'
  | 'credential-mismatch'
  | 'malformed-reply'
  | 'malformed-base64url'

export class OwnerPasskeyCeremonyError extends Error {
  readonly reason: OwnerPasskeyCeremonyFailure

  constructor(reason: OwnerPasskeyCeremonyFailure, message: string) {
    super(message)
    this.name = 'OwnerPasskeyCeremonyError'
    this.reason = reason
  }
}

/** An owner route answered with a status that is not 2xx; `detail` is the engine's text. */
export class OwnerRouteRefusal extends Error {
  readonly status: number
  readonly path: string
  readonly detail: string

  constructor(status: number, path: string, detail: string) {
    super(`${path} answered ${status}: ${detail}`)
    this.name = 'OwnerRouteRefusal'
    this.status = status
    this.path = path
    this.detail = detail
  }
}

/** One enrolled owner passkey, as `GET /v1/owner/owner-passkeys` lists it. */
export type OwnerPasskey = Readonly<{
  /** The enrollment's authority entry, 64 hex. */
  entry: string
  /** The carrier that served its ceremony, 32 hex. */
  machine: string
  /** The owner whose act enrolled it, 32 hex. */
  owner: string
  /** The passkey's key, compressed SEC1, hex. */
  publicKey: string
  /** The passkey's credential id, base64url. */
  credentialId: string
  /** On the roster and not revoked. */
  live: boolean
  /** When it was signed, advisory unix seconds. */
  at: number
}>

/** The receipt of an owner passkey's enrollment. */
export type OwnerPasskeyEnrollmentReceipt = Readonly<{
  entry: string
  machine: string
  publicKey: string
  credentialId: string
}>

/** The receipt of the owner's binding to their own passkey. */
export type OwnerPasskeyBindingReceipt = Readonly<{
  entry: string
  owner: string
  publicKey: string
  epoch: number
}>

/**
 * How the owner's binding to their passkey ended: it landed now, a binding
 * named the owner already (nothing to do), or it failed or was cancelled.
 * A failed binding leaves the passkey enrolled; bind it again with
 * `bindWithOwnerPasskey`, never by enrolling again.
 */
export type OwnerPasskeyBindingOutcome =
  | Readonly<{ state: 'bound'; receipt: OwnerPasskeyBindingReceipt }>
  | Readonly<{ state: 'already-bound' }>
  | Readonly<{ state: 'failed'; error: unknown }>

/** The receipt of a device key a passkey vouched for. */
export type OwnerKeyVouchReceipt = Readonly<{
  entry: string
  machine: string
  publicKey: string
}>

/** What a recovery hold is now, on the engine's clock. */
export type RecoveryHoldState = 'waiting' | 'due' | 'landed' | 'cancelled' | 'void'

const RECOVERY_HOLD_STATES: readonly RecoveryHoldState[] = [
  'waiting',
  'due',
  'landed',
  'cancelled',
  'void',
]

/** One box recovery's attempt, as `GET /v1/owner/recovery-holds` lists it. */
export type RecoveryHold = Readonly<{
  /** The attempt id: the hold's authority entry, 64 hex. */
  hold: string
  /** The owner whose recovery this is, 32 hex. */
  owner: string
  /** The machine that holds the successor key, 32 hex. */
  successorMachine: string
  /** The successor key the landing enrols, hex. */
  successorKey: string
  /** The lost keys the landing revokes, hex. */
  lost: readonly string[]
  /** Unix seconds the wait ends at. */
  landsAt: number
  /** `waiting` and `due` are live: a Cancel still stops them. */
  state: RecoveryHoldState
  /** Who stopped the attempt, 32 hex each; empty unless cancelled. */
  cancelledBy: readonly string[]
}>

/** A live recovery hold for an enrolled passkey to cancel. */
export type RecoveryHoldCancel = Readonly<{
  /** The hold, 64 hex, as `listRecoveryHolds` names it. */
  hold: string
  /** The owner's enrolled passkey that signs the Cancel, by its credential id, base64url. */
  credentialId: string
  signal?: AbortSignal
}>

/** The receipt of a passkey's Cancel of a recovery hold. */
export type RecoveryHoldCancelReceipt = Readonly<{
  /** The Cancel's authority entry, 64 hex. */
  entry: string
}>

export type OwnerPasskeyEnrollment = Readonly<{
  relyingParty: Readonly<{ name: string }>
  /** The WebAuthn user: `id` is the user handle (at most 64 bytes). */
  user: Readonly<{ id: Uint8Array<ArrayBuffer>; name: string; displayName: string }>
  signal?: AbortSignal
}>

/** A new device's owner key as the device hands it over, for a passkey to vouch for. */
export type OwnerKeyVouch = Readonly<{
  /** The machine that holds the new key, 32 hex. */
  machine: string
  /** The new device key, 64 hex. */
  publicKey: string
  /** The new key's signature over its challenge, 128 hex. */
  proof: string
  /** The enrolled passkey that vouches, by its credential id, base64url. */
  credentialId: string
  signal?: AbortSignal
}>

const BASE64URL_TEXT = /^[A-Za-z0-9_-]*={0,2}$/

/** Bytes as base64url with no padding, as WebAuthn's JSON forms and these routes spell them. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The bytes base64url text spells, padded or not. */
export function base64UrlDecode(text: string): Uint8Array<ArrayBuffer> {
  const unpadded = text.replace(/=+$/, '')
  if (
    !BASE64URL_TEXT.test(text) ||
    unpadded.length % 4 === 1 ||
    (unpadded.length === 0 && text.length > 0)
  ) {
    throw new OwnerPasskeyCeremonyError('malformed-base64url', 'the text is not base64url')
  }
  const standard = unpadded.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(standard.padEnd(standard.length + ((4 - (standard.length % 4)) % 4), '='))
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

/**
 * A transport over `fetch`: JSON in and out under the engine's base URL.
 * Pass a `fetch` that carries the owner's session (its credentials or
 * headers); a reply that is not 2xx rejects with {@link OwnerRouteRefusal}.
 */
export function fetchOwnerRouteTransport(
  fetchOwnerRoute: (input: string, init: RequestInit) => Promise<Response>,
  baseUrl: string,
): OwnerRouteTransport {
  const base = baseUrl.replace(/\/+$/, '')
  return async (method, path, body) => {
    const init: RequestInit =
      body === undefined
        ? { method, headers: { accept: 'application/json' } }
        : {
            method,
            headers: { accept: 'application/json', 'content-type': 'application/json' },
            body: JSON.stringify(body),
          }
    const response = await fetchOwnerRoute(`${base}${path}`, init)
    if (!response.ok) throw new OwnerRouteRefusal(response.status, path, await response.text())
    return response.json()
  }
}

/** Every owner passkey the vault enrolled, a revoked one included, ascending by key. */
export async function listOwnerPasskeys(
  transport: OwnerRouteTransport,
): Promise<readonly OwnerPasskey[]> {
  const reply = record(await transport('GET', OWNER_PASSKEYS_ROUTE), OWNER_PASSKEYS_ROUTE)
  if (!Array.isArray(reply.passkeys)) throw malformedReply(OWNER_PASSKEYS_ROUTE)
  return reply.passkeys.map((value: unknown) => {
    const passkey = record(value, OWNER_PASSKEYS_ROUTE)
    if (typeof passkey.live !== 'boolean' || typeof passkey.at !== 'number') {
      throw malformedReply(OWNER_PASSKEYS_ROUTE)
    }
    return {
      entry: text(passkey, 'entry', OWNER_PASSKEYS_ROUTE),
      machine: text(passkey, 'machine', OWNER_PASSKEYS_ROUTE),
      owner: text(passkey, 'owner', OWNER_PASSKEYS_ROUTE),
      publicKey: text(passkey, 'public_key', OWNER_PASSKEYS_ROUTE),
      credentialId: text(passkey, 'credential_id', OWNER_PASSKEYS_ROUTE),
      live: passkey.live,
      at: passkey.at,
    }
  })
}

/**
 * Enrolls a new passkey of this browser as an owner key of the vault:
 * creates an ES256 credential, asks the engine for the challenge over its
 * key, has the person assert it with that credential, and hands the key and
 * the assertion to the engine, which carries and cosigns the act.
 */
export async function enrollOwnerPasskey(
  { transport, credentials }: OwnerPasskeyDependencies,
  enrollment: OwnerPasskeyEnrollment,
): Promise<OwnerPasskeyEnrollmentReceipt> {
  const created = await credentials.create({
    publicKey: {
      rp: { name: enrollment.relyingParty.name },
      user: {
        id: enrollment.user.id,
        name: enrollment.user.name,
        displayName: enrollment.user.displayName,
      },
      // The engine reads no attestation: the assertion below proves the key.
      challenge: crypto.getRandomValues(new Uint8Array(REGISTRATION_CHALLENGE_BYTES)),
      pubKeyCredParams: [{ type: 'public-key', alg: OWNER_PASSKEY_ALGORITHM_ES256 }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      attestation: 'none',
    },
    signal: enrollment.signal,
  })
  const credential = createdCredential(created)
  const rawId = new Uint8Array(credential.rawId)
  const publicKey = base64UrlEncode(new Uint8Array(credential.publicKey))

  const challengeRoute = `${OWNER_PASSKEYS_ROUTE}/challenge`
  const challenge = text(
    record(await transport('POST', challengeRoute, { public_key: publicKey }), challengeRoute),
    'challenge',
    challengeRoute,
  )
  const assertion = await requestAssertion(credentials, rawId, challenge, enrollment.signal)

  const enrollRoute = `${OWNER_PASSKEYS_ROUTE}/enroll`
  const receipt = record(
    await transport('POST', enrollRoute, {
      credential_id: base64UrlEncode(rawId),
      public_key: publicKey,
      authenticator_data: assertion.authenticatorData,
      client_data_json: assertion.clientDataJson,
      signature: assertion.signature,
    }),
    enrollRoute,
  )
  return {
    entry: text(receipt, 'entry', enrollRoute),
    machine: text(receipt, 'machine', enrollRoute),
    publicKey: text(receipt, 'public_key', enrollRoute),
    credentialId: text(receipt, 'credential_id', enrollRoute),
  }
}

/**
 * Vouches for a new device's owner key with an enrolled passkey: the engine
 * prepares the enrollment with the passkey as its predecessor, the person
 * asserts its challenge with that passkey, and the engine lands it. The key
 * acts in part until an owner key that is no passkey confirms it.
 */
export async function vouchWithOwnerPasskey(
  { transport, credentials }: OwnerPasskeyDependencies,
  vouch: OwnerKeyVouch,
): Promise<OwnerKeyVouchReceipt> {
  const rawId = base64UrlDecode(vouch.credentialId)
  const prepareRoute = `${OWNER_PASSKEYS_ROUTE}/vouch/prepare`
  const prepared = record(
    await transport('POST', prepareRoute, {
      machine: vouch.machine,
      public_key: vouch.publicKey,
      proof: vouch.proof,
      credential_id: vouch.credentialId,
    }),
    prepareRoute,
  )
  const entry = text(prepared, 'entry', prepareRoute)
  const assertion = await requestAssertion(
    credentials,
    rawId,
    text(prepared, 'challenge', prepareRoute),
    vouch.signal,
  )

  const landRoute = `${OWNER_PASSKEYS_ROUTE}/vouch/land`
  const receipt = record(
    await transport('POST', landRoute, {
      entry,
      authenticator_data: assertion.authenticatorData,
      client_data_json: assertion.clientDataJson,
      signature: assertion.signature,
    }),
    landRoute,
  )
  return {
    entry: text(receipt, 'entry', landRoute),
    machine: text(receipt, 'machine', landRoute),
    publicKey: text(receipt, 'public_key', landRoute),
  }
}

/** The engine's refusal text when a live `human` binding names the owner already. */
const OWNER_ALREADY_BOUND_DETAIL = 'a live human binding already names this owner'

/**
 * The owner's enrolled passkey `credentialId` (base64url) signs their own
 * first `human` binding: the engine prepares the binding with the passkey as
 * its one signer, the person asserts its challenge with that passkey, and the
 * engine lands it once the vault counted it. Answers `already-bound` when a
 * binding names the owner already, at prepare or (a binding that landed
 * elsewhere in between) at land. Other refusals and a cancelled assertion
 * throw, and nothing is bound.
 */
export async function bindWithOwnerPasskey(
  { transport, credentials }: OwnerPasskeyDependencies,
  credentialId: string,
  signal?: AbortSignal,
): Promise<OwnerPasskeyBindingOutcome> {
  const rawId = base64UrlDecode(credentialId)
  const prepareRoute = `${OWNER_PASSKEYS_ROUTE}/bind/prepare`
  const answer = await askUnlessBound(transport, prepareRoute, { credential_id: credentialId })
  if (answer === ALREADY_BOUND) return { state: 'already-bound' }
  const prepared = record(answer, prepareRoute)
  const entry = text(prepared, 'entry', prepareRoute)
  const assertion = await requestAssertion(
    credentials,
    rawId,
    text(prepared, 'challenge', prepareRoute),
    signal,
  )

  // A binding that landed elsewhere since prepare answers the same refusal here.
  const landRoute = `${OWNER_PASSKEYS_ROUTE}/bind/land`
  const landed = await askUnlessBound(transport, landRoute, {
    entry,
    authenticator_data: assertion.authenticatorData,
    client_data_json: assertion.clientDataJson,
    signature: assertion.signature,
  })
  if (landed === ALREADY_BOUND) return { state: 'already-bound' }
  const receipt = record(landed, landRoute)
  const epoch = receipt.epoch
  if (typeof epoch !== 'number') throw malformedReply(landRoute)
  return {
    state: 'bound',
    receipt: {
      entry: text(receipt, 'entry', landRoute),
      owner: text(receipt, 'owner', landRoute),
      publicKey: text(receipt, 'public_key', landRoute),
      epoch,
    },
  }
}

/** What `askUnlessBound` answers when a live binding names the owner already. */
const ALREADY_BOUND = Symbol('already-bound')

/**
 * `transport`'s answer to `body` at `route`, or `ALREADY_BOUND` when the
 * engine refused it because a live `human` binding names the owner already.
 * Every other refusal throws.
 */
async function askUnlessBound(
  transport: OwnerRouteTransport,
  route: string,
  body: Readonly<Record<string, string>>,
): Promise<unknown> {
  try {
    return await transport('POST', route, body)
  } catch (error) {
    if (error instanceof OwnerRouteRefusal && error.detail.includes(OWNER_ALREADY_BOUND_DETAIL)) {
      return ALREADY_BOUND
    }
    throw error
  }
}

/**
 * Enrolls a new passkey (`enrollOwnerPasskey`), then has it sign the
 * owner's own binding (`bindWithOwnerPasskey`) with a second assertion. The
 * enrollment stands whatever the binding does: a failed or cancelled binding
 * answers `failed` with its error, and the page offers to bind this passkey
 * again.
 */
export async function enrollAndBindOwnerPasskey(
  dependencies: OwnerPasskeyDependencies,
  enrollment: OwnerPasskeyEnrollment,
): Promise<
  Readonly<{ enrollment: OwnerPasskeyEnrollmentReceipt; binding: OwnerPasskeyBindingOutcome }>
> {
  const enrolled = await enrollOwnerPasskey(dependencies, enrollment)
  let binding: OwnerPasskeyBindingOutcome
  try {
    binding = await bindWithOwnerPasskey(dependencies, enrolled.credentialId, enrollment.signal)
  } catch (error) {
    binding = { state: 'failed', error }
  }
  return { enrollment: enrolled, binding }
}

const RECOVERY_HOLDS_ROUTE = '/v1/owner/recovery-holds'

/**
 * Every recovery hold the vault's log holds, with its state on the engine's
 * clock: landed first, then cancelled, void, and the live ones.
 */
export async function listRecoveryHolds(
  transport: OwnerRouteTransport,
): Promise<readonly RecoveryHold[]> {
  const reply = record(await transport('GET', RECOVERY_HOLDS_ROUTE), RECOVERY_HOLDS_ROUTE)
  if (!Array.isArray(reply.holds)) throw malformedReply(RECOVERY_HOLDS_ROUTE)
  return reply.holds.map((value: unknown) => {
    const hold = record(value, RECOVERY_HOLDS_ROUTE)
    const state = RECOVERY_HOLD_STATES.find((known) => known === hold.state)
    if (state === undefined || typeof hold.lands_at !== 'number') {
      throw malformedReply(RECOVERY_HOLDS_ROUTE)
    }
    return {
      hold: text(hold, 'hold', RECOVERY_HOLDS_ROUTE),
      owner: text(hold, 'owner', RECOVERY_HOLDS_ROUTE),
      successorMachine: text(hold, 'successor_machine', RECOVERY_HOLDS_ROUTE),
      successorKey: text(hold, 'successor_key', RECOVERY_HOLDS_ROUTE),
      lost: texts(hold, 'lost', RECOVERY_HOLDS_ROUTE),
      landsAt: hold.lands_at,
      state,
      cancelledBy: texts(hold, 'cancelled_by', RECOVERY_HOLDS_ROUTE),
    }
  })
}

/**
 * Cancels the live recovery hold `cancel.hold` with the owner's enrolled
 * passkey: the engine prepares the Cancel with the passkey as its one
 * signer, the person asserts its challenge with that passkey, and the engine
 * lands it once the vault counted it. The hold then never lands. A refusal
 * (the hold ended, the passkey is not the acting owner's) and a cancelled
 * assertion throw, and nothing is cancelled.
 */
export async function cancelRecoveryHoldWithOwnerPasskey(
  { transport, credentials }: OwnerPasskeyDependencies,
  cancel: RecoveryHoldCancel,
): Promise<RecoveryHoldCancelReceipt> {
  const rawId = base64UrlDecode(cancel.credentialId)
  const prepareRoute = `${OWNER_PASSKEYS_ROUTE}/recovery-hold-cancel/prepare`
  const prepared = record(
    await transport('POST', prepareRoute, {
      hold: cancel.hold,
      credential_id: cancel.credentialId,
    }),
    prepareRoute,
  )
  const entry = text(prepared, 'entry', prepareRoute)
  const assertion = await requestAssertion(
    credentials,
    rawId,
    text(prepared, 'challenge', prepareRoute),
    cancel.signal,
  )

  const landRoute = `${OWNER_PASSKEYS_ROUTE}/recovery-hold-cancel/land`
  const receipt = record(
    await transport('POST', landRoute, {
      entry,
      authenticator_data: assertion.authenticatorData,
      client_data_json: assertion.clientDataJson,
      signature: assertion.signature,
    }),
    landRoute,
  )
  return { entry: text(receipt, 'entry', landRoute) }
}

type AssertionParts = Readonly<{
  authenticatorData: string
  clientDataJson: string
  signature: string
}>

/**
 * The person asserts `challenge` (base64url, as the route answered it) with
 * the credential `rawId`, the user verified; answers the parts as the routes
 * take them. An assertion by any other credential stops here.
 */
async function requestAssertion(
  credentials: PasskeyCredentials,
  rawId: Uint8Array<ArrayBuffer>,
  challenge: string,
  signal: AbortSignal | undefined,
): Promise<AssertionParts> {
  const asserted = await credentials.get({
    publicKey: {
      challenge: base64UrlDecode(challenge),
      allowCredentials: [{ type: 'public-key', id: rawId }],
      userVerification: 'required',
    },
    signal,
  })
  if (!isPublicKeyCredential(asserted)) {
    throw new OwnerPasskeyCeremonyError('no-credential', 'the browser answered no assertion')
  }
  const response = asserted.response as Partial<
    Record<'authenticatorData' | 'clientDataJSON' | 'signature', unknown>
  >
  if (
    !(response.authenticatorData instanceof ArrayBuffer) ||
    !(response.clientDataJSON instanceof ArrayBuffer) ||
    !(response.signature instanceof ArrayBuffer)
  ) {
    throw new OwnerPasskeyCeremonyError('no-credential', 'the browser answered no assertion')
  }
  if (base64UrlEncode(new Uint8Array(asserted.rawId)) !== base64UrlEncode(rawId)) {
    throw new OwnerPasskeyCeremonyError(
      'credential-mismatch',
      'the assertion was made by another credential than the one asked for',
    )
  }
  return {
    authenticatorData: base64UrlEncode(new Uint8Array(response.authenticatorData)),
    clientDataJson: base64UrlEncode(new Uint8Array(response.clientDataJSON)),
    signature: base64UrlEncode(new Uint8Array(response.signature)),
  }
}

type PublicKeyCredentialShape = Readonly<{
  type: 'public-key'
  rawId: ArrayBuffer
  response: object
}>

function isPublicKeyCredential(value: unknown): value is PublicKeyCredentialShape {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as Partial<Record<'type' | 'rawId' | 'response', unknown>>
  return (
    candidate.type === 'public-key' &&
    candidate.rawId instanceof ArrayBuffer &&
    typeof candidate.response === 'object' &&
    candidate.response !== null
  )
}

/** A new credential's id and key, when it is an ES256 credential whose key the browser handed over. */
function createdCredential(created: Credential | null): { rawId: ArrayBuffer; publicKey: ArrayBuffer } {
  if (!isPublicKeyCredential(created)) {
    throw new OwnerPasskeyCeremonyError('no-credential', 'the browser created no passkey')
  }
  const response = created.response as Partial<
    Record<'getPublicKey' | 'getPublicKeyAlgorithm', unknown>
  >
  if (typeof response.getPublicKey !== 'function') {
    throw new OwnerPasskeyCeremonyError(
      'no-public-key',
      'this browser does not hand over a new passkey\'s public key',
    )
  }
  // The creation asked for ES256 alone, and the challenge route refuses a key
  // that is not an ES256 SubjectPublicKeyInfo. A browser that names the
  // algorithm is held to it here, before any route is called.
  if (typeof response.getPublicKeyAlgorithm === 'function') {
    const algorithm: unknown = response.getPublicKeyAlgorithm.call(created.response)
    if (algorithm !== OWNER_PASSKEY_ALGORITHM_ES256) {
      throw new OwnerPasskeyCeremonyError(
        'not-es256',
        'the passkey is not an ES256 (P-256) credential, the only kind the vault enrolls',
      )
    }
  }
  const publicKey: unknown = response.getPublicKey.call(created.response)
  if (!(publicKey instanceof ArrayBuffer)) {
    throw new OwnerPasskeyCeremonyError(
      'no-public-key',
      'this browser does not hand over a new passkey\'s public key',
    )
  }
  return { rawId: created.rawId, publicKey }
}

function malformedReply(route: string): OwnerPasskeyCeremonyError {
  return new OwnerPasskeyCeremonyError('malformed-reply', `${route} answered an unexpected shape`)
}

function record(value: unknown, route: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw malformedReply(route)
  }
  return value as Record<string, unknown>
}

function text(reply: Record<string, unknown>, field: string, route: string): string {
  const value = reply[field]
  if (typeof value !== 'string') throw malformedReply(route)
  return value
}

function texts(reply: Record<string, unknown>, field: string, route: string): readonly string[] {
  const value = reply[field]
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw malformedReply(route)
  }
  return value
}
