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

/** The receipt of a device key a passkey vouched for. */
export type OwnerKeyVouchReceipt = Readonly<{
  entry: string
  machine: string
  publicKey: string
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
  if (!BASE64URL_TEXT.test(text) || unpadded.length % 4 === 1) {
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
  if (
    typeof response.getPublicKey !== 'function' ||
    typeof response.getPublicKeyAlgorithm !== 'function'
  ) {
    throw new OwnerPasskeyCeremonyError(
      'no-public-key',
      'this browser does not hand over a new passkey\'s public key',
    )
  }
  const algorithm: unknown = response.getPublicKeyAlgorithm.call(created.response)
  if (algorithm !== OWNER_PASSKEY_ALGORITHM_ES256) {
    throw new OwnerPasskeyCeremonyError(
      'not-es256',
      'the passkey is not an ES256 (P-256) credential, the only kind the vault enrolls',
    )
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
