import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  OWNER_PASSKEY_ALGORITHM_ES256,
  OwnerPasskeyCeremonyError,
  OwnerRouteRefusal,
  base64UrlDecode,
  base64UrlEncode,
  enrollOwnerPasskey,
  fetchOwnerRouteTransport,
  listOwnerPasskeys,
  vouchWithOwnerPasskey,
  type OwnerRouteTransport,
  type PasskeyCredentials,
} from '../src/runtime/owner-passkey-client'

const bytes = (...values: number[]) => new Uint8Array(values)
const buffer = (view: Uint8Array) => view.slice().buffer

const RAW_ID = bytes(1, 2, 3, 250, 251, 252)
const SPKI = bytes(48, 89, 48, 19, 6, 7, 42, 134, 72)
const AUTHENTICATOR_DATA = bytes(9, 8, 7, 6, 5)
const CLIENT_DATA_JSON = new TextEncoder().encode('{"type":"webauthn.get"}')
const SIGNATURE = bytes(48, 69, 2, 33, 0, 255)
const CHALLENGE = Uint8Array.from({ length: 32 }, (_, index) => index * 7)

type RouteCall = { method: string; path: string; body?: Readonly<Record<string, string>> }

function recordingTransport(replies: Record<string, unknown>) {
  const calls: RouteCall[] = []
  const transport: OwnerRouteTransport = async (method, path, body) => {
    calls.push(body === undefined ? { method, path } : { method, path, body })
    if (!(path in replies)) throw new Error(`no reply for ${path}`)
    return replies[path]
  }
  return { calls, transport }
}

type CreationCall = CredentialCreationOptions
type RequestCall = CredentialRequestOptions

function fakeCredentials(options: {
  algorithm?: number
  publicKey?: ArrayBuffer | null
  assertionRawId?: Uint8Array
}) {
  const created: CreationCall[] = []
  const requested: RequestCall[] = []
  const credentials: PasskeyCredentials = {
    async create(creation) {
      created.push(creation)
      return {
        id: base64UrlEncode(RAW_ID),
        type: 'public-key',
        rawId: buffer(RAW_ID),
        response: {
          clientDataJSON: buffer(bytes(1)),
          getPublicKey: () => (options.publicKey === undefined ? buffer(SPKI) : options.publicKey),
          getPublicKeyAlgorithm: () => options.algorithm ?? OWNER_PASSKEY_ALGORITHM_ES256,
        },
      } as unknown as Credential
    },
    async get(request) {
      requested.push(request)
      const rawId = options.assertionRawId ?? RAW_ID
      return {
        id: base64UrlEncode(rawId),
        type: 'public-key',
        rawId: buffer(rawId),
        response: {
          authenticatorData: buffer(AUTHENTICATOR_DATA),
          clientDataJSON: buffer(CLIENT_DATA_JSON),
          signature: buffer(SIGNATURE),
          userHandle: null,
        },
      } as unknown as Credential
    },
  }
  return { created, requested, credentials }
}

const asBytes = (source: BufferSource | undefined) => {
  assert.ok(source !== undefined)
  return source instanceof ArrayBuffer
    ? new Uint8Array(source)
    : new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
}

const ENROLL_RECEIPT = {
  entry: 'ab'.repeat(32),
  machine: 'cd'.repeat(16),
  public_key: '02' + 'ef'.repeat(32),
  credential_id: base64UrlEncode(RAW_ID),
}

const enrollment = {
  relyingParty: { name: 'Oneiron' },
  user: { id: bytes(7, 7, 7), name: 'owner', displayName: 'The owner' },
}

describe('base64url, as WebAuthn JSON and the owner passkey routes spell bytes', () => {
  it('encodes with the URL alphabet and no padding', () => {
    assert.equal(base64UrlEncode(bytes(251, 255, 191)), '-_-_')
    assert.equal(base64UrlEncode(bytes(1)), 'AQ')
    assert.equal(base64UrlEncode(new Uint8Array(0)), '')
  })

  it('decodes padded and unpadded text to the same bytes', () => {
    assert.deepEqual(base64UrlDecode('AQ'), bytes(1))
    assert.deepEqual(base64UrlDecode('AQ=='), bytes(1))
    assert.deepEqual(base64UrlDecode('-_-_'), bytes(251, 255, 191))
    assert.deepEqual(base64UrlDecode(base64UrlEncode(CHALLENGE)), CHALLENGE)
  })

  it('refuses text outside the URL alphabet', () => {
    assert.throws(() => base64UrlDecode('+/+/'), OwnerPasskeyCeremonyError)
    assert.throws(() => base64UrlDecode('A'), OwnerPasskeyCeremonyError)
  })
})

describe('enrolling the browser passkey as an owner key', () => {
  it('creates an ES256 credential, asks the route for its challenge, asserts it and enrolls', async () => {
    const challenge = base64UrlEncode(CHALLENGE)
    const { calls, transport } = recordingTransport({
      '/v1/owner/owner-passkeys/challenge': { challenge },
      '/v1/owner/owner-passkeys/enroll': ENROLL_RECEIPT,
    })
    const { created, requested, credentials } = fakeCredentials({})

    const receipt = await enrollOwnerPasskey({ transport, credentials }, enrollment)

    assert.equal(created.length, 1)
    const creation = created[0].publicKey
    assert.ok(creation)
    assert.deepEqual(creation.pubKeyCredParams, [
      { type: 'public-key', alg: OWNER_PASSKEY_ALGORITHM_ES256 },
    ])
    assert.equal(creation.authenticatorSelection?.userVerification, 'required')
    assert.equal(creation.attestation, 'none')
    assert.deepEqual(creation.rp, { name: 'Oneiron' })
    assert.deepEqual(asBytes(creation.user.id), bytes(7, 7, 7))
    assert.equal(asBytes(creation.challenge).length, 32)

    assert.deepEqual(calls, [
      {
        method: 'POST',
        path: '/v1/owner/owner-passkeys/challenge',
        body: { public_key: base64UrlEncode(SPKI) },
      },
      {
        method: 'POST',
        path: '/v1/owner/owner-passkeys/enroll',
        body: {
          credential_id: base64UrlEncode(RAW_ID),
          public_key: base64UrlEncode(SPKI),
          authenticator_data: base64UrlEncode(AUTHENTICATOR_DATA),
          client_data_json: base64UrlEncode(CLIENT_DATA_JSON),
          signature: base64UrlEncode(SIGNATURE),
        },
      },
    ])

    assert.equal(requested.length, 1)
    const request = requested[0].publicKey
    assert.ok(request)
    assert.deepEqual(asBytes(request.challenge), CHALLENGE)
    assert.equal(request.userVerification, 'required')
    assert.equal(request.allowCredentials?.length, 1)
    assert.equal(request.allowCredentials?.[0].type, 'public-key')
    assert.deepEqual(asBytes(request.allowCredentials?.[0].id), RAW_ID)

    assert.deepEqual(receipt, {
      entry: ENROLL_RECEIPT.entry,
      machine: ENROLL_RECEIPT.machine,
      publicKey: ENROLL_RECEIPT.public_key,
      credentialId: ENROLL_RECEIPT.credential_id,
    })
  })

  it('refuses a credential that is not ES256 before any route is called', async () => {
    const { calls, transport } = recordingTransport({})
    const { requested, credentials } = fakeCredentials({ algorithm: -8 })
    await assert.rejects(
      enrollOwnerPasskey({ transport, credentials }, enrollment),
      (error: unknown) =>
        error instanceof OwnerPasskeyCeremonyError && error.reason === 'not-es256',
    )
    assert.deepEqual(calls, [])
    assert.equal(requested.length, 0)
  })

  it('refuses a credential whose public key the browser does not hand over', async () => {
    const { calls, transport } = recordingTransport({})
    const { credentials } = fakeCredentials({ publicKey: null })
    await assert.rejects(
      enrollOwnerPasskey({ transport, credentials }, enrollment),
      (error: unknown) =>
        error instanceof OwnerPasskeyCeremonyError && error.reason === 'no-public-key',
    )
    assert.deepEqual(calls, [])
  })

  it('sends no enrollment when the assertion comes from another credential', async () => {
    const { calls, transport } = recordingTransport({
      '/v1/owner/owner-passkeys/challenge': { challenge: base64UrlEncode(CHALLENGE) },
      '/v1/owner/owner-passkeys/enroll': ENROLL_RECEIPT,
    })
    const { credentials } = fakeCredentials({ assertionRawId: bytes(9, 9) })
    await assert.rejects(
      enrollOwnerPasskey({ transport, credentials }, enrollment),
      (error: unknown) =>
        error instanceof OwnerPasskeyCeremonyError && error.reason === 'credential-mismatch',
    )
    assert.deepEqual(
      calls.map((call) => call.path),
      ['/v1/owner/owner-passkeys/challenge'],
    )
  })

  it('refuses a challenge reply of the wrong shape', async () => {
    const { transport } = recordingTransport({
      '/v1/owner/owner-passkeys/challenge': { challenge: 7 },
    })
    const { requested, credentials } = fakeCredentials({})
    await assert.rejects(
      enrollOwnerPasskey({ transport, credentials }, enrollment),
      (error: unknown) =>
        error instanceof OwnerPasskeyCeremonyError && error.reason === 'malformed-reply',
    )
    assert.equal(requested.length, 0)
  })
})

describe('vouching for a new device key with an enrolled passkey', () => {
  const device = {
    machine: '11'.repeat(16),
    publicKey: '22'.repeat(32),
    proof: '33'.repeat(64),
    credentialId: base64UrlEncode(RAW_ID),
  }
  const entry = base64UrlEncode(bytes(5, 4, 3, 2, 1))
  const landReceipt = { entry: '44'.repeat(32), machine: device.machine, public_key: device.publicKey }

  it('prepares the enrollment, asserts its challenge with that passkey and lands it', async () => {
    const { calls, transport } = recordingTransport({
      '/v1/owner/owner-passkeys/vouch/prepare': { entry, challenge: base64UrlEncode(CHALLENGE) },
      '/v1/owner/owner-passkeys/vouch/land': landReceipt,
    })
    const { created, requested, credentials } = fakeCredentials({})

    const receipt = await vouchWithOwnerPasskey({ transport, credentials }, device)

    assert.equal(created.length, 0)
    assert.deepEqual(calls, [
      {
        method: 'POST',
        path: '/v1/owner/owner-passkeys/vouch/prepare',
        body: {
          machine: device.machine,
          public_key: device.publicKey,
          proof: device.proof,
          credential_id: device.credentialId,
        },
      },
      {
        method: 'POST',
        path: '/v1/owner/owner-passkeys/vouch/land',
        body: {
          entry,
          authenticator_data: base64UrlEncode(AUTHENTICATOR_DATA),
          client_data_json: base64UrlEncode(CLIENT_DATA_JSON),
          signature: base64UrlEncode(SIGNATURE),
        },
      },
    ])
    const request = requested[0].publicKey
    assert.ok(request)
    assert.deepEqual(asBytes(request.challenge), CHALLENGE)
    assert.equal(request.userVerification, 'required')
    assert.deepEqual(asBytes(request.allowCredentials?.[0].id), RAW_ID)
    assert.deepEqual(receipt, {
      entry: landReceipt.entry,
      machine: landReceipt.machine,
      publicKey: landReceipt.public_key,
    })
  })

  it('lands nothing when the assertion comes from another credential', async () => {
    const { calls, transport } = recordingTransport({
      '/v1/owner/owner-passkeys/vouch/prepare': { entry, challenge: base64UrlEncode(CHALLENGE) },
      '/v1/owner/owner-passkeys/vouch/land': landReceipt,
    })
    const { credentials } = fakeCredentials({ assertionRawId: bytes(9, 9) })
    await assert.rejects(
      vouchWithOwnerPasskey({ transport, credentials }, device),
      (error: unknown) =>
        error instanceof OwnerPasskeyCeremonyError && error.reason === 'credential-mismatch',
    )
    assert.deepEqual(
      calls.map((call) => call.path),
      ['/v1/owner/owner-passkeys/vouch/prepare'],
    )
  })
})

describe('listing enrolled owner passkeys', () => {
  it('reads every passkey the route lists', async () => {
    const listed = {
      entry: 'aa'.repeat(32),
      machine: 'bb'.repeat(16),
      owner: 'cc'.repeat(16),
      public_key: '03' + 'dd'.repeat(32),
      credential_id: base64UrlEncode(RAW_ID),
      live: false,
      at: 1_794_700_000,
    }
    const { calls, transport } = recordingTransport({
      '/v1/owner/owner-passkeys': { passkeys: [listed] },
    })
    const passkeys = await listOwnerPasskeys(transport)
    assert.deepEqual(calls, [{ method: 'GET', path: '/v1/owner/owner-passkeys' }])
    assert.deepEqual(passkeys, [
      {
        entry: listed.entry,
        machine: listed.machine,
        owner: listed.owner,
        publicKey: listed.public_key,
        credentialId: listed.credential_id,
        live: false,
        at: listed.at,
      },
    ])
  })
})

describe('the fetch transport for owner routes', () => {
  type FetchCall = { url: string; init: RequestInit | undefined }

  function recordingFetch(response: Response) {
    const calls: FetchCall[] = []
    const fetchOwnerRoute = async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init })
      return response
    }
    return { calls, fetchOwnerRoute }
  }

  it('posts JSON under the engine base URL and reads the JSON reply', async () => {
    const { calls, fetchOwnerRoute } = recordingFetch(
      new Response(JSON.stringify({ challenge: 'AQ' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    )
    const transport = fetchOwnerRouteTransport(fetchOwnerRoute, 'https://vault.example/')
    const reply = await transport('POST', '/v1/owner/owner-passkeys/challenge', {
      public_key: 'AQ',
    })
    assert.deepEqual(reply, { challenge: 'AQ' })
    assert.equal(calls.length, 1)
    assert.equal(calls[0].url, 'https://vault.example/v1/owner/owner-passkeys/challenge')
    assert.equal(calls[0].init?.method, 'POST')
    assert.equal(calls[0].init?.body, JSON.stringify({ public_key: 'AQ' }))
    assert.equal(new Headers(calls[0].init?.headers).get('content-type'), 'application/json')
  })

  it('sends a GET with no body', async () => {
    const { calls, fetchOwnerRoute } = recordingFetch(
      new Response(JSON.stringify({ passkeys: [] }), { status: 200 }),
    )
    const transport = fetchOwnerRouteTransport(fetchOwnerRoute, 'https://vault.example')
    assert.deepEqual(await transport('GET', '/v1/owner/owner-passkeys'), { passkeys: [] })
    assert.equal(calls[0].url, 'https://vault.example/v1/owner/owner-passkeys')
    assert.equal(calls[0].init?.method, 'GET')
    assert.equal(calls[0].init?.body, undefined)
  })

  it('answers a refusal with its status and the engine text', async () => {
    const { fetchOwnerRoute } = recordingFetch(
      new Response('no live passkey of this vault has that credential id', { status: 409 }),
    )
    const transport = fetchOwnerRouteTransport(fetchOwnerRoute, 'https://vault.example')
    await assert.rejects(
      transport('POST', '/v1/owner/owner-passkeys/vouch/prepare', {}),
      (error: unknown) =>
        error instanceof OwnerRouteRefusal &&
        error.status === 409 &&
        error.path === '/v1/owner/owner-passkeys/vouch/prepare' &&
        error.detail === 'no live passkey of this vault has that credential id',
    )
  })
})
