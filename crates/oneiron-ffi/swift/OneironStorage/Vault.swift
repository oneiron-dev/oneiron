import COneironFFI
import Foundation

public enum OneironStorageError: Error, Equatable, CustomStringConvertible {
    case nullArgument
    case invalidArgument
    case notFound
    case engineError
    case panic
    case bufferTooSmall
    case utf8
    case modelUnavailable
    case missingHandle
    case unexpectedStatus(UInt32)
    /// An engine call's failure, by its stable cause (`ENGINE_STOPPED`, `ENGINE_CLOSED`,
    /// `ENGINE_RELAY_REFUSED`, `ENGINE_WRONG_THREAD`, `ENGINE_CONFIG`, `ENGINE_VAULT_OPEN`,
    /// `ENGINE_START_FAILED`, `ENGINE_CONNECTION_ENDED`, `ENGINE_REPLY_TOO_LARGE`,
    /// `ENGINE_BAD_REQUEST`, or `INTERNAL_SERVER_ERROR` when none is named), with its words.
    case engine(code: String, message: String)

    public var description: String {
        switch self {
        case .nullArgument:
            "a required pointer argument was null"
        case .invalidArgument:
            "an argument failed validation"
        case .notFound:
            "the requested value was not found"
        case .engineError:
            "the storage engine returned an error"
        case .panic:
            "a Rust panic was caught at the FFI boundary"
        case .bufferTooSmall:
            "the caller-owned buffer was too small"
        case .utf8:
            "bytes were not valid UTF-8"
        case .modelUnavailable:
            "the request needs a model this library does not serve (a context pack's media needs an ai.embed rung); retry without it or on a server"
        case .missingHandle:
            "opening the vault did not return a handle"
        case let .unexpectedStatus(status):
            "unexpected Oneiron status \(status)"
        case let .engine(code, message):
            "\(code): \(message)"
        }
    }

    /// `check`, with an `EngineError` thrown as the cause the failed engine call left on this
    /// thread (`oneiron_engine_last_error`).
    static func checkEngine(_ status: OneironStatus) throws {
        guard status == OneironStatus_EngineError else { return try check(status) }
        var code = OneironEngineErrorCode_None
        var message = OneironBuffer(ptr: nil, len: 0, cap: 0)
        guard oneiron_engine_last_error(&code, &message) == OneironStatus_Ok else {
            throw OneironStorageError.engineError
        }
        defer { _ = oneiron_buffer_free(message) }
        throw OneironStorageError.engine(
            code: engineCode(code), message: String(decoding: bytes(message), as: UTF8.self))
    }

    static func check(_ status: OneironStatus) throws {
        switch status {
        case OneironStatus_Ok:
            return
        case OneironStatus_NullArg:
            throw OneironStorageError.nullArgument
        case OneironStatus_InvalidArg:
            throw OneironStorageError.invalidArgument
        case OneironStatus_NotFound:
            throw OneironStorageError.notFound
        case OneironStatus_EngineError:
            throw OneironStorageError.engineError
        case OneironStatus_Panic:
            throw OneironStorageError.panic
        case OneironStatus_BufferTooSmall:
            throw OneironStorageError.bufferTooSmall
        case OneironStatus_Utf8:
            throw OneironStorageError.utf8
        case OneironStatus_ModelUnavailable:
            throw OneironStorageError.modelUnavailable
        default:
            throw OneironStorageError.unexpectedStatus(status.rawValue)
        }
    }
}

/// One entity `Vault.batchPut` stores, as `Vault.put` takes it.
public struct EntityInput: Equatable {
    public var id: Data
    public var entityType: UInt32
    public var occurredStart: Int64
    public var occurredEnd: Int64
    public var learnedAt: Int64
    public var data: Data

    public init(
        id: Data,
        entityType: UInt32,
        occurredStart: Int64,
        occurredEnd: Int64,
        learnedAt: Int64,
        data: Data
    ) {
        self.id = id
        self.entityType = entityType
        self.occurredStart = occurredStart
        self.occurredEnd = occurredEnd
        self.learnedAt = learnedAt
        self.data = data
    }
}

/// One stored edge (`Vault.edgesOut`, `Vault.edgesIn`): `source` to `target`, both 16-byte
/// entity ids, of the wire edge `kind`, with its `weight`, its creation time `createdAt`, and
/// its `vad` when it carries one.
public struct VaultEdge: Equatable {
    public struct Vad: Equatable {
        public let valence: Double
        public let arousal: Double
        public let dominance: Double
    }

    public let source: Data
    public let kind: UInt32
    public let target: Data
    public let weight: Double
    public let createdAt: Int64
    public let vad: Vad?

    fileprivate init(_ info: OneironEdgeInfo) {
        source = withUnsafeBytes(of: info.src) { Data($0) }
        kind = info.kind
        target = withUnsafeBytes(of: info.tgt) { Data($0) }
        weight = info.weight
        createdAt = info.created_at
        vad = info.has_vad != 0
            ? Vad(valence: info.valence, arousal: info.arousal, dominance: info.dominance)
            : nil
    }
}

/// One vector search hit (`Vault.searchVector`): the 16-byte entity `id` and its `score`.
public struct ScoredEntity: Equatable {
    public let id: Data
    public let score: Double
}

/// A context pack's media query (`Vault.contextPack`, OF-370): `bytes` of the media type
/// `mime`, to embed into the declared space `space` (an `ai.embed` rung id, then `@` and its
/// provider), its list keeping the item `kinds` (`text`, `image`, `audio`), every kind the
/// space holds when empty. It crosses as the served route's JSON.
public struct ContextPackMedia: Encodable, Equatable {
    public var space: String
    public var mime: String
    public var bytes: Data
    public var kinds: [String]

    public init(space: String, mime: String, bytes: Data, kinds: [String] = []) {
        self.space = space
        self.mime = mime
        self.bytes = bytes
        self.kinds = kinds
    }

    private enum CodingKeys: String, CodingKey {
        case space
        case mime
        case bytes = "bytes_b64"
        case kinds
    }
}

public final class Vault {
    private let handle: OpaquePointer

    fileprivate init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        _ = oneiron_vault_free(handle)
    }

    public static func open(
        path: String,
        dimensions: Int = 0
    ) throws -> Vault {
        var rawHandle: OpaquePointer?
        var mutablePath = path
        let status: OneironStatus = try mutablePath.withUTF8 { pathBytes in
            guard let pathBase = pathBytes.baseAddress else {
                throw OneironStorageError.invalidArgument
            }
            return oneiron_vault_open(
                pathBase,
                pathBytes.count,
                dimensions,
                nil,
                0,
                &rawHandle
            )
        }
        try OneironStorageError.check(status)
        guard let handle = rawHandle else {
            throw OneironStorageError.missingHandle
        }
        return Vault(handle: handle)
    }

    /// `open(path:dimensions:)`, then this install's own machine profile from the vault's
    /// host root secret (FIX 4730), so the owner's acts carry from it. `hostRootSecret` is the
    /// exact bytes of the server's configured `auth_secret`; nil opens as `open(path:dimensions:)`
    /// does. `initializeRoot` roots the vault under that secret when this open creates its
    /// store and its authority log is empty, a new local-origin vault: never set it for a
    /// replica awaiting its root. A secret that cannot profile the install throws
    /// `engineError`, and the engine logs why.
    public static func open(
        path: String,
        dimensions: Int = 0,
        hostRootSecret: Data?,
        initializeRoot: Bool = false
    ) throws -> Vault {
        if hostRootSecret?.isEmpty == true || (initializeRoot && hostRootSecret == nil) {
            throw OneironStorageError.invalidArgument
        }
        var rawHandle: OpaquePointer?
        var mutablePath = path
        let status: OneironStatus = try mutablePath.withUTF8 { pathBytes in
            guard let pathBase = pathBytes.baseAddress else {
                throw OneironStorageError.invalidArgument
            }
            return withOptionalBytes(hostRootSecret) { secretPtr, secretLen in
                oneiron_vault_open_with_host_root(
                    pathBase,
                    pathBytes.count,
                    dimensions,
                    nil,
                    0,
                    secretPtr,
                    secretLen,
                    initializeRoot ? 1 : 0,
                    &rawHandle
                )
            }
        }
        try OneironStorageError.check(status)
        guard let handle = rawHandle else {
            throw OneironStorageError.missingHandle
        }
        return Vault(handle: handle)
    }

    /// A NEW handle over this same open vault, from `open` or `Engine.vault()`, whose
    /// writes run as one caller (OF-063): the principal `actorKey` names (`human:<ref>`,
    /// `agent:<ref>` or `system:<ref>`), or the embedded owner when it is nil, inside the
    /// off-record session `session` names, or outside any when it is nil. This handle is
    /// unchanged.
    public func bound(actorKey: String? = nil, session: String? = nil) throws -> Vault {
        if actorKey?.isEmpty == true || session?.isEmpty == true {
            throw OneironStorageError.invalidArgument
        }
        var rawVault: OpaquePointer?
        let status = withOptionalUTF8(actorKey) { actorPtr, actorLen in
            withOptionalUTF8(session) { sessionPtr, sessionLen in
                oneiron_vault_bind(handle, actorPtr, actorLen, sessionPtr, sessionLen, &rawVault)
            }
        }
        try OneironStorageError.check(status)
        guard let vaultHandle = rawVault else { throw OneironStorageError.missingHandle }
        return Vault(handle: vaultHandle)
    }

    /// Store one entity blob under the 16-byte `id`. A bound handle (`bound`) stores it as its
    /// caller; every other handle as the host. `entityType` must fit one byte, and a negative
    /// time counts as 0, as the C ABI's does.
    public func put(
        id: Data,
        entityType: UInt32,
        occurredStart: Int64,
        occurredEnd: Int64,
        learnedAt: Int64,
        data: Data
    ) throws {
        let status = withBytes(id) { idPtr, idLen in
            withBytes(data) { dataPtr, dataLen in
                oneiron_vault_put_entity(
                    handle, idPtr, idLen, entityType, occurredStart, occurredEnd, learnedAt,
                    dataPtr, dataLen
                )
            }
        }
        try OneironStorageError.check(status)
    }

    /// Store every entity of `entities` in one transaction, or none of them. A bound handle
    /// stores them as its caller.
    public func batchPut(_ entities: [EntityInput]) throws {
        var arena = Data()
        for entity in entities {
            guard entity.id.count == 16 else { throw OneironStorageError.invalidArgument }
            arena.append(entity.data)
        }
        let status: OneironStatus = withBytes(arena) { base, _ in
            var offset = 0
            var inputs: [OneironEntityInput] = []
            inputs.reserveCapacity(entities.count)
            for entity in entities {
                var input = OneironEntityInput()
                withUnsafeMutableBytes(of: &input.id) { $0.copyBytes(from: entity.id) }
                input.entity_type = entity.entityType
                input.occurred_start = entity.occurredStart
                input.occurred_end = entity.occurredEnd
                input.learned_at = entity.learnedAt
                input.data = OneironByteSlice(ptr: base + offset, len: entity.data.count)
                offset += entity.data.count
                inputs.append(input)
            }
            return inputs.withUnsafeBufferPointer { values in
                oneiron_vault_batch_put_entities(handle, values.baseAddress, values.count)
            }
        }
        try OneironStorageError.check(status)
    }

    /// The blob stored under `id`, or nil when none is.
    public func get(id: Data) throws -> Data? {
        var buffer = OneironBuffer(ptr: nil, len: 0, cap: 0)
        let status = withBytes(id) { idPtr, idLen in
            oneiron_vault_get_entity(handle, idPtr, idLen, &buffer)
        }
        if status == OneironStatus_NotFound {
            return nil
        }
        try OneironStorageError.check(status)
        defer {
            _ = oneiron_buffer_free(buffer)
        }
        return bytes(buffer)
    }

    /// Delete the entity under `id` and answer whether one was there. A bound handle deletes as
    /// its caller through the `vault.delete` door: owner-only, and an id naming no record is
    /// `notFound`.
    public func delete(id: Data) throws -> Bool {
        var existed: UInt8 = 0
        let status = withBytes(id) { idPtr, idLen in
            oneiron_vault_delete_entity(handle, idPtr, idLen, &existed)
        }
        try OneironStorageError.check(status)
        return existed != 0
    }

    /// Store the directed edge `source` to `target` of the wire edge `kind`. A bound handle
    /// stores it as its caller.
    public func putEdge(source: Data, kind: UInt32, target: Data, weight: Double) throws {
        let status = withBytes(source) { sourcePtr, sourceLen in
            withBytes(target) { targetPtr, targetLen in
                oneiron_vault_put_edge(
                    handle, sourcePtr, sourceLen, kind, targetPtr, targetLen, weight
                )
            }
        }
        try OneironStorageError.check(status)
    }

    /// The edges out of `source`.
    public func edgesOut(source: Data) throws -> [VaultEdge] {
        try edges { out in
            withBytes(source) { oneiron_vault_edges_out(handle, $0, $1, out) }
        }
    }

    /// The edges into `target`.
    public func edgesIn(target: Data) throws -> [VaultEdge] {
        try edges { out in
            withBytes(target) { oneiron_vault_edges_in(handle, $0, $1, out) }
        }
    }

    private func edges(
        _ read: (UnsafeMutablePointer<OneironEdgeInfoArray>) -> OneironStatus
    ) throws -> [VaultEdge] {
        var array = OneironEdgeInfoArray(ptr: nil, len: 0, cap: 0)
        let status = withUnsafeMutablePointer(to: &array) { read($0) }
        try OneironStorageError.check(status)
        defer {
            _ = oneiron_edge_info_array_free(array)
        }
        return UnsafeMutableBufferPointer(start: array.ptr, count: array.len).map { VaultEdge($0) }
    }

    /// Store `id`'s embedding; its length must be the vault's dimensions. A bound handle stores
    /// it as its caller.
    public func putVector(id: Data, vector: [Double]) throws {
        let status = withBytes(id) { idPtr, idLen in
            vector.withUnsafeBufferPointer { values in
                oneiron_vault_put_vector(handle, idPtr, idLen, values.baseAddress, values.count)
            }
        }
        try OneironStorageError.check(status)
    }

    /// The `limit` (at most 1000) entities nearest `query`, best first; `query`'s length must be
    /// the vault's dimensions.
    public func searchVector(_ query: [Double], limit: UInt32 = 10) throws -> [ScoredEntity] {
        var array = OneironScoredEntityArray(ptr: nil, len: 0, cap: 0)
        let status = query.withUnsafeBufferPointer { values in
            oneiron_vault_search_vector(handle, values.baseAddress, values.count, limit, &array)
        }
        try OneironStorageError.check(status)
        defer {
            _ = oneiron_scored_entity_array_free(array)
        }
        return UnsafeMutableBufferPointer(start: array.ptr, count: array.len).map { hit in
            ScoredEntity(id: withUnsafeBytes(of: hit.id) { Data($0) }, score: hit.score)
        }
    }

    /// A context pack over `text` and `vector` as UTF-8 in `format` (`json` when nil or
    /// unknown; `yaml`, `toon`, `markdown`, `plaintext`), at most `limit` items (10 when nil,
    /// at most 1000). A pack naming `media` is refused `modelUnavailable` once every input
    /// validates: this library serves no `ai.embed` rung, and never packs without the media.
    public func contextPack(
        text: String? = nil,
        vector: [Double]? = nil,
        limit: UInt32? = nil,
        format: String? = nil,
        media: ContextPackMedia? = nil
    ) throws -> String {
        let mediaJSON = try media.map { try JSONEncoder().encode($0) }
        var buffer = OneironBuffer(ptr: nil, len: 0, cap: 0)
        let status: OneironStatus = withOptionalUTF8(text) { textPtr, textLen in
            withOptionalDoubles(vector) { vectorPtr, vectorLen in
                withOptionalUTF8(format) { formatPtr, formatLen in
                    withOptionalBytes(mediaJSON) { mediaPtr, mediaLen in
                        oneiron_vault_context_pack(
                            handle, textPtr, textLen, vectorPtr, vectorLen, limit ?? 0,
                            limit == nil ? 0 : 1, formatPtr, formatLen, mediaPtr, mediaLen,
                            &buffer
                        )
                    }
                }
            }
        }
        try OneironStorageError.check(status)
        defer {
            _ = oneiron_buffer_free(buffer)
        }
        guard let string = String(data: bytes(buffer), encoding: .utf8) else {
            throw OneironStorageError.utf8
        }
        return string
    }

    public func healthJSONData() throws -> Data {
        var buffer = OneironBuffer(ptr: nil, len: 0, cap: 0)
        try OneironStorageError.check(oneiron_vault_health_json(handle, &buffer))
        defer {
            _ = oneiron_buffer_free(buffer)
        }
        guard let bytes = buffer.ptr else {
            return Data()
        }
        return Data(bytes: bytes, count: buffer.len)
    }

    public func healthJSONString() throws -> String {
        let data = try healthJSONData()
        guard let string = String(data: data, encoding: .utf8) else {
            throw OneironStorageError.utf8
        }
        return string
    }
}

/// The app's side of an `Engine`. The engine calls these on threads of its
/// own; never call back into the engine from one.
public protocol EngineHost: AnyObject {
    func keychain(_ name: String) -> Data?
    func scheduleWake(atUnixMs: UInt64?)
    func ready()
}

private final class EngineHostBox {
    let host: EngineHost
    init(_ host: EngineHost) { self.host = host }
    static func of(_ userData: UnsafeMutableRawPointer?) -> EngineHost? {
        userData.map { Unmanaged<EngineHostBox>.fromOpaque($0).takeUnretainedValue().host }
    }
}

/// The full Oneiron server inside this process, over the vault at `path`
/// (OF-237). Its calls block: make them from app threads. `deinit` stops it
/// in order. An engine failure throws `OneironStorageError.engine(code:message:)`.
/// The native library must be built with `--features engine`
/// (`cargo build -p oneiron-ffi --features engine`).
public final class Engine {
    private let handle: OpaquePointer

    private init(handle: OpaquePointer) { self.handle = handle }

    deinit { _ = oneiron_engine_free(handle) }

    public static func start(path: String, host: EngineHost, dimensions: Int = 0) throws -> Engine {
        var table = OneironAppHost()
        table.user_data = Unmanaged.passRetained(EngineHostBox(host)).toOpaque()
        table.keychain = { userData, namePtr, nameLen, sink in
            guard let namePtr,
                  let secret = EngineHostBox.of(userData)?.keychain(
                      String(decoding: UnsafeBufferPointer(start: namePtr, count: nameLen), as: UTF8.self))
            else { return }
            secret.withUnsafeBytes { bytes in
                _ = oneiron_secret_sink_write(sink, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
            }
        }
        table.schedule_wake = { userData, hasAt, atUnixMs in
            EngineHostBox.of(userData)?.scheduleWake(atUnixMs: hasAt != 0 ? atUnixMs : nil)
        }
        table.ready = { userData in EngineHostBox.of(userData)?.ready() }
        table.release = { userData in
            if let userData { Unmanaged<EngineHostBox>.fromOpaque(userData).release() }
        }
        var rawHandle: OpaquePointer?
        var mutablePath = path
        let status = mutablePath.withUTF8 { pathBytes in
            oneiron_engine_start(pathBytes.baseAddress, pathBytes.count, dimensions, nil, 0, table, 0, 0, &rawHandle)
        }
        try OneironStorageError.checkEngine(status)
        guard let handle = rawHandle else { throw OneironStorageError.missingHandle }
        return Engine(handle: handle)
    }

    /// One buffered HTTP/1.1 request; `headers` is `name: value` lines, each ended by CRLF.
    /// `/ws` and a reply body over 64 MiB throw: open a connection for those.
    public func request(method: String, path: String, headers: String = "", body: Data = Data()) throws
        -> (status: Int, headers: String, body: Data)
    {
        try exchange(method: method, path: path, headers: headers, body: body, artifacts: false)
    }

    /// `request` on the artifact app's own origin (`/a/`), apart from the API's: what a web
    /// view loads artifacts through.
    public func artifactRequest(method: String, path: String, headers: String = "", body: Data = Data())
        throws -> (status: Int, headers: String, body: Data)
    {
        try exchange(method: method, path: path, headers: headers, body: body, artifacts: true)
    }

    private func exchange(method: String, path: String, headers: String, body: Data, artifacts: Bool) throws
        -> (status: Int, headers: String, body: Data)
    {
        var reply = OneironReply()
        let status = Data(method.utf8).withUnsafeBytes { m in Data(path.utf8).withUnsafeBytes { p in
            Data(headers.utf8).withUnsafeBytes { h in body.withUnsafeBytes { b in
                artifacts
                    ? oneiron_engine_artifact_request(handle, slice(m), slice(p), slice(h), slice(b), &reply)
                    : oneiron_engine_request(handle, slice(m), slice(p), slice(h), slice(b), &reply)
            } }
        } }
        try OneironStorageError.checkEngine(status)
        defer { _ = oneiron_engine_reply_free(reply) }
        return (Int(reply.status), String(decoding: bytes(reply.headers), as: UTF8.self), bytes(reply.body))
    }

    /// Opens a connection this app holds to the engine's server: one in-process stream it serves
    /// as a socket's connection, HTTP/1.1 with upgrades, so `/ws` and streamed replies ride it.
    /// A stop drains it, so after `wake` open another. It keeps this engine alive.
    public func openConnection() throws -> EngineConnection {
        var rawConnection: OpaquePointer?
        try OneironStorageError.checkEngine(oneiron_engine_connection_open(handle, &rawConnection))
        guard let connection = rawConnection else { throw OneironStorageError.missingHandle }
        return EngineConnection(handle: connection, engine: self)
    }

    /// `openConnection` on the artifact app's own origin (`/a/`), apart from the API's.
    public func openArtifactConnection() throws -> EngineConnection {
        var rawConnection: OpaquePointer?
        try OneironStorageError.checkEngine(oneiron_engine_artifact_connection_open(handle, &rawConnection))
        guard let connection = rawConnection else { throw OneironStorageError.missingHandle }
        return EngineConnection(handle: connection, engine: self)
    }

    public func wake() throws { try OneironStorageError.checkEngine(oneiron_engine_wake(handle)) }

    public func stop() throws { try OneironStorageError.checkEngine(oneiron_engine_stop(handle)) }

    /// The engine's own open vault, shared rather than opened again.
    public func vault() throws -> Vault {
        var rawVault: OpaquePointer?
        try OneironStorageError.checkEngine(oneiron_engine_vault(handle, &rawVault))
        guard let vaultHandle = rawVault else { throw OneironStorageError.missingHandle }
        return Vault(handle: vaultHandle)
    }
}

/// One connection this app holds to its `Engine`'s server (OF-237): bytes both ways over one
/// in-process stream the server serves as a socket's connection, HTTP/1.1 with upgrades. Write
/// the request with `send` (a `GET /ws` with its upgrade headers holds `/ws`; after the `101`,
/// send the upgraded protocol's frames, and bring your own auth) and read what the server writes
/// with `receive`. A `send` and a `receive` may block two threads at once, and `close` from a
/// third returns the blocked `receive`. It keeps its engine alive until it goes; once the engine
/// stops, `receive` returns empty data and `send` throws. `deinit` closes and frees it.
public final class EngineConnection {
    private let handle: OpaquePointer
    private let engine: Engine

    fileprivate init(handle: OpaquePointer, engine: Engine) {
        self.handle = handle
        self.engine = engine
    }

    deinit { _ = oneiron_engine_connection_free(handle) }

    /// Writes all of `bytes` to the server, blocking until the connection has taken them.
    public func send(_ bytes: Data) throws {
        let status = bytes.withUnsafeBytes { raw in oneiron_engine_connection_send(handle, slice(raw)) }
        try OneironStorageError.checkEngine(status)
    }

    /// The next bytes the server wrote, at most 64 KiB, blocking until some arrive; empty once
    /// the connection has ended.
    public func receive() throws -> Data {
        var buffer = OneironBuffer(ptr: nil, len: 0, cap: 0)
        try OneironStorageError.checkEngine(oneiron_engine_connection_receive(handle, &buffer))
        defer { _ = oneiron_buffer_free(buffer) }
        return bytes(buffer)
    }

    /// Ends this side: a blocked `receive` returns empty and the server reads the end of the
    /// stream. Closing again does nothing.
    public func close() throws { try OneironStorageError.checkEngine(oneiron_engine_connection_close(handle)) }
}

/// The stable code of an engine failure's cause, as every binding names it.
private func engineCode(_ code: OneironEngineErrorCode) -> String {
    switch code {
    case OneironEngineErrorCode_Stopped: "ENGINE_STOPPED"
    case OneironEngineErrorCode_Closed: "ENGINE_CLOSED"
    case OneironEngineErrorCode_RelayRefused: "ENGINE_RELAY_REFUSED"
    case OneironEngineErrorCode_WrongThread: "ENGINE_WRONG_THREAD"
    case OneironEngineErrorCode_Config: "ENGINE_CONFIG"
    case OneironEngineErrorCode_VaultOpen: "ENGINE_VAULT_OPEN"
    case OneironEngineErrorCode_StartFailed: "ENGINE_START_FAILED"
    case OneironEngineErrorCode_ConnectionEnded: "ENGINE_CONNECTION_ENDED"
    case OneironEngineErrorCode_ReplyTooLarge: "ENGINE_REPLY_TOO_LARGE"
    case OneironEngineErrorCode_BadRequest: "ENGINE_BAD_REQUEST"
    default: "INTERNAL_SERVER_ERROR"
    }
}

private func slice(_ raw: UnsafeRawBufferPointer) -> OneironByteSlice {
    OneironByteSlice(ptr: raw.bindMemory(to: UInt8.self).baseAddress, len: raw.count)
}

/// `text`'s UTF-8 bytes borrowed for `body`, or a null pointer and 0 when it is nil.
private func withOptionalUTF8<R>(_ text: String?, _ body: (UnsafePointer<UInt8>?, Int) -> R) -> R {
    guard let text else { return body(nil, 0) }
    return withOptionalBytes(Data(text.utf8), body)
}

/// `data`'s bytes borrowed for `body`, or a null pointer and 0 when it is nil.
private func withOptionalBytes<R>(_ data: Data?, _ body: (UnsafePointer<UInt8>?, Int) -> R) -> R {
    guard let data else { return body(nil, 0) }
    return data.withUnsafeBytes { raw in
        body(raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
    }
}

/// `values` borrowed for `body`, or a null pointer and 0 when it is nil.
private func withOptionalDoubles<R>(
    _ values: [Double]?,
    _ body: (UnsafePointer<Double>?, Int) -> R
) -> R {
    guard let values else { return body(nil, 0) }
    return values.withUnsafeBufferPointer { body($0.baseAddress, $0.count) }
}

/// `data`'s bytes borrowed for `body`, never through a null pointer: the C ABI wants a non-null
/// pointer for every required input, so an empty value lends one placeholder byte at length 0.
private func withBytes<R>(_ data: Data, _ body: (UnsafePointer<UInt8>, Int) -> R) -> R {
    var placeholder: UInt8 = 0
    guard !data.isEmpty else {
        return withUnsafePointer(to: &placeholder) { body($0, 0) }
    }
    return data.withUnsafeBytes { raw in
        guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
            return withUnsafePointer(to: &placeholder) { body($0, 0) }
        }
        return body(base, raw.count)
    }
}

private func bytes(_ buffer: OneironBuffer) -> Data {
    guard let ptr = buffer.ptr else { return Data() }
    return Data(bytes: ptr, count: buffer.len)
}
