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
    case missingHandle
    case unexpectedStatus(UInt32)

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
        case .missingHandle:
            "opening the vault did not return a handle"
        case let .unexpectedStatus(status):
            "unexpected Oneiron status \(status)"
        }
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
        default:
            throw OneironStorageError.unexpectedStatus(status.rawValue)
        }
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
/// in order. The native library must be built with `--features engine`
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
        try OneironStorageError.check(status)
        guard let handle = rawHandle else { throw OneironStorageError.missingHandle }
        return Engine(handle: handle)
    }

    /// One buffered HTTP/1.1 request; `headers` is `name: value` lines, each ended by CRLF.
    public func request(method: String, path: String, headers: String = "", body: Data = Data()) throws
        -> (status: Int, headers: String, body: Data)
    {
        var reply = OneironReply()
        let status = Data(method.utf8).withUnsafeBytes { m in Data(path.utf8).withUnsafeBytes { p in
            Data(headers.utf8).withUnsafeBytes { h in body.withUnsafeBytes { b in
                oneiron_engine_request(handle, slice(m), slice(p), slice(h), slice(b), &reply)
            } }
        } }
        try OneironStorageError.check(status)
        defer { _ = oneiron_engine_reply_free(reply) }
        return (Int(reply.status), String(decoding: bytes(reply.headers), as: UTF8.self), bytes(reply.body))
    }

    public func wake() throws { try OneironStorageError.check(oneiron_engine_wake(handle)) }

    public func stop() throws { try OneironStorageError.check(oneiron_engine_stop(handle)) }

    /// The engine's own open vault, shared rather than opened again.
    public func vault() throws -> Vault {
        var rawVault: OpaquePointer?
        try OneironStorageError.check(oneiron_engine_vault(handle, &rawVault))
        guard let vaultHandle = rawVault else { throw OneironStorageError.missingHandle }
        return Vault(handle: vaultHandle)
    }
}

private func slice(_ raw: UnsafeRawBufferPointer) -> OneironByteSlice {
    OneironByteSlice(ptr: raw.bindMemory(to: UInt8.self).baseAddress, len: raw.count)
}

private func bytes(_ buffer: OneironBuffer) -> Data {
    guard let ptr = buffer.ptr else { return Data() }
    return Data(bytes: ptr, count: buffer.len)
}
