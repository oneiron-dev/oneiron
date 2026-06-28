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

    private init(handle: OpaquePointer) {
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
