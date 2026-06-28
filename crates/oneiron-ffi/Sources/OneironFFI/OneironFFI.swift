import COneironFFI
import Foundation

public enum StatusCode: Equatable, Sendable {
    case ok
    case nullArgument
    case invalidArgument
    case notFound
    case engineError
    case panic
    case bufferTooSmall
    case utf8
    case unknown(Int32)

    fileprivate init(_ status: COneironFFI.OneironStatus) {
        switch Int32(status.rawValue) {
        case 0:
            self = .ok
        case 1:
            self = .nullArgument
        case 2:
            self = .invalidArgument
        case 3:
            self = .notFound
        case 4:
            self = .engineError
        case 5:
            self = .panic
        case 6:
            self = .bufferTooSmall
        case 7:
            self = .utf8
        case let raw:
            self = .unknown(raw)
        }
    }
}

public enum OneironError: Swift.Error, Equatable, Sendable {
    case closedVault
    case emptyPath
    case invalidEntityIDLength(Int)
    case invalidReturnedBuffer
    case negativeDimensions
    case status(StatusCode)
}

public struct EntityID: Equatable, Hashable, Sendable {
    public static let byteCount = 16
    public static let zero = EntityID(uncheckedBytes: Array(repeating: 0, count: byteCount))

    public let bytes: [UInt8]

    public init(bytes: [UInt8]) throws {
        guard bytes.count == Self.byteCount else {
            throw OneironError.invalidEntityIDLength(bytes.count)
        }
        self.bytes = bytes
    }

    private init(uncheckedBytes bytes: [UInt8]) {
        self.bytes = bytes
    }
}

public struct StorageHealth: Equatable, Sendable {
    public let opened: Bool
    public let readable: Bool
}

public final class Vault {
    private var handle: OpaquePointer?

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        close()
    }

    public static func open(fileURL: URL, dimensions: Int = 0) throws -> Vault {
        try open(path: fileURL.path, dimensions: dimensions)
    }

    public static func open(path: String, dimensions: Int = 0) throws -> Vault {
        guard !path.isEmpty else {
            throw OneironError.emptyPath
        }
        guard dimensions >= 0 else {
            throw OneironError.negativeDimensions
        }

        var rawVault: OpaquePointer?
        let pathBytes = Array(path.utf8)
        let status = pathBytes.withUnsafeBufferPointer { pathBuffer in
            COneironFFI.oneiron_vault_open(
                pathBuffer.baseAddress,
                pathBuffer.count,
                dimensions,
                nil,
                0,
                &rawVault
            )
        }
        try check(status)

        guard let rawVault else {
            throw OneironError.status(.nullArgument)
        }
        return Vault(handle: rawVault)
    }

    public func close() {
        guard let current = handle else {
            return
        }
        handle = nil
        _ = COneironFFI.oneiron_vault_free(current)
    }

    public func readHealth() throws -> StorageHealth {
        try withLiveHandle { current in
            var exists: UInt8 = 0
            let idBytes = EntityID.zero.bytes
            let status = idBytes.withUnsafeBufferPointer { idBuffer in
                COneironFFI.oneiron_vault_entity_exists(
                    current,
                    idBuffer.baseAddress,
                    idBuffer.count,
                    &exists
                )
            }
            try check(status)
            return StorageHealth(opened: true, readable: true)
        }
    }

    public func readEntity(id: EntityID) throws -> [UInt8]? {
        try withLiveHandle { current in
            var buffer = COneironFFI.OneironBuffer(ptr: nil, len: 0, cap: 0)
            let idBytes = id.bytes
            let rawStatus = idBytes.withUnsafeBufferPointer { idBuffer in
                COneironFFI.oneiron_vault_get_entity(
                    current,
                    idBuffer.baseAddress,
                    idBuffer.count,
                    &buffer
                )
            }
            let status = StatusCode(rawStatus)
            if status == .notFound {
                return nil
            }
            try check(status)

            if buffer.len == 0 {
                return []
            }
            guard let pointer = buffer.ptr else {
                throw OneironError.invalidReturnedBuffer
            }

            defer {
                _ = COneironFFI.oneiron_buffer_free(buffer)
            }
            return Array(UnsafeBufferPointer(start: pointer, count: buffer.len))
        }
    }

    public func readEntity(id bytes: [UInt8]) throws -> [UInt8]? {
        try readEntity(id: EntityID(bytes: bytes))
    }

    private func withLiveHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        guard let handle else {
            throw OneironError.closedVault
        }
        return try body(handle)
    }
}

private func check(_ status: COneironFFI.OneironStatus) throws {
    try check(StatusCode(status))
}

private func check(_ status: StatusCode) throws {
    guard status == .ok else {
        throw OneironError.status(status)
    }
}
