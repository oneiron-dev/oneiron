import COneironFFI
import Foundation

/// The complete native MemoryError wire value, including its stable code, suggestions,
/// pending invocation and payload. Keep the bytes when retrying a pending acceptance.
public struct SharedMemoryError: Error, Equatable {
    public let json: Data

    public init(json: Data) {
        self.json = json
    }
}

extension OneironStorageError {
    /// Read on the same thread as the failed call, before another shared call replaces it.
    static func checkShared(_ status: OneironStatus) throws {
        if status == OneironStatus_EngineError {
            var buffer = OneironBuffer(ptr: nil, len: 0, cap: 0)
            let readStatus = oneiron_shared_last_error_json(&buffer)
            defer { _ = oneiron_buffer_free(buffer) }
            if readStatus == OneironStatus_Ok, buffer.len != 0 {
                throw SharedMemoryError(json: sharedBytes(buffer))
            }
        }
        try checkEngine(status)
    }
}

/// A connected native HTTPS SDK client. Calls block; do not make them from an EngineHost
/// callback. The credential is passed directly to the native client.
public final class RemoteClient {
    private let handle: OpaquePointer

    fileprivate init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit { _ = oneiron_remote_free(handle) }

    public static func connect(url: String, credential: String) throws -> RemoteClient {
        var raw: OpaquePointer?
        let status = sharedWithBytes(Data(url.utf8)) { urlPtr, urlLen in
            sharedWithBytes(Data(credential.utf8)) { keyPtr, keyLen in
                oneiron_remote_connect(urlPtr, urlLen, keyPtr, keyLen, &raw)
            }
        }
        try OneironStorageError.checkShared(status)
        guard let raw else { throw OneironStorageError.missingHandle }
        return RemoteClient(handle: raw)
    }

    /// The native SharedInvitationAcceptWithCredentialRequest JSON. Its vault_id is a decimal
    /// string. The result holds the original native acceptance, not a decoded receipt.
    public func acceptSharedInvitationHTTPS(requestJSON: Data) throws -> SharedInvitationAcceptance {
        var raw: OpaquePointer?
        let status = sharedWithBytes(requestJSON) { requestPtr, requestLen in
            oneiron_remote_accept_https(handle, requestPtr, requestLen, &raw)
        }
        try OneironStorageError.checkShared(status)
        guard let raw else { throw OneironStorageError.missingHandle }
        return SharedInvitationAcceptance(handle: raw)
    }

    /// Retry with the complete native pending MemoryError and the original request JSON.
    public func retrySharedInvitationHTTPS(
        pending: SharedMemoryError, requestJSON: Data
    ) throws -> SharedInvitationAcceptance {
        var raw: OpaquePointer?
        let status = sharedWithBytes(pending.json) { pendingPtr, pendingLen in
            sharedWithBytes(requestJSON) { requestPtr, requestLen in
                oneiron_remote_retry_https(
                    handle, pendingPtr, pendingLen, requestPtr, requestLen, &raw
                )
            }
        }
        try OneironStorageError.checkShared(status)
        guard let raw else { throw OneironStorageError.missingHandle }
        return SharedInvitationAcceptance(handle: raw)
    }
}

/// The original native HTTPS acceptance, kept opaque across the ABI. Its serialized request
/// and complete reply are reads only; neither reconstructs an acceptance or its provenance.
public final class SharedInvitationAcceptance {
    let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit { _ = oneiron_shared_acceptance_free(handle) }

    public func homeURL() throws -> String {
        try sharedString { oneiron_shared_acceptance_home_url(handle, $0) }
    }

    public func acceptanceURL() throws -> String {
        try sharedString { oneiron_shared_acceptance_url(handle, $0) }
    }

    public func requestJSON() throws -> Data {
        try sharedBuffer { oneiron_shared_acceptance_request_json(handle, $0) }
    }

    public func replyJSON() throws -> Data {
        try sharedBuffer { oneiron_shared_acceptance_reply_json(handle, $0) }
    }

    public func memberClient() throws -> RemoteClient {
        var raw: OpaquePointer?
        try OneironStorageError.checkShared(oneiron_shared_acceptance_member_client(handle, &raw))
        guard let raw else { throw OneironStorageError.missingHandle }
        return RemoteClient(handle: raw)
    }
}

/// The native import result and committed bit are independent. A failed import can have
/// committed rows; read committed() even when vaultPath() throws, then inspect memoryError().
public final class SharedBootstrapOutcome {
    private let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit { _ = oneiron_shared_outcome_free(handle) }

    public func committed() throws -> Bool {
        var committed: UInt8 = 0
        try OneironStorageError.checkShared(oneiron_shared_outcome_committed(handle, &committed))
        return committed != 0
    }

    /// The actual held vault's path on success. Import failure always throws, never an empty
    /// or fabricated success path. Native MemoryError bytes remain in memoryError().
    public func vaultPath() throws -> String {
        try sharedString { oneiron_shared_outcome_vault_path(handle, $0) }
    }

    /// Non-consuming read of the original native MemoryError. Nil means success or a
    /// non-MemoryError failure; vaultPath() still reports any such engine failure.
    public func memoryError() throws -> SharedMemoryError? {
        let json = try sharedBuffer { oneiron_shared_outcome_error_json(handle, $0) }
        return json.isEmpty ? nil : SharedMemoryError(json: json)
    }
}

private func sharedBuffer(
    _ read: (UnsafeMutablePointer<OneironBuffer>) -> OneironStatus
) throws -> Data {
    var buffer = OneironBuffer(ptr: nil, len: 0, cap: 0)
    let status = read(&buffer)
    defer { _ = oneiron_buffer_free(buffer) }
    try OneironStorageError.checkShared(status)
    return sharedBytes(buffer)
}

private func sharedString(
    _ read: (UnsafeMutablePointer<OneironBuffer>) -> OneironStatus
) throws -> String {
    guard let text = try String(data: sharedBuffer(read), encoding: .utf8) else {
        throw OneironStorageError.utf8
    }
    return text
}

private func sharedBytes(_ buffer: OneironBuffer) -> Data {
    guard let ptr = buffer.ptr else { return Data() }
    return Data(bytes: ptr, count: buffer.len)
}

private func sharedWithBytes<R>(
    _ data: Data, _ body: (UnsafePointer<UInt8>, Int) -> R
) -> R {
    var placeholder: UInt8 = 0
    return data.withUnsafeBytes { raw in
        if let base = raw.bindMemory(to: UInt8.self).baseAddress {
            return body(base, raw.count)
        }
        return withUnsafePointer(to: &placeholder) { body($0, 0) }
    }
}
