import Foundation
import OneironStorage

enum SmokeError: Error {
    case invalidHealthJSON
    case missingStorageABIVersion
}

let vaultURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("oneiron-storage-smoke-\(UUID().uuidString)", isDirectory: true)

try FileManager.default.createDirectory(at: vaultURL, withIntermediateDirectories: true)
defer {
    try? FileManager.default.removeItem(at: vaultURL)
}

do {
    let vault = try Vault.open(path: vaultURL.path)
    let healthData = try vault.healthJSONData()
    let healthObject = try JSONSerialization.jsonObject(with: healthData)
    guard let health = healthObject as? [String: Any] else {
        throw SmokeError.invalidHealthJSON
    }
    guard health["storage_abi_version"] != nil else {
        throw SmokeError.missingStorageABIVersion
    }
}

print("oneiron storage smoke ok")
