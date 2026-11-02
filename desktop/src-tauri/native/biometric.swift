// Touch ID unlock through a Secure Enclave key. CryptoKit keeps the key as a blob
// only this Mac's Secure Enclave can use, so no Keychain entitlement or Apple
// Developer signature is needed. The key is usable only after a successful check
// of the fingerprints enrolled when it was made: adding or removing a finger ends it.
//
// The 32-byte secret comes from a key agreement between that key and a throwaway
// public key, so it exists only while the Secure Enclave allows it. The vault key
// never comes here: the Python core wraps it under this secret.
import CryptoKit
import Foundation
import LocalAuthentication

private let ok: Int32 = 0
private let cancelled: Int32 = 1
private let invalidKey: Int32 = 2
private let unavailable: Int32 = 3
private let failed: Int32 = 4
private let publicKeyBytes = 65
private let secretBytes = 32
private let secretLabel = Data("ciphermoth/v2/secure-enclave-secret".utf8)

@_cdecl("cm_biometric_available")
public func cmBiometricAvailable() -> Int32 {
    var error: NSError?
    let usable = LAContext().canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics, error: &error)
    return SecureEnclave.isAvailable && usable ? 1 : 0
}

private func authorized(reason: String) -> (LAContext?, Int32) {
    let context = LAContext()
    let done = DispatchSemaphore(value: 0)
    var outcome = failed
    context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics, localizedReason: reason
    ) { success, error in
        if success {
            outcome = ok
        } else if let error = error as? LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                outcome = cancelled
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout:
                outcome = unavailable
            default:
                outcome = failed
            }
        }
        done.signal()
    }
    done.wait()
    return (outcome == ok ? context : nil, outcome)
}

private func secret(
    key: SecureEnclave.P256.KeyAgreement.PrivateKey,
    peer: P256.KeyAgreement.PublicKey
) throws -> Data {
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    let derived = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: Data(), sharedInfo: secretLabel,
        outputByteCount: secretBytes)
    return derived.withUnsafeBytes { Data($0) }
}

private func copy(_ data: Data, to out: UnsafeMutablePointer<UInt8>, capacity: Int) -> Bool {
    guard data.count <= capacity else { return false }
    data.copyBytes(to: out, count: data.count)
    return true
}

/// Writes the material to store (peer public key, then key blob) and the secret.
@_cdecl("cm_biometric_enroll")
public func cmBiometricEnroll(
    _ material: UnsafeMutablePointer<UInt8>, _ materialCapacity: Int,
    _ materialLength: UnsafeMutablePointer<Int>,
    _ secretOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return unavailable }
    let (context, outcome) = authorized(reason: "turn on Touch ID for your CipherMoth vault")
    guard let context else { return outcome }
    guard
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], nil)
    else { return failed }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: access, authenticationContext: context)
        let peer = P256.KeyAgreement.PrivateKey().publicKey
        var stored = peer.x963Representation
        stored.append(key.dataRepresentation)
        guard copy(stored, to: material, capacity: materialCapacity) else { return failed }
        materialLength.pointee = stored.count
        _ = copy(try secret(key: key, peer: peer), to: secretOut, capacity: secretBytes)
        return ok
    } catch {
        return failed
    }
}

@_cdecl("cm_biometric_derive")
public func cmBiometricDerive(
    _ material: UnsafePointer<UInt8>, _ materialLength: Int,
    _ secretOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return unavailable }
    guard materialLength > publicKeyBytes else { return invalidKey }
    let stored = Data(bytes: material, count: materialLength)
    let (context, outcome) = authorized(reason: "unlock your CipherMoth vault")
    guard let context else { return outcome }
    do {
        let peer = try P256.KeyAgreement.PublicKey(
            x963Representation: stored.prefix(publicKeyBytes))
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: stored.dropFirst(publicKeyBytes),
            authenticationContext: context)
        _ = copy(try secret(key: key, peer: peer), to: secretOut, capacity: secretBytes)
        return ok
    } catch {
        // The fingerprint check above passed, so the key itself is what failed:
        // fingerprints changed, or this blob belongs to another Mac.
        return invalidKey
    }
}
