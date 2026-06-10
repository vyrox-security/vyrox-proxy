//! HMAC-SHA256 Signature Verification
//!
//! This module is the only authentication boundary the proxy has. Every
//! call to `/execute` runs through `verify_signature`. If this module is
//! wrong, an attacker can execute arbitrary containment actions on
//! customer endpoints. Treat it as security-critical.
//!
//! ## Security Properties
//!
//! - **HMAC-SHA256** - industry-standard authenticated MAC. 32-byte output.
//! - **Constant-time comparison** - uses `subtle::ConstantTimeEq` so the
//!   number of CPU cycles spent comparing two signatures does not depend on
//!   how many leading bytes match. Defeats timing side-channel attacks where
//!   an attacker measures response latency to learn the expected signature
//!   one byte at a time.
//! - **Algorithm prefix** (`sha256=`) - allows for future migration to
//!   stronger MACs without breaking older clients.
//! - **Generic error messages** - error strings never leak which part of the
//!   verification failed (prefix, secret length, signature mismatch all
//!   collapse to caller-side `UNAUTHORIZED`). Prevents signature enumeration.
//!
//! ## Threat Model
//!
//! Out of scope for this module:
//! - Replay attacks (handled separately in `main.rs::check_replay_window`).
//! - Duplicate request execution (handled separately by the nonce store).
//! - Secret rotation (handled by the deployment environment).
//!
//! In scope:
//! - Forging a signature without knowing the shared secret.
//! - Recovering the expected signature via timing side channels.
//! - Trivial typos (malformed signatures) being silently accepted.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Type alias for HMAC-SHA256.
///
/// HMAC (Hash-based Message Authentication Code, RFC 2104) provides both
/// integrity (the message wasn't tampered with) and authenticity (the
/// sender knew the shared secret).
type HmacSha256 = Hmac<Sha256>;

/// Prefix used to identify the MAC algorithm in the wire format.
///
/// A signature header looks like: `sha256=<64 hex chars>`. Future protocol
/// versions can add `sha512=...` or `blake3=...` without breaking clients.
const ALG_PREFIX: &str = "sha256=";

/// Verify an HMAC-SHA256 signature against the request body using a
/// constant-time comparison.
///
/// # Algorithm
///
/// 1. Strip the `sha256=` prefix from the supplied signature. If the prefix
///    is missing, reject. We accept *only* signatures with the prefix so
///    that future algorithm rotations are unambiguous.
/// 2. Hex-decode the supplied signature into raw bytes. If decoding fails
///    (odd length, non-hex chars), reject. We compare raw bytes, not hex
///    strings - hex-string comparison would still be timing-safe with
///    `ConstantTimeEq`, but raw-byte comparison is half the work and the
///    canonical form.
/// 3. Compute the expected HMAC-SHA256 of `body` using `secret`.
/// 4. Compare the supplied and computed MACs with `ConstantTimeEq`. The
///    `ct_eq` method evaluates to `Choice(1)` if equal and `Choice(0)` if
///    not, and runs in time proportional to MAC length regardless of where
///    the first byte difference appears.
///
/// # Arguments
///
/// - `secret`: Shared secret key. SHOULD be ≥32 bytes of cryptographic
///   randomness (the same size as the MAC output, per RFC 2104). Shorter
///   secrets work but reduce security margin.
/// - `body`: Exact bytes that were signed by the client. Must match
///   byte-for-byte; even reordering JSON keys upstream will break
///   verification. The caller is responsible for using the *raw* request
///   body, not a re-serialized version.
/// - `supplied`: Signature string from the request header, e.g.
///   `sha256=a1b2c3...`. Must include the algorithm prefix.
///
/// # Returns
///
/// - `Ok(())` if the signature is valid.
/// - `Err(VerifyError)` otherwise. The caller MUST translate every error
///   variant into the same HTTP response (typically 401) so that the
///   variant itself is not observable to an attacker.
///
/// # Example
///
/// ```ignore
/// // Inside a handler:
/// let sig = headers
///     .get("X-Vyrox-Signature")
///     .and_then(|v| v.to_str().ok())
///     .ok_or(StatusCode::UNAUTHORIZED)?;
/// hmac::verify_signature(secret.as_bytes(), &body, sig)
///     .map_err(|_| StatusCode::UNAUTHORIZED)?;
/// ```
pub fn verify_signature(secret: &[u8], body: &[u8], supplied: &str) -> Result<(), VerifyError> {
    // 1. Strip prefix. We reject signatures without the algorithm tag so that
    //    we never accidentally compare against a signature computed under a
    //    different algorithm. A bare hex string is not acceptable.
    let hex_sig = supplied
        .strip_prefix(ALG_PREFIX)
        .ok_or(VerifyError::MissingPrefix)?;

    // 2. Hex-decode. Reject malformed input early - there is no scenario
    //    where a typo in the hex string should be silently treated as a
    //    valid-but-mismatched signature.
    let supplied_bytes = hex::decode(hex_sig).map_err(|_| VerifyError::MalformedSignature)?;

    // SHA-256 output is exactly 32 bytes. If the caller sent something
    // longer or shorter, it cannot possibly match. Reject before doing the
    // expensive MAC computation.
    if supplied_bytes.len() != 32 {
        return Err(VerifyError::Mismatch);
    }

    // 3. Compute the expected MAC over the body.
    //
    //    `new_from_slice` only fails if the key length is incompatible with
    //    the underlying hash. SHA-256 HMAC accepts any key length, so this
    //    error path is in practice unreachable - but we still surface it
    //    explicitly rather than `expect`-ing, because panicking inside a
    //    request handler turns a config bug into a denial-of-service.
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| VerifyError::InvalidSecret)?;
    mac.update(body);
    let computed = mac.finalize().into_bytes();

    // 4. Constant-time comparison. `ConstantTimeEq` returns a `Choice`,
    //    which is a `u8` wrapper that resists branch-prediction-based
    //    leakage. Converting to bool with `.into()` is also constant-time
    //    because the conversion only does bit-masking, no branches.
    //
    //    Why this matters: a naive `computed[..] == supplied_bytes[..]`
    //    short-circuits on the first byte mismatch, letting an attacker
    //    measure response latency to recover the expected signature one
    //    byte at a time over millions of attempts.
    if computed.ct_eq(&supplied_bytes).into() {
        Ok(())
    } else {
        Err(VerifyError::Mismatch)
    }
}

/// Reasons a signature could fail verification.
///
/// The variants exist for logging and metrics. Callers MUST collapse all
/// variants into a single response (e.g. 401 Unauthorized) on the wire so
/// that the variant is not observable to an attacker. Use the variants
/// internally for `tracing` output only.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Signature header did not start with `sha256=`.
    #[error("signature missing algorithm prefix")]
    MissingPrefix,

    /// Signature was not valid hex or had wrong length.
    #[error("signature is malformed")]
    MalformedSignature,

    /// HMAC secret key was rejected by the underlying primitive.
    /// This is a configuration error, not a client error.
    #[error("hmac secret is invalid")]
    InvalidSecret,

    /// Signature did not match the computed MAC.
    /// This is the only variant an attacker can normally cause.
    #[error("signature mismatch")]
    Mismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A known secret used across tests. In real deployments this comes from
    /// the environment, never the source code.
    const TEST_SECRET: &[u8] = b"test-secret-32-bytes-long-padding";

    /// Compute a valid signature for use in positive-path tests.
    /// Mirrors what the Python client does, so that the cross-service
    /// contract is exercised by the test suite.
    fn sign(secret: &[u8], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).expect("test secret");
        mac.update(body);
        format!("{}{}", ALG_PREFIX, hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn accepts_valid_signature() {
        let body = br#"{"hello":"world"}"#;
        let sig = sign(TEST_SECRET, body);
        assert!(verify_signature(TEST_SECRET, body, &sig).is_ok());
    }

    #[test]
    fn rejects_missing_prefix() {
        let body = br#"{"hello":"world"}"#;
        let raw_hex = sign(TEST_SECRET, body)
            .strip_prefix(ALG_PREFIX)
            .unwrap()
            .to_string();
        let err = verify_signature(TEST_SECRET, body, &raw_hex).unwrap_err();
        assert!(matches!(err, VerifyError::MissingPrefix));
    }

    #[test]
    fn rejects_malformed_hex() {
        let body = br#"{"hello":"world"}"#;
        let err = verify_signature(TEST_SECRET, body, "sha256=not-hex").unwrap_err();
        assert!(matches!(err, VerifyError::MalformedSignature));
    }

    #[test]
    fn rejects_wrong_length_signature() {
        // 16 hex chars = 8 bytes (half a SHA-256). Must be rejected.
        let body = br#"{"hello":"world"}"#;
        let err = verify_signature(TEST_SECRET, body, "sha256=0011223344556677").unwrap_err();
        assert!(matches!(err, VerifyError::Mismatch));
    }

    #[test]
    fn rejects_wrong_secret() {
        let body = br#"{"hello":"world"}"#;
        let sig = sign(TEST_SECRET, body);
        let err = verify_signature(b"different-secret-32-bytes-padding", body, &sig).unwrap_err();
        assert!(matches!(err, VerifyError::Mismatch));
    }

    #[test]
    fn rejects_tampered_body() {
        let original = br#"{"action":"isolate","host":"a"}"#;
        let tampered = br#"{"action":"isolate","host":"b"}"#;
        let sig = sign(TEST_SECRET, original);
        let err = verify_signature(TEST_SECRET, tampered, &sig).unwrap_err();
        assert!(matches!(err, VerifyError::Mismatch));
    }
}
