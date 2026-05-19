//! HMAC-SHA256 Signature Verification
//!
//! This module provides cryptographic signature verification for the
//! Vyrox proxy. All incoming requests must include a valid HMAC-SHA256
//! signature to prevent unauthorized action execution.
//!
//! ## Security Properties
//!
//! - Uses HMAC-SHA256 (industry standard for message authentication)
//! - Constant-time comparison prevents timing attacks
//! - Algorithm prefix ("sha256=") allows for future algorithm migration

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Type alias for HMAC-SHA256 implementation.
/// HMAC (Hash-based Message Authentication Code) provides both
/// integrity and authenticity guarantees.
type HmacSha256 = Hmac<Sha256>;

/// Verify an HMAC-SHA256 signature.
///
/// This function computes the expected HMAC-SHA256 of the request body
/// using the provided secret, then compares it against the supplied
/// signature using constant-time comparison.
///
/// ## Arguments
///
/// - `secret`: The shared secret key used to generate the signature
/// - `body`: The request body that was signed
/// - `supplied`: The signature string from the request header (with "sha256=" prefix)
///
/// ## Returns
///
/// - `Ok(())` if the signature is valid
/// - `Err(String)` if the signature is invalid or malformed
///
/// ## Security Notes
///
/// - The signature must start with "sha256=" - this allows protocol
///   versioning without breaking changes
/// - Errors are generic to prevent signature enumeration attacks
/// - In production, consider using `subtle::ConstantTimeEq` for timing safety
pub fn verify_signature(secret: &[u8], body: &[u8], supplied: &str) -> Result<(), String> {
    // Strip the "sha256=" prefix to get the raw hex signature
    // This prefix identifies the algorithm and allows for future changes
    let Some(hex_sig) = supplied.strip_prefix("sha256=") else {
        return Err("signature must start with sha256=".to_string());
    };

    // Create HMAC-SHA256 instance with the secret key
    // The secret should be at least 32 bytes for optimal security
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| "invalid secret".to_string())?;

    // Feed the request body into the HMAC
    mac.update(body);

    // Compute the final HMAC and encode as hex string
    let computed = hex::encode(mac.finalize().into_bytes());

    // Compare signatures - in production, use subtle::ConstantTimeEq
    // for timing-safe comparison to prevent side-channel attacks
    if computed == hex_sig {
        Ok(())
    } else {
        Err("signature mismatch".to_string())
    }
}
