use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn verify_signature(secret: &[u8], body: &[u8], supplied: &str) -> Result<(), String> {
    let Some(hex_sig) = supplied.strip_prefix("sha256=") else {
        return Err("signature must start with sha256=".to_string());
    };

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| "invalid secret".to_string())?;
    mac.update(body);
    let computed = hex::encode(mac.finalize().into_bytes());

    if computed == hex_sig {
        Ok(())
    } else {
        Err("signature mismatch".to_string())
    }
}
