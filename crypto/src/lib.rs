use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// --- Hardcoded high security parameters ---
const ARGON2_MEMORY_COST: u32 = 262144; // 256 MiB
const ARGON2_TIME_COST: u32 = 4; // 4 iterations
const ARGON2_PARALLELISM: u32 = 8; // 8 threads
const CURRENT_VERSION: u8 = 1;

// --- Error types ---
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Argon2 error: {0}")]
    Argon2Error(String),

    #[error("Invalid salt format")]
    InvalidSalt,

    #[error("Encryption failed")]
    EncryptionError,

    #[error("Decryption failed - wrong password or corrupted data")]
    DecryptionError,

    #[error("Unsupported encryption version: {0}")]
    UnsupportedVersion(u8),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Random number generation failed")]
    RandomGenerationError,
}

// --- Encrypted payload ---
// Note: The salt is not secret and is safe to store publicly.
// Its purpose is to prevent rainbow table attacks and ensure
// unique outputs even when the same password is used multiple times.
#[derive(Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub version: u8,
    pub salt: String,   // Base64-encoded salt (safe to be public)
    pub nonce: Vec<u8>, // AES-GCM nonce (safe to be public)
    pub ciphertext: Vec<u8>,
}

// --- Platform-specific random number generation ---
#[cfg(not(target_arch = "wasm32"))]
fn fill_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(dest);
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn fill_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    use web_sys::window;

    let window = window().ok_or(CryptoError::RandomGenerationError)?;
    let crypto = window
        .crypto()
        .map_err(|_| CryptoError::RandomGenerationError)?;

    crypto
        .get_random_values_with_u8_array(dest)
        .map_err(|_| CryptoError::RandomGenerationError)?;

    Ok(())
}

// --- Key derivation ---
#[derive(ZeroizeOnDrop)]
struct SecureKey {
    #[zeroize(drop)]
    bytes: [u8; 32],
}

fn derive_key(password: &[u8], salt_bytes: &[u8]) -> Result<SecureKey, CryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| CryptoError::Argon2Error(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password, salt_bytes, &mut key_bytes)
        .map_err(|e| CryptoError::Argon2Error(e.to_string()))?;

    Ok(SecureKey { bytes: key_bytes })
}

// --- Core encryption/decryption functions ---
pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<EncryptedPayload, CryptoError> {
    // Generate salt
    let mut salt_bytes = [0u8; 16];
    fill_random(&mut salt_bytes)?;

    // Derive key using raw salt bytes
    let key = derive_key(password, &salt_bytes)?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key.bytes);

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    fill_random(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let cipher = Aes256Gcm::new(aes_key);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionError)?;

    // Encode salt as base64 for storage
    use base64::{Engine, engine::general_purpose::STANDARD};
    let salt_b64 = STANDARD.encode(&salt_bytes);

    Ok(EncryptedPayload {
        version: CURRENT_VERSION,
        salt: salt_b64,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

pub fn decrypt(payload: &EncryptedPayload, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Check version
    if payload.version != CURRENT_VERSION {
        return Err(CryptoError::UnsupportedVersion(payload.version));
    }

    // Decode salt from base64
    use base64::{Engine, engine::general_purpose::STANDARD};
    let salt_bytes = STANDARD
        .decode(&payload.salt)
        .map_err(|_| CryptoError::InvalidSalt)?;

    // Derive key using raw salt bytes
    let key = derive_key(password, &salt_bytes)?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key.bytes);

    // Decrypt
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&payload.nonce);

    cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionError)
}

// --- JSON convenience functions ---
pub fn encrypt_json<T: Serialize>(
    data: &T,
    password: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    let json =
        serde_json::to_vec(data).map_err(|e| CryptoError::SerializationError(e.to_string()))?;
    encrypt(&json, password)
}

pub fn decrypt_json<T: for<'de> Deserialize<'de>>(
    payload: &EncryptedPayload,
    password: &[u8],
) -> Result<T, CryptoError> {
    let plaintext = decrypt(payload, password)?;
    serde_json::from_slice(&plaintext).map_err(|e| CryptoError::SerializationError(e.to_string()))
}

// --- WASM bindings ---
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct WasmCrypto;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl WasmCrypto {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        WasmCrypto
    }

    pub fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<String, JsValue> {
        let payload = crate::encrypt(plaintext, password.as_bytes())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_json::to_string(&payload).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn decrypt(&self, payload_json: &str, password: &str) -> Result<Vec<u8>, JsValue> {
        let payload: EncryptedPayload =
            serde_json::from_str(payload_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        crate::decrypt(&payload, password.as_bytes()).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn encrypt_json(&self, json: &str, password: &str) -> Result<String, JsValue> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let payload = crate::encrypt_json(&value, password.as_bytes())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_json::to_string(&payload).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn decrypt_json(&self, payload_json: &str, password: &str) -> Result<String, JsValue> {
        let payload: EncryptedPayload =
            serde_json::from_str(payload_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let value: serde_json::Value = crate::decrypt_json(&payload, password.as_bytes())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_json::to_string(&value).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_encrypt_decrypt() {
        let data = json!({
            "secret": "my secret data",
            "number": 42
        });

        let password = b"my-strong-password";

        let encrypted = encrypt_json(&data, password).expect("Encryption failed");
        let decrypted: serde_json::Value =
            decrypt_json(&encrypted, password).expect("Decryption failed");

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let data = json!({"secret": "data"});
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        let encrypted = encrypt_json(&data, password).expect("Encryption failed");
        let result = decrypt_json::<serde_json::Value>(&encrypted, wrong_password);

        assert!(matches!(result, Err(CryptoError::DecryptionError)));
    }

    #[test]
    fn test_raw_bytes() {
        let data = b"raw byte data";
        let password = b"test-password";

        let encrypted = encrypt(data, password).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, password).expect("Decryption failed");

        assert_eq!(data.to_vec(), decrypted);
    }
}
