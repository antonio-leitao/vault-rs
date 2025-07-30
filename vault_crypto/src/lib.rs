use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use thiserror::Error;

// --- Define our custom Error type for clear, specific errors ---
#[derive(Error, Debug)]
pub enum CryptoError {
    // FIX 2: This now correctly uses `argon2::Error` which is what the hasher returns.
    #[error("Argon2 password hashing failed: {0:?}")]
    Argon2Error(argon2::Error),
    #[error(
        "AES-256-GCM encryption/decryption failed - this often indicates a wrong password or corrupted data"
    )]
    AesError,
    #[error("Failed to convert salt from/to string: {0:?}")]
    SaltError(argon2::password_hash::Error),
}

// --- Define the structure of our encrypted payload ---
// This is what we'll serialize/deserialize to/from the `data.enc` file.
// For now, we'll just store the raw bytes. We could use serde later.
pub struct EncryptedPayload {
    pub salt: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Derives a 32-byte encryption key from a user password and a salt.
/// This uses Argon2, which is deliberately slow to thwart brute-force attacks.
fn derive_key(password: &[u8], salt: &SaltString) -> Result<[u8; 32], CryptoError> {
    println!("[CRYPTO-LOGIC] Deriving encryption key using Argon2 (this should be slow)...");
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt.as_ref().as_bytes(), &mut key)
        .map_err(CryptoError::Argon2Error)?;
    println!("[CRYPTO-LOGIC] Key derived successfully.");
    Ok(key)
}

pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<EncryptedPayload, CryptoError> {
    println!("[CRYPTO-LOGIC] Starting encryption process...");
    let salt = SaltString::generate(&mut OsRng);
    println!("[CRYPTO-LOGIC] Generated a new random salt.");

    let key_bytes = derive_key(password, &salt)?;
    let key = key_bytes.into();
    let cipher = Aes256Gcm::new(&key);

    // `generate_nonce` is from the `AeadCore` trait we imported.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    println!("[CRYPTO-LOGIC] Generated a new random nonce.");

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        // We map the unit-like `aes_gcm::Error` to our more descriptive variant.
        .map_err(|_| CryptoError::AesError)?;
    println!("[CRYPTO-LOGIC] Encryption complete.");

    Ok(EncryptedPayload {
        // <-- FIX 5: Convert SaltString to a regular String for storage.
        salt: salt.to_string(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

pub fn decrypt(payload: &EncryptedPayload, password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    println!("[CRYPTO-LOGIC] Starting decryption process...");

    // <-- FIX 6: Recreate the SaltString from the stored string.
    let salt = SaltString::from_b64(&payload.salt).map_err(CryptoError::SaltError)?;

    let key_bytes = derive_key(password, &salt)?;
    let key = key_bytes.into();

    // <-- FIX 7: Corrected typo from `Aes25Gcm` to `Aes256Gcm`
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(&payload.nonce);

    let plaintext = cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|_| CryptoError::AesError)?;

    println!("[CRYPTO-LOGIC] Decryption and authentication successful!");
    Ok(plaintext)
}
