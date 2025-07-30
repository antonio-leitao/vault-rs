use serde::{Deserialize, Serialize};
use vault_crypto::{EncryptedPayload, decrypt, encrypt};
use wasm_bindgen::prelude::*;

// This custom struct is identical to EncryptedPayload, but adds
// Serialize and Deserialize so we can easily convert it to a JSON string.
#[derive(Serialize, Deserialize)]
struct SerializablePayload {
    pub salt: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// When the WASM is loaded, this function will be called.
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    // Use `web_sys`'s `console.log` to prove we loaded successfully.
    web_sys::console::log_1(&"WASM module for vault has been loaded.".into());
    Ok(())
}

#[wasm_bindgen]
pub fn encrypt_wrapper(plaintext: &[u8], password: &str) -> Result<String, JsValue> {
    // Call our real Rust crypto function
    match encrypt(plaintext, password.as_bytes()) {
        Ok(payload) => {
            // Convert our EncryptedPayload to the serializable version
            let serializable = SerializablePayload {
                salt: payload.salt,
                nonce: payload.nonce,
                ciphertext: payload.ciphertext,
            };
            // Return it as a JSON string to JavaScript
            Ok(serde_json::to_string(&serializable).unwrap())
        }
        // If encryption fails, convert the error into a JavaScript Error object
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn decrypt_wrapper(json_payload: &str, password: &str) -> Result<Vec<u8>, JsValue> {
    // Parse the JSON string from JavaScript into our serializable struct
    let serializable: SerializablePayload = match serde_json::from_str(json_payload) {
        Ok(p) => p,
        Err(_) => {
            return Err(JsValue::from_str(
                "Invalid payload format (not valid JSON).",
            ));
        }
    };

    // Convert back to the EncryptedPayload our crypto function expects
    let payload = EncryptedPayload {
        salt: serializable.salt,
        nonce: serializable.nonce,
        ciphertext: serializable.ciphertext,
    };

    // Call our real Rust decrypt function
    match decrypt(&payload, password.as_bytes()) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}
