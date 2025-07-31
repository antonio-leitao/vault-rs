# Cross-Platform Crypto Build and Usage Guide

## Simple API Overview

```rust
// Encrypt
let encrypted = encrypt_json(&data, password)?;

// Decrypt
let decrypted: T = decrypt_json(&encrypted, password)?;
```

That's it! No configuration needed. Uses high-security Argon2id + AES-256-GCM automatically.

## Building for Native (CLI)

```bash
# Build for native
cargo build --release

# Run tests
cargo test
```

## Building for WASM (Browser)

### 1. Install wasm-pack

```bash
cargo install wasm-pack
```

### 2. Build WASM module

```bash
# Build for web
wasm-pack build --target web --out-dir pkg

# Or for bundler (webpack, etc.)
wasm-pack build --target bundler --out-dir pkg

# Or for Node.js
wasm-pack build --target nodejs --out-dir pkg
```

### 3. Optional: Optimize WASM size

```bash
# Install wasm-opt
npm install -g wasm-opt

# Optimize the WASM file
wasm-opt -Oz pkg/secure_crypto_bg.wasm -o pkg/secure_crypto_bg.wasm
```

## Usage Examples

### Native Rust (CLI)

```rust
use secure_crypto::{encrypt_json, decrypt_json, EncryptedPayload};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_data = json!({
        "api_key": "secret-123",
        "user": "john_doe"
    });

    let password = b"my-secure-password";

    // Encrypt (always uses high security: 256MB RAM, 4 iterations)
    let encrypted = encrypt_json(&secret_data, password)?;

    // Save to file
    let encrypted_json = serde_json::to_string_pretty(&encrypted)?;
    std::fs::write("data.enc", encrypted_json)?;

    // Load and decrypt
    let loaded_json = std::fs::read_to_string("data.enc")?;
    let loaded_payload: EncryptedPayload = serde_json::from_str(&loaded_json)?;

    let decrypted: serde_json::Value = decrypt_json(&loaded_payload, password)?;
    println!("Decrypted: {}", serde_json::to_string_pretty(&decrypted)?);

    Ok(())
}
```

### Browser JavaScript

```html
<!doctype html>
<html>
  <head>
    <title>Secure Crypto Demo</title>
  </head>
  <body>
    <script type="module">
      import init, { WasmCrypto } from "./pkg/secure_crypto.js";

      async function demo() {
        // Initialize WASM
        await init();

        // Create crypto instance
        const crypto = new WasmCrypto();

        // Your sensitive data
        const data = {
          apiKey: "secret-123",
          user: "john_doe",
        };

        const password = "my-secure-password";

        // Encrypt
        const encrypted = crypto.encrypt_json(JSON.stringify(data), password);
        console.log("Encrypted:", encrypted);

        // Decrypt
        const decrypted = crypto.decrypt_json(encrypted, password);
        console.log("Decrypted:", JSON.parse(decrypted));

        // The encrypted data is compatible with Rust CLI!
        console.log("Save this JSON to decrypt with Rust:", encrypted);
      }

      demo().catch(console.error);
    </script>
  </body>
</html>
```

### Node.js

```javascript
const { WasmCrypto } = require("./pkg/secure_crypto.js");

async function demo() {
  const crypto = new WasmCrypto();

  const data = { secret: "my-secret-data" };
  const password = "strong-password";

  // Encrypt
  const encrypted = crypto.encrypt_json(JSON.stringify(data), password);

  // Decrypt
  const decrypted = crypto.decrypt_json(encrypted, password);
  console.log(JSON.parse(decrypted));
}

demo();
```

## Important Notes

### Hardcoded Security Parameters

The implementation uses high-security Argon2id parameters:

- **Memory**: 256 MiB
- **Iterations**: 4
- **Parallelism**: 8 threads

This provides ~1-2 seconds per decryption attempt on modern hardware, making brute force attacks extremely expensive.

### Same Results Guarantee

The implementation ensures identical results across platforms by:

1. Using the same cryptographic algorithms (Argon2id, AES-256-GCM)
2. Using the same parameter configurations
3. Abstracting RNG to use platform-appropriate sources
4. Using the same serialization format (JSON)

### Security Considerations for WASM

1. **Memory Protection**: WASM memory is isolated but can be inspected by JavaScript. Sensitive data is still zeroized after use.
2. **RNG Quality**: Browser's `crypto.getRandomValues()` is cryptographically secure.
3. **Performance**: Argon2 will be slower in WASM than native, but still provides good protection.

### File Size Optimization

WASM build size can be reduced by:

- Using `opt-level = "z"` in Cargo.toml
- Running wasm-opt
- Excluding unused features
- Using `--no-default-features` if applicable

### Performance Expectations

With the hardcoded high-security settings:

- **Native (Rust CLI)**: ~1-2 seconds per encryption/decryption
- **Browser (WASM)**: ~3-5 seconds per encryption/decryption
- **Memory usage**: ~256MB during key derivation

These settings make brute force attacks prohibitively expensive while keeping legitimate use reasonable.

### Testing Cross-Platform Compatibility

Create test vectors in one environment and verify in the other:

```rust
// Generate test vector in Rust
let payload = encrypt(b"test data", b"password", None)?;
println!("Test vector: {}", serde_json::to_string(&payload)?);
```

```javascript
// Verify in browser
const testVector = '{"version":1,"kdf_params":{...},...}';
const decrypted = crypto.decrypt(testVector, "password");
console.log(new TextDecoder().decode(decrypted)); // Should print "test data"
```
