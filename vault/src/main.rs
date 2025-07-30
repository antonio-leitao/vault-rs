use clap::{Args, Parser, Subcommand};
use serde_json::Value;
use vault_crypto::{CryptoError, EncryptedPayload, decrypt, encrypt};
// --- 1. DEFINE THE CLI STRUCTURE (REDUCED) ---
#[derive(Parser, Debug)]
#[command(author, version, about = "A secure, Git-backed secret manager.", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// Enum for subcommands, with Dump and Edit removed.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Initializes a new vault and links it to a remote Git repository
    Init(InitArgs),
    #[command(alias = "ls")]
    /// Lists all top-level secret keys
    List,
    /// Retrieves a secret from the vault
    Get(GetArgs),
    /// Adds or updates a secret in the vault
    Set(SetArgs),
    /// Removes a secret from the vault
    Rm(RmArgs),
    /// Forces a synchronization with the remote repository
    Sync,
    /// Shows the current status of the vault (remote, last sync)
    Status,
}

// Argument structs remain the same.
#[derive(Args, Debug)]
struct InitArgs {
    remote_url: String,
}
#[derive(Args, Debug)]
struct GetArgs {
    key: String,
}
#[derive(Args, Debug)]
struct SetArgs {
    key: String,
    value: String,
}
#[derive(Args, Debug)]
struct RmArgs {
    key: String,
}

// --- 2. MAIN FUNCTION - THE DISPATCHER ---
fn main() {
    let cli = Cli::parse();

    // The match statement now has fewer arms.
    match cli.command {
        Commands::Init(args) => handle_init(args),
        Commands::List => handle_list(),
        Commands::Get(args) => handle_get(args),
        Commands::Set(args) => handle_set(args),
        Commands::Rm(args) => handle_rm(args),
        Commands::Sync => {
            if let Err(_) = handle_git_sync() {
                println!(
                    "[ERROR] Manual sync failed. Please check your connection and Git configuration."
                );
            }
        }
        Commands::Status => handle_status(),
    }
}

// --- 3. COMMAND HANDLERS (WITH BRANCHING LOGIC) ---

fn handle_init(args: InitArgs) {
    println!("--- Command: vault init ---");
    println!("1. Check for existing configuration...");
    println!("2. Prompt for a new master password and confirm it.");
    let master_password = "a_very_strong_password_from_user"; // Hardcoded for testing

    println!("3. Create an initial, empty JSON object as plaintext.");
    let initial_data = serde_json::to_vec(&serde_json::json!({})).unwrap();

    println!("4. Encrypt the initial empty data.");
    match encrypt(&initial_data, master_password.as_bytes()) {
        Ok(payload) => {
            println!("[SUCCESS] Initial empty vault encrypted successfully.");
            // In a real implementation, we would now save this 'payload' to a file.
            // For now, we just show it's working.
            save_and_sync_vault(payload, "Initial commit".to_string()).unwrap();
        }
        Err(e) => {
            println!("[CRITICAL ERROR] Failed to encrypt initial vault: {}", e);
        }
    }
}

fn handle_list() {
    println!("--- Command: vault list ---");
    match load_decrypted_vault() {
        Ok(json_data) => {
            println!("5. Parse the decrypted JSON.");
            if let Some(obj) = json_data.as_object() {
                println!("Available keys:");
                for key in obj.keys() {
                    println!("- {}", key);
                }
            }
        }
        Err(_) => {
            println!("[ERROR] Could not list secrets. Aborting.");
        }
    }
}

fn handle_get(args: GetArgs) {
    println!("--- Command: vault get ---");
    match load_decrypted_vault() {
        Ok(json_data) => {
            println!("5. Parse decrypted JSON and find key '{}'.", args.key);
            // This is a simplified search. A real one would handle nested keys.
            if let Some(value) = json_data.get(&args.key) {
                println!("\nValue for '{}': {}", args.key, value);
            } else {
                println!("[ERROR] The key '{}' was not found in the vault.", args.key);
            }
        }
        Err(_) => {
            println!("[ERROR] Could not get secret. Aborting.");
        }
    }
}

fn handle_set(args: SetArgs) {
    println!("--- Command: vault set ---");
    match load_decrypted_vault() {
        Ok(mut json_data) => {
            println!("5. Parse decrypted JSON.");
            println!("6. Add or update the key '{}'.", args.key);
            // Simplified update logic
            if let Some(obj) = json_data.as_object_mut() {
                obj.insert(args.key.clone(), Value::String(args.value));
            }

            println!("7. Re-encrypting modified data...");
            let master_password = "a_very_strong_password_from_user";
            let modified_plaintext = serde_json::to_vec(&json_data).unwrap();

            match encrypt(&modified_plaintext, master_password.as_bytes()) {
                Ok(new_payload) => {
                    let commit_message = format!("Update secret: {}", args.key);
                    if let Err(_) = save_and_sync_vault(new_payload, commit_message) {
                        println!(
                            "[ERROR] Secret was updated locally, but failed to sync with remote."
                        );
                    }
                }
                Err(e) => println!("[CRITICAL ERROR] Failed to re-encrypt vault: {}", e),
            }
        }
        Err(_) => {
            println!("[ERROR] Could not set secret. Aborting.");
        }
    }
}

fn handle_rm(args: RmArgs) {
    println!("--- Command: vault rm ---");
    println!("[LOGIC] Remove secret with key '{}'", args.key);
    match load_decrypted_vault() {
        Ok(mut json_data) => {
            println!("5. Parse decrypted JSON.");

            // The core logic for removal.
            let key_was_removed = if let Some(obj) = json_data.as_object_mut() {
                // .remove() returns the value if the key existed, or None if it didn't.
                // This is a great way to check if our operation actually did anything.
                obj.remove(&args.key).is_some()
            } else {
                false
            };

            // Check if we actually changed anything before proceeding.
            if !key_was_removed {
                println!("[ERROR] Key '{}' not found. Nothing to remove.", args.key);
                return; // Exit the function early, no need to re-encrypt or save.
            }

            println!(
                "6. Key '{}' found and removed. Re-encrypting vault...",
                args.key
            );
            let master_password = "a_very_strong_password_from_user";
            let modified_plaintext = serde_json::to_vec(&json_data).unwrap();

            match encrypt(&modified_plaintext, master_password.as_bytes()) {
                Ok(new_payload) => {
                    // Create the specific commit message for a removal.
                    let commit_message = format!("Remove secret: {}", args.key);
                    if let Err(_) = save_and_sync_vault(new_payload, commit_message) {
                        println!(
                            "[ERROR] Secret was removed locally, but failed to sync with remote."
                        );
                    }
                }
                Err(e) => println!(
                    "[CRITICAL ERROR] Failed to re-encrypt vault after removal: {}",
                    e
                ),
            }
        }
        Err(_) => {
            println!("[ERROR] Could not remove secret. Aborting.");
        }
    }
}

fn handle_status() {
    println!("--- Command: vault status ---");
    println!("1. Read the configuration file.");
    println!("2. Print the remote repository URL.");
    println!("3. Check the timestamp of the local vault file.");
    println!("4. Print the last sync time.");
}

// --- 4. REFINED REUSABLE LOGIC (WITH FAILURE PATHS) ---

/// Attempts to sync with the remote Git repo.
/// This is now a separate function to be called by others.
/// In a real implementation, this would return a `Result<(), GitError>`.
fn handle_git_sync() -> Result<(), ()> {
    println!("--- Reusable Logic: Syncing with Git remote ---");
    println!("1. Enter the local Git cache directory.");
    println!("2. Run 'git pull' to fetch latest changes.");

    // SIMULATED FAILURE BRANCH (e.g., no internet)
    let git_pull_succeeds = true; // Change to false to see this path
    if git_pull_succeeds {
        println!("[SUCCESS] Local cache is up to date.");
        Ok(())
    } else {
        println!("[WARNING] Could not sync with remote. No internet connection?");
        Err(())
    }
}

/// A more complex workflow to load and decrypt the vault.
/// In a real implementation, this would return `Result<serde_json::Value, AppError>`.
fn load_decrypted_vault() -> Result<Value, ()> {
    println!("--- Reusable Logic: Loading Vault ---");
    if handle_git_sync().is_err() {
        println!("       Proceeding in OFFLINE mode with local cache.");
    }

    // --- TEST SETUP ---
    // Let's create a "real" encrypted payload to test our decryption against.
    let master_password_correct = "a_very_strong_password_from_user";
    let original_data = serde_json::json!({
        "gmail": { "username": "test@gmail.com", "password": "old_password_123" },
        "aws": { "access_key": "AKIA..." }
    });
    let original_plaintext = serde_json::to_vec(&original_data).unwrap();

    // Create the payload to test against, handling the potential error.
    let payload_to_test_against =
        match encrypt(&original_plaintext, master_password_correct.as_bytes()) {
            Ok(payload) => payload,
            Err(e) => {
                println!(
                    "[CRITICAL TEST SETUP ERROR] Could not create test payload: {}",
                    e
                );
                return Err(());
            }
        };
    // --- END TEST SETUP ---

    println!("3. Prompt for the master password (input hidden).");
    // To test failure, change this to an incorrect password
    let user_provided_password = "a_very_strong_password_from_user";
    // let user_provided_password = "the_WRONG_password"; // <-- UNCOMMENT TO TEST WRONG PASSWORD

    println!("4. Read the encrypted vault file from the local cache (simulated).");
    println!("5. Attempting to decrypt vault...");

    // Now we call our REAL decrypt function
    match decrypt(&payload_to_test_against, user_provided_password.as_bytes()) {
        Ok(decrypted_plaintext) => {
            println!("[SUCCESS] Decryption and authentication successful!");
            println!("--- End Reusable Logic ---\n");
            // If successful, parse the bytes into a JSON Value
            match serde_json::from_slice(&decrypted_plaintext) {
                Ok(json) => Ok(json),
                Err(e) => {
                    println!(
                        "[CRITICAL ERROR] Data decrypted but is not valid JSON: {}",
                        e
                    );
                    Err(())
                }
            }
        }
        Err(e) => {
            // This is the CRITICAL failure path for a wrong password
            println!("[ERROR] Decryption failed: {}", e);
            println!("       This almost always means the password was incorrect.");
            println!("--- End Reusable Logic ---\n");
            Err(())
        }
    }
}

fn save_and_sync_vault(payload: EncryptedPayload, commit_message: String) -> Result<(), ()> {
    println!("\n--- Reusable Logic: Saving Vault ---");
    println!("7. Writing encrypted payload to local file (simulated).");
    // In a real app, you'd serialize `payload` (e.g., as JSON or a custom binary format)
    // and write it to `data.enc`.
    println!(
        "   - Salt (len {}): {:?}...",
        payload.salt.len(),
        &payload.salt[..8]
    );
    println!(
        "   - Nonce (len {}): {:?}...",
        payload.nonce.len(),
        &payload.nonce[..8]
    );
    println!(
        "   - Ciphertext (len {}): {:?}...",
        payload.ciphertext.len(),
        &payload.ciphertext[..8]
    );

    println!(
        "8. Commit the change to the local Git repository with message: '{}'",
        commit_message
    );
    println!("9. Run 'git push' to sync the commit to the remote repository.");

    let git_push_succeeds = true;
    if git_push_succeeds {
        println!("[SUCCESS] All changes have been synced to the remote.");
        println!("--- End Reusable Logic ---");
        Ok(())
    } else {
        println!("[ERROR] Failed to push changes to the remote.");
        println!("--- End Reusable Logic ---");
        Err(())
    }
}
