use chrono;
use clap::{Args, Parser, Subcommand};
use crypto::{CryptoError, EncryptedPayload, decrypt, encrypt};
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::{Map, Value};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use thiserror::Error;

// --- Constants ---
const CONFIG_DIR: &str = ".creds";
const VAULT_FILE: &str = "vault.enc";
const CONFIG_FILE: &str = "config.json";

// --- Error handling ---
#[derive(Error, Debug)]
enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Git error: {0}")]
    Git(String),

    #[error("Vault not initialized. Run 'creds init <remote-url>' first")]
    NotInitialized,

    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

// --- CLI Structure ---
#[derive(Parser, Debug)]
#[command(author, version, about = "A secure, Git-backed secret manager.", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

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

    #[command(alias = "passwd")]
    /// Changes the master password for the vault
    ChangePassword,
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Remote Git repository URL (optional, will prompt if not provided)
    remote_url: Option<String>,
}

#[derive(Args, Debug)]
struct GetArgs {
    /// Key to retrieve (supports dot notation: gmail.password)
    key: String,
}

#[derive(Args, Debug)]
struct SetArgs {
    /// Key to set (supports dot notation: gmail.password)
    key: String,
    /// Value to set
    value: String,
}

#[derive(Args, Debug)]
struct RmArgs {
    /// Key to remove (supports dot notation)
    key: String,
}

// --- Config structure ---
#[derive(serde::Serialize, serde::Deserialize)]
struct Config {
    remote_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_sync: Option<String>,
}

// --- Main ---
fn main() {
    let cli = Cli::parse();

    if let Err(e) = run_command(cli.command) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run_command(command: Commands) -> Result<(), AppError> {
    match command {
        Commands::Init(args) => handle_init(args),
        Commands::List => handle_list(),
        Commands::Get(args) => handle_get(args),
        Commands::Set(args) => handle_set(args),
        Commands::Rm(args) => handle_rm(args),
        Commands::Sync => handle_sync(),
        Commands::Status => handle_status(),
        Commands::ChangePassword => handle_change_password(),
    }
}

// --- Command Handlers ---

fn handle_init(args: InitArgs) -> Result<(), AppError> {
    let config_dir = get_config_dir()?;

    // Check if already initialized
    if config_dir.exists() {
        eprintln!("Vault already initialized in {}", config_dir.display());
        return Ok(());
    }

    // Get remote URL
    let remote_url = match args.remote_url {
        Some(url) => url,
        None => {
            print!("Enter remote Git repository URL: ");
            io::stdout().flush()?;
            let mut url = String::new();
            io::stdin().read_line(&mut url)?;
            url.trim().to_string()
        }
    };

    // Get master password
    let password = prompt_password("Enter new master password: ")?;
    let password_confirm = prompt_password("Confirm master password: ")?;

    if password != password_confirm {
        eprintln!("Passwords do not match!");
        return Ok(());
    }

    // Create config directory
    fs::create_dir_all(&config_dir)?;

    // Initialize Git repository with spinner
    let spinner = create_spinner("Initializing Git repository...");
    git_init(&config_dir)?;
    git_remote_add(&config_dir, &remote_url)?;
    spinner.finish_with_message("✓ Git repository initialized");

    // Create empty vault with spinner
    let spinner = create_spinner("Creating encrypted vault (this may take a few seconds)...");
    let empty_data = serde_json::json!({});
    let plaintext = serde_json::to_vec(&empty_data)?;
    let encrypted = encrypt(&plaintext, password.as_bytes())?;
    spinner.finish_with_message("✓ Vault encrypted successfully");

    // Save encrypted vault
    save_vault(&encrypted)?;

    // Save config
    let config = Config {
        remote_url,
        last_sync: None,
    };
    save_config(&config)?;

    // Initial commit and push with spinner
    let spinner = create_spinner("Committing and pushing to remote...");
    git_add(&config_dir, VAULT_FILE)?;
    git_add(&config_dir, CONFIG_FILE)?;
    git_commit(&config_dir, "Initial vault commit")?;

    if let Err(e) = git_push(&config_dir) {
        spinner.finish_with_message("⚠ Could not push to remote");
        eprintln!("Warning: {}", e);
        eprintln!("You may need to manually push later with 'creds sync'");
    } else {
        spinner.finish_with_message("✓ Vault synced to remote");
    }

    println!("\n Vault initialized successfully!");

    Ok(())
}

fn handle_list() -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    let password = prompt_password("Enter master password: ")?;

    let spinner = create_spinner("Decrypting vault...");
    let data = load_decrypted_vault(&password)?;
    spinner.finish_with_message("✓ Vault decrypted");

    println!("\nAvailable keys:");
    print_keys(&data, "", 0);

    Ok(())
}

fn handle_get(args: GetArgs) -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    let password = prompt_password("Enter master password: ")?;

    let spinner = create_spinner("Decrypting vault...");
    let data = load_decrypted_vault(&password)?;
    spinner.finish_and_clear();

    let value = get_nested_value(&data, &args.key)?;

    match value {
        Value::Object(map) => {
            println!("\n{} contains:", args.key);
            print_json_value(&Value::Object(map.clone()), 1);
        }
        Value::String(s) => {
            println!("{}", s);
        }
        _ => {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
    }

    Ok(())
}

fn handle_set(args: SetArgs) -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    let password = prompt_password("Enter master password: ")?;

    let spinner = create_spinner("Decrypting vault...");
    let mut data = load_decrypted_vault(&password)?;
    spinner.finish_with_message("✓ Vault decrypted");

    // Set nested value
    set_nested_value(&mut data, &args.key, Value::String(args.value.clone()))?;

    // Re-encrypt and save with spinner
    let spinner = create_spinner("Encrypting updated vault...");
    let plaintext = serde_json::to_vec(&data)?;
    let encrypted = encrypt(&plaintext, password.as_bytes())?;
    save_vault(&encrypted)?;
    spinner.finish_with_message("✓ Vault encrypted");

    // Commit and push with spinner
    let config_dir = get_config_dir()?;
    git_add(&config_dir, VAULT_FILE)?;
    git_commit(&config_dir, &format!("Update secret: {}", args.key))?;

    let spinner = create_spinner("Syncing with remote...");
    if let Err(e) = git_push(&config_dir) {
        spinner.finish_with_message("⚠ Failed to sync");
        eprintln!("Warning: Secret updated locally but failed to sync: {}", e);
        eprintln!("Run 'creds sync' to retry");
    } else {
        spinner.finish_with_message("✓ Synced to remote");
    }

    println!("\n✓ Secret '{}' updated successfully", args.key);

    Ok(())
}

fn handle_rm(args: RmArgs) -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    let password = prompt_password("Enter master password: ")?;

    let spinner = create_spinner("Decrypting vault...");
    let mut data = load_decrypted_vault(&password)?;
    spinner.finish_with_message("✓ Vault decrypted");

    // Remove nested value
    if !remove_nested_value(&mut data, &args.key)? {
        eprintln!("Key '{}' not found", args.key);
        return Ok(());
    }

    // Re-encrypt and save with spinner
    let spinner = create_spinner("Encrypting updated vault...");
    let plaintext = serde_json::to_vec(&data)?;
    let encrypted = encrypt(&plaintext, password.as_bytes())?;
    save_vault(&encrypted)?;
    spinner.finish_with_message("✓ Vault encrypted");

    // Commit and push with spinner
    let config_dir = get_config_dir()?;
    git_add(&config_dir, VAULT_FILE)?;
    git_commit(&config_dir, &format!("Remove secret: {}", args.key))?;

    let spinner = create_spinner("Syncing with remote...");
    if let Err(e) = git_push(&config_dir) {
        spinner.finish_with_message("⚠ Failed to sync");
        eprintln!("Warning: Secret removed locally but failed to sync: {}", e);
        eprintln!("Run 'creds sync' to retry");
    } else {
        spinner.finish_with_message("✓ Synced to remote");
    }

    println!("\n✓ Secret '{}' removed successfully", args.key);

    Ok(())
}

fn handle_sync() -> Result<(), AppError> {
    ensure_initialized()?;

    let config_dir = get_config_dir()?;

    let spinner = create_spinner("Pulling from remote...");
    match git_pull(&config_dir) {
        Ok(_) => spinner.finish_with_message("✓ Pulled latest changes"),
        Err(e) => {
            spinner.finish_with_message("⚠ Pull failed");
            return Err(e);
        }
    }

    let spinner = create_spinner("Pushing to remote...");
    match git_push(&config_dir) {
        Ok(_) => spinner.finish_with_message("✓ Pushed local changes"),
        Err(e) => {
            spinner.finish_with_message("⚠ Push failed");
            return Err(e);
        }
    }

    // Update last sync time
    let mut config = load_config()?;
    config.last_sync = Some(chrono::Utc::now().to_rfc3339());
    save_config(&config)?;

    println!("\n󰓦 Synchronized successfully");
    Ok(())
}

fn handle_status() -> Result<(), AppError> {
    ensure_initialized()?;

    let config = load_config()?;
    let config_dir = get_config_dir()?;

    println!("\n=== Vault Status ===");
    println!("Remote URL: {}", config.remote_url);

    if let Some(last_sync) = config.last_sync {
        println!("Last sync: {}", last_sync);
    } else {
        println!("Last sync: Never");
    }

    // Check Git status
    let output = Command::new("git")
        .args(&["status", "--short"])
        .current_dir(&config_dir)
        .output()
        .map_err(|e| AppError::Git(e.to_string()))?;

    if !output.stdout.is_empty() {
        println!("\nLocal changes:");
        print!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("\n✓ No local changes");
    }

    Ok(())
}

fn handle_change_password() -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    println!(" Change Master Password");

    // Get current password
    let current_password = prompt_password("Enter current master password: ")?;

    // Try to decrypt with current password to verify it's correct
    let spinner = create_spinner("Verifying current password...");
    let payload = load_vault()?;
    let plaintext = match decrypt(&payload, current_password.as_bytes()) {
        Ok(data) => {
            spinner.finish_with_message("✓ Current password verified");
            data
        }
        Err(_) => {
            spinner.finish_with_message("✗ Incorrect password");
            eprintln!("\nError: Current password is incorrect");
            return Ok(());
        }
    };

    println!();

    // Get new password
    let new_password = prompt_password("Enter new master password: ")?;

    // Validate new password strength
    if new_password.len() < 8 {
        eprintln!("\nError: New password must be at least 8 characters long");
        return Ok(());
    }

    let new_password_confirm = prompt_password("Confirm new master password: ")?;

    if new_password != new_password_confirm {
        eprintln!("\nError: New passwords do not match!");
        return Ok(());
    }

    if new_password == current_password {
        eprintln!("\nError: New password must be different from current password");
        return Ok(());
    }

    println!();

    // Re-encrypt with new password
    let spinner =
        create_spinner("Re-encrypting vault with new password (this may take a few seconds)...");
    let encrypted = encrypt(&plaintext, new_password.as_bytes())?;
    spinner.finish_with_message("✓ Vault re-encrypted successfully");

    // Save the re-encrypted vault
    save_vault(&encrypted)?;

    // Commit and push the change
    let config_dir = get_config_dir()?;
    git_add(&config_dir, VAULT_FILE)?;
    git_commit(&config_dir, "Change master password")?;

    let spinner = create_spinner("Syncing with remote...");
    if let Err(e) = git_push(&config_dir) {
        spinner.finish_with_message("⚠ Failed to sync");
        eprintln!(
            "Warning: Password changed locally but failed to sync: {}",
            e
        );
        eprintln!("Run 'creds sync' to retry");
        println!("\n⚠️  IMPORTANT: Your local password has been changed!");
        println!("   Make sure to remember your NEW password.");
        println!("   The old password will no longer work.");
    } else {
        spinner.finish_with_message("✓ Synced to remote");
        println!("\n Master password changed successfully!");
        println!("\n IMPORTANT: Your vault is now encrypted with the new password.");
        println!("   Make sure to remember it - there is no recovery mechanism!");
    }

    Ok(())
}

// --- Helper Functions ---

fn create_spinner(msg: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("|/-\\ ")
            .template("{spinner:} {msg}")
            .unwrap(),
    );
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner
}

fn get_config_dir() -> Result<PathBuf, AppError> {
    let home = dirs::home_dir().ok_or_else(|| {
        AppError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "Could not find home directory",
        ))
    })?;
    Ok(home.join(CONFIG_DIR))
}

fn get_vault_path() -> Result<PathBuf, AppError> {
    Ok(get_config_dir()?.join(VAULT_FILE))
}

fn get_config_path() -> Result<PathBuf, AppError> {
    Ok(get_config_dir()?.join(CONFIG_FILE))
}

fn ensure_initialized() -> Result<(), AppError> {
    let config_dir = get_config_dir()?;
    if !config_dir.exists() {
        return Err(AppError::NotInitialized);
    }
    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String, AppError> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let password = rpassword::read_password()?;
    Ok(password)
}

fn save_vault(payload: &EncryptedPayload) -> Result<(), AppError> {
    let vault_path = get_vault_path()?;
    let json = serde_json::to_string_pretty(payload)?;
    fs::write(vault_path, json)?;
    Ok(())
}

fn load_vault() -> Result<EncryptedPayload, AppError> {
    let vault_path = get_vault_path()?;
    let json = fs::read_to_string(vault_path)?;
    let payload = serde_json::from_str(&json)?;
    Ok(payload)
}

fn save_config(config: &Config) -> Result<(), AppError> {
    let config_path = get_config_path()?;
    let json = serde_json::to_string_pretty(config)?;
    fs::write(config_path, json)?;
    Ok(())
}

fn load_config() -> Result<Config, AppError> {
    let config_path = get_config_path()?;
    let json = fs::read_to_string(config_path)?;
    let config = serde_json::from_str(&json)?;
    Ok(config)
}

fn load_decrypted_vault(password: &str) -> Result<Value, AppError> {
    let payload = load_vault()?;
    let plaintext = decrypt(&payload, password.as_bytes())?;
    let data = serde_json::from_slice(&plaintext)?;
    Ok(data)
}

// --- Nested key handling ---

fn get_nested_value<'a>(data: &'a Value, key: &str) -> Result<&'a Value, AppError> {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = data;

    for part in parts {
        match current {
            Value::Object(map) => {
                current = map
                    .get(part)
                    .ok_or_else(|| AppError::InvalidKey(format!("Key '{}' not found", key)))?;
            }
            _ => {
                return Err(AppError::InvalidKey(format!(
                    "Cannot access '{}' in non-object",
                    part
                )));
            }
        }
    }

    Ok(current)
}

fn set_nested_value(data: &mut Value, key: &str, value: Value) -> Result<(), AppError> {
    let parts: Vec<&str> = key.split('.').collect();

    if parts.is_empty() {
        return Err(AppError::InvalidKey("Empty key".to_string()));
    }

    // Ensure data is an object
    if !data.is_object() {
        *data = Value::Object(Map::new());
    }

    let mut current = data;

    for i in 0..parts.len() - 1 {
        let part = parts[i];

        // Ensure we have an object at this level
        if !current.is_object() {
            return Err(AppError::InvalidKey(format!(
                "Cannot create nested structure at '{}'",
                part
            )));
        }

        let map = current.as_object_mut().unwrap();

        // Create intermediate objects if they don't exist
        if !map.contains_key(part) {
            map.insert(part.to_string(), Value::Object(Map::new()));
        }

        current = map.get_mut(part).unwrap();
    }

    // Set the final value
    let last_part = parts.last().unwrap();
    if let Some(map) = current.as_object_mut() {
        map.insert(last_part.to_string(), value);
    } else {
        return Err(AppError::InvalidKey(
            "Cannot set value in non-object".to_string(),
        ));
    }

    Ok(())
}

fn remove_nested_value(data: &mut Value, key: &str) -> Result<bool, AppError> {
    let parts: Vec<&str> = key.split('.').collect();

    if parts.is_empty() {
        return Ok(false);
    }

    if parts.len() == 1 {
        // Simple key
        if let Some(map) = data.as_object_mut() {
            return Ok(map.remove(parts[0]).is_some());
        }
        return Ok(false);
    }

    // Navigate to parent
    let parent_key = parts[..parts.len() - 1].join(".");
    let last_part = parts.last().unwrap();

    // Get mutable reference to parent
    let parent_parts: Vec<&str> = parent_key.split('.').collect();
    let mut current = data;

    for part in parent_parts {
        match current {
            Value::Object(map) => {
                current = map.get_mut(part).ok_or_else(|| {
                    AppError::InvalidKey(format!("Parent key '{}' not found", parent_key))
                })?;
            }
            _ => return Ok(false),
        }
    }

    // Remove from parent
    if let Some(map) = current.as_object_mut() {
        Ok(map.remove(*last_part).is_some())
    } else {
        Ok(false)
    }
}

// --- Display helpers ---

fn print_keys(data: &Value, prefix: &str, indent: usize) {
    if let Some(map) = data.as_object() {
        for (key, value) in map {
            let full_key = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", prefix, key)
            };

            print!("{:indent$}- {}", "", full_key, indent = indent * 2);

            match value {
                Value::Object(_) => {
                    println!(" (object)");
                    print_keys(value, &full_key, indent + 1);
                }
                Value::String(_) => println!(" (string)"),
                Value::Number(_) => println!(" (number)"),
                Value::Bool(_) => println!(" (bool)"),
                Value::Array(_) => println!(" (array)"),
                Value::Null => println!(" (null)"),
            }
        }
    }
}

fn print_json_value(value: &Value, indent: usize) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                print!("{:indent$}{}: ", "", k, indent = indent * 2);
                match v {
                    Value::String(s) => println!("{}", s),
                    Value::Object(_) => {
                        println!();
                        print_json_value(v, indent + 1);
                    }
                    _ => println!("{}", v),
                }
            }
        }
        _ => println!("{}", value),
    }
}

// --- Git operations ---

fn git_init(dir: &Path) -> Result<(), AppError> {
    let output = Command::new("git")
        .arg("init")
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to run git init: {}", e)))?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(())
}

fn git_remote_add(dir: &Path, url: &str) -> Result<(), AppError> {
    let output = Command::new("git")
        .args(&["remote", "add", "origin", url])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to add remote: {}", e)))?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(())
}

fn git_add(dir: &Path, file: &str) -> Result<(), AppError> {
    let output = Command::new("git")
        .args(&["add", file])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to git add: {}", e)))?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(())
}

fn git_commit(dir: &Path, message: &str) -> Result<(), AppError> {
    let output = Command::new("git")
        .args(&["commit", "-m", message])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to commit: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Check if it's just "nothing to commit"
        if stderr.contains("nothing to commit") {
            return Ok(());
        }
        return Err(AppError::Git(stderr.to_string()));
    }

    Ok(())
}

fn git_push(dir: &Path) -> Result<(), AppError> {
    let output = Command::new("git")
        .args(&["push", "origin", "main"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to push: {}", e)))?;

    if !output.status.success() {
        // Try to push to master if main doesn't exist
        let output = Command::new("git")
            .args(&["push", "origin", "master"])
            .current_dir(dir)
            .output()
            .map_err(|e| AppError::Git(format!("Failed to push: {}", e)))?;

        if !output.status.success() {
            return Err(AppError::Git(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
    }

    Ok(())
}

fn git_pull(dir: &Path) -> Result<(), AppError> {
    let output = Command::new("git")
        .args(&["pull", "origin", "main"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to pull: {}", e)))?;

    if !output.status.success() {
        // Try to pull from master if main doesn't exist
        let output = Command::new("git")
            .args(&["pull", "origin", "master"])
            .current_dir(dir)
            .output()
            .map_err(|e| AppError::Git(format!("Failed to pull: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // It's okay if the remote branch doesn't exist yet
            if !stderr.contains("couldn't find remote ref") {
                return Err(AppError::Git(stderr.to_string()));
            }
        }
    }

    Ok(())
}

fn sync_if_possible() -> Result<(), AppError> {
    let config_dir = get_config_dir()?;

    // Try to pull silently in the background
    // We don't show a spinner here because this is a background operation
    // and we don't want to block the user's main task
    if let Err(_) = git_pull(&config_dir) {
        // Silent fail - we'll work with local cache
    }

    Ok(())
}
