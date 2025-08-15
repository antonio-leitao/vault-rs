mod ui;
use arboard::Clipboard;
use chrono;
use clap::{Args, Parser, Subcommand};
use crypto::{CryptoError, EncryptedPayload, decrypt, encrypt};
use serde_json::{Map, Value};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use ui::StatusUI;

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

    #[error("Clipboard error: {0}")]
    Clipboard(String),
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
    /// Initializes a vault - either creates new or connects to existing remote vault
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

    /// Compress vault history to save space
    Cleanup(CleanupArgs),
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

    /// Display the secret visibly instead of copying to clipboard
    #[arg(long, short = 'v')]
    visible: bool,
}

#[derive(Args, Debug)]
struct SetArgs {
    /// Key to set (supports dot notation: gmail.password)
    key: String,
}

#[derive(Args, Debug)]
struct RmArgs {
    /// Key to remove (supports dot notation)
    key: String,
}

#[derive(Args, Debug)]
struct CleanupArgs {
    /// Keep last N commits (default: 3)
    #[arg(long, default_value = "3")]
    keep: usize,

    /// Force cleanup even if recently cleaned
    #[arg(long, short)]
    force: bool,
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
        StatusUI::render_error(e);
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
        Commands::Cleanup(args) => handle_cleanup(args),
    }
}

// --- Command Handlers ---

fn handle_init(args: InitArgs) -> Result<(), AppError> {
    let config_dir = get_config_dir()?;

    // Check if already initialized
    if config_dir.exists() {
        StatusUI::warning(&format!(
            "Vault already initialized in {}",
            config_dir.display()
        ));
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

    // Try to clone existing repository first
    let spinner = StatusUI::spinner("Checking remote repository...");
    let temp_dir = config_dir.with_extension("tmp");

    // Ensure temp dir doesn't exist before cloning
    let _ = fs::remove_dir_all(&temp_dir);

    // Attempt to clone the repository (handle path conversion safely)
    let temp_dir_str = temp_dir.to_str().ok_or_else(|| {
        AppError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid path characters",
        ))
    })?;

    let clone_result = Command::new("git")
        .args(&["clone", &remote_url, temp_dir_str])
        .output()
        .map_err(|e| AppError::Git(format!("Failed to run git clone: {}", e)))?;

    if clone_result.status.success() {
        // Repository exists and was cloned successfully
        // Check if vault file exists in the cloned repo
        let vault_exists = temp_dir.join(VAULT_FILE).exists();
        let config_exists = temp_dir.join(CONFIG_FILE).exists();

        if vault_exists && config_exists {
            // Finish the checking spinner before moving to password verification
            StatusUI::finish_spinner_success(spinner, "Found existing vault in remote repository");

            // Existing vault found - verify password
            StatusUI::info(
                "Existing vault detected. Please enter the master password to verify access.",
            );

            let password = prompt_password("Enter master password: ")?;

            // Try to decrypt the vault to verify the password
            let vault_path = temp_dir.join(VAULT_FILE);
            let json = fs::read_to_string(&vault_path)?;
            let payload: EncryptedPayload = serde_json::from_str(&json)?;

            let verify_spinner = StatusUI::spinner("Verifying password...");
            match decrypt(&payload, password.as_bytes()) {
                Ok(_) => {
                    StatusUI::finish_spinner_success(
                        verify_spinner,
                        "Password verified successfully",
                    );

                    // Move temp directory to actual config directory
                    fs::rename(&temp_dir, &config_dir)?;

                    StatusUI::success("Successfully connected to existing vault!");
                    StatusUI::info(&format!("Vault location: {}", config_dir.display()));

                    return Ok(());
                }
                Err(_) => {
                    StatusUI::finish_spinner_error(verify_spinner, "Incorrect password");
                    // Clean up temp directory
                    let _ = fs::remove_dir_all(&temp_dir);
                    StatusUI::error("Failed to decrypt vault with provided password");
                    return Ok(());
                }
            }
        } else {
            // Repository exists but no vault found - clean up and create new
            StatusUI::finish_spinner_info(
                spinner,
                "Remote repository exists but contains no vault",
            );
            let _ = fs::remove_dir_all(&temp_dir);

            StatusUI::info("Initializing new vault in existing repository...");

            // Continue with new vault creation
            create_new_vault(config_dir, remote_url)?;
        }
    } else {
        // Repository doesn't exist or couldn't be cloned
        let stderr = String::from_utf8_lossy(&clone_result.stderr);

        if stderr.contains("Repository not found") || stderr.contains("does not exist") {
            StatusUI::finish_spinner_info(spinner, "Remote repository not found");
            StatusUI::info("Creating new vault and repository...");
        } else if stderr.contains("already exists") {
            // Shouldn't happen but handle it
            StatusUI::finish_spinner_warning(spinner, "Directory already exists");
            let _ = fs::remove_dir_all(&temp_dir);
            return Ok(());
        } else {
            StatusUI::finish_spinner_warning(spinner, "Could not access remote repository");
            StatusUI::info("Creating new local vault (will sync when remote is available)...");
        }

        // Clean up temp directory if it exists
        let _ = fs::remove_dir_all(&temp_dir);

        // Create new vault
        create_new_vault(config_dir, remote_url)?;
    }

    Ok(())
}

fn create_new_vault(config_dir: PathBuf, remote_url: String) -> Result<(), AppError> {
    // Get master password for new vault
    let password = prompt_password("Enter new master password: ")?;
    let password_confirm = prompt_password("Confirm master password: ")?;

    if password != password_confirm {
        StatusUI::error("Passwords do not match!");
        return Ok(());
    }

    // Create config directory
    fs::create_dir_all(&config_dir)?;

    // Initialize Git repository with spinner
    let spinner = StatusUI::spinner("Initializing Git repository...");
    git_init(&config_dir)?;
    git_remote_add(&config_dir, &remote_url)?;
    StatusUI::finish_spinner_success(spinner, "Git repository initialized");

    // Create empty vault with spinner
    let spinner = StatusUI::spinner("Creating encrypted vault (this may take a few seconds)...");
    let empty_data = serde_json::json!({});
    let plaintext = serde_json::to_vec(&empty_data)?;
    let encrypted = encrypt(&plaintext, password.as_bytes())?;
    StatusUI::finish_spinner_success(spinner, "Vault encrypted successfully");

    // Save encrypted vault
    let vault_path = config_dir.join(VAULT_FILE);
    let json = serde_json::to_string_pretty(&encrypted)?;
    fs::write(vault_path, json)?;

    // Save config
    let config = Config {
        remote_url: remote_url.clone(),
        last_sync: None, // Will be updated if push succeeds
    };
    let config_path = config_dir.join(CONFIG_FILE);
    let config_json = serde_json::to_string_pretty(&config)?;
    fs::write(config_path, config_json)?;

    // Initial commit and push with spinner
    let spinner = StatusUI::spinner("Committing and pushing to remote...");
    git_add(&config_dir, VAULT_FILE)?;
    git_add(&config_dir, CONFIG_FILE)?;
    git_commit(&config_dir, "Initial vault commit")?;

    if let Err(e) = git_push(&config_dir) {
        StatusUI::finish_spinner_warning(spinner, "Could not push to remote");
        StatusUI::warning(&format!("{}", e));
        StatusUI::info("You may need to manually push later with 'creds sync'");
    } else {
        StatusUI::finish_spinner_success(spinner, "Vault synced to remote");
        // Update last sync time after successful push
        update_last_sync_time()?;
    }

    StatusUI::success("New vault created successfully!");

    Ok(())
}

fn handle_list() -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    let password = prompt_password("Enter master password: ")?;

    let spinner = StatusUI::spinner("Decrypting vault...");
    let data = load_decrypted_vault(&password)?;
    StatusUI::finish_spinner_success(spinner, "Vault decrypted");

    println!("\nAvailable keys:");
    print_keys(&data, "", 0);

    Ok(())
}

fn handle_get(args: GetArgs) -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    let password = prompt_password("Enter master password: ")?;

    let spinner = StatusUI::spinner("Decrypting vault...");
    let data = load_decrypted_vault(&password)?;
    spinner.finish_and_clear();

    let value = get_nested_value(&data, &args.key)?;

    match value {
        Value::Object(map) => {
            if args.visible {
                println!("\n{} contains:", args.key);
                print_json_value(&Value::Object(map.clone()), 1);
            } else {
                StatusUI::error("Cannot copy object to clipboard. Use --visible flag to display.");
            }
        }
        Value::String(s) => {
            if args.visible {
                println!("{}", s);
            } else {
                // Copy to clipboard
                match Clipboard::new() {
                    Ok(mut clipboard) => match clipboard.set_text(s) {
                        Ok(_) => {
                            StatusUI::success(&format!(
                                "Secret '{}' copied to clipboard",
                                args.key
                            ));
                        }
                        Err(e) => {
                            return Err(AppError::Clipboard(format!(
                                "Failed to copy to clipboard: {}",
                                e
                            )));
                        }
                    },
                    Err(e) => {
                        return Err(AppError::Clipboard(format!(
                            "Failed to access clipboard: {}",
                            e
                        )));
                    }
                }
            }
        }
        _ => {
            if args.visible {
                println!("{}", serde_json::to_string_pretty(value)?);
            } else {
                let text = serde_json::to_string(value)?;
                match Clipboard::new() {
                    Ok(mut clipboard) => match clipboard.set_text(&text) {
                        Ok(_) => {
                            StatusUI::success(&format!(
                                "Secret '{}' copied to clipboard",
                                args.key
                            ));
                        }
                        Err(e) => {
                            return Err(AppError::Clipboard(format!(
                                "Failed to copy to clipboard: {}",
                                e
                            )));
                        }
                    },
                    Err(e) => {
                        return Err(AppError::Clipboard(format!(
                            "Failed to access clipboard: {}",
                            e
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}

fn handle_set(args: SetArgs) -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    // Prompt for the secret value FIRST (before asking for master password)
    print!("Enter value for '{}': ", args.key);
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_string();

    // Clear the line that contained the secret value
    print!("\x1B[1A\x1B[2K"); // Move up one line and clear it
    io::stdout().flush()?;

    if value.is_empty() {
        StatusUI::warning("Empty value provided, operation cancelled");
        return Ok(());
    }

    StatusUI::info(&format!("Value for '{}' received", args.key));

    // NOW ask for the master password
    let password = prompt_password("Enter master password: ")?;

    let spinner = StatusUI::spinner("Decrypting vault...");
    let mut data = load_decrypted_vault(&password)?;
    StatusUI::finish_spinner_success(spinner, "Vault decrypted");

    // Set nested value
    set_nested_value(&mut data, &args.key, Value::String(value))?;

    // Re-encrypt and save with spinner
    let spinner = StatusUI::spinner("Encrypting updated vault...");
    let plaintext = serde_json::to_vec(&data)?;
    let encrypted = encrypt(&plaintext, password.as_bytes())?;
    save_vault(&encrypted)?;
    StatusUI::finish_spinner_success(spinner, "Vault encrypted");

    // Commit and push with spinner
    let config_dir = get_config_dir()?;
    git_add(&config_dir, VAULT_FILE)?;
    git_commit(&config_dir, &format!("Update secret: {}", args.key))?;

    let spinner = StatusUI::spinner("Syncing with remote...");
    if let Err(e) = git_push(&config_dir) {
        StatusUI::finish_spinner_warning(spinner, "Failed to sync");
        StatusUI::warning(&format!("Secret updated locally but failed to sync: {}", e));
        StatusUI::info("Run 'creds sync' to retry");
    } else {
        StatusUI::finish_spinner_success(spinner, "Synced to remote");
        update_last_sync_time()?;
    }

    StatusUI::success(&format!("Secret '{}' updated successfully", args.key));

    Ok(())
}

fn handle_rm(args: RmArgs) -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    let password = prompt_password("Enter master password: ")?;

    let spinner = StatusUI::spinner("Decrypting vault...");
    let mut data = load_decrypted_vault(&password)?;
    StatusUI::finish_spinner_success(spinner, "Vault decrypted");

    // Remove nested value
    if !remove_nested_value(&mut data, &args.key)? {
        StatusUI::error(&format!("Key '{}' not found", args.key));
        return Ok(());
    }

    // Re-encrypt and save with spinner
    let spinner = StatusUI::spinner("Encrypting updated vault...");
    let plaintext = serde_json::to_vec(&data)?;
    let encrypted = encrypt(&plaintext, password.as_bytes())?;
    save_vault(&encrypted)?;
    StatusUI::finish_spinner_success(spinner, "Vault encrypted");

    // Commit and push with spinner
    let config_dir = get_config_dir()?;
    git_add(&config_dir, VAULT_FILE)?;
    git_commit(&config_dir, &format!("Remove secret: {}", args.key))?;

    let spinner = StatusUI::spinner("Syncing with remote...");
    if let Err(e) = git_push(&config_dir) {
        StatusUI::finish_spinner_warning(spinner, "Failed to sync");
        StatusUI::warning(&format!("Secret removed locally but failed to sync: {}", e));
        StatusUI::info("Run 'creds sync' to retry");
    } else {
        StatusUI::finish_spinner_success(spinner, "Synced to remote");
        update_last_sync_time()?;
    }

    StatusUI::success(&format!("Secret '{}' removed successfully", args.key));

    Ok(())
}

fn handle_sync() -> Result<(), AppError> {
    ensure_initialized()?;

    let config_dir = get_config_dir()?;

    let spinner = StatusUI::spinner("Pulling from remote...");
    match git_pull_safe(&config_dir) {
        Ok(_) => StatusUI::finish_spinner_success(spinner, "Pulled latest changes"),
        Err(e) => {
            StatusUI::finish_spinner_error(spinner, "Pull failed");
            return Err(e);
        }
    }

    let spinner = StatusUI::spinner("Pushing to remote...");
    match git_push(&config_dir) {
        Ok(_) => StatusUI::finish_spinner_success(spinner, "Pushed local changes"),
        Err(e) => {
            StatusUI::finish_spinner_error(spinner, "Push failed");
            return Err(e);
        }
    }

    // Check if we should auto-cleanup (every 50 commits)
    if should_auto_cleanup(&config_dir)? {
        StatusUI::info("Running automatic cleanup to save space...");
        git_compress_history(&config_dir, 3)?;

        // Clean local objects
        Command::new("git")
            .args(&["gc", "--aggressive", "--prune=now"])
            .current_dir(&config_dir)
            .output()
            .ok();

        // Force push
        let _ = git_push_force(&config_dir);
        StatusUI::success("Automatic cleanup completed");
    }

    // Update last sync time
    let mut config = load_config()?;
    config.last_sync = Some(chrono::Utc::now().to_rfc3339());
    save_config(&config)?;

    StatusUI::success("Synchronized successfully");
    Ok(())
}

fn should_auto_cleanup(dir: &Path) -> Result<bool, AppError> {
    // Check commit count
    let output = Command::new("git")
        .args(&["rev-list", "--count", "HEAD"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to count commits: {}", e)))?;

    let count: usize = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0);

    // Auto-cleanup if we have more than 50 commits
    Ok(count > 50)
}

fn handle_status() -> Result<(), AppError> {
    ensure_initialized()?;

    let config = load_config()?;
    let config_dir = get_config_dir()?;

    println!("\n=== Vault Status ===");
    StatusUI::info(&format!("Remote URL: {}", config.remote_url));

    if let Some(last_sync) = config.last_sync {
        StatusUI::info(&format!("Last sync: {}", last_sync));
    } else {
        StatusUI::info("Last sync: Never");
    }

    // Show repository size
    let repo_size = get_repo_size(&config_dir)?;
    StatusUI::info(&format!(
        "Repository size: {}",
        StatusUI::format_file_size(repo_size)
    ));

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
        StatusUI::success("No local changes");
    }

    Ok(())
}

fn handle_change_password() -> Result<(), AppError> {
    ensure_initialized()?;
    sync_if_possible()?;

    println!("\n=== Change Master Password ===");

    // Get current password
    let current_password = prompt_password("Enter current master password: ")?;

    // Try to decrypt with current password to verify it's correct
    let spinner = StatusUI::spinner("Verifying current password...");
    let payload = load_vault()?;
    let plaintext = match decrypt(&payload, current_password.as_bytes()) {
        Ok(data) => {
            StatusUI::finish_spinner_success(spinner, "Current password verified");
            data
        }
        Err(_) => {
            StatusUI::finish_spinner_error(spinner, "Incorrect password");
            StatusUI::error("Current password is incorrect");
            return Ok(());
        }
    };

    // Get new password
    let new_password = prompt_password("Enter new master password: ")?;

    // Validate new password strength
    if new_password.len() < 8 {
        StatusUI::error("New password must be at least 8 characters long");
        return Ok(());
    }

    let new_password_confirm = prompt_password("Confirm new master password: ")?;

    if new_password != new_password_confirm {
        StatusUI::error("New passwords do not match!");
        return Ok(());
    }

    if new_password == current_password {
        StatusUI::error("New password must be different from current password");
        return Ok(());
    }

    // Re-encrypt with new password
    let spinner =
        StatusUI::spinner("Re-encrypting vault with new password (this may take a few seconds)...");
    let encrypted = encrypt(&plaintext, new_password.as_bytes())?;
    StatusUI::finish_spinner_success(spinner, "Vault re-encrypted successfully");

    // Save the re-encrypted vault
    save_vault(&encrypted)?;

    // Commit and push the change
    let config_dir = get_config_dir()?;
    git_add(&config_dir, VAULT_FILE)?;
    git_commit(&config_dir, "Change master password")?;

    let spinner = StatusUI::spinner("Syncing with remote...");
    if let Err(e) = git_push(&config_dir) {
        StatusUI::finish_spinner_warning(spinner, "Failed to sync");
        StatusUI::warning(&format!(
            "Password changed locally but failed to sync: {}",
            e
        ));
        StatusUI::info("Run 'creds sync' to retry");
        StatusUI::warning("IMPORTANT: Your local password has been changed!");
        StatusUI::info("Make sure to remember your NEW password.");
        StatusUI::info("The old password will no longer work.");
    } else {
        StatusUI::finish_spinner_success(spinner, "Synced to remote");
        update_last_sync_time()?;
        StatusUI::success("Master password changed successfully!");
        StatusUI::warning("IMPORTANT: Your vault is now encrypted with the new password.");
        StatusUI::info("Make sure to remember it - there is no recovery mechanism!");
    }

    Ok(())
}

fn handle_cleanup(args: CleanupArgs) -> Result<(), AppError> {
    ensure_initialized()?;
    let config_dir = get_config_dir()?;

    // Get size before cleanup
    let size_before = get_repo_size(&config_dir)?;

    StatusUI::info(&format!(
        "Current repository size: {}",
        StatusUI::format_file_size(size_before)
    ));
    StatusUI::info(&format!(
        "Compressing history to {} commit(s)...",
        args.keep
    ));

    // First, ensure we're synced with remote
    let spinner = StatusUI::spinner("Syncing with remote...");
    if let Err(e) = git_pull_safe(&config_dir) {
        StatusUI::finish_spinner_warning(spinner, "Could not sync with remote");
        StatusUI::warning(&format!("{}", e));
        if !args.force {
            StatusUI::error("Cleanup aborted. Use --force to cleanup anyway.");
            return Ok(());
        }
    } else {
        StatusUI::finish_spinner_success(spinner, "Synced with remote");
    }

    // Compress history
    let spinner = StatusUI::spinner("Compressing history...");
    git_compress_history(&config_dir, args.keep)?;
    StatusUI::finish_spinner_success(spinner, "History compressed");

    // Clean up local git objects
    let spinner = StatusUI::spinner("Cleaning local repository...");
    Command::new("git")
        .args(&["gc", "--aggressive", "--prune=now"])
        .current_dir(&config_dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to run git gc: {}", e)))?;
    StatusUI::finish_spinner_success(spinner, "Local repository cleaned");

    // Force push to remote
    let spinner = StatusUI::spinner("Pushing cleaned history to remote...");
    if let Err(e) = git_push_force(&config_dir) {
        StatusUI::finish_spinner_warning(spinner, "Failed to push to remote");
        StatusUI::warning(&format!("{}", e));
        StatusUI::info("Run 'creds sync' to retry");
    } else {
        StatusUI::finish_spinner_success(spinner, "Pushed to remote");
        update_last_sync_time()?;
    }

    // Get size after cleanup
    let size_after = get_repo_size(&config_dir)?;
    let saved = size_before.saturating_sub(size_after);

    StatusUI::success(&format!(
        "Cleanup complete! Saved {} ({}% reduction)",
        StatusUI::format_file_size(saved),
        if size_before > 0 {
            (saved * 100) / size_before
        } else {
            0
        }
    ));
    StatusUI::info(&format!(
        "New repository size: {}",
        StatusUI::format_file_size(size_after)
    ));

    Ok(())
}

// --- Helper Functions ---

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

fn update_last_sync_time() -> Result<(), AppError> {
    let mut config = load_config()?;
    config.last_sync = Some(chrono::Utc::now().to_rfc3339());
    save_config(&config)?;
    Ok(())
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

            println!("{:indent$}- {}", "", full_key, indent = indent * 2);

            // Recursively print nested objects
            if let Value::Object(_) = value {
                print_keys(value, &full_key, indent + 1);
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
fn get_current_branch(dir: &Path) -> Result<String, AppError> {
    let output = Command::new("git")
        .args(&["branch", "--show-current"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to determine current branch: {}", e)))?;

    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !branch.is_empty() {
            return Ok(branch);
        }
    }
    // Fallback if not on a branch (e.g., detached HEAD) or if command fails.
    // We prefer 'master' because fuck main
    Ok("master".to_string())
}

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
    let branch = get_current_branch(dir)?;
    let output = Command::new("git")
        .args(&["push", "origin", &branch])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to push: {}", e)))?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(())
}

fn git_push_force(dir: &Path) -> Result<(), AppError> {
    let branch = get_current_branch(dir)?;
    let output = Command::new("git")
        .args(&["push", "origin", &branch, "--force"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to force push: {}", e)))?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(())
}

fn git_pull(dir: &Path) -> Result<(), AppError> {
    let branch = get_current_branch(dir)?;
    let output = Command::new("git")
        .args(&["pull", "origin", &branch])
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

    Ok(())
}

// Safe pull that handles diverged histories (remote as source of truth)
fn git_pull_safe(dir: &Path) -> Result<(), AppError> {
    // First fetch to see what's on remote
    let output = Command::new("git")
        .args(&["fetch", "origin"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to fetch: {}", e)))?;

    if !output.status.success() {
        // If fetch fails, we might not have network
        return Err(AppError::Git("Failed to fetch from remote".to_string()));
    }

    // Check if histories have diverged
    let output = Command::new("git")
        .args(&["status", "-uno"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to check status: {}", e)))?;

    let status = String::from_utf8_lossy(&output.stdout);

    if status.contains("have diverged") {
        StatusUI::warning(
            "Local and remote histories have diverged. Accepting remote as source of truth...",
        );

        // Stash any local changes
        let stash_output = Command::new("git")
            .args(&["stash"])
            .current_dir(dir)
            .output()?;

        let stashed = !String::from_utf8_lossy(&stash_output.stdout).contains("No local changes");

        // Get current branch name
        let branch_output = Command::new("git")
            .args(&["branch", "--show-current"])
            .current_dir(dir)
            .output()?;

        let branch = String::from_utf8_lossy(&branch_output.stdout)
            .trim()
            .to_string();
        let branch = if branch.is_empty() {
            "master".to_string()
        } else {
            branch
        };

        // Hard reset to remote
        Command::new("git")
            .args(&["reset", "--hard", &format!("origin/{}", branch)])
            .current_dir(dir)
            .output()
            .map_err(|e| AppError::Git(format!("Failed to reset to remote: {}", e)))?;

        // Try to reapply stashed changes if any
        if stashed {
            let pop_result = Command::new("git")
                .args(&["stash", "pop"])
                .current_dir(dir)
                .output();

            if pop_result.is_err() || !pop_result.unwrap().status.success() {
                StatusUI::warning(
                    "Could not automatically reapply local changes. They are saved in git stash.",
                );
            }
        }

        StatusUI::info("Successfully synchronized with remote state");
    } else {
        // Normal pull
        git_pull(dir)?;
    }

    Ok(())
}

fn git_compress_history(dir: &Path, keep_last: usize) -> Result<(), AppError> {
    // Get commit count
    let output = Command::new("git")
        .args(&["rev-list", "--count", "HEAD"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to count commits: {}", e)))?;

    let count: usize = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0);

    if count <= keep_last {
        StatusUI::info(&format!("Already at {} commits or fewer", keep_last));
        return Ok(());
    }

    let original_branch = get_current_branch(dir)?;
    // Create a new orphan branch with current state
    Command::new("git")
        .args(&["checkout", "--orphan", "temp-compress"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to create orphan branch: {}", e)))?;

    // Add all files
    Command::new("git")
        .args(&["add", "-A"])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to add files: {}", e)))?;

    // Commit with timestamp
    let message = format!("Vault state: {}", chrono::Utc::now().to_rfc3339());
    Command::new("git")
        .args(&["commit", "-m", &message])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to commit: {}", e)))?;

    // Delete old branch and rename new one
    Command::new("git")
        .args(&["branch", "-D", &original_branch])
        .current_dir(dir)
        .output()
        .ok(); // Ignore error if it somehow fails

    Command::new("git")
        .args(&["branch", "-m", "temp-compress", &original_branch])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to rename branch: {}", e)))?;

    Ok(())
}

fn get_repo_size(dir: &Path) -> Result<usize, AppError> {
    let output = Command::new("du")
        .args(&["-sb", "."])
        .current_dir(dir)
        .output()
        .map_err(|e| AppError::Git(format!("Failed to calculate size: {}", e)))?;

    if output.status.success() {
        let size_str = String::from_utf8_lossy(&output.stdout);
        let size = size_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        Ok(size)
    } else {
        Ok(0)
    }
}

fn sync_if_possible() -> Result<(), AppError> {
    let config_dir = get_config_dir()?;

    // Try to pull safely in the background
    // We don't show a spinner here because this is a background operation
    // and we don't want to block the user's main task
    if let Err(_) = git_pull_safe(&config_dir) {
        // Silent fail - we'll work with local cache
    }

    Ok(())
}
