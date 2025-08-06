# Creds - Secure Git-Backed Credential Manager

A simple yet robust command-line tool for managing credentials with strong encryption and automatic Git synchronization.

## Features

- 🔐 **Strong Encryption**: Uses Argon2id + AES-256-GCM for maximum security
- 🔄 **Git Synchronization**: Automatically syncs with a remote Git repository
- 🔑 **Nested Keys**: Support for hierarchical organization (e.g., `gmail.password`)
- 🛡️ **Local First**: Local vault is always the source of truth
- 🚀 **Simple CLI**: Intuitive commands for everyday use
- ⏳ **Progress Indicators**: Visual feedback during encryption/decryption and sync operations
- 🔒 **Password Rotation**: Secure master password changes with full re-encryption

## Installation

```bash
# Clone the repository
git clone <your-repo>
cd creds

# Build the project
cargo build --release

# Optional: Install globally
cargo install --path creds
```

## Quick Start

### 1. Initialize a new vault

```bash
# Initialize with a remote repository
creds init https://github.com/yourusername/my-secrets.git

# Or let it prompt you for the URL
creds init
```

You'll be prompted to:

- Enter the remote repository URL (if not provided)
- Create a master password (typed hidden)
- Confirm the master password

### 2. Store credentials

```bash
# Store a simple value
creds set github_token "ghp_xxxxxxxxxxxxx"

# Store nested values
creds set gmail.username "user@gmail.com"
creds set gmail.password "super_secret_password"
creds set gmail.app_password "abcd efgh ijkl mnop"

# Store complex nested structures
creds set aws.prod.access_key "AKIA..."
creds set aws.prod.secret_key "xxxxx"
creds set aws.dev.access_key "AKIA..."
```

### 3. Retrieve credentials

```bash
# Get a specific value
creds get gmail.password
# Output: super_secret_password

# Get all values under a key
creds get gmail
# Output:
# gmail contains:
#   username: user@gmail.com
#   password: super_secret_password
#   app_password: abcd efgh ijkl mnop

# Get a deeply nested value
creds get aws.prod.access_key
# Output: AKIA...
```

### 4. List all keys

```bash
creds list
# Output:
# Available keys:
# - github_token (string)
# - gmail (object)
#   - username (string)
#   - password (string)
#   - app_password (string)
# - aws (object)
#   - prod (object)
#     - access_key (string)
#     - secret_key (string)
#   - dev (object)
#     - access_key (string)
```

### 5. Remove credentials

```bash
# Remove a specific value
creds rm gmail.app_password

# Remove an entire section
creds rm aws.dev

# Remove a top-level key
creds rm github_token
```

### 6. Synchronization

```bash
# Force a manual sync
creds sync

# Check sync status
creds status
# Output:
# === Vault Status ===
# Remote URL: https://github.com/yourusername/my-secrets.git
# Last sync: 2024-01-20T10:30:00Z
# ✓ No local changes
```

### 7. Change Master Password

```bash
# Change your master password
creds change-password
# Or use the short alias
creds passwd

# You'll be prompted for:
# 1. Current master password (to verify)
# 2. New master password
# 3. Confirm new master password

# The vault will be re-encrypted with the new password
# Output:
# 🔐 Change Master Password
# ─────────────────────────
# Enter current master password:
# ⠋ Verifying current password...
# ✓ Current password verified
#
# Enter new master password:
# Confirm new master password:
#
# ⠙ Re-encrypting vault with new password...
# ✓ Vault re-encrypted successfully
# ⠹ Syncing with remote...
# ✓ Synced to remote
#
# ✅ Master password changed successfully!
#
# 🔒 IMPORTANT: Your vault is now encrypted with the new password.
#    Make sure to remember it - there is no recovery mechanism!
```

## Command Reference

| Command             | Alias    | Description                       | Example                                          |
| ------------------- | -------- | --------------------------------- | ------------------------------------------------ |
| `init [URL]`        | -        | Initialize vault with remote repo | `creds init https://github.com/user/secrets.git` |
| `list`              | `ls`     | List all keys                     | `creds list`                                     |
| `get <key>`         | -        | Get value(s) for a key            | `creds get gmail.password`                       |
| `set <key> <value>` | -        | Set a value                       | `creds set api.key "secret123"`                  |
| `rm <key>`          | -        | Remove a key                      | `creds rm old.password`                          |
| `sync`              | -        | Force sync with remote            | `creds sync`                                     |
| `status`            | -        | Show vault status                 | `creds status`                                   |
| `change-password`   | `passwd` | Change master password            | `creds change-password`                          |

## How It Works

### Storage Structure

The vault is stored in `~/.creds/` with the following structure:

```
~/.creds/
├── vault.enc       # Encrypted credentials (JSON)
├── config.json     # Configuration (remote URL, last sync)
└── .git/          # Git repository
```

### Data Format

Internally, credentials are stored as nested JSON:

```json
{
  "github_token": "ghp_xxxxx",
  "gmail": {
    "username": "user@gmail.com",
    "password": "secret"
  },
  "aws": {
    "prod": {
      "access_key": "AKIA...",
      "secret_key": "xxxxx"
    }
  }
}
```

### Security

- **Encryption**: Uses Argon2id for key derivation (256MB RAM, 4 iterations) and AES-256-GCM for encryption
- **Password**: Never stored, always prompted when needed
- **Git**: Only the encrypted vault is committed to Git
- **Salt**: Each encryption uses a unique salt to prevent rainbow table attacks

### Synchronization

- **Automatic**: Attempts to sync before reads and after writes
- **Offline Mode**: Works offline, syncs when connection is available
- **Conflict Resolution**: Local changes always take precedence
- **Manual Sync**: Use `creds sync` to force synchronization

## Advanced Usage

### Working with Multiple Vaults

You can manage multiple vaults by using different Git repositories:

```bash
# Personal vault
cd ~
creds init https://github.com/user/personal-secrets.git

# Work vault (in a different location)
cd ~/work
CREDS_HOME=~/work/.creds creds init https://github.com/company/work-secrets.git
```

### Backup Strategy

1. **Git Remote**: Your primary backup (GitHub, GitLab, etc.)
2. **Local Backup**: Periodically backup `~/.creds/vault.enc`
3. **Export**: For critical recovery, you can decrypt and export:
   ```bash
   # Create a plaintext export (be careful!)
   creds get . > backup.json
   ```

### Integration Examples

**In shell scripts:**

```bash
#!/bin/bash
API_KEY=$(creds get api.key)
curl -H "Authorization: Bearer $API_KEY" https://api.example.com
```

**In aliases:**

```bash
# Add to ~/.bashrc or ~/.zshrc
alias gcptoken='creds get gcp.token | pbcopy'
alias awsenv='export AWS_ACCESS_KEY=$(creds get aws.access_key) && export AWS_SECRET_KEY=$(creds get aws.secret_key)'
```

## Troubleshooting

### "Vault not initialized"

Run `creds init <remote-url>` first.

### "Decryption failed - wrong password"

You entered the wrong master password. Try again.

### "Git push failed"

- Check your internet connection
- Verify you have push access to the repository
- Run `creds sync` to retry

### "Key not found"

Use `creds list` to see available keys. Check for typos.

### Password change issues

- **"Current password is incorrect"**: Verify you're entering the right password
- **"New password must be at least 8 characters"**: Choose a longer password
- **"New passwords do not match"**: Type carefully when confirming
- **Sync failed after change**: Your local password is changed! Use the new one. Run `creds sync` later.

### Lost master password

There's no recovery mechanism. The vault cannot be decrypted without the password. You'll need to:

1. Delete the vault: `rm -rf ~/.creds`
2. Re-initialize: `creds init <remote-url>`
3. Re-enter all credentials

## Security Considerations

1. **Master Password**: Choose a strong, unique password. This is your only defense.
2. **Git Repository**: Use a private repository. While the vault is encrypted, metadata (commit times) could reveal usage patterns.
3. **Local Security**: The decrypted data exists in memory only during operations.
4. **No Password Recovery**: There's no backdoor or recovery mechanism by design.
5. **Password Changes**: When changing passwords:
   - The entire vault is re-encrypted with the new password
   - The old password immediately stops working
   - All devices using the vault will need the new password
   - Consider informing team members if sharing a vault
