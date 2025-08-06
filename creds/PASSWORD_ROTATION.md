# Password Rotation Guide

## Why Change Your Master Password?

Regular password rotation is a security best practice. Consider changing your master password:

- **Every 90 days** for high-security environments
- **Immediately** if you suspect compromise
- **After team member changes** if sharing vaults
- **When upgrading** from a weak to strong password

## How to Change Your Password

### Basic Usage

```bash
creds change-password
# Or use the short alias
creds passwd
```

### Step-by-Step Process

1. **Verify Current Password**

   ```
   Enter current master password: ****
   ⠋ Verifying current password...
   ✓ Current password verified
   ```

2. **Set New Password**

   ```
   Enter new master password: ****
   Confirm new master password: ****
   ```

3. **Automatic Re-encryption**
   ```
   ⠙ Re-encrypting vault with new password...
   ✓ Vault re-encrypted successfully
   ⠹ Syncing with remote...
   ✓ Synced to remote
   ```

## Password Requirements

The new password must:

- ✅ Be at least 8 characters long
- ✅ Be different from the current password
- ✅ Match when confirmed

### Recommended Password Strength

For optimal security with Argon2id encryption:

- **Minimum**: 12 characters
- **Recommended**: 16+ characters
- **Include**: Mixed case, numbers, and symbols
- **Avoid**: Dictionary words, personal information

### Example Strong Passwords

```
# Good passwords (examples only - create your own!)
Tr0ub4dor&3_H0rse_B4tt3ry
correct-horse-battery-staple-2024
My$ecure_V@ult_P@ssw0rd#2024
```

## Important Considerations

### Before Changing

1. **Ensure you remember the current password** - You need it to decrypt the vault
2. **Choose a strong new password** - Write it down temporarily if needed
3. **Sync first** - Run `creds sync` to ensure you have the latest vault

### During Change

- The process takes ~5 seconds due to high-security encryption
- The vault is re-encrypted entirely with the new password
- A Git commit is automatically created

### After Changing

1. **The old password immediately stops working**
2. **Update all devices/scripts** using the vault
3. **Notify team members** if sharing the vault
4. **Securely destroy** any written passwords

## Team Vault Password Rotation

If sharing a vault with a team:

### 1. Coordinate the Change

```bash
# Notify team members
echo "Password rotation scheduled for $(date +%Y-%m-%d)"
```

### 2. Perform the Change

```bash
# One person changes the password
creds change-password
```

### 3. Secure Distribution

- Use a secure channel (Signal, encrypted email)
- Consider using a password manager for sharing
- Never send passwords in plain text

### 4. Verify Access

```bash
# Each team member verifies
creds list  # Should prompt for new password
```

## Automation Script

For regular rotation reminders:

```bash
#!/bin/bash
# password-rotation-reminder.sh

LAST_CHANGE_FILE="$HOME/.creds/.last_password_change"
DAYS_THRESHOLD=90

if [ -f "$LAST_CHANGE_FILE" ]; then
    LAST_CHANGE=$(cat "$LAST_CHANGE_FILE")
    DAYS_SINCE=$((( $(date +%s) - $LAST_CHANGE ) / 86400))

    if [ $DAYS_SINCE -ge $DAYS_THRESHOLD ]; then
        echo "⚠️  Your creds password is $DAYS_SINCE days old"
        echo "   Consider running: creds change-password"
    fi
else
    # Create initial timestamp
    date +%s > "$LAST_CHANGE_FILE"
fi
```

Add to your `.bashrc` or `.zshrc`:

```bash
# Check password age on shell startup
~/bin/password-rotation-reminder.sh
```

## Recovery Scenarios

### Forgot Current Password

- ❌ **No recovery possible** - The vault cannot be decrypted
- Must restore from backup or re-initialize

### Changed Password But Forgot New One

- ❌ **No recovery possible** - The vault is already re-encrypted
- If not synced yet, could restore from Git remote

### Sync Failed After Change

- ⚠️ **Local password is changed** - Use the new password
- Run `creds sync` when connection restored
- Remote still has old encryption until synced

## Security Benefits

Password rotation with creds provides:

1. **Forward Secrecy** - Old passwords can't decrypt new vaults
2. **Compromise Mitigation** - Limits exposure window
3. **Compliance** - Meets password rotation requirements
4. **Audit Trail** - Git commits show rotation history

## Best Practices Summary

✅ **DO:**

- Rotate passwords regularly (every 90 days)
- Use strong, unique passwords
- Sync before and after changing
- Update all systems using the vault
- Test the new password immediately

❌ **DON'T:**

- Share passwords via insecure channels
- Reuse old passwords
- Write passwords in plain text files
- Delay updating automated systems
- Forget to notify team members

## Quick Reference

```bash
# Change password
creds change-password

# Verify it worked
creds list  # Should accept new password

# Check sync status
creds status

# Force sync if needed
creds sync
```

Remember: **There is no password recovery mechanism.** Always ensure you can remember or securely store your new password!
