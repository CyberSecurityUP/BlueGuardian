# Artifacts Storage

This directory stores analyzed artifacts (malware samples, documents, etc.).

## ⚠️ SECURITY WARNING

**DO NOT commit actual malware samples to version control!**

This directory should be:
- Added to `.gitignore`
- Encrypted if stored on disk
- Regularly backed up to secure storage
- Access-controlled with strict permissions

## Directory Structure

Artifacts are organized by date and job ID:

```
artifacts/
├── 2025-01-15/
│   ├── job-abc123-suspicious.exe
│   ├── job-def456-phishing.eml
│   └── job-ghi789-document.pdf
├── 2025-01-16/
│   └── job-jkl012-malware.dll
└── quarantine/
    └── confirmed_malware/
```

## File Naming Convention

Format: `job-{job_id}-{original_name}`

Example: `job-550e8400-e29b-41d4-a716-446655440000-suspicious.exe`

## Storage Limits

- Maximum file size: 100 MB (configurable)
- Retention period: 30 days (configurable)
- Automatic cleanup of old artifacts

## Security Best Practices

1. **Encryption**: Encrypt artifacts at rest
2. **Isolation**: Store in isolated filesystem or container
3. **Access Logs**: Log all access to this directory
4. **Permissions**: Restrict to BlueGuardian service account only
5. **Scanning**: Regularly scan for unauthorized access

## Cleanup

Manual cleanup:
```bash
# Remove artifacts older than 30 days
find storage/artifacts -type f -mtime +30 -delete
```

Automated cleanup:
```bash
# Enable automatic cleanup in settings
ARTIFACTS_RETENTION_DAYS=30
AUTO_CLEANUP_ENABLED=true
```

## Backup

```bash
# Backup to encrypted archive
tar -czf artifacts-backup-$(date +%Y%m%d).tar.gz storage/artifacts/
gpg --encrypt --recipient blueguardian artifacts-backup-*.tar.gz
```
