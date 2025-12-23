# Malware Signatures

This directory contains malware signatures and hash databases for quick identification.

## File Types

### IOC Lists
- `malicious_hashes.txt` - Known malicious file hashes (MD5, SHA1, SHA256)
- `malicious_ips.txt` - Known malicious IP addresses
- `malicious_domains.txt` - Known malicious domains
- `malicious_urls.txt` - Known malicious URLs

### Signature Databases
- `ssdeep_signatures.db` - Fuzzy hashes for similarity matching
- `import_hashes.db` - Import hash (imphash) database
- `mutex_signatures.txt` - Known malware mutex names
- `registry_keys.txt` - Known malware registry keys

## Format Examples

### Hash List (malicious_hashes.txt)
```
# MD5 hashes of known malware
44d88612fea8a8f36de82e1278abb02f  Eicar test file
# SHA256 hashes
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  WannaCry
```

### IP List (malicious_ips.txt)
```
# Known C2 servers
192.0.2.1     # Emotet C2
198.51.100.1  # TrickBot C2
```

### Domain List (malicious_domains.txt)
```
# Phishing domains
evil-paypal-login.com
secure-bank-update.net
```

## Updating Signatures

### Manual Update
Add new signatures to the appropriate file using the format above.

### Automated Update
```bash
# Download latest threat feeds
python scripts/update_signatures.py

# Or use the CLI
blueguardian update-signatures
```

## Integration

Signatures are automatically checked during analysis:

```python
from src.agents.malware_agent import MalwareAgent

agent = MalwareAgent(settings)
result = await agent.analyze("unknown_file.exe")

# If file hash matches signature database:
# result.verdict = 'malicious'
# result.tags = ['known_malware', 'emotet']
```

## Sources

Consider using threat feeds from:
- [Abuse.ch](https://abuse.ch/)
- [CIRCL Hash Lookup](https://hashlookup.circl.lu/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [URLhaus](https://urlhaus.abuse.ch/)
- [AlienVault OTX](https://otx.alienvault.com/)

## Maintenance

1. **Regular Updates**: Update signatures weekly
2. **False Positives**: Remove false positives promptly
3. **Verification**: Verify hashes from multiple sources
4. **Cleanup**: Remove outdated signatures (>1 year old)
