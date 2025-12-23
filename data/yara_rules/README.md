# YARA Rules

This directory contains YARA rules for malware detection and classification.

## Directory Structure

```
yara_rules/
├── malware/              # Generic malware detection rules
├── ransomware/           # Ransomware-specific rules
├── apt/                  # APT group rules
├── packers/              # Packer and obfuscation detection
├── exploits/             # Exploit kit rules
└── custom/               # Custom user-defined rules
```

## Adding Rules

Place your YARA rules (.yar or .yara files) in the appropriate subdirectory.

### Example Rule

```yara
rule Suspicious_PE_Characteristics
{
    meta:
        description = "Detects PE files with suspicious characteristics"
        author = "BlueGuardian AI"
        date = "2025-01-01"
        severity = "medium"

    strings:
        $mz = "MZ"
        $sus1 = "cmd.exe" nocase
        $sus2 = "powershell.exe" nocase

    condition:
        $mz at 0 and any of ($sus*)
}
```

## Using YARA Rules

Rules in this directory are automatically loaded by the malware agent during analysis.

```python
from src.agents.malware_agent import MalwareAgent

# YARA rules are loaded automatically
agent = MalwareAgent(settings)
result = await agent.analyze("suspicious.exe")
# YARA matches will be included in the analysis
```

## Rule Sources

Consider downloading rules from:
- [Yara-Rules Project](https://github.com/Yara-Rules/rules)
- [Signature Base](https://github.com/Neo23x0/signature-base)
- [Awesome YARA](https://github.com/InQuest/awesome-yara)

## Best Practices

1. **Test Rules**: Always test new rules before deploying
2. **Metadata**: Include author, description, and severity in metadata
3. **Performance**: Avoid overly complex rules that slow down scanning
4. **Updates**: Regularly update rules to detect new threats
5. **Documentation**: Document custom rules clearly
