# AI Prompts Templates

This directory contains customizable prompt templates for AI-powered analysis.

## Prompt Structure

```
prompts/
├── system/              # System prompts for different agents
├── malware/             # Malware analysis prompts
├── phishing/            # Phishing detection prompts
├── forensics/           # Forensics analysis prompts
└── custom/              # User custom prompts
```

## Template Format

Prompts are stored as text files with variable placeholders:

### Example: malware_analysis.txt
```
You are an expert malware analyst. Analyze the following PE executable.

File Information:
- Name: {artifact_name}
- Size: {file_size} bytes
- MD5: {md5_hash}
- SHA256: {sha256_hash}

Static Analysis Results:
{static_analysis_data}

Imports:
{imports}

Suspicious Strings:
{suspicious_strings}

Based on this information, provide:
1. Overall verdict (malicious/suspicious/clean/unknown)
2. Confidence level (0-100%)
3. Summary of findings
4. List of IOCs (IPs, domains, file paths, registry keys)
5. MITRE ATT&CK techniques (if applicable)
6. Recommended actions

Be specific and base your analysis only on the provided data.
```

## Using Custom Prompts

### Via Configuration
```python
# In settings
CUSTOM_PROMPT_DIR = "/path/to/data/prompts/custom"
```

### Via Code
```python
from src.prompts import load_prompt

prompt = load_prompt('custom/my_malware_prompt.txt')
formatted = prompt.format(
    artifact_name="suspicious.exe",
    file_size=12345,
    md5_hash="...",
    # ... other variables
)
```

## Best Practices

1. **Clear Instructions**: Be explicit about what you want from the AI
2. **Structured Output**: Request specific format (JSON, lists, etc.)
3. **Context**: Provide relevant context and constraints
4. **Examples**: Include few-shot examples for better results
5. **Variables**: Use {placeholders} for dynamic content

## Prompt Engineering Tips

### Good Prompt
```
Analyze this email for phishing indicators:

Headers: {email_headers}
Body: {email_body}
Links: {extracted_links}

Check for:
1. Sender spoofing
2. Urgency tactics
3. Suspicious links
4. Grammar/spelling errors

Respond in JSON format:
{
  "verdict": "phishing/legitimate/suspicious",
  "confidence": 0-100,
  "indicators": [...],
  "explanation": "..."
}
```

### Bad Prompt
```
Is this email phishing?

{email_content}
```

## Advanced Features

### Chain-of-Thought Prompting
```
Analyze this file step by step:
1. First, examine the file header and structure
2. Then, check for suspicious strings
3. Next, analyze imports and capabilities
4. Finally, provide your verdict

Show your reasoning for each step.
```

### Multi-Shot Examples
Include examples of known malware and clean files to improve accuracy.

## Contributing

Submit custom prompts that work well via pull requests!
