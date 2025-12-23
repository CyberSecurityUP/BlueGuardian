"""Specialized prompts for document analysis.

This module contains prompts for analyzing potentially malicious documents
including PDFs, Office files, and shortcuts (LNK).
"""

DOCUMENT_ANALYSIS_SYSTEM_PROMPT = """You are an expert document security analyst specializing in:
- PDF malware analysis and exploit detection
- Microsoft Office macro analysis (VBA, OLE, OOXML)
- Windows shortcut (LNK) file analysis
- Document-based attack vectors and delivery mechanisms
- Social engineering tactics used in document-based attacks

Your role is to analyze potentially malicious documents and provide accurate threat assessments.

CRITICAL RULES:
1. Base ALL conclusions on the actual analysis data provided
2. Distinguish between confirmed threats vs. suspicious indicators
3. Never speculate beyond the evidence
4. Focus on defensive analysis for Blue Team operations
5. Identify specific malicious behaviors and techniques
6. Extract actionable IOCs and defensive recommendations
7. Map behaviors to MITRE ATT&CK techniques where applicable

OUTPUT FORMAT:
- Start with verdict (Malicious/Suspicious/Clean) and confidence (0-100%)
- Provide executive summary (2-3 sentences)
- Detail technical findings with evidence
- List all IOCs and suspicious elements
- Map to MITRE ATT&CK techniques
- Provide defensive recommendations

Remember: Accuracy over assumptions. If uncertain, state confidence level clearly."""

PDF_ANALYSIS_PROMPT = """Analyze this PDF file for malicious content:

FILE INFORMATION:
{file_info}

PDF STRUCTURE:
{pdf_structure}

JAVASCRIPT DETECTED:
{javascript}

EMBEDDED FILES:
{embedded_files}

SUSPICIOUS ELEMENTS:
{suspicious_elements}

URLS FOUND:
{urls}

{virustotal_data}

ANALYSIS TASKS:
1. **Verdict**: Malicious/Suspicious/Clean (with confidence %)
2. **Threat Type**: What type of threat? (exploit, phishing, dropper, etc.)
3. **JavaScript Analysis**: If JavaScript present, what does it do?
4. **Exploit Detection**: Any known CVE exploits? (e.g., CVE-2013-2729)
5. **Embedded Content**: Analysis of embedded files or streams
6. **Social Engineering**: How might this document trick users?
7. **IOCs**: Extract ALL indicators:
   - URLs and domains
   - IP addresses
   - File hashes
   - Suspicious strings
8. **MITRE ATT&CK**: Map to techniques (e.g., T1204.002 - Malicious File)
9. **Evasion Techniques**: Any anti-analysis or obfuscation?
10. **Recommendations**: Specific actions for defenders

Focus on evidence-based analysis. Cite specific elements from the data."""

OFFICE_ANALYSIS_PROMPT = """Analyze this Microsoft Office document for malicious content:

FILE INFORMATION:
{file_info}

DOCUMENT TYPE:
{doc_type}

MACROS:
{macros}

EMBEDDED OBJECTS:
{embedded_objects}

EXTERNAL LINKS:
{external_links}

DDE LINKS:
{dde_links}

{virustotal_data}

ANALYSIS TASKS:
1. **Verdict**: Malicious/Suspicious/Clean (confidence %)
2. **Threat Vector**: How is this document weaponized?
3. **Macro Analysis**:
   - What do the macros do?
   - Auto-execution methods?
   - Obfuscation techniques?
   - Malicious capabilities?
4. **DDE Exploitation**: If DDE present, what commands are executed?
5. **Embedded Content**: Analysis of OLE objects, executables
6. **External Resources**: Where do external links point?
7. **Delivery Method**: How might this be delivered to victims?
8. **IOCs**: Extract ALL indicators:
   - URLs, domains, IPs
   - File paths
   - Registry keys
   - Command lines
9. **MITRE ATT&CK**: Map behaviors to techniques
10. **Defensive Actions**: Block, detect, hunt recommendations

Analyze VBA code for specific malicious functions. Be detailed but concise."""

LNK_ANALYSIS_PROMPT = """Analyze this Windows shortcut (LNK) file:

FILE INFORMATION:
{file_info}

TARGET:
{target}

ARGUMENTS:
{arguments}

WORKING DIRECTORY:
{working_directory}

SUSPICIOUS INDICATORS:
{suspicious_indicators}

{virustotal_data}

ANALYSIS TASKS:
1. **Verdict**: Malicious/Suspicious/Clean (confidence %)
2. **Attack Vector**: How is this LNK weaponized?
3. **Command Analysis**:
   - What commands are executed?
   - PowerShell/CMD analysis
   - Obfuscation techniques?
4. **Payload Delivery**: How does it download/execute payload?
5. **Persistence**: Any persistence mechanisms?
6. **Evasion**: Hidden window? Obfuscation?
7. **IOCs**: Extract:
   - URLs, domains, IPs
   - File paths
   - Commands
8. **MITRE ATT&CK**: Map to techniques (e.g., T1204.002, T1059.001)
9. **Delivery Context**: Likely phishing attachment or USB drop?
10. **Mitigation**: How to detect and block?

Focus on the execution chain. What happens when user clicks this LNK?"""

DOCUMENT_IOC_EXTRACTION_PROMPT = """Extract ALL Indicators of Compromise from this document analysis:

{analysis_data}

Extract and categorize:

1. **Network IOCs**:
   - URLs (both obfuscated and clear)
   - Domains
   - IP addresses
   - Email addresses

2. **File IOCs**:
   - Dropped file paths
   - Embedded file names
   - Temporary file locations

3. **Command IOCs**:
   - PowerShell commands
   - CMD commands
   - WMI queries
   - Registry operations

4. **Behavioral IOCs**:
   - Macro auto-execution methods
   - JavaScript eval/unescape patterns
   - DDE field commands
   - ActiveX/OLE object creation

5. **Obfuscation Patterns**:
   - Base64 encoded strings
   - Hex encoded strings
   - String concatenation patterns
   - Chr() or Asc() usage

Format each IOC with:
- type: IOC type
- value: The indicator
- confidence: 0.0-1.0
- context: Where/how found

Only extract with HIGH confidence based on actual data."""

DOCUMENT_MITRE_MAPPING_PROMPT = """Map this document's behaviors to MITRE ATT&CK techniques:

OBSERVED BEHAVIORS:
{behaviors}

MACRO/SCRIPT CAPABILITIES:
{capabilities}

For each behavior, provide:
1. **Technique ID**: (e.g., T1204.002)
2. **Technique Name**: (e.g., User Execution: Malicious File)
3. **Sub-technique**: If applicable
4. **Evidence**: Specific evidence from analysis
5. **Confidence**: High/Medium/Low

Common document-based techniques:
- **Initial Access**:
  - T1566.001: Phishing - Spearphishing Attachment
  - T1566.002: Phishing - Spearphishing Link

- **Execution**:
  - T1204.002: User Execution - Malicious File
  - T1059.001: Command and Scripting - PowerShell
  - T1059.003: Command and Scripting - Windows Command Shell
  - T1059.005: Command and Scripting - Visual Basic
  - T1059.007: Command and Scripting - JavaScript

- **Defense Evasion**:
  - T1027: Obfuscated Files or Information
  - T1140: Deobfuscate/Decode Files or Information
  - T1221: Template Injection

- **Command and Control**:
  - T1071.001: Application Layer Protocol - Web Protocols
  - T1105: Ingress Tool Transfer

Only map techniques actually evidenced in the analysis."""

def format_prompt(prompt_template: str, **kwargs) -> str:
    """Format a prompt template with provided arguments.

    Args:
        prompt_template: Template string with {placeholders}
        **kwargs: Values to fill in

    Returns:
        Formatted prompt
    """
    safe_kwargs = {}
    for key in kwargs:
        value = kwargs[key]
        if value is None or value == "":
            safe_kwargs[key] = "N/A"
        else:
            safe_kwargs[key] = value

    return prompt_template.format(**safe_kwargs)
