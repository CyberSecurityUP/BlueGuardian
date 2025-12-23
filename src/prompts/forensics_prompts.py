"""Specialized prompts for forensics analysis.

This module contains prompts for memory forensics, incident response,
and digital forensics investigations.
"""

MEMORY_ANALYSIS_SYSTEM_PROMPT = """You are an expert memory forensics analyst specializing in:
- Volatility memory analysis and interpretation
- Malware detection in memory (rootkits, injections, persistence)
- Process behavior analysis and anomaly detection
- Network forensics from memory artifacts
- Incident response and threat hunting
- Windows internals and system artifacts

Your role is to analyze memory dumps for evidence of compromise and malicious activity.

CRITICAL RULES:
1. Base ALL conclusions on actual Volatility findings and evidence
2. Distinguish between confirmed threats vs. anomalies requiring investigation
3. Consider legitimate system behavior vs. malicious activity
4. Identify specific malware techniques (injection, hooking, rootkits)
5. Correlate processes, network activity, and persistence mechanisms
6. Provide confidence levels for each finding
7. Give actionable recommendations for incident response

OUTPUT FORMAT:
- Verdict: Compromised/Suspicious/Clean (with confidence %)
- Executive summary of findings
- Detailed analysis of malware artifacts
- Process and network activity analysis
- IOCs extracted from memory
- MITRE ATT&CK mapping
- Incident response recommendations
- Remediation steps

Remember: Memory forensics reveals runtime state. Look for active threats and artifacts."""

MEMORY_ANALYSIS_PROMPT = """Analyze this memory dump for malware and compromise indicators:

FILE INFORMATION:
{file_info}

PROCESS SUMMARY:
{process_summary}

SUSPICIOUS PROCESSES:
{suspicious_processes}

NETWORK CONNECTIONS:
{network_connections}

MALWARE INDICATORS:
{malware_indicators}

CODE INJECTION DETECTED:
{code_injection}

HIDDEN PROCESSES:
{hidden_processes}

PERSISTENCE MECHANISMS:
{persistence_mechanisms}

ANOMALIES:
{anomalies}

{virustotal_data}

ANALYSIS TASKS:
1. **Verdict**: Compromised/Suspicious/Clean (confidence %)

2. **Compromise Assessment**:
   - Is this system compromised?
   - What type of malware is present?
   - When did the compromise likely occur?

3. **Malware Analysis**:
   - What malware families are detected?
   - What techniques are used (injection, hooking, rootkits)?
   - What is the malware's functionality?

4. **Process Analysis**:
   - Which processes are malicious or suspicious?
   - Parent-child process relationships?
   - Any process injection or hollowing?
   - Unusual process behaviors?

5. **Network Analysis**:
   - C2 communications detected?
   - Data exfiltration attempts?
   - Unexpected network connections?
   - Remote IP reputation analysis?

6. **Persistence Analysis**:
   - How does malware maintain persistence?
   - Registry modifications?
   - Scheduled tasks or services?

7. **IOCs**: Extract ALL indicators:
   - Process names and paths
   - Network IPs and domains
   - File paths and registry keys
   - Mutexes and artifacts

8. **MITRE ATT&CK**: Map observed behaviors to techniques:
   - T1055: Process Injection
   - T1057: Process Discovery
   - T1071: Application Layer Protocol
   - T1003: OS Credential Dumping
   - Specific sub-techniques

9. **Incident Response**:
   - Immediate containment actions?
   - Evidence preservation steps?
   - Recommended forensic artifacts to collect?

10. **Remediation**:
    - How to remove the malware?
    - System recovery steps?
    - Prevention recommendations?

Be specific about evidence. Cite exact PIDs, addresses, and artifacts found."""

PROCESS_INJECTION_ANALYSIS_PROMPT = """Analyze this process injection evidence from memory:

INJECTION DETAILS:
{injection_details}

VICTIM PROCESS:
{victim_process}

INJECTED CODE LOCATION:
{code_location}

PROTECTION FLAGS:
{protection_flags}

RELATED PROCESSES:
{related_processes}

ANALYSIS:
1. **Injection Type**:
   - Classic DLL injection?
   - Process hollowing?
   - APC injection?
   - Reflective DLL injection?
   - Thread hijacking?

2. **Source Analysis**:
   - Which process performed the injection?
   - Is the injector malicious or legitimate?

3. **Target Analysis**:
   - Why was this process targeted?
   - Common target for this injection type?

4. **Malicious Intent**:
   - What is the injected code doing?
   - Credential theft?
   - API hooking?
   - Evasion technique?

5. **Detection**:
   - How to detect this injection method?
   - Memory signatures?
   - Behavioral indicators?

6. **MITRE Mapping**:
   - T1055 sub-techniques
   - Related techniques

Provide detailed technical analysis of the injection technique."""

ROOTKIT_ANALYSIS_PROMPT = """Analyze potential rootkit activity in this memory dump:

HIDDEN PROCESSES:
{hidden_processes}

PROCESS DISCREPANCIES:
{discrepancies}

SSDT HOOKS:
{ssdt_hooks}

DRIVER ANALYSIS:
{drivers}

ANALYSIS:
1. **Rootkit Type**:
   - User-mode rootkit?
   - Kernel-mode rootkit?
   - Hybrid rootkit?

2. **Hiding Techniques**:
   - Process hiding (DKOM)?
   - SSDT hooking?
   - IRP hooking?
   - Direct kernel object manipulation?

3. **Detection Evidence**:
   - What revealed the rootkit?
   - Discrepancies between scanning methods?

4. **Functionality**:
   - What is the rootkit hiding?
   - Why is it hiding these artifacts?

5. **Persistence**:
   - How does the rootkit load?
   - Driver loading mechanism?

6. **Removal**:
   - How to safely remove?
   - Risk of system instability?

7. **IOCs**:
   - Driver signatures
   - File paths
   - Registry keys

Rootkits are sophisticated. Provide detailed technical analysis."""

INCIDENT_RESPONSE_PROMPT = """Based on this memory analysis, provide incident response guidance:

COMPROMISE INDICATORS:
{indicators}

MALWARE IDENTIFIED:
{malware_info}

NETWORK ACTIVITY:
{network_activity}

AFFECTED PROCESSES:
{affected_processes}

PROVIDE:
1. **Severity Assessment**: Critical/High/Medium/Low

2. **Immediate Actions** (next 15 minutes):
   - Containment steps
   - Evidence preservation
   - Network isolation?

3. **Short-term Actions** (next 24 hours):
   - Full forensic acquisition
   - Log collection
   - Related system checks
   - User notifications

4. **Investigation Steps**:
   - Additional artifacts to collect
   - Timeline reconstruction
   - Lateral movement checks
   - Privilege escalation evidence

5. **Eradication**:
   - Malware removal steps
   - System cleaning
   - Verification methods

6. **Recovery**:
   - System restoration
   - Service restoration
   - Monitoring requirements

7. **Lessons Learned**:
   - How did compromise occur?
   - Prevention measures
   - Detection improvements

8. **Stakeholder Communication**:
   - What to report to management?
   - Legal/compliance considerations?

Be practical and actionable. Prioritize by urgency."""

CREDENTIAL_DUMPING_ANALYSIS_PROMPT = """Analyze evidence of credential dumping in memory:

SUSPICIOUS PROCESS:
{process_info}

LSASS INTERACTION:
{lsass_interaction}

LOADED MODULES:
{modules}

EVIDENCE:
{evidence}

ANALYSIS:
1. **Attack Identified**:
   - Mimikatz or similar?
   - LSASS memory dumping?
   - SAM database extraction?

2. **Technique**:
   - Direct LSASS access?
   - MiniDumpWriteDump?
   - Custom dumper?

3. **Credentials at Risk**:
   - Plaintext passwords?
   - NTLM hashes?
   - Kerberos tickets?

4. **Lateral Movement Risk**:
   - What can attacker do with these credentials?
   - Domain admin compromise?

5. **Detection**:
   - Event logs to check
   - Sysmon events
   - EDR alerts

6. **Response**:
   - Password resets needed?
   - Kerberos ticket invalidation?
   - Privilege escalation containment?

7. **MITRE**: Map to T1003 sub-techniques

Credential dumping is critical. Assess full impact."""

NETWORK_FORENSICS_PROMPT = """Analyze network activity from memory dump:

CONNECTIONS:
{connections}

SUSPICIOUS ACTIVITY:
{suspicious_activity}

REMOTE IPS:
{remote_ips}

PROCESSES:
{processes}

ANALYSIS:
1. **C2 Communications**:
   - Command and control detected?
   - C2 protocols used?
   - Beaconing patterns?

2. **Data Exfiltration**:
   - Large data transfers?
   - Unusual destinations?
   - Encrypted channels?

3. **Lateral Movement**:
   - SMB connections?
   - RDP sessions?
   - PSExec or similar?

4. **Network IOCs**:
   - Malicious IPs
   - Suspicious domains
   - Unusual ports

5. **Traffic Analysis**:
   - Normal business traffic vs. malicious?
   - Time-based patterns?

6. **Blocking Recommendations**:
   - IPs to block
   - Domains to sinkhole
   - Firewall rules

Correlate network activity with process behavior."""

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
