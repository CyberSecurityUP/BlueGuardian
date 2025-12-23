"""Specialized prompts for SIEM log analysis.

This module contains prompts for analyzing security logs from SIEM platforms
to detect threats, anomalies, and security incidents.
"""

SIEM_LOG_ANALYSIS_SYSTEM_PROMPT = """You are an expert security analyst specializing in:
- SIEM log analysis and threat hunting
- Security incident detection and investigation
- Attack pattern recognition across multiple log sources
- Behavioral anomaly detection
- Threat actor TTPs (Tactics, Techniques, and Procedures)
- Security operations center (SOC) analysis

Your role is to analyze security logs and identify threats, incidents, and anomalies.

CRITICAL RULES:
1. Base analysis on actual log data and statistical patterns
2. Distinguish between normal operations and malicious activity
3. Consider context: time of day, user behavior patterns, business operations
4. Identify attack chains and related events across logs
5. Assess severity and urgency accurately
6. Provide actionable incident response recommendations
7. Map findings to MITRE ATT&CK framework
8. Prioritize high-confidence threats

OUTPUT FORMAT:
- Verdict: Attack Detected/Suspicious Activity/Normal Activity (confidence %)
- Executive summary of findings
- Attack timeline (if attack detected)
- Detailed analysis of suspicious events
- Affected assets and users
- IOCs extracted from logs
- MITRE ATT&CK mapping
- Recommended immediate actions
- Investigation steps

Remember: Context matters. Consider business operations and user patterns."""

SIEM_LOG_ANALYSIS_PROMPT = """Analyze these security logs for threats and anomalies:

LOG SUMMARY:
- Total Logs: {total_logs}
- Time Range: {time_range}
- Unique IPs: {unique_ip_count}
- Unique Users: {unique_user_count}

AUTHENTICATION ACTIVITY:
- Failed Logins: {failed_logins}
- Successful Logins: {successful_logins}
- Privilege Escalations: {privilege_escalations}

HIGH SEVERITY EVENTS:
- High Severity Count: {high_severity_count}

TOP SOURCE IPs:
{top_sources}

SUSPICIOUS COMMANDS:
{suspicious_commands}

DETECTED ANOMALIES:
{anomalies}

SAMPLE LOG ENTRIES:
{sample_logs}

ANALYSIS TASKS:
1. **Verdict**: Attack Detected/Suspicious Activity/Normal Activity (confidence %)

2. **Threat Assessment**:
   - What type of attack or threat is present?
   - Severity level: Critical/High/Medium/Low
   - Confidence in assessment?

3. **Attack Timeline**:
   - Initial access time?
   - Attack progression through logs?
   - Current attack stage?

4. **Attack Pattern Analysis**:
   - What is the attacker trying to achieve?
   - Reconnaissance phase?
   - Exploitation attempts?
   - Lateral movement?
   - Data exfiltration?
   - Persistence mechanisms?

5. **Authentication Analysis**:
   - Are failed logins part of brute force attack?
   - Credential stuffing or password spraying?
   - Compromised accounts?
   - Unusual login times or locations?

6. **Command Analysis**:
   - What do suspicious commands indicate?
   - Living-off-the-land techniques?
   - Privilege escalation attempts?
   - Reconnaissance activities?

7. **Network Behavior**:
   - Unusual connections or traffic?
   - C2 communications?
   - Port scanning?
   - Data exfiltration patterns?

8. **Affected Assets**:
   - Which systems are compromised or targeted?
   - User accounts at risk?
   - Critical systems involved?

9. **IOCs**: Extract ALL indicators:
   - Attacker IP addresses
   - Compromised accounts
   - Malicious commands
   - File paths
   - Network connections

10. **MITRE ATT&CK Mapping**:
    - Initial Access techniques
    - Execution methods
    - Persistence mechanisms
    - Privilege Escalation
    - Defense Evasion
    - Credential Access
    - Discovery
    - Lateral Movement
    - Collection
    - Exfiltration

11. **Immediate Actions**:
    - What should be done RIGHT NOW?
    - Accounts to disable?
    - Systems to isolate?
    - IPs to block?

12. **Investigation Steps**:
    - Additional logs to review?
    - Systems to forensically analyze?
    - Users to interview?
    - Threat hunting queries?

13. **Root Cause**:
    - How did the attacker gain access?
    - What vulnerability was exploited?
    - Was this preventable?

Correlate events across logs. Look for attack chains, not isolated events."""

BRUTE_FORCE_DETECTION_PROMPT = """Analyze these authentication logs for brute force attacks:

FAILED LOGIN STATISTICS:
{failed_login_stats}

TARGETED ACCOUNTS:
{targeted_accounts}

SOURCE IPs:
{source_ips}

TIME DISTRIBUTION:
{time_distribution}

ANALYSIS:
1. **Brute Force Assessment**: Is this a brute force attack? (Yes/No + confidence)

2. **Attack Type**:
   - Password spraying (many accounts, few attempts each)?
   - Credential stuffing (using leaked passwords)?
   - Traditional brute force (one account, many attempts)?

3. **Attack Characteristics**:
   - Number of unique IPs involved?
   - Distributed vs. single source?
   - Attack rate (attempts per minute)?
   - Duration of attack?

4. **Target Analysis**:
   - Specific accounts targeted?
   - Service accounts vs. user accounts?
   - Privileged accounts targeted?

5. **Success Rate**:
   - Any successful logins from attacker IPs?
   - Compromised accounts?

6. **Sophistication**:
   - Using Tor or VPN?
   - Rotating IPs?
   - Time-delayed attempts (evasion)?

7. **Response Actions**:
   - Block IPs?
   - Enforce MFA?
   - Reset passwords?
   - Account lockout policies?

8. **MITRE**: T1110 (Brute Force) sub-techniques

Distinguish between legitimate failed logins and attack."""

PRIVILEGE_ESCALATION_PROMPT = """Analyze these logs for privilege escalation:

PRIVILEGE CHANGES:
{privilege_changes}

SUSPICIOUS COMMANDS:
{suspicious_commands}

USER ACTIVITY:
{user_activity}

ANALYSIS:
1. **Escalation Detected**: Yes/No (confidence %)

2. **Escalation Type**:
   - Sudo/su usage?
   - UAC bypass?
   - Exploit-based escalation?
   - Token manipulation?
   - Service account abuse?

3. **User Analysis**:
   - Who performed escalation?
   - Authorized vs. unauthorized?
   - Usual behavior for this user?

4. **Command Analysis**:
   - What commands were run with elevated privileges?
   - Malicious intent?
   - Reconnaissance?
   - Persistence creation?

5. **Impact**:
   - What level of access achieved?
   - Admin/root access gained?
   - Domain admin compromise?

6. **Legitimacy**:
   - Authorized change?
   - During business hours?
   - Expected for this user/role?

7. **Response**:
   - Revoke elevated access?
   - Investigate further?
   - User interview needed?

8. **MITRE**: T1068, T1548, T1134, etc."""

LATERAL_MOVEMENT_PROMPT = """Analyze these logs for lateral movement:

NETWORK CONNECTIONS:
{network_connections}

AUTHENTICATION PATTERNS:
{authentication_patterns}

SERVICE USAGE:
{service_usage}

ANALYSIS:
1. **Lateral Movement**: Detected? (Yes/No + confidence)

2. **Movement Pattern**:
   - RDP connections?
   - SMB/CIFS activity?
   - PSExec or remote execution?
   - Pass-the-hash indicators?
   - Pass-the-ticket indicators?

3. **Source and Destination**:
   - Origin system?
   - Target systems?
   - Movement path through network?

4. **Credentials Used**:
   - Which accounts?
   - Service accounts abused?
   - Compromised admin accounts?

5. **Timeline**:
   - When did movement start?
   - Progression rate?
   - Active ongoing?

6. **Targets**:
   - Critical systems reached?
   - Domain controllers accessed?
   - Database servers?

7. **Detection Gaps**:
   - Was movement stealthy?
   - Living-off-the-land techniques?

8. **Containment**:
   - Network segmentation needed?
   - Isolate affected systems?
   - Credential reset?

9. **MITRE**: T1021 (Remote Services) sub-techniques"""

DATA_EXFILTRATION_PROMPT = """Analyze these logs for data exfiltration:

NETWORK TRAFFIC:
{network_traffic}

LARGE TRANSFERS:
{large_transfers}

EXTERNAL CONNECTIONS:
{external_connections}

ANALYSIS:
1. **Exfiltration Detected**: Yes/No (confidence %)

2. **Exfiltration Method**:
   - Direct download?
   - DNS tunneling?
   - Email/cloud storage?
   - FTP/SFTP?
   - Encrypted channels?

3. **Data Volume**:
   - How much data transferred?
   - Unusual for baseline?

4. **Destination**:
   - Where is data going?
   - Known malicious IP?
   - Cloud storage service?
   - Unusual country?

5. **Data Type**:
   - What was exfiltrated?
   - Database dumps?
   - Documents?
   - Credentials?

6. **Source**:
   - Which systems?
   - Sensitive data stores?

7. **Timeline**:
   - When did exfiltration start?
   - Ongoing or complete?

8. **Response**:
   - Block destination IPs?
   - Isolate source systems?
   - DLP policies?

9. **MITRE**: T1041, T1048, T1567"""

MALWARE_INFECTION_PROMPT = """Analyze these logs for malware infection indicators:

PROCESS EXECUTIONS:
{process_executions}

NETWORK CONNECTIONS:
{network_connections}

FILE MODIFICATIONS:
{file_modifications}

REGISTRY CHANGES:
{registry_changes}

ANALYSIS:
1. **Infection Status**: Infected/Likely Infected/Clean (confidence %)

2. **Malware Type**:
   - Ransomware?
   - Trojan/RAT?
   - Cryptominer?
   - Wiper?
   - Rootkit?

3. **Infection Vector**:
   - Phishing email?
   - Drive-by download?
   - Exploit?
   - USB/removable media?

4. **Malware Behavior**:
   - What is the malware doing?
   - C2 communications?
   - Persistence mechanisms?
   - Anti-analysis techniques?

5. **Spread**:
   - Worm characteristics?
   - Spreading to other systems?
   - Infection count?

6. **IOCs**:
   - Malicious processes
   - C2 IPs/domains
   - File hashes
   - Registry keys
   - Mutexes

7. **Containment**:
   - Isolate infected systems?
   - Block C2 communications?
   - Network segmentation?

8. **Recovery**:
   - Clean vs. reimage?
   - Backup restoration?

9. **MITRE**: Map to full kill chain"""

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
