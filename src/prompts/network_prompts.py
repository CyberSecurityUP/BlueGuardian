"""Specialized prompts for network indicator analysis.

This module contains prompts for analyzing IPs, domains, and URLs
for threat intelligence and malicious infrastructure detection.
"""

NETWORK_ANALYSIS_SYSTEM_PROMPT = """You are an expert network threat analyst specializing in:
- IP address reputation and geolocation analysis
- Domain name analysis and DGA detection
- URL analysis and phishing detection
- C2 infrastructure identification
- Malicious hosting provider detection
- Network threat intelligence

Your role is to analyze network indicators for signs of malicious activity.

CRITICAL RULES:
1. Base analysis on actual DNS, WHOIS, and reputation data
2. Consider legitimate vs. malicious uses of infrastructure
3. Identify specific threat actor infrastructure patterns
4. Distinguish between compromised and malicious infrastructure
5. Assess confidence based on available evidence
6. Provide actionable intelligence for blocking/monitoring
7. Map to MITRE ATT&CK techniques where applicable

OUTPUT FORMAT:
- Verdict: Malicious/Suspicious/Clean (with confidence %)
- Executive summary of findings
- Detailed technical analysis
- Threat intelligence context
- IOCs and related indicators
- MITRE ATT&CK mapping
- Defensive recommendations

Remember: Infrastructure can be shared. Consider all context before verdict."""

IP_ANALYSIS_PROMPT = """Analyze this IP address for malicious activity:

IP ADDRESS: {ip_address}

REVERSE DNS: {reverse_dns}

CHARACTERISTICS:
- Private IP: {is_private}
- Cloud Provider: {is_cloud}
- Provider: {cloud_provider}

ANOMALIES:
{anomalies}

{virustotal_data}

ANALYSIS TASKS:
1. **Verdict**: Malicious/Suspicious/Clean (confidence %)

2. **Infrastructure Assessment**:
   - What type of infrastructure is this?
   - Hosting provider analysis?
   - Is this typical for malware C2?
   - Shared hosting vs. dedicated?

3. **Reputation Analysis**:
   - Known malicious activity?
   - Abuse reports?
   - Historical context?

4. **Reverse DNS Analysis**:
   - Does reverse DNS make sense?
   - Generic vs. specific hostname?
   - Cloud provider patterns?

5. **Threat Context**:
   - Associated malware families?
   - APT group infrastructure?
   - Commodity malware?

6. **Geolocation Considerations**:
   - Is location unusual for target?
   - Bulletproof hosting country?
   - Jurisdiction concerns?

7. **Related IOCs**:
   - Associated domains
   - Related IPs
   - ASN/network blocks

8. **MITRE ATT&CK**:
   - T1071: Application Layer Protocol (if C2)
   - T1573: Encrypted Channel
   - T1090: Proxy

9. **Defensive Actions**:
   - Should this IP be blocked?
   - Monitor vs. block decision
   - EDR/firewall rules
   - SIEM alerts

10. **Confidence Assessment**:
    - Strong indicators vs. circumstantial
    - False positive risk
    - Additional validation needed?

Be specific about why this IP is/isn't malicious."""

DOMAIN_ANALYSIS_PROMPT = """Analyze this domain for malicious activity:

DOMAIN: {domain}

DOMAIN PROPERTIES:
- TLD: {tld}
- Length: {length}
- Entropy: {entropy}
- Possible DGA: {is_dga}
- Subdomain Count: {subdomain_count}

RESOLVED IPs:
{resolved_ips}

ANOMALIES:
{anomalies}

{virustotal_data}

ANALYSIS TASKS:
1. **Verdict**: Malicious/Suspicious/Clean (confidence %)

2. **Domain Legitimacy**:
   - Legitimate business domain?
   - Personal vs. corporate?
   - Brand or trademark infringement?

3. **DGA Analysis**:
   - Domain generation algorithm?
   - Entropy analysis suggests DGA?
   - Botnet family identification?

4. **Typosquatting**:
   - Similar to known brand?
   - Homograph attack?
   - Lookalike domain?

5. **Registration Analysis**:
   - Domain age (if known)?
   - Recent registration flag?
   - Privacy-protected WHOIS?
   - Registrar reputation?

6. **DNS Analysis**:
   - Resolves to expected IPs?
   - Fast-flux DNS pattern?
   - Multiple A records (round robin)?
   - Suspicious nameservers?

7. **TLD Assessment**:
   - Suspicious TLD (.tk, .ml, etc.)?
   - Free vs. paid TLD?
   - TLD abuse history?

8. **Content Prediction**:
   - What might be hosted here?
   - Phishing kit?
   - Malware download?
   - C2 server?

9. **IOCs**:
   - Domain itself
   - Resolved IPs
   - Related domains
   - Nameservers

10. **MITRE ATT&CK**:
    - T1583.001: Acquire Infrastructure - Domains
    - T1584.001: Compromise Infrastructure - Domains
    - T1071.001: Web Protocols

11. **Defensive Actions**:
    - DNS sinkholing?
    - Block at firewall/proxy?
    - Monitor traffic?
    - Threat intel feeds?

Provide clear reasoning based on evidence."""

URL_ANALYSIS_PROMPT = """Analyze this URL for malicious activity:

URL: {url}

URL COMPONENTS:
- Scheme: {scheme}
- Domain: {domain}
- Path: {path}

URL CHARACTERISTICS:
- URL Shortener: {is_shortened}
- Uses IP Address: {uses_ip}
- Suspicious TLD: {suspicious_tld}
- Suspicious Path: {has_suspicious_path}
- Suspicious Parameters: {has_suspicious_params}

ANOMALIES:
{anomalies}

{virustotal_data}

ANALYSIS TASKS:
1. **Verdict**: Malicious/Suspicious/Clean (confidence %)

2. **URL Purpose**:
   - What is this URL for?
   - Legitimate service?
   - Phishing page?
   - Malware download?
   - C2 communication?

3. **Domain Analysis**:
   - Is domain legitimate?
   - Compromised legitimate site?
   - Malicious infrastructure?

4. **Path Analysis**:
   - Suspicious keywords in path?
   - Login/account/verify patterns?
   - Obfuscated path?
   - File download indicators?

5. **Parameter Analysis**:
   - What do parameters suggest?
   - Command execution parameters?
   - Redirect chains?
   - Tracking/session IDs?

6. **Obfuscation Detection**:
   - URL encoding abuse?
   - Unicode/punycode tricks?
   - IP address obfuscation?

7. **URL Shortener**:
   - If shortened, what's the risk?
   - Legitimate use vs. obfuscation?

8. **Phishing Indicators**:
   - Impersonating a brand?
   - Credential harvesting page?
   - Social engineering tactics?

9. **Malware Distribution**:
   - Drive-by download?
   - Exploit kit?
   - Malicious payload hosting?

10. **IOCs**:
    - Full URL
    - Domain
    - IP addresses
    - File hashes (if downloaded)

11. **MITRE ATT&CK**:
    - T1566.002: Phishing - Spearphishing Link
    - T1204.002: User Execution - Malicious Link
    - T1105: Ingress Tool Transfer
    - T1071.001: Web Protocols

12. **User Impact**:
    - What happens if user clicks?
    - Credential theft?
    - Malware infection?
    - Data theft?

13. **Defensive Actions**:
    - Block URL at proxy/firewall?
    - Add to phishing filter?
    - User awareness training?
    - Quarantine emails with this URL?

Assess the full attack chain this URL represents."""

C2_INFRASTRUCTURE_ANALYSIS_PROMPT = """Analyze this network indicator as potential C2 infrastructure:

INDICATOR: {indicator}
TYPE: {type}

CHARACTERISTICS:
{characteristics}

NETWORK BEHAVIOR:
{network_behavior}

ANALYSIS:
1. **C2 Assessment**: Is this C2 infrastructure? (Yes/No + confidence)

2. **C2 Type**:
   - HTTP/HTTPS C2?
   - DNS tunneling?
   - Custom protocol?

3. **Malware Family**:
   - Known malware family using this infrastructure?
   - Commodity malware?
   - APT infrastructure?

4. **Communication Pattern**:
   - Beaconing detected?
   - Request/response?
   - Data exfiltration?

5. **Infrastructure Longevity**:
   - Long-lived infrastructure?
   - Fast-flux rotation?
   - DGA domains?

6. **Shared Infrastructure**:
   - Multiple malware families?
   - Bulletproof hosting?
   - VPS/cloud provider?

7. **Blocking Impact**:
   - Safe to block?
   - Collateral damage risk?
   - Alternative C2s likely?

Map to C2 frameworks (Cobalt Strike, Metasploit, etc.) if applicable."""

DGA_DOMAIN_ANALYSIS_PROMPT = """Analyze this domain for DGA (Domain Generation Algorithm) characteristics:

DOMAIN: {domain}

ENTROPY: {entropy}
LENGTH: {length}
CHARACTER DISTRIBUTION: {char_dist}

ANALYSIS:
1. **DGA Probability**: High/Medium/Low (confidence %)

2. **Algorithm Characteristics**:
   - Random vs. dictionary-based?
   - Length patterns?
   - Character distribution?

3. **Malware Family**:
   - Known DGA family?
   - Conficker, Zeus, Locky, etc.?

4. **Seed Analysis**:
   - Time-based seed?
   - Predictable algorithm?

5. **Detection**:
   - How to detect similar DGA domains?
   - YARA rules for DGA?

6. **Mitigation**:
   - Sinkholing strategy?
   - Predicted future domains?

DGA analysis requires technical depth. Be specific."""

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
