"""Specialized prompts for phishing email analysis.

This module contains prompts for analyzing phishing emails, detecting
social engineering, and identifying malicious patterns.
"""

PHISHING_ANALYSIS_SYSTEM_PROMPT = """You are an expert email security analyst specializing in:
- Phishing and spear-phishing detection
- Social engineering tactics and psychological manipulation
- Email authentication (SPF, DKIM, DMARC)
- Brand impersonation and business email compromise (BEC)
- Malicious attachment and link analysis
- Email header forensics

Your role is to analyze emails for phishing indicators and provide actionable intelligence.

CRITICAL RULES:
1. Base analysis on actual email data and headers
2. Identify social engineering techniques used
3. Verify email authentication results (SPF/DKIM/DMARC)
4. Analyze sender reputation and domain age
5. Examine links and attachments for malicious content
6. Provide confidence levels for each finding
7. Give actionable recommendations for defenders

OUTPUT FORMAT:
- Verdict: Phishing/Suspicious/Legitimate (with confidence %)
- Executive summary of threat
- Social engineering tactics identified
- Technical indicators (headers, authentication, links)
- IOCs and reputation data
- MITRE ATT&CK mapping
- User education points
- Defensive recommendations

Remember: Phishing is about deception. Look for inconsistencies and social manipulation."""

EMAIL_PHISHING_ANALYSIS_PROMPT = """Analyze this email for phishing indicators:

EMAIL HEADERS:
From: {sender}
Reply-To: {reply_to}
To: {recipients}
Subject: {subject}
Date: {date}

AUTHENTICATION:
SPF: {spf}
DKIM: {dkim}
DMARC: {dmarc}

EMAIL BODY:
{body}

ATTACHMENTS ({attachment_count}):
{attachments}

LINKS ({link_count}):
{links}

HEADER ANOMALIES:
{header_anomalies}

SUSPICIOUS PATTERNS:
{suspicious_patterns}

{virustotal_data}

ANALYSIS TASKS:
1. **Verdict**: Phishing/Suspicious/Legitimate (confidence %)

2. **Phishing Type**:
   - Generic phishing
   - Spear-phishing (targeted)
   - Business Email Compromise (BEC)
   - Brand impersonation
   - Credential harvesting
   - Malware delivery

3. **Social Engineering Analysis**:
   - What urgency/fear tactics are used?
   - Authority/trust exploitation?
   - Emotional triggers?
   - Impersonated entity?

4. **Sender Analysis**:
   - Is sender legitimate?
   - Domain reputation?
   - SPF/DKIM/DMARC pass/fail significance?
   - Reply-To mismatch concerns?

5. **Content Analysis**:
   - Grammatical errors or suspicious phrasing?
   - Generic vs. personalized content?
   - Urgency keywords?
   - Financial/credential requests?

6. **Link Analysis**:
   - Where do links really point?
   - URL obfuscation or shorteners?
   - Credential harvesting pages?
   - Malware download sites?

7. **Attachment Analysis**:
   - File types and extensions?
   - Malicious potential?
   - Double extension tricks?

8. **IOCs**:
   - Sender email/domain
   - URLs and domains
   - IP addresses
   - File hashes (if attachments)

9. **MITRE ATT&CK**:
   - T1566: Phishing techniques
   - T1598: Phishing for Information
   - Specific sub-techniques

10. **Recommendations**:
    - Should this be blocked/quarantined?
    - User education points
    - Detection rules
    - Response actions

Be specific about WHY this is/isn't phishing. Cite evidence."""

BRAND_IMPERSONATION_PROMPT = """Analyze this email for brand impersonation:

CLAIMED BRAND/SENDER:
{suspected_brand}

ACTUAL SENDER:
{sender}

EMAIL AUTHENTICATION:
SPF: {spf}
DKIM: {dkim}
DMARC: {dmarc}

BODY CONTENT:
{body}

LINKS:
{links}

ANALYSIS:
1. **Is this brand impersonation?** (Yes/No + confidence %)

2. **Evidence**:
   - Does sender domain match brand?
   - Authentication results?
   - Link destinations legitimate?
   - Content/branding accurate?

3. **Impersonation Quality**:
   - Sophisticated (looks very real)
   - Moderate (some indicators)
   - Poor (obvious fake)

4. **Intent**:
   - Credential theft?
   - Malware delivery?
   - Financial fraud?
   - Information gathering?

5. **Real vs. Fake Indicators**:
   - List signs it's fake
   - Any legitimate elements?

6. **User Impact**:
   - How convincing to average user?
   - What might they do?

7. **Defensive Measures**:
   - Block sender domain?
   - DMARC policy recommendations?
   - User awareness training?

Provide clear verdict on whether this impersonates the claimed brand."""

BEC_ANALYSIS_PROMPT = """Analyze for Business Email Compromise (BEC) indicators:

SENDER:
{sender}

CLAIMED IDENTITY:
{claimed_identity}

EMAIL CONTENT:
{content}

REQUEST TYPE:
{request_type}

ANALYSIS:
1. **BEC Likelihood**: (High/Medium/Low + confidence %)

2. **BEC Type**:
   - CEO Fraud (fake executive)
   - Account Compromise (real account hacked)
   - Attorney Impersonation
   - Vendor Email Compromise

3. **Red Flags**:
   - Unexpected request?
   - Unusual language/style?
   - Urgency or secrecy demands?
   - Financial transaction request?
   - Authentication bypass (SPF/DKIM fail)?
   - External email from internal sender?

4. **Social Engineering**:
   - Authority exploitation?
   - Time pressure?
   - Confidentiality demands?
   - Deviation from normal process?

5. **Verification Steps**:
   - How to verify legitimacy?
   - Out-of-band confirmation needed?
   - Policy violations?

6. **Financial Risk**:
   - Monetary amount at risk?
   - Wire transfer requests?
   - Change of payment details?

7. **Recommendations**:
   - Immediate actions?
   - Verification procedures?
   - Policy enforcement?

BEC is sophisticated. Look for subtle deviations from normal communication."""

LINK_ANALYSIS_PROMPT = """Analyze these links for malicious intent:

LINKS FOUND:
{links}

CONTEXT:
{context}

For each link, analyze:
1. **URL Structure**:
   - Display text vs. actual URL
   - Obfuscation techniques?
   - URL shorteners?

2. **Domain Analysis**:
   - Domain age and reputation?
   - Typosquatting?
   - Suspicious TLD?

3. **Destination**:
   - Credential harvesting page?
   - Malware download?
   - Phishing kit?
   - Legitimate site?

4. **Obfuscation**:
   - Encoded characters?
   - Homograph attacks (similar chars)?
   - Multiple redirects?

5. **Risk Assessment**:
   - Malicious/Suspicious/Benign
   - Confidence level
   - Evidence

Provide verdict for each link with supporting evidence."""

ATTACHMENT_THREAT_ANALYSIS_PROMPT = """Analyze these email attachments for threats:

ATTACHMENTS:
{attachments}

CONTEXT:
{context}

For each attachment, analyze:
1. **File Type Assessment**:
   - Extension and actual type match?
   - Commonly weaponized type?
   - Double extension trick?

2. **Threat Potential**:
   - Can execute code?
   - Can contain macros?
   - Can exploit vulnerabilities?

3. **Delivery Method**:
   - Expected attachment for this email?
   - Legitimate business context?
   - Unsolicited?

4. **Naming**:
   - Generic vs. specific filename?
   - Social engineering in name?
   - Misleading extension?

5. **Risk Level**:
   - Critical/High/Medium/Low
   - Should be blocked?
   - Safe to open in sandbox?

6. **Recommendations**:
   - Quarantine?
   - Sandbox analysis?
   - Block file type?

Be conservative. Unknown attachments should be treated as suspicious."""

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
