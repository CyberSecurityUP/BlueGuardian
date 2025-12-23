"""JavaScript deobfuscation and analysis.

This module provides deobfuscation capabilities for malicious JavaScript,
handling common obfuscation techniques used in malware and exploits.
"""

import base64
import html
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import jsbeautifier
from loguru import logger


@dataclass
class DeobfuscationResult:
    """Results from JavaScript deobfuscation."""

    original_code: str
    deobfuscated_code: str
    obfuscation_layers: int
    techniques_detected: List[str] = field(default_factory=list)
    decoded_strings: List[Tuple[str, str]] = field(default_factory=list)  # (method, value)
    urls_found: List[str] = field(default_factory=list)
    suspicious_functions: List[str] = field(default_factory=list)
    eval_chains: List[str] = field(default_factory=list)
    shell_commands: List[str] = field(default_factory=list)
    is_obfuscated: bool = False
    entropy: Optional[float] = None
    anomalies: List[str] = field(default_factory=list)


class JavaScriptDeobfuscator:
    """JavaScript deobfuscator for malware analysis.

    This class handles common JavaScript obfuscation techniques including:
    - Base64 encoding
    - Hex encoding
    - URL encoding
    - String concatenation
    - eval() chains
    - Character code obfuscation
    - JSFuck and similar techniques
    """

    # Suspicious JavaScript functions commonly used in malware
    SUSPICIOUS_FUNCTIONS = {
        'eval', 'Function', 'setTimeout', 'setInterval',
        'document.write', 'document.writeln', 'innerHTML',
        'ActiveXObject', 'WScript.Shell', 'WScript.CreateObject',
        'XMLHttpRequest', 'fetch', 'importScripts',
        'unescape', 'decodeURI', 'decodeURIComponent',
        'fromCharCode', 'atob', 'btoa',
    }

    # Patterns for encoded strings
    ENCODING_PATTERNS = {
        'base64': r'([A-Za-z0-9+/]{20,}={0,2})',
        'hex': r'(?:\\x[0-9a-fA-F]{2})+',
        'unicode': r'(?:\\u[0-9a-fA-F]{4})+',
        'octal': r'(?:\\[0-7]{1,3})+',
        'charcode': r'String\.fromCharCode\([^)]+\)',
        'url_encoded': r'(?:%[0-9a-fA-F]{2})+',
    }

    def __init__(self, max_iterations: int = 10):
        """Initialize deobfuscator.

        Args:
            max_iterations: Maximum deobfuscation iterations to prevent infinite loops
        """
        self.max_iterations = max_iterations
        logger.info(f"Initialized JavaScriptDeobfuscator (max_iterations={max_iterations})")

    def deobfuscate(self, javascript_code: str) -> DeobfuscationResult:
        """Deobfuscate JavaScript code.

        Args:
            javascript_code: Obfuscated JavaScript code

        Returns:
            DeobfuscationResult with findings
        """
        logger.debug("Starting JavaScript deobfuscation")

        result = DeobfuscationResult(
            original_code=javascript_code,
            deobfuscated_code=javascript_code,
            obfuscation_layers=0,
        )

        # Calculate entropy
        result.entropy = self._calculate_entropy(javascript_code)
        if result.entropy > 5.0:
            result.is_obfuscated = True
            result.techniques_detected.append(f"High entropy ({result.entropy:.2f})")

        # Detect obfuscation techniques
        self._detect_obfuscation_techniques(javascript_code, result)

        # Perform iterative deobfuscation
        current_code = javascript_code
        for iteration in range(self.max_iterations):
            logger.debug(f"Deobfuscation iteration {iteration + 1}")

            # Try various deobfuscation techniques
            new_code = current_code
            new_code = self._decode_base64(new_code, result)
            new_code = self._decode_hex(new_code, result)
            new_code = self._decode_unicode(new_code, result)
            new_code = self._decode_url_encoding(new_code, result)
            new_code = self._decode_html_entities(new_code, result)
            new_code = self._decode_charcode(new_code, result)
            new_code = self._simplify_string_concatenation(new_code)
            new_code = self._unescape_strings(new_code, result)

            # If no changes, we're done
            if new_code == current_code:
                break

            result.obfuscation_layers += 1
            current_code = new_code

        # Beautify the result
        try:
            result.deobfuscated_code = jsbeautifier.beautify(current_code)
        except:
            result.deobfuscated_code = current_code

        # Extract artifacts
        self._extract_urls(result.deobfuscated_code, result)
        self._extract_suspicious_functions(result.deobfuscated_code, result)
        self._extract_eval_chains(result.deobfuscated_code, result)
        self._extract_shell_commands(result.deobfuscated_code, result)

        logger.info(
            f"Deobfuscation complete: {result.obfuscation_layers} layers, "
            f"{len(result.techniques_detected)} techniques detected"
        )

        return result

    def _detect_obfuscation_techniques(
        self, code: str, result: DeobfuscationResult
    ) -> None:
        """Detect which obfuscation techniques are used.

        Args:
            code: JavaScript code
            result: Result object to update
        """
        # Check for various encoding patterns
        for technique, pattern in self.ENCODING_PATTERNS.items():
            if re.search(pattern, code):
                result.techniques_detected.append(technique)
                result.is_obfuscated = True

        # Check for eval
        if re.search(r'\beval\s*\(', code):
            result.techniques_detected.append('eval')
            result.is_obfuscated = True

        # Check for Function constructor
        if re.search(r'new\s+Function\s*\(', code) or re.search(r'Function\s*\(', code):
            result.techniques_detected.append('Function constructor')
            result.is_obfuscated = True

        # Check for excessive string concatenation
        if code.count('+') > 50:
            result.techniques_detected.append('string concatenation')
            result.is_obfuscated = True

        # Check for JSFuck-style obfuscation
        if code.count('[]') + code.count('!') + code.count('+') > len(code) * 0.3:
            result.techniques_detected.append('JSFuck-style')
            result.is_obfuscated = True

    def _decode_base64(self, code: str, result: DeobfuscationResult) -> str:
        """Decode base64 strings in JavaScript.

        Args:
            code: JavaScript code
            result: Result object to update

        Returns:
            Code with base64 decoded
        """
        # Find base64 strings
        pattern = self.ENCODING_PATTERNS['base64']

        def decode_match(match):
            b64_string = match.group(1)
            try:
                decoded = base64.b64decode(b64_string).decode('utf-8', errors='ignore')
                # Only decode if it looks like text (not binary)
                if decoded.isprintable() or '\n' in decoded:
                    result.decoded_strings.append(('base64', decoded[:200]))
                    return f'"{decoded}"'
            except:
                pass
            return match.group(0)

        return re.sub(pattern, decode_match, code)

    def _decode_hex(self, code: str, result: DeobfuscationResult) -> str:
        """Decode hex-encoded strings.

        Args:
            code: JavaScript code
            result: Result object to update

        Returns:
            Code with hex decoded
        """
        pattern = self.ENCODING_PATTERNS['hex']

        def decode_match(match):
            hex_string = match.group(0)
            try:
                # Extract hex values
                hex_values = re.findall(r'\\x([0-9a-fA-F]{2})', hex_string)
                decoded = ''.join(chr(int(h, 16)) for h in hex_values)
                if decoded.isprintable():
                    result.decoded_strings.append(('hex', decoded[:200]))
                    return f'"{decoded}"'
            except:
                pass
            return match.group(0)

        return re.sub(pattern, decode_match, code)

    def _decode_unicode(self, code: str, result: DeobfuscationResult) -> str:
        """Decode unicode escape sequences.

        Args:
            code: JavaScript code
            result: Result object to update

        Returns:
            Code with unicode decoded
        """
        pattern = self.ENCODING_PATTERNS['unicode']

        def decode_match(match):
            unicode_string = match.group(0)
            try:
                # Extract unicode values
                unicode_values = re.findall(r'\\u([0-9a-fA-F]{4})', unicode_string)
                decoded = ''.join(chr(int(u, 16)) for u in unicode_values)
                result.decoded_strings.append(('unicode', decoded[:200]))
                return f'"{decoded}"'
            except:
                pass
            return match.group(0)

        return re.sub(pattern, decode_match, code)

    def _decode_url_encoding(self, code: str, result: DeobfuscationResult) -> str:
        """Decode URL-encoded strings.

        Args:
            code: JavaScript code
            result: Result object to update

        Returns:
            Code with URL encoding decoded
        """
        pattern = self.ENCODING_PATTERNS['url_encoded']

        def decode_match(match):
            url_string = match.group(0)
            try:
                decoded = urllib.parse.unquote(url_string)
                if decoded != url_string:
                    result.decoded_strings.append(('url_encoding', decoded[:200]))
                    return decoded
            except:
                pass
            return match.group(0)

        return re.sub(pattern, decode_match, code)

    def _decode_html_entities(self, code: str, result: DeobfuscationResult) -> str:
        """Decode HTML entities.

        Args:
            code: JavaScript code
            result: Result object to update

        Returns:
            Code with HTML entities decoded
        """
        decoded = html.unescape(code)
        if decoded != code:
            result.decoded_strings.append(('html_entities', 'HTML entities decoded'))
        return decoded

    def _decode_charcode(self, code: str, result: DeobfuscationResult) -> str:
        """Decode String.fromCharCode constructions.

        Args:
            code: JavaScript code
            result: Result object to update

        Returns:
            Code with fromCharCode decoded
        """
        pattern = r'String\.fromCharCode\(([^)]+)\)'

        def decode_match(match):
            charcode_expr = match.group(1)
            try:
                # Extract numbers
                numbers = re.findall(r'\d+', charcode_expr)
                decoded = ''.join(chr(int(n)) for n in numbers if 0 < int(n) < 1114112)
                if decoded:
                    result.decoded_strings.append(('charcode', decoded[:200]))
                    return f'"{decoded}"'
            except:
                pass
            return match.group(0)

        return re.sub(pattern, decode_match, code)

    def _simplify_string_concatenation(self, code: str) -> str:
        """Simplify excessive string concatenation.

        Args:
            code: JavaScript code

        Returns:
            Simplified code
        """
        # Simple pattern: "a" + "b" + "c" -> "abc"
        pattern = r'"([^"]+)"\s*\+\s*"([^"]+)"'

        while re.search(pattern, code):
            code = re.sub(pattern, r'"\1\2"', code)

        return code

    def _unescape_strings(self, code: str, result: DeobfuscationResult) -> str:
        """Unescape JavaScript strings using unescape().

        Args:
            code: JavaScript code
            result: Result object to update

        Returns:
            Unescaped code
        """
        pattern = r'unescape\(["\']([^"\']+)["\']\)'

        def decode_match(match):
            escaped_string = match.group(1)
            try:
                decoded = urllib.parse.unquote(escaped_string)
                result.decoded_strings.append(('unescape', decoded[:200]))
                return f'"{decoded}"'
            except:
                pass
            return match.group(0)

        return re.sub(pattern, decode_match, code)

    def _extract_urls(self, code: str, result: DeobfuscationResult) -> None:
        """Extract URLs from code.

        Args:
            code: JavaScript code
            result: Result object to update
        """
        # URL pattern
        url_pattern = r'https?://[^\s"\']+'
        urls = re.findall(url_pattern, code)
        result.urls_found = list(set(urls))

    def _extract_suspicious_functions(
        self, code: str, result: DeobfuscationResult
    ) -> None:
        """Extract suspicious function calls.

        Args:
            code: JavaScript code
            result: Result object to update
        """
        for func in self.SUSPICIOUS_FUNCTIONS:
            if func in code:
                result.suspicious_functions.append(func)

                # Add to anomalies
                if func in ['eval', 'Function', 'ActiveXObject', 'WScript.Shell']:
                    result.anomalies.append(f"Uses dangerous function: {func}")

    def _extract_eval_chains(self, code: str, result: DeobfuscationResult) -> None:
        """Extract eval chains.

        Args:
            code: JavaScript code
            result: Result object to update
        """
        # Find eval expressions
        pattern = r'eval\s*\(([^)]+)\)'
        matches = re.findall(pattern, code)

        for match in matches[:10]:  # Limit to first 10
            # Truncate long expressions
            if len(match) > 200:
                match = match[:200] + "..."
            result.eval_chains.append(match)

    def _extract_shell_commands(self, code: str, result: DeobfuscationResult) -> None:
        """Extract shell commands (for VBScript/JScript in HTML applications).

        Args:
            code: JavaScript code
            result: Result object to update
        """
        # Look for WScript.Shell commands
        patterns = [
            r'WScript\.Shell.*?\.Run\s*\(["\']([^"\']+)["\']',
            r'WScript\.Shell.*?\.Exec\s*\(["\']([^"\']+)["\']',
            r'cmd\.exe.*?/c\s+([^"\';\n]+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            result.shell_commands.extend(matches[:10])  # Limit to first 10

        if result.shell_commands:
            result.anomalies.append(
                f"Executes shell commands: {len(result.shell_commands)} found"
            )

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text.

        Args:
            text: Text to analyze

        Returns:
            Entropy value
        """
        import math
        from collections import Counter

        if not text:
            return 0.0

        # Calculate frequency of each character
        counts = Counter(text)
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy
