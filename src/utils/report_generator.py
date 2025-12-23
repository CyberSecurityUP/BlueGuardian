"""Report generation system for analysis results.

This module generates reports in multiple formats (JSON, HTML, PDF)
from analysis results.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger

from src.agents.base_agent import AnalysisResult, Verdict


class ReportGenerator:
    """Generator for analysis reports in multiple formats."""

    def __init__(self, template_dir: Optional[Path] = None):
        """Initialize report generator.

        Args:
            template_dir: Directory containing report templates
        """
        self.template_dir = template_dir or Path("templates")
        self.template_dir.mkdir(exist_ok=True)

        logger.info("Initialized ReportGenerator")

    def generate_json_report(
        self,
        result: AnalysisResult,
        output_path: Optional[str] = None,
    ) -> str:
        """Generate JSON report.

        Args:
            result: Analysis result
            output_path: Optional path to save report

        Returns:
            JSON string
        """
        logger.debug(f"Generating JSON report for {result.artifact_name}")

        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'generator': 'BlueGuardian AI',
                'version': '1.0.0',
            },
            'analysis': {
                'artifact_name': result.artifact_name,
                'agent_name': result.agent_name,
                'started_at': result.started_at.isoformat(),
                'completed_at': result.completed_at.isoformat() if result.completed_at else None,
                'duration_seconds': result.duration_seconds,
                'status': result.status.value,
            },
            'verdict': {
                'verdict': result.verdict.value,
                'confidence': result.confidence,
                'summary': result.summary,
            },
            'iocs': [
                {
                    'type': ioc.type,
                    'value': ioc.value,
                    'confidence': ioc.confidence,
                    'description': ioc.description,
                }
                for ioc in result.iocs
            ],
            'mitre_attack': {
                'techniques': result.mitre_techniques,
            },
            'tags': result.tags,
            'details': result.details,
            'warnings': result.warnings,
            'errors': result.errors,
        }

        json_str = json.dumps(report, indent=2, ensure_ascii=False)

        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            logger.info(f"JSON report saved to {output_path}")

        return json_str

    def generate_html_report(
        self,
        result: AnalysisResult,
        output_path: Optional[str] = None,
    ) -> str:
        """Generate HTML report.

        Args:
            result: Analysis result
            output_path: Optional path to save report

        Returns:
            HTML string
        """
        logger.debug(f"Generating HTML report for {result.artifact_name}")

        # Determine verdict color
        verdict_colors = {
            Verdict.MALICIOUS: '#dc3545',  # Red
            Verdict.SUSPICIOUS: '#ffc107',  # Yellow
            Verdict.CLEAN: '#28a745',  # Green
            Verdict.UNKNOWN: '#6c757d',  # Gray
        }
        verdict_color = verdict_colors.get(result.verdict, '#6c757d')

        # Format IOCs table
        iocs_html = self._format_iocs_html(result.iocs)

        # Format MITRE ATT&CK
        mitre_html = self._format_mitre_html(result.mitre_techniques)

        # Format tags
        tags_html = ' '.join([f'<span class="badge">{tag}</span>' for tag in result.tags])

        # Build HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlueGuardian AI - Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007bff;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .header .meta {{
            color: #666;
            font-size: 0.9em;
        }}
        .verdict {{
            background: {verdict_color};
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .verdict h2 {{
            font-size: 1.8em;
            margin-bottom: 10px;
        }}
        .verdict .confidence {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .section h3 {{
            color: #007bff;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #007bff;
            margin-bottom: 20px;
            white-space: pre-wrap;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #007bff;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            background: #007bff;
            color: white;
            border-radius: 4px;
            font-size: 0.85em;
            margin-right: 5px;
            margin-bottom: 5px;
        }}
        .technique-badge {{
            background: #6f42c1;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }}
        .stat-card h4 {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        .stat-card p {{
            font-size: 1.5em;
            font-weight: 600;
            color: #333;
        }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px 15px;
            margin: 10px 0;
        }}
        .error {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 10px 15px;
            margin: 10px 0;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ BlueGuardian AI Security Analysis Report</h1>
            <div class="meta">
                <strong>Artifact:</strong> {result.artifact_name}<br>
                <strong>Agent:</strong> {result.agent_name}<br>
                <strong>Analyzed:</strong> {result.started_at.strftime('%Y-%m-%d %H:%M:%S')}<br>
                <strong>Duration:</strong> {result.duration_seconds:.2f}s
            </div>
        </div>

        <div class="verdict">
            <h2>Verdict: {result.verdict.value.upper()}</h2>
            <div class="confidence">Confidence: {result.confidence:.0%}</div>
        </div>

        <div class="section">
            <h3>📋 Executive Summary</h3>
            <div class="summary">{result.summary or 'No summary available.'}</div>
        </div>

        <div class="section">
            <h3>📊 Analysis Statistics</h3>
            <div class="stat-grid">
                <div class="stat-card">
                    <h4>IOCs Found</h4>
                    <p>{len(result.iocs)}</p>
                </div>
                <div class="stat-card">
                    <h4>MITRE Techniques</h4>
                    <p>{len(result.mitre_techniques)}</p>
                </div>
                <div class="stat-card">
                    <h4>Tags</h4>
                    <p>{len(result.tags)}</p>
                </div>
                <div class="stat-card">
                    <h4>Confidence</h4>
                    <p>{result.confidence:.0%}</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h3>🏷️ Tags</h3>
            {tags_html if result.tags else '<p>No tags.</p>'}
        </div>

        <div class="section">
            <h3>🔍 Indicators of Compromise (IOCs)</h3>
            {iocs_html}
        </div>

        <div class="section">
            <h3>🎯 MITRE ATT&CK Techniques</h3>
            {mitre_html}
        </div>

        {'<div class="section"><h3>⚠️ Warnings</h3>' + ''.join([f'<div class="warning">{w}</div>' for w in result.warnings]) + '</div>' if result.warnings else ''}

        {'<div class="section"><h3>❌ Errors</h3>' + ''.join([f'<div class="error">{e}</div>' for e in result.errors]) + '</div>' if result.errors else ''}

        <div class="footer">
            <p>Generated by <strong>BlueGuardian AI v1.0.0</strong></p>
            <p>Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""

        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            logger.info(f"HTML report saved to {output_path}")

        return html

    def _format_iocs_html(self, iocs) -> str:
        """Format IOCs as HTML table."""
        if not iocs:
            return '<p>No IOCs found.</p>'

        rows = []
        for ioc in iocs:
            rows.append(f"""
                <tr>
                    <td><span class="badge">{ioc.type}</span></td>
                    <td><code>{ioc.value}</code></td>
                    <td>{ioc.confidence:.0%}</td>
                    <td>{ioc.description or 'N/A'}</td>
                </tr>
            """)

        return f"""
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Confidence</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        """

    def _format_mitre_html(self, techniques) -> str:
        """Format MITRE techniques as HTML."""
        if not techniques:
            return '<p>No MITRE ATT&CK techniques identified.</p>'

        badges = [f'<span class="badge technique-badge">{tech}</span>' for tech in techniques]
        return ' '.join(badges)

    def generate_pdf_report(
        self,
        result: AnalysisResult,
        output_path: str,
    ) -> None:
        """Generate PDF report.

        Args:
            result: Analysis result
            output_path: Path to save PDF

        Note:
            Requires weasyprint or similar library for HTML to PDF conversion.
            For now, generates HTML report.
        """
        logger.debug(f"Generating PDF report for {result.artifact_name}")

        try:
            # Try to use weasyprint if available
            from weasyprint import HTML

            # Generate HTML first
            html_content = self.generate_html_report(result)

            # Convert to PDF
            HTML(string=html_content).write_pdf(output_path)

            logger.info(f"PDF report saved to {output_path}")

        except ImportError:
            logger.warning("weasyprint not installed, generating HTML instead")
            # Fallback to HTML
            html_path = output_path.replace('.pdf', '.html')
            self.generate_html_report(result, html_path)
            logger.info(f"HTML report saved to {html_path} (install weasyprint for PDF support)")

    def generate_markdown_report(
        self,
        result: AnalysisResult,
        output_path: Optional[str] = None,
    ) -> str:
        """Generate Markdown report.

        Args:
            result: Analysis result
            output_path: Optional path to save report

        Returns:
            Markdown string
        """
        logger.debug(f"Generating Markdown report for {result.artifact_name}")

        # Build markdown
        md = f"""# BlueGuardian AI Security Analysis Report

## Artifact Information
- **File**: {result.artifact_name}
- **Agent**: {result.agent_name}
- **Analyzed**: {result.started_at.strftime('%Y-%m-%d %H:%M:%S')}
- **Duration**: {result.duration_seconds:.2f}s

## Verdict
**{result.verdict.value.upper()}** (Confidence: {result.confidence:.0%})

## Executive Summary
{result.summary or 'No summary available.'}

## Statistics
- IOCs Found: {len(result.iocs)}
- MITRE Techniques: {len(result.mitre_techniques)}
- Tags: {len(result.tags)}

## Tags
{', '.join([f'`{tag}`' for tag in result.tags]) if result.tags else 'None'}

## Indicators of Compromise

"""

        if result.iocs:
            md += "| Type | Value | Confidence | Description |\n"
            md += "|------|-------|------------|-------------|\n"
            for ioc in result.iocs:
                md += f"| `{ioc.type}` | `{ioc.value}` | {ioc.confidence:.0%} | {ioc.description or 'N/A'} |\n"
        else:
            md += "No IOCs found.\n"

        md += "\n## MITRE ATT&CK Techniques\n\n"
        if result.mitre_techniques:
            for tech in result.mitre_techniques:
                md += f"- `{tech}`\n"
        else:
            md += "No techniques identified.\n"

        if result.warnings:
            md += "\n## Warnings\n\n"
            for warning in result.warnings:
                md += f"⚠️ {warning}\n\n"

        if result.errors:
            md += "\n## Errors\n\n"
            for error in result.errors:
                md += f"❌ {error}\n\n"

        md += f"\n---\n*Generated by BlueGuardian AI v1.0.0 at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md)
            logger.info(f"Markdown report saved to {output_path}")

        return md
