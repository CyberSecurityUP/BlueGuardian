# Analysis Reports Storage

This directory stores generated analysis reports in various formats.

## Directory Structure

Reports are organized by date and format:

```
reports/
├── 2025-01-15/
│   ├── json/
│   │   ├── report-abc123.json
│   │   └── report-def456.json
│   ├── html/
│   │   ├── report-abc123.html
│   │   └── report-def456.html
│   └── pdf/
│       ├── report-abc123.pdf
│       └── report-def456.pdf
└── 2025-01-16/
    └── ...
```

## Report Formats

### JSON Reports
Machine-readable format for API consumption and automation.
- Full analysis results
- IOCs in structured format
- MITRE ATT&CK techniques
- Metadata and timestamps

### HTML Reports
Human-readable format for viewing in browsers.
- Styled presentation
- Charts and visualizations
- Syntax highlighting
- Print-friendly layout

### PDF Reports
Professional format for documentation and sharing.
- Executive summary
- Technical details
- IOC tables
- MITRE ATT&CK matrix visualization

### Markdown Reports
Plain text format for documentation and wikis.
- Easy to read and edit
- Version control friendly
- Can be converted to other formats

## File Naming Convention

Format: `report-{job_id}.{format}`

Example: `report-550e8400-e29b-41d4-a716-446655440000.pdf`

## Accessing Reports

### Via API
```bash
# Download HTML report
curl http://localhost:8000/api/v1/jobs/{job_id}/report/html -o report.html

# Download PDF report
curl http://localhost:8000/api/v1/jobs/{job_id}/report/pdf -o report.pdf
```

### Via CLI
```bash
# Generate report
blueguardian report {job_id} --format pdf --output report.pdf
```

### Via Web UI
Navigate to Job Details → Download Report → Select Format

## Storage Configuration

```bash
# In .env or settings
REPORTS_STORAGE_PATH=./storage/reports
REPORTS_RETENTION_DAYS=90
MAX_REPORT_SIZE_MB=50
```

## Cleanup

```bash
# Remove reports older than 90 days
find storage/reports -type f -mtime +90 -delete

# Remove empty directories
find storage/reports -type d -empty -delete
```

## Backup

```bash
# Backup reports to archive
tar -czf reports-backup-$(date +%Y%m%d).tar.gz storage/reports/
```

## Security

- Reports may contain sensitive information
- Implement access controls
- Consider encrypting PDF reports with passwords
- Sanitize before sharing externally
